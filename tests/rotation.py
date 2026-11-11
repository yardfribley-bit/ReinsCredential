"""Local-only graceful log rotation contract; creates no external connection."""
import json
import os
import pathlib
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(os.environ.get('AGENT_MONITOR_BINARY', ROOT / 'agent-monitor'))
checks = []

with tempfile.TemporaryDirectory(prefix='agentsec-rotation-') as directory:
    root = pathlib.Path(directory)
    for label, prefix in [('threshold_during_collection', b''), ('already_over_threshold', b'{}\n')]:
        log = root / (label + '.jsonl')
        log.write_bytes(prefix)
        log.chmod(0o600)
        threshold = 2048 if not prefix else 1
        result = subprocess.run([str(BINARY), '--log', str(log), '--max-log-bytes', str(threshold),
                                 '--duration', '20', '--interval-ms', '100', '--sensitive', str(root)],
                                capture_output=True, timeout=45)
        assert result.returncode == 3, (label, result.returncode, result.stderr.decode(errors='replace'))
        data = log.read_bytes()
        assert data.startswith(prefix) and data.endswith(b'\n')
        records = [json.loads(line) for line in data[len(prefix):].splitlines()]
        final = records[-1]
        assert final['type'] == 'shutdown_summary'
        assert final['metrics']['log_rotation_required'] == 1
        assert final['metrics']['log_limit_bytes'] == threshold
        assert final['metrics']['shutdown_flush_not_filesystem_barrier'] == 1
        assert all(isinstance(final['metrics'][name], int) for name in
                   ['retirement_pending', 'retirement_retry_exhausted', 'cooccurrence_pairs_truncated'])
        assert data and len(data) >= threshold
        assert [r['sequence'] for r in records] == list(range(1, len(records) + 1))
        assert not result.stdout and not result.stderr
        checks.append({'case': label, 'passed': True, 'exit_code': result.returncode,
                       'threshold_bytes': threshold, 'final_bytes': len(data), 'records': len(records)})
    for value in ['0', '-1', '1x', '18446744073709551616']:
        result = subprocess.run([str(BINARY), '--max-log-bytes', value], capture_output=True, timeout=5)
        assert result.returncode == 1 and json.loads(result.stderr)['type'] == 'fatal_error'
        checks.append({'case': 'reject_invalid_limit_' + value, 'passed': True})

summary = {'test_kind': 'daemon_rotation_contract', 'passed': True, 'checks': checks,
           'limits': ['Threshold is checked between scans; queued records and final summary can overshoot.',
                      'Backend requests rotation; the native supervisor owns rename, retention and restart.']}
output = pathlib.Path(os.environ.get('AGENTSEC_ROTATION_REPORT', ROOT / 'tests/results/rotation.json'))
output.write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary))
