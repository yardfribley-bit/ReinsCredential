"""Measure implemented controls and known misses against independent ground truth.
Exit 0 means regression expectations held; --require-full-acceptance also fails on
any detection miss. Fixtures are never counted as autonomous real-agent tests.
"""
import argparse
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import uuid
from acceptance_support import ROOT, Receiver, load_records, request, sanitized_record, sha, spawn, stop, wait_for

parser = argparse.ArgumentParser()
parser.add_argument('--report', default='tests/results/acceptance_matrix.json')
parser.add_argument('--require-full-acceptance', action='store_true')
args = parser.parse_args()
root = pathlib.Path(tempfile.mkdtemp(prefix='as-matrix-', dir='/private/tmp'))
run_id = str(uuid.uuid4())
source = root / 'synthetic.env'
source.write_text('TEST_ONLY_SECRET="' + str(uuid.uuid4()) + '"\n')
os.chmod(source, 0o600)
receiver = Receiver(root / 'receipts.jsonl')
gateway_log, passive_log = root / 'gateway.jsonl', root / 'passive.jsonl'
sock = root / 'g.sock'
processes = []
report = {'run_id': run_id, 'test_kind': 'synthetic_behavior_matrix_not_real_agent',
          'synthetic_only': True, 'source_sha256': sha(source.read_bytes()), 'cases': [], 'checks': {},
          'full_acceptance_passed': False, 'limits': ['gateway is opt-in, bypass remains possible',
          'whole-content matching does not cover arbitrary transformations',
          'local receiver is not an external internet server or a model service']}

def check(name, passed, **details):
    report['checks'][name] = {'passed': bool(passed), **details}

def has_root(record):
    return any(pathlib.Path(a['executable']).name == 'codex' for a in (record.get('actor_process') or {}).get('ppid_tree', []))

try:
    gateway = spawn([str(ROOT / 'agent-gateway'), '--socket', str(sock), '--log', str(gateway_log),
                     '--sensitive-file', str(source), '--upstream', receiver.url, '--allow-loopback-http'], root, 'gateway')
    processes.append(gateway)
    passive = spawn([str(ROOT / 'agent-monitor'), '--log', str(passive_log), '--sensitive', str(source),
                     '--interval-ms', '100'], root, 'passive')
    processes.append(passive)
    wait_for(lambda: any(r['type'] == 'gateway_ready' for r in load_records(gateway_log)))
    wait_for(lambda: any(r['type'] == 'coverage' for r in load_records(passive_log)))
    status, content = request(sock, 'GET', '/read')
    check('mediated_read_exact_bytes', status == 200 and content == source.read_bytes())
    definitions = [(mode, False) for mode in ('raw', 'json', 'base64') for _ in range(5)]
    definitions += [('benign', False)] * 20
    definitions += [(mode, False) for mode in ('read_only', 'open_only', 'read_then_delay', 'gzip', 'split')]
    definitions += [('raw', True)] * 5
    for index, (mode, direct) in enumerate(definitions):
        if gateway.poll() is not None or passive.poll() is not None:
            raise RuntimeError('a detector exited before all cases completed')
        case_id = f'{index:02d}-{mode}-' + str(uuid.uuid4())
        config_path = root / f'case-{index}.json'
        proof_path = root / f'proof-{index}.json'
        config_path.write_text(json.dumps({'mode': mode, 'direct': direct, 'case_id': case_id,
            'source': str(source), 'socket': str(sock), 'upstream': receiver.url, 'proof': str(proof_path)}))
        start = time.monotonic()
        process = subprocess.run(['/usr/bin/python3', str(ROOT / 'tests/acceptance_fixture.py'), str(config_path)],
                                 capture_output=True, text=True, timeout=30)
        if process.returncode:
            raise RuntimeError('fixture failed: ' + process.stderr[-500:])
        proof = json.loads(proof_path.read_text())
        if gateway.poll() is not None or passive.poll() is not None:
            raise RuntimeError('a detector exited during a case; coverage result invalid')
        # Flush-aware event polling; no artificial file-descriptor hold for positive sends.
        if proof['requests'] and not direct:
            hashes = {p['body_sha256'] for p in proof['requests']}
            wait_for(lambda: len([r for r in load_records(gateway_log) if r['type'] == 'transfer_result' and r['content_sha256'] in hashes]) == len(hashes))
        events = load_records(gateway_log)
        hashes = {p['body_sha256'] for p in proof['requests']}
        hits = [r for r in events if r['type'] == 'sensitive_payload_observed' and r['content_sha256'] in hashes]
        transfers = [r for r in events if r['type'] == 'transfer_result' and r['content_sha256'] in hashes]
        received = [r for r in receiver.receipts if r['body_sha256'] in hashes]
        expect = mode in ('raw', 'json', 'base64', 'read_then_delay', 'gzip') and not direct
        truth_sensitive_send = mode not in ('benign', 'read_only', 'open_only')
        result = {'case_id': case_id, 'mode': mode, 'direct_bypass': direct, 'fixture_pid': proof['pid'],
            'source_read': proof['source_read'], 'read_duration_us': proof.get('read_duration_us'),
            'truth_sensitive_send': truth_sensitive_send, 'ground_truth': proof['requests'],
            'independent_receipt_count': len(received), 'detected': bool(hits),
            'detection_status': ('TP' if hits else 'FN') if truth_sensitive_send else ('FP' if hits else 'TN'),
            'regression_expectation_met': bool(hits) == expect,
            'actor_pid_correct': all(r['actor_process']['process']['identity']['pid'] == proof['pid'] for r in hits + transfers) if hits or transfers else None,
            'destination_correct': all(r['destination'] == receiver.url for r in hits + transfers) if hits or transfers else None,
            'upstream_receipts_verified': len(received) == len(proof['requests']) and all(p['receiver_ack'] and p['receiver_ack']['body_sha256'] == p['body_sha256'] for p in proof['requests']) if proof['requests'] else None,
            'wall_ms': round((time.monotonic() - start) * 1000, 2),
            'evidence': [sanitized_record(r, root) for r in hits + transfers]}
        report['cases'].append(result)
    # Negative HTTP/protocol and durability checks.
    before = len(receiver.receipts)
    status, _ = request(sock, 'GET', '/unknown')
    check('unknown_route_rejected', status == 400 and len(receiver.receipts) == before)
    def malformed(data):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(sock)); client.sendall(data)
            return client.recv(4096).startswith(b'HTTP/1.1 400')
    check('duplicate_content_length_rejected', malformed(b'POST /submit HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n'))
    check('chunked_request_rejected', malformed(b'POST /submit HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'))
    check('oversize_body_rejected', malformed(b'POST /submit HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n'))
    check('no_protocol_failure_forwarded', len(receiver.receipts) == before)
    # Even a spoofed PID header cannot change the kernel-derived identity.
    status, _ = request(sock, 'POST', '/submit', b'benign-spoof-header-check', {'X-Agent-Pid': '1'})
    wait_for(lambda: any(r.get('content_sha256') == sha(b'benign-spoof-header-check') for r in load_records(gateway_log)))
    spoof = [r for r in load_records(gateway_log) if r.get('content_sha256') == sha(b'benign-spoof-header-check')]
    check('client_pid_header_ignored', status == 200 and bool(spoof) and all(r['actor_process']['process']['identity']['pid'] == os.getpid() for r in spoof))
    original = source.read_bytes()
    source.write_bytes(b'REPLACED_SYNTHETIC_VERSION_' + uuid.uuid4().hex.encode())
    status, _ = request(sock, 'GET', '/read')
    check('changed_source_version_rejected', status == 400)
    source.write_bytes(original)
    # Actual transfer failure must not become a confirmed success.
    receiver.close()
    status, _ = request(sock, 'POST', '/submit', b'failed-transfer-' + original)
    check('unreachable_upstream_returns_failure', status == 502)
    wait_for(lambda: any(r['type'] == 'transfer_result' and r['transfer_outcome'].startswith('failed_') for r in load_records(gateway_log)))
    time.sleep(1)
    for process in processes:
        stop(process)
    ge, pe = load_records(gateway_log), load_records(passive_log)
    # Every completed file must parse, rather than silently ignoring a partial tail.
    check('complete_jsonl_after_shutdown', all(json.loads(line) for path in (gateway_log, passive_log) for line in path.read_text().splitlines()))
    check('clean_shutdown', all(p.returncode == 0 for p in processes))
    check('socket_removed_after_shutdown', not sock.exists())
    check('evidence_permissions_0600', all((p.stat().st_mode & 0o777) == 0o600 for p in (gateway_log, passive_log)))
    check('payload_not_persisted', original.decode() not in gateway_log.read_text() and original.decode() not in passive_log.read_text())
    check('unique_event_ids', len({r['event_id'] for r in ge}) == len(ge))
    check('monotonic_sequences', [r['sequence'] for r in ge] == list(range(1, len(ge) + 1)))
    check('delivery_and_upload_correlation', any(r['type'] == 'sensitive_payload_observed' and r['related_event_ids'] for r in ge))
    check('raw_read_claim_not_fabricated', all('not_native_peer_read' in r['evidence_basis'] for r in ge if r['type'] == 'sensitive_content_delivered'))
    for case in report['cases']:
        observed = [r for r in pe if (r.get('actor_process') or {}).get('process', {}).get('identity', {}).get('pid') == case['fixture_pid']]
        case['passive_process_seen'] = any(r['type'] in ('agent_discovered', 'process_discovered') for r in observed)
        case['passive_sensitive_fd_seen'] = any(r.get('detail', '').startswith('sensitive_file_open:') for r in observed)
        case['passive_content_upload_confirmed'] = any(r['type'] == 'sensitive_payload_observed' for r in observed)
        case['passive_cooccurrence_signal'] = any('risk_signal:' in r.get('detail', '') for r in observed)
    counts = {kind: sum(c['detection_status'] == kind for c in report['cases']) for kind in ('TP', 'TN', 'FP', 'FN')}
    report['confusion_matrix_all_cases'] = counts
    report['scope'] = {'mediated_supported_positives': sum(c['truth_sensitive_send'] and not c['direct_bypass'] and c['mode'] != 'split' for c in report['cases']),
                       'negative_cases': counts['TN'] + counts['FP'], 'blind_spot_cases': counts['FN']}
    report['regression_passed'] = all(c['regression_expectation_met'] and c['actor_pid_correct'] is not False and c['destination_correct'] is not False and c['upstream_receipts_verified'] is not False for c in report['cases']) and all(c['passed'] for c in report['checks'].values())
    report['private_evidence_sha256'] = {name: sha(path.read_bytes()) for name, path in [('gateway', gateway_log), ('passive', passive_log), ('receiver', receiver.receipt_path)]}
    report['environment'] = {'os': subprocess.check_output(['/usr/bin/sw_vers', '-productVersion'], text=True).strip(),
                             'arch': os.uname().machine, 'sampling_interval_ms': 100, 'uid_is_root': os.geteuid() == 0}
    report['full_acceptance_passed'] = counts['FN'] == 0 and counts['FP'] == 0 and report['regression_passed']
finally:
    for process in processes:
        stop(process)
    if receiver.thread.is_alive():
        receiver.close()
path = ROOT / args.report
path.parent.mkdir(exist_ok=True)
path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'private_workspace': str(root), 'report': str(path), 'regression_passed': report.get('regression_passed'),
                  'full_acceptance_passed': report['full_acceptance_passed'], 'matrix': report.get('confusion_matrix_all_cases'),
                  'failed_checks': [k for k, v in report['checks'].items() if not v['passed']]}))
raise SystemExit(0 if report.get('regression_passed') and (not args.require_full_acceptance or report['full_acceptance_passed']) else 2)
