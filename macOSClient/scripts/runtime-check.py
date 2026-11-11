#!/usr/bin/env python3
"""Native supervisor acceptance; only generated files and loopback sockets.

Run after `make` and `swift build --package-path macOSClient`:
  python3 macOSClient/scripts/runtime-check.py
No LaunchAgent is installed; every supervisor uses an isolated /private/tmp root.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import signal
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--runtime', type=pathlib.Path, default=ROOT / 'macOSClient/.build/debug/ReinsRuntime')
parser.add_argument('--monitor', type=pathlib.Path, default=ROOT / 'agent-monitor')
parser.add_argument('--report', type=pathlib.Path, default=ROOT / 'macOSClient/tests-results/runtime.json')
args = parser.parse_args()
args.runtime = args.runtime.resolve()
args.monitor = args.monitor.resolve()
cases = []


def check(name, predicate, description):
    if not predicate:
        cases.append(dict(name=name, status='FAIL', detail=description))
        raise AssertionError(description)
    cases.append(dict(name=name, status='PASS', detail=description))


def wait_for(predicate, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError('Timed out waiting for supervisor condition')


def load_status(base):
    try:
        with (base / 'runtime/status.plist').open('rb') as source:
            return plistlib.load(source)
    except (FileNotFoundError, plistlib.InvalidFileException):
        return {}


def records(base):
    try:
        data = (base / 'runtime/evidence.jsonl').read_text()
    except FileNotFoundError:
        return []
    values = []
    for line in data.splitlines():
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # A concurrently appended final line is not yet complete.
    return values


def write_config(base, paths, interval=100):
    name = base / '.config-test-tmp'
    with name.open('wb') as output:
        os.chmod(name, 0o600)
        plistlib.dump(dict(sensitivePaths=[str(p) for p in paths], intervalMilliseconds=interval), output)
        output.flush()
        os.fsync(output.fileno())
    os.replace(name, base / 'config.plist')


def start(base, monitor, output):
    return subprocess.Popen([str(args.runtime), '--data-root', str(base), '--monitor', str(monitor)],
                            stdout=output, stderr=output)


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError('Supervisor did not terminate within the shutdown budget')


def exists(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def native_case(root, output):
    base = root / 'native'
    base.mkdir(mode=0o700)
    sensitive = root / 'synthetic.env'
    sensitive.write_text('REINS_SYNTHETIC_ONLY=runtime-test\n')
    os.chmod(sensitive, 0o600)
    write_config(base, [sensitive])
    supervisor = probe = None
    try:
        supervisor = start(base, args.monitor, output)
        def running():
            if supervisor.poll() is not None:
                raise AssertionError('Supervisor exited before ready: status ' + str(supervisor.returncode))
            s = load_status(base)
            return s if s.get('state') == 'running' else None
        state = wait_for(running)
        monitor_pid = state['monitorPID']
        coverage = wait_for(lambda: next((r for r in records(base) if r.get('type') == 'coverage'), None), 60)
        epoch = state['monitorStartedAt'].replace(tzinfo=datetime.timezone.utc).timestamp()
        check('live_monitor_epoch', coverage['timestamp'] / 1_000_000 >= epoch,
              'A current monitor emits coverage at or after the supervisor monitor-start epoch.')
        check('private_runtime_files', (base / 'runtime/evidence.jsonl').stat().st_mode & 0o777 == 0o600 and
              (base / 'runtime/status.plist').stat().st_mode & 0o777 == 0o600,
              'Live evidence and status are private mode 0600.')
        duplicate = start(base, args.monitor, output)
        check('single_instance_lock', duplicate.wait(timeout=10) != 0 and
              load_status(base).get('supervisorPID') == supervisor.pid,
              'A second supervisor is refused without overwriting the first status.')
        probe_path = base / 'runtime/self-test/synthetic.env'
        probe_path.write_text('SYNTHETIC_TEST_DATA_ONLY\n')
        os.chmod(probe_path, 0o600)
        probe = subprocess.Popen([str(args.runtime), '--probe', str(probe_path), '--hold-seconds', '10'],
                                 stdout=subprocess.PIPE, stderr=output, text=True)
        ready = probe.stdout.readline().strip()
        check('synthetic_probe_ready', ready == 'PROBE_READY ' + str(probe.pid),
              'Bundled probe opens the synthetic file and connects only to loopback.')
        def matching_pair():
            for item in records(base):
                actor = (item.get('actor_process') or {}).get('process', {}).get('identity', {})
                if item.get('type') == 'sensitive_network_cooccurrence' and actor.get('pid') == probe.pid and item.get('target_resource') == str(probe_path):
                    return item
        pair = wait_for(matching_pair, 20)
        check('live_synthetic_file_peer_detection', pair['destination'].startswith('127.0.0.1:') and
              pair['evidence_basis'] == 'same_identity_descriptor_snapshot' and
              not pair['transfer_outcome'] and not pair['content_sha256'],
              'Real monitor independently associates the probe identity, synthetic path and loopback peer; no upload claim.')
        actor = pair['actor_process']
        check('live_identity_and_ancestor_chain', actor['process']['identity']['start_seconds'] > 0 and
              any(p['identity']['pid'] == os.getpid() for p in actor['ppid_tree']),
              'The probe identity includes start time and its observed Python test parent appears in the ancestor chain.')
        check('probe_completed', probe.wait(timeout=15) == 0, 'Probe exits normally after holding descriptors.')
        previous_session = state['sessionID']
        write_config(base, [sensitive], interval=250)
        restarted = wait_for(lambda: s if (s := load_status(base)).get('state') == 'running' and
                             s.get('sessionID') != previous_session else None, 45)
        check('configuration_reload_restarts_monitor', restarted['monitorPID'] != monitor_pid and not exists(monitor_pid),
              'Changing saved configuration gracefully replaces the owned monitor with a fresh session.')
        archives = list((base / 'runtime/archives').glob('*.jsonl'))
        check('restart_archives_previous_evidence', len(archives) == 1 and
              json.loads(archives[0].read_text().splitlines()[-1])['type'] == 'shutdown_summary',
              'The prior closed log is archived with a shutdown summary before a new log is opened.')
        new_pid = restarted['monitorPID']
        stop(supervisor)
        check('signal_shutdown_reaps_child', supervisor.returncode == 0 and not exists(new_pid) and
              load_status(base).get('state') == 'stopped',
              'SIGTERM stops the supervisor and its owned monitor, reaps the child and publishes stopped.')
    finally:
        if probe and probe.poll() is None:
            probe.terminate()
            probe.wait(timeout=5)
        stop(supervisor)


def mock_cases(root, output):
    # Deliberately synthetic executable: these cases exercise supervisor control
    # flow, while native_case above exercises actual C++ observations.
    source = root / 'mock.c'
    executable = root / 'mock-monitor'
    source.write_text(r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
  const char *log=NULL; for(int i=1;i+1<argc;i++) if(!strcmp(argv[i],"--log")) log=argv[++i];
  if(!log) return 90;
  int count=0; FILE *old=fopen("starts","r"); if(old){fscanf(old,"%d",&count);fclose(old);}
  FILE *state=fopen("starts","w"); if(!state)return 91; fprintf(state,"%d",++count);fclose(state);
  int fd=open(log,O_WRONLY|O_CREAT|O_EXCL,0600); if(fd<0)return 92;
  dprintf(fd,"{\"synthetic_mock_start\":%d}\n",count); fsync(fd); close(fd);
  if(access("force_failure",F_OK)==0)return 9;
  if(count<=7)return 3;
  while(1) pause();
}
''')
    subprocess.run(['/usr/bin/clang', str(source), '-o', str(executable)], check=True, stdout=output, stderr=output)
    base = root / 'rotation'
    base.mkdir(mode=0o700)
    write_config(base, [root / 'synthetic.env'])
    supervisor = None
    try:
        supervisor = start(base, executable, output)
        wait_for(lambda: (base / 'runtime/starts').exists() and (base / 'runtime/starts').read_text() == '8')
        state = wait_for(lambda: s if (s := load_status(base)).get('state') == 'running' else None)
        archives = list((base / 'runtime/archives').glob('*.jsonl'))
        check('rotation_exit3_restart', len(archives) == 5 and
              records(base) == [dict(synthetic_mock_start=8)],
              'Synthetic exit 3 repeatedly rotates and restarts; only five prior log archives remain.')
        pid = state['monitorPID']
        stop(supervisor)
        check('mock_shutdown_has_no_child', not exists(pid), 'An owned synthetic child is also reaped on supervisor shutdown.')
    finally:
        stop(supervisor)
    failure_base = root / 'failure'
    failure_base.mkdir(mode=0o700)
    write_config(failure_base, [root / 'synthetic.env'])
    (failure_base / 'runtime').mkdir(mode=0o700)
    (failure_base / 'runtime/force_failure').touch(mode=0o600)
    try:
        supervisor = start(failure_base, executable, output)
        failed = wait_for(lambda: s if (s := load_status(failure_base)).get('state') == 'failed' else None, 85)
        check('bounded_failure_retry', (failure_base / 'runtime/starts').read_text() == '5' and
              'monitorPID' not in failed and supervisor.poll() is None,
              'Five synthetic failures trip the retry budget; the live supervisor reports failed without a monitor.')
        time.sleep(2)
        check('failure_circuit_stays_open', (failure_base / 'runtime/starts').read_text() == '5',
              'Failure state does not immediately respawn another child.')
    finally:
        stop(supervisor)


result = 'FAIL'
try:
    with tempfile.TemporaryDirectory(prefix='reins-runtime-e2e-', dir='/private/tmp') as temporary:
        root = pathlib.Path(temporary)
        with (root / 'private-output.log').open('wb') as output:
            os.chmod(root / 'private-output.log', 0o600)
            native_case(root, output)
            mock_cases(root, output)
    result = 'PASS'
except Exception as error:
    cases.append(dict(name='integration_completion', status='FAIL', detail=str(error)))
    raise
finally:
    report = dict(result=result, generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  platform=dict(system=platform.system(), version=platform.mac_ver()[0], architecture=platform.machine()),
                  scope='Isolated runtime processes; no LaunchAgent installation; generated data and loopback only.',
                  binaries={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
                            [('runtime', args.runtime), ('monitor', args.monitor)]},
                  cases=cases, counts=dict(passed=sum(c['status'] == 'PASS' for c in cases),
                                          failed=sum(c['status'] == 'FAIL' for c in cases)))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': result, 'counts': report['counts'], 'report': str(args.report)}))
