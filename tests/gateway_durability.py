"""Independent receiver proves no payload is sent after admission-log failure.
Uses only a synthetic file, loopback server and RLIMIT_FSIZE on owned children.
"""
import http.client
import http.server
import json
import os
import pathlib
import resource
import signal
import subprocess
import tempfile
import threading
import time
from acceptance_support import ROOT, load_records, request, sha, stop, wait_for

root = pathlib.Path(tempfile.mkdtemp(prefix='as-durable-', dir='/private/tmp'))
source = root / 'synthetic.env'
source.write_bytes(b'TEST_ONLY_DURABILITY_0123456789abcdef\n')
received, checks = [], {}
current_log = None

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        # Observed independently at the moment of receipt, not read from the client.
        events = load_records(current_log)
        admission = [event for event in events if event['type'] == 'sensitive_payload_observed'
                     and event['content_sha256'] == sha(body)]
        received.append({'sha256': sha(body), 'admission_already_readable': bool(admission)})
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
processes = []
try:
    for label, limited, method in [('success', False, 'POST'), ('write_fail_forward', True, 'POST'), ('write_fail_read', True, 'GET')]:
        folder = root / label
        folder.mkdir(mode=0o700)
        current_log = folder / 'evidence.jsonl'
        sock = folder / 'g.sock'
        def limit_child():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
        command = [os.environ.get('AGENT_GATEWAY_BINARY', str(ROOT / 'agent-gateway')), '--socket', str(sock),
                   '--log', str(current_log), '--sensitive-file', str(source),
                   '--upstream', f'http://127.0.0.1:{server.server_port}/ingest', '--allow-loopback-http']
        with (folder / 'stdout').open('wb') as out, (folder / 'stderr').open('wb') as err:
            process = subprocess.Popen(command, stdout=out, stderr=err, preexec_fn=limit_child if limited else None)
        processes.append(process)
        wait_for(lambda: any(r['type'] == 'gateway_ready' for r in load_records(current_log)))
        assert process.poll() is None, 'failure must occur after successful startup'
        before = len(received)
        response_body, status, error = b'', None, None
        try:
            status, response_body = request(sock, method, '/submit' if method == 'POST' else '/read',
                                            source.read_bytes() if method == 'POST' else None)
        except (OSError, http.client.HTTPException) as failure:
            error = type(failure).__name__
        if limited:
            process.wait(timeout=15)
            checks[label] = {'passed': process.returncode != 0 and len(received) == before and
                             source.read_bytes() not in response_body and current_log.stat().st_size == 1024,
                             'gateway_exit': process.returncode, 'upstream_receipts': len(received) - before,
                             'response_status': status, 'client_error': error, 'log_bytes': current_log.stat().st_size}
        else:
            checks[label] = {'passed': status == 200 and len(received) == before + 1 and
                             received[-1]['admission_already_readable'], 'upstream_receipts': len(received) - before}
            stop(process)
    summary = {'test_kind': 'gateway_admission_durability', 'checks': checks,
               'passed': all(check['passed'] for check in checks.values()),
               'limits': ['receiver file read proves ordering; unit syscall interposition checks fsync',
                          'remote delivery and local outcome record are not an atomic transaction'],
               'private_log_sha256': {p.parent.name: sha(p.read_bytes()) for p in root.glob('*/evidence.jsonl')}}
    output = ROOT / os.environ.get('AGENTSEC_REPORT', 'tests/results/gateway_durability.json')
    output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    raise SystemExit(0 if summary['passed'] else 2)
finally:
    for process in processes:
        stop(process)
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
