"""Local fault injection for the opt-in content gateway."""
import concurrent.futures
import http.server
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
from acceptance_support import ROOT, load_records, request, sha, spawn, stop, wait_for
gateway_binary = os.environ.get('AGENT_GATEWAY_BINARY', str(ROOT / 'agent-gateway'))

root = pathlib.Path(tempfile.mkdtemp(prefix='as-fault-', dir='/private/tmp'))
source = root / 'synthetic.env'
content = b'TEST_ONLY_CONTENT_0123456789abcdef\n'
source.write_bytes(content)
results, processes, received = {}, [], []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        received.append(sha(body))
        code = 503 if body.startswith(b'503:') else 302 if body.startswith(b'302:') else 200
        self.send_response(code)
        if code == 302:
            self.send_header('Location', 'http://127.0.0.1:1/must-not-follow')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')
    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
sock, log = root / 'gateway.sock', root / 'gateway.jsonl'
try:
    proc = spawn([gateway_binary, '--socket', str(sock), '--log', str(log),
                  '--sensitive-file', str(source), '--upstream', f'http://127.0.0.1:{server.server_port}/ingest',
                  '--allow-loopback-http', '--correlation-seconds', '1'], root, 'gateway')
    processes.append(proc)
    wait_for(lambda: any(r['type'] == 'gateway_ready' for r in load_records(log)))
    request(sock, 'GET', '/read')
    time.sleep(1.2)
    status, _ = request(sock, 'POST', '/submit', content)
    wait_for(lambda: any(r['type'] == 'transfer_result' for r in load_records(log)))
    event = [r for r in load_records(log) if r['type'] == 'sensitive_payload_observed'][-1]
    results['expired_delivery_not_linked'] = status == 200 and not event['related_event_ids']
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda i: request(sock, 'POST', '/submit', str(i).encode() + content)[0], range(8)))
    results['eight_concurrent_requests'] = statuses == [200] * 8
    for code in (503, 302):
        body = str(code).encode() + b':' + content
        before = len(received)
        status, _ = request(sock, 'POST', '/submit', body)
        wait_for(lambda: any(r['type'] == 'transfer_result' and r['content_sha256'] == sha(body) for r in load_records(log)))
        event = [r for r in load_records(log) if r['type'] == 'transfer_result' and r['content_sha256'] == sha(body)][-1]
        results[f'http_{code}_not_success_or_followed'] = status == code and len(received) == before + 1 and event['transfer_outcome'].startswith('failed_')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(15)
        client.connect(str(sock))
        client.sendall(b'POST /submit HTTP/1.1\r\nContent-Length: 100\r\n\r\nx')
        results['incomplete_body_deadline'] = client.recv(1024).startswith(b'HTTP/1.1 400')
    results['service_recovers_after_slow_client'] = request(sock, 'POST', '/submit', b'ordinary public data')[0] == 200
    stop(proc)
    sentinel = root / 'occupied.sock'
    sentinel.write_text('preserve-me')
    command = [gateway_binary, '--socket', str(sentinel), '--log', str(root / 'rejected.jsonl'),
               '--sensitive-file', str(source), '--upstream', 'https://example.invalid/ingest']
    result = subprocess.run(command, capture_output=True, timeout=20)
    results['existing_path_preserved'] = result.returncode != 0 and sentinel.read_text() == 'preserve-me'
    link = root / 'source-link'
    link.symlink_to(source)
    command[command.index('--socket') + 1] = str(root / 'link.sock')
    command[command.index('--sensitive-file') + 1] = str(link)
    result = subprocess.run(command, capture_output=True, timeout=20)
    results['symlink_source_rejected'] = result.returncode != 0 and not (root / 'link.sock').exists()
finally:
    for process in processes:
        stop(process)
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)
summary = {'test_kind': 'gateway_fault_injection', 'results': results, 'passed': all(results.values()),
           'not_tested': ['self-signed TLS endpoint', 'system-wide bypass prevention'],
           'evidence_sha256': {p.name: sha(p.read_bytes()) for p in root.glob('*.jsonl')}}
(ROOT / os.environ.get('AGENTSEC_REPORT', 'tests/results/gateway_security.json')).write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary))
raise SystemExit(0 if summary['passed'] else 2)
