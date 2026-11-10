"""Independent receiver/fixtures for acceptance; never imported by the detector."""
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import signal
import socket
import subprocess
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def load_records(path):
    if not path.exists():
        return []
    result = []
    for line in path.read_text().splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # Only while a live writer is still appending.
    return result

def wait_for(check, timeout=20):
    end = time.monotonic() + timeout
    while not check():
        if time.monotonic() > end:
            raise TimeoutError('readiness condition timed out')
        time.sleep(.05)

def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

def spawn(command, root, name):
    out = os.open(root / (name + '.stdout'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    err = os.open(root / (name + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        return subprocess.Popen(command, stdout=out, stderr=err, start_new_session=True)
    finally:
        os.close(out)
        os.close(err)

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=25)
        self.path = str(path)
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

def request(path, method, route, body=None, headers=None):
    connection = UnixHTTP(path)
    try:
        connection.request(method, route, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()

class Receiver:
    def __init__(self, receipt_path):
        self.receipts = []
        self.receipt_path = receipt_path
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                receipt = {'received_us': time.time_ns() // 1000, 'body_sha256': sha(body),
                           'bytes': len(body), 'peer': 'loopback', 'path': self.path}
                owner.receipts.append(receipt)
                with owner.receipt_path.open('a') as log:
                    log.write(json.dumps(receipt) + '\n')
                result = json.dumps(receipt).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(result)))
                self.end_headers()
                self.wfile.write(result)
            def log_message(self, *_):
                pass
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    @property
    def url(self):
        return f'http://127.0.0.1:{self.server.server_port}/ingest'
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

def sanitized_record(record, root):
    """Public evidence retains identities and test paths; no other process paths/IPs."""
    actor = record.get('actor_process') or {}
    def entry(item):
        return {'identity': item['identity'], 'ppid': item['ppid'],
                'executable_basename': pathlib.Path(item['executable']).name,
                'observed_parent_identity': item.get('observed_parent_identity')}
    return {k: v for k, v in record.items() if k in (
        'event_id', 'timestamp', 'type', 'risk_level', 'content_sha256', 'correlation_id',
        'related_event_ids', 'evidence_basis', 'transfer_outcome', 'attribution', 'metrics')} | {
        'target_resource': record.get('target_resource', '').replace(str(root), '<TEST_ROOT>'),
        'destination': record.get('destination', ''),
        'actor': entry(actor['process']) if actor else None,
        'ancestors': [entry(a) for a in actor.get('ppid_tree', [])],
        'chain_complete': actor.get('chain_complete'), 'chain_status': actor.get('chain_status'),
        'classification': actor.get('classification')}
