"""Ground-truth workload. A fixture, NOT a real autonomous AI client."""
import base64
import gzip
import http.client
import json
import os
import pathlib
import sys
import time
from acceptance_support import request, sha

config = json.loads(pathlib.Path(sys.argv[1]).read_text())
mode = config['mode']
source = pathlib.Path(config['source'])
proof = {'case_id': config['case_id'], 'mode': mode, 'pid': os.getpid(), 'ppid': os.getppid(),
         'started_us': time.time_ns() // 1000, 'source_read': False}
body = ('ordinary-public-data-' + config['case_id']).encode()
held = None
if mode == 'open_only':
    held = source.open('rb')
    time.sleep(1)
elif mode != 'benign':
    started = time.time_ns() // 1000
    content = source.read_bytes()
    proof.update(source_read=True, source_sha256=sha(content), read_duration_us=time.time_ns() // 1000 - started)
    if mode == 'read_only':
        body = None
    elif mode == 'json':
        body = json.dumps({'case_id': config['case_id'], 'data': content.decode()}).encode()
    elif mode == 'base64':
        body = config['case_id'].encode() + b':' + base64.b64encode(content)
    elif mode == 'gzip':
        body = gzip.compress(content + config['case_id'].encode())
    elif mode == 'split':
        middle = len(content) // 2
        body = [content[:middle] + config['case_id'].encode(), content[middle:] + config['case_id'].encode()]
    else:
        body = config['case_id'].encode() + b':' + content
    if mode == 'read_then_delay':
        time.sleep(1)
proof['requests'] = []
for payload in (body if isinstance(body, list) else [body]):
    if payload is None:
        continue
    if config.get('direct'):
        url = config['upstream']
        connection = http.client.HTTPConnection('127.0.0.1', int(url.split(':')[2].split('/')[0]), timeout=10)
        connection.request('POST', '/ingest', body=payload)
        response = connection.getresponse()
        status, reply = response.status, response.read()
        connection.close()
    else:
        status, reply = request(config['socket'], 'POST', '/submit', payload)
    proof['requests'].append({'body_sha256': sha(payload), 'bytes': len(payload), 'status': status,
                              'receiver_ack': json.loads(reply) if status == 200 else None})
if held:
    time.sleep(1)
    held.close()
proof['completed_us'] = time.time_ns() // 1000
pathlib.Path(config['proof']).write_text(json.dumps(proof, indent=2))
