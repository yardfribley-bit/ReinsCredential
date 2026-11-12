#!/usr/bin/env python3
"""Stand-in process for the acceptance harness.

This is not Codex, Cursor, or WorkBuddy. It reads one fake file and, when
asked, sends those bytes only to 127.0.0.1. It never prints the file bytes.
"""
from __future__ import annotations

import hashlib
import os
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


def fail(message):
    sys.stderr.write(message + "\n")
    raise SystemExit(2)


def wait_ready(path, limit=100):
    deadline = time.time() + limit
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    fail("ready file did not appear")


def read_response(sock):
    sock.settimeout(10)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        block = sock.recv(4096)
        if not block:
            break
        data += block
    return data


def loopback_port(host, port):
    if host not in ("127.0.0.1", "localhost"):
        fail("sink host must be loopback")
    if port < 1 or port > 65535:
        fail("sink port is invalid")
    return port


def proxy_endpoint():
    raw = ""
    for name in ("http_proxy", "HTTP_PROXY"):
        if os.environ.get(name):
            raw = os.environ[name]
            break
    if not raw:
        fail("post mode requires http_proxy from the launched tree")
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    port = parsed.port
    if host not in ("127.0.0.1", "localhost") or not port:
        fail("http_proxy is not a loopback proxy")
    return port


def send_direct(port, body):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    head = (
        f"POST /ingest HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.sendall(head + body)
    # Keep the socket visible so a direct send stays 看不到 rather than 未发现.
    time.sleep(1.2)
    sock.close()


def send_via_proxy(sink_port, body):
    proxy_port = proxy_endpoint()
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    target = f"http://127.0.0.1:{sink_port}/ingest"
    head = (
        f"POST {target} HTTP/1.1\r\nHost: 127.0.0.1:{sink_port}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.sendall(head + body)
    read_response(sock)
    sock.close()


def main(argv):
    if len(argv) < 5:
        fail("usage: stand_in_agent.py FILE post|direct|read 127.0.0.1 PORT [--wait-ready PATH]")
    path, mode, host, port_text = argv[1], argv[2], argv[3], argv[4]
    ready = None
    if "--wait-ready" in argv:
        index = argv.index("--wait-ready")
        if index + 1 >= len(argv):
            fail("missing ready path")
        ready = Path(argv[index + 1])
    if mode not in ("post", "direct", "read"):
        fail("unknown mode")
    port = loopback_port(host, int(port_text))
    if ready is not None:
        wait_ready(ready)
    handle = open(path, "rb")
    try:
        body = handle.read()
        if len(body) < 16:
            fail("fake file is too short to be a useful fixture")
        digest = hashlib.sha256(body).hexdigest()
        if mode == "direct":
            send_direct(port, body)
        elif mode == "post":
            send_via_proxy(port, body)
            time.sleep(0.8)
        else:
            time.sleep(1.0)
    finally:
        handle.close()
        del body
    sys.stdout.write(f"stand_in_ok mode={mode} sha256={digest}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
