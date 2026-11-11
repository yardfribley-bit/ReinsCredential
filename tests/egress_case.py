#!/usr/bin/env python3
"""One synthetic egress action. The file bytes are a fake secret, not a credential.

The process speaks ordinary HTTP. It does not use the Unix content gateway.
"""
import base64
import gzip
import json
import os
import socket
import ssl
import sys
import time


def split_http(url):
    if url.startswith("https://"):
        rest = url[len("https://"):]
    elif url.startswith("http://"):
        rest = url[len("http://"):]
    else:
        raise SystemExit("destination must be http or https")
    slash = rest.find("/")
    authority = rest if slash < 0 else rest[:slash]
    path = "/" if slash < 0 else rest[slash:]
    host, port_text = authority.rsplit(":", 1)
    return host, int(port_text), path


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            break
        data += block
    return data


def read_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        block = sock.recv(4096)
        if not block:
            break
        data += block
        if len(data) > 65536:
            break
    return data


def proxy_post(proxy_port, url, body):
    host, port, path = split_http(url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", proxy_port))
    head = (
        f"POST {url} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    sock.sendall(head + body)
    sock.settimeout(10)
    try:
        read_headers(sock)
    except socket.timeout:
        pass
    sock.close()


def direct_post(url, body):
    host, port, path = split_http(url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    sock.sendall(head + body)
    # Keep the socket open long enough for a libproc sample. The bytes are not
    # on the proxy, so the verdict has to stay 看不到.
    time.sleep(1.0)
    sock.close()


def connect_tunnel(proxy_port, url, body):
    host, port, _path = split_http(url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", proxy_port))
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    sock.settimeout(5)
    read_headers(sock)
    sock.sendall(body)
    time.sleep(0.4)
    sock.close()


def https_via_proxy(proxy_port, url, body, cafile, trust):
    host, port, path = split_http(url)
    sock = socket.create_connection(("127.0.0.1", proxy_port))
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    sock.settimeout(15)
    read_headers(sock)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_alpn_protocols(["http/1.1"])
    if trust:
        context.load_verify_locations(cafile)
    else:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    try:
        tls = context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError:
        sock.close()
        return
    request = (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    tls.sendall(request)
    try:
        tls.recv(4096)
    except Exception:
        pass
    tls.close()


def main():
    if len(sys.argv) < 4:
        raise SystemExit("usage: egress_case.py MODE URL SENSITIVE_PATH [PAYLOAD_PATH]")
    mode, url, sensitive = sys.argv[1], sys.argv[2], sys.argv[3]
    payload_path = sys.argv[4] if len(sys.argv) > 4 else sensitive
    proxy_port = int(os.environ["EGRESS_PROXY_PORT"])
    hold_ms = int(os.environ.get("EGRESS_HOLD_MS", "0"))
    fd = None
    if mode != "noopen":
        fd = os.open(sensitive, os.O_RDONLY)
    with open(payload_path, "rb") as handle:
        secret = handle.read()
    if mode == "plaintext" or mode == "bypass" or mode == "fail500" or mode == "refused" or mode == "noopen":
        body = secret
    elif mode == "json":
        body = json.dumps({"payload": secret.decode("utf-8")}).encode("utf-8")
    elif mode == "base64":
        body = base64.b64encode(secret)
    elif mode == "gzip":
        body = gzip.compress(secret, mtime=0)
    elif mode == "benign":
        body = b"ordinary public payload without a registered secret"
    elif mode == "direct":
        direct_post(url, secret)
        body = b""
    elif mode == "connect":
        connect_tunnel(proxy_port, url, secret)
        body = b""
    elif mode == "https":
        https_via_proxy(proxy_port, url, secret, os.environ["TLS_CA"], True)
        body = b""
    elif mode == "https-json":
        encoded = json.dumps({"payload": secret.decode("utf-8")}).encode("utf-8")
        https_via_proxy(proxy_port, url, encoded, os.environ["TLS_CA"], True)
        body = b""
    elif mode == "https-fail":
        https_via_proxy(proxy_port, url, secret, os.environ["TLS_CA"], True)
        body = b""
    elif mode == "https-pinned":
        https_via_proxy(proxy_port, url, secret, "", False)
        body = b""
    else:
        raise SystemExit("unknown mode")
    if mode not in ("direct", "connect", "https", "https-json", "https-fail", "https-pinned"):
        proxy_post(proxy_port, url, body)
    if hold_ms:
        time.sleep(hold_ms / 1000)
    if fd is not None:
        os.close(fd)
    # Do not print the payload.
    print(f"case-finished {mode}", flush=True)


if __name__ == "__main__":
    main()
