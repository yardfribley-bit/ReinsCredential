#!/usr/bin/env python3
"""Egress-proxy verdicts for a launched process tree.

The sensitive bytes are synthetic. This does not read real credentials and it
does not start the Unix content gateway.
"""
import gzip
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / "agent-egress"
CASE = ROOT / "tests" / "egress_case.py"
MARKER = b"SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef\n"
LABELS = {
    "uploaded": "已上传",
    "attempted": "已尝试未成功",
    "not_found": "未发现",
    "not_visible": "看不到",
}


def redact(text):
    secret = MARKER.decode("utf-8")
    return text.replace(secret, "[redacted-synthetic]").replace(MARKER.decode().strip(), "[redacted-synthetic]")


def median(values):
    if not values:
        return None
    return statistics.median(values)


def sample_process(pid, seconds):
    cpu, rss = [], []
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            out = subprocess.check_output(["ps", "-p", str(pid), "-o", "%cpu=,rss="], text=True)
        except subprocess.CalledProcessError:
            break
        parts = out.split()
        if len(parts) >= 2:
            cpu.append(float(parts[0]))
            rss.append(int(parts[1]))
        time.sleep(0.25)
    return cpu, rss


class Server:
    def __init__(self, status=200, raw=False, tls_cert=None, tls_key=None, accept_timeout=15, bind_host="127.0.0.1"):
        self.status = status
        self.raw = raw
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.bind_host = bind_host
        self.box = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, 0))
        self.sock.listen(1)
        self.sock.settimeout(accept_timeout)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def url(self, path, scheme="http"):
        return f"{scheme}://127.0.0.1:{self.port}{path}"

    def _run(self):
        try:
            conn, _addr = self.sock.accept()
        except Exception as error:
            self.box["error"] = str(error)
            return
        if self.tls_cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            chain = self.tls_cert
            ca_path = str(Path(self.tls_cert).with_name("ca.crt"))
            if Path(ca_path).exists() and Path(ca_path).resolve() != Path(self.tls_cert).resolve():
                combined = Path(self.tls_cert).with_name("server-chain.crt")
                combined.write_bytes(Path(self.tls_cert).read_bytes() + b"\n" + Path(ca_path).read_bytes())
                chain = str(combined)
            context.load_cert_chain(chain, self.tls_key)
            try:
                conn = context.wrap_socket(conn, server_side=True)
            except ssl.SSLError as error:
                self.box["error"] = str(error)
                return
        conn.settimeout(3)
        data = b""
        try:
            while len(data) < 2 * 1024 * 1024:
                block = conn.recv(8192)
                if not block:
                    break
                data += block
                if not self.raw and b"\r\n\r\n" in data:
                    head, rest = data.split(b"\r\n\r\n", 1)
                    length = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            length = int(line.split(b":", 1)[1].strip())
                    while len(rest) < length:
                        block = conn.recv(8192)
                        if not block:
                            break
                        rest += block
                    data = head + b"\r\n\r\n" + rest[:length]
                    break
        except socket.timeout:
            pass
        self.box["data"] = data
        try:
            if not self.raw:
                # Stay open briefly so a direct client socket remains visible.
                time.sleep(1.0)
                body = b"ok"
                conn.sendall(
                    f"HTTP/1.1 {self.status} Result\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
            conn.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def join(self):
        self.thread.join(timeout=5)


def routable_ip():
    """Source address the stack would use for an off-host packet. Loopback does not count."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        address = sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()
    if address.startswith("127."):
        return None
    return address


def load_records(path):
    records = []
    text = path.read_text()
    if MARKER.decode() in text or MARKER.decode().strip() in text:
        raise SystemExit("evidence log contains the synthetic secret bytes")
    for line in text.splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def run_proxy(log, secret, command, env, extra=None):
    command_line = [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--sample-ms", "20",
                    "--timeout-sec", "40"]
    if extra:
        command_line.extend(extra)
    command_line.extend(["--launch", "--", *command])
    return subprocess.Popen(command_line, cwd=str(ROOT), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def finish(proc):
    try:
        out, err = proc.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        proc.send_signal(15)
        out, err = proc.communicate(timeout=5)
    if proc.returncode != 0:
        raise SystemExit(f"agent-egress exited {proc.returncode}\n{redact(out or '')}\n{redact(err or '')}")
    return out or "", err or ""


def assert_case(mode, expected, records, receipt):
    closed = [record for record in records if record["type"] == "sensitive_access_closed"]
    transfers = [record for record in records if record["type"] == "egress_transfer"]
    if mode == "noopen":
        if closed:
            raise SystemExit(f"noopen invented an access close: {redact(json.dumps(closed))}")
        if any(record["type"] == "sensitive_fd_observed" for record in records):
            raise SystemExit("noopen recorded a sensitive file descriptor")
        matched = [record for record in transfers if record.get("upload_verdict") == "uploaded"]
        if len(matched) != 1:
            raise SystemExit(f"noopen transfer missing: {redact(json.dumps(transfers))}")
        if "open_of_source_file_not_proven_by_this_record" not in matched[0]["detail"]:
            raise SystemExit("noopen transfer claims the file was opened")
        if not matched[0]["destination"] or not matched[0]["transfer_outcome"]:
            raise SystemExit("noopen transfer is missing destination or transfer_outcome")
        if MARKER.split(b"\n")[0] not in receipt.get("data", b""):
            raise SystemExit("noopen receiver did not see the synthetic marker")
        return "transfer_only"
    if len(closed) != 1:
        raise SystemExit(f"{mode} expected one access close, got {len(closed)}: {redact(json.dumps(records))}")
    record = closed[0]
    return finish_close(mode, expected, record, records, receipt)


def assert_live_case(mode, expected, records, receipt, file_name):
    named = [record for record in records if record["type"] == "sensitive_access_closed" and file_name in (record.get("target_resource") or "")]
    if len(named) < 1:
        raise SystemExit(f"{mode} expected a close for {file_name}, got {redact(json.dumps(records))}")
    rank = {"uploaded": 4, "attempted": 3, "not_visible": 2, "not_found": 1}
    named.sort(key=lambda record: rank.get(record.get("upload_verdict"), 0))
    return finish_close(mode, expected, named[-1], records, receipt)


def finish_close(mode, expected, record, records, receipt):
    if record["upload_verdict"] != expected:
        raise SystemExit(f"{mode} verdict {record['upload_verdict']} != {expected}\n{redact(json.dumps(record))}")
    if not record["transfer_outcome"] or (not record["destination"] and "live_agent_observed_no_" not in record["transfer_outcome"]):
        raise SystemExit(f"{mode} missing destination or transfer_outcome: {redact(json.dumps(record))}")
    if not record["summary"].startswith(LABELS[expected]):
        raise SystemExit(f"{mode} summary does not start with {LABELS[expected]}: {record['summary']}")
    if expected == "not_visible" and record["upload_verdict"] == "not_found":
        raise SystemExit("invisible channel was labeled 未发现")
    if expected in ("not_found", "not_visible") and record["upload_verdict"] in ("uploaded", "attempted"):
        raise SystemExit(f"{mode} invented an upload")
    if MARKER.decode() in json.dumps(record):
        raise SystemExit("closing record contains the synthetic secret")
    if mode == "direct":
        if "socket_body_not_visible" not in record["transfer_outcome"]:
            raise SystemExit(f"direct outcome {record['transfer_outcome']}")
        if str(receipt["port"]) not in record["destination"]:
            raise SystemExit(f"direct destination {record['destination']} does not name the receiver")
        if MARKER not in receipt["data"]:
            raise SystemExit("direct receiver did not get the synthetic bytes; the unseen case was not real")
    if mode == "connect":
        if record["transfer_outcome"] != "opaque_tunnel_body_not_visible":
            raise SystemExit(f"connect outcome {record['transfer_outcome']}")
        if str(receipt["port"]) not in record["destination"]:
            raise SystemExit(f"connect destination {record['destination']}")
        if any(item.get("evidence_basis") in ("exact_bytes", "json_escaped_bytes", "base64_whole_value", "gzip:exact_bytes") for item in records):
            raise SystemExit("opaque tunnel was content-matched")
        if MARKER not in receipt["data"]:
            raise SystemExit("tunnel receiver did not get the synthetic bytes")
    if mode == "bypass":
        if any(item["type"] in ("sensitive_payload_observed", "gateway_ready", "sensitive_content_delivered") for item in records):
            raise SystemExit("bypass case used the Unix content gateway")
        if "/bypass-gateway" not in record["destination"]:
            raise SystemExit(f"bypass destination {record['destination']}")
    if mode == "benign":
        if MARKER in receipt.get("data", b""):
            raise SystemExit("benign receiver saw the synthetic secret")
        if record["transfer_outcome"] != "watched_http_no_registered_content":
            raise SystemExit(f"benign outcome {record['transfer_outcome']}")
    if mode in ("fail500", "https-fail") and not record["transfer_outcome"].startswith("upstream_http_500"):
        raise SystemExit(f"{mode} outcome {record['transfer_outcome']}")
    if mode == "refused" and record["transfer_outcome"] != "connect_failed":
        raise SystemExit(f"refused outcome {record['transfer_outcome']}")
    if mode in ("https", "https-json", "https-fail") and "tls_intercept" not in record["detail"]:
        raise SystemExit(f"{mode} was not inspected as TLS: {record['detail']}")
    if mode == "https-pinned" and "upstream_http_2xx" in record["transfer_outcome"]:
        raise SystemExit("pinned TLS was treated as a successful inspected upload")
    if mode == "live-proxy" and "live_agent_connected_to_proxy" not in record["detail"]:
        raise SystemExit(f"{mode} detail does not say the live agent connected itself: {record['detail']}")
    if mode == "live-udp" and "udp_or_quic" not in record["transfer_outcome"]:
        raise SystemExit(f"udp outcome {record['transfer_outcome']}")
    if mode == "live-direct":
        if "loopback_not_off_host" not in record["transfer_outcome"]:
            raise SystemExit(f"live direct outcome {record['transfer_outcome']}")
        if record["evidence_basis"] != "live_agent_observed":
            raise SystemExit(f"live direct basis {record['evidence_basis']}")
        if MARKER not in receipt.get("data", b""):
            raise SystemExit("live direct receiver did not get the synthetic bytes; the observed case was not real")
    if mode == "live-offhost":
        if record["evidence_basis"] != "flow_txbytes":
            raise SystemExit(f"offhost basis {record['evidence_basis']}")
        if "left_host" not in record["transfer_outcome"] or "match=flow_txbytes" not in record["detail"]:
            raise SystemExit(f"offhost outcome {record['transfer_outcome']} detail {record['detail']}")
        if MARKER not in receipt.get("data", b""):
            raise SystemExit("offhost receiver did not get the synthetic bytes")
    if mode == "live-attempt":
        if record["evidence_basis"] != "flow_attempt":
            raise SystemExit(f"attempt basis {record['evidence_basis']}")
        if "203.0.113.10" not in record["destination"]:
            raise SystemExit(f"attempt destination {record['destination']}")
    if expected == "uploaded" and mode != "live-offhost" and "upstream_http_2xx" not in record["transfer_outcome"]:
        raise SystemExit(f"uploaded outcome {record['transfer_outcome']}")
    if mode in ("plaintext", "json", "base64", "gzip", "bypass", "fail500", "noopen", "https", "https-json", "https-fail", "live-proxy", "live-direct"):
        if not receipt or MARKER.split(b"\n")[0] not in receipt["data"] and mode != "base64" and mode != "gzip":
            if mode not in ("base64", "gzip"):
                raise SystemExit(f"{mode} receiver did not observe the synthetic marker")
        if mode == "gzip":
            body = receipt["data"].split(b"\r\n\r\n", 1)[1]
            if MARKER not in gzip.decompress(body):
                raise SystemExit("gzip receiver body did not decompress to the synthetic secret")
        if mode == "base64":
            import base64
            body = receipt["data"].split(b"\r\n\r\n", 1)[1]
            if base64.b64decode(body) != MARKER:
                raise SystemExit("base64 receiver body did not decode to the synthetic secret")
    return expected


def make_ca(directory):
    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    server_key = directory / "server.key"
    server_csr = directory / "server.csr"
    server_cert = directory / "server.crt"
    ext = directory / "server.ext"
    ext.write_text("[ext]\nbasicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1\n")
    subprocess.check_call(["/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)])
    subprocess.check_call(["/usr/bin/openssl", "req", "-new", "-x509", "-key", str(ca_key), "-subj", "/CN=ReinsEphemeralTestCA",
                           "-days", "1", "-out", str(ca_cert)])
    subprocess.check_call(["/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(server_key)])
    subprocess.check_call(["/usr/bin/openssl", "req", "-new", "-key", str(server_key), "-subj", "/CN=127.0.0.1", "-out", str(server_csr)])
    subprocess.check_call(["/usr/bin/openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                           "-CAcreateserial", "-out", str(server_cert), "-days", "1", "-extfile", str(ext), "-extensions", "ext"])
    return ca_cert, ca_key, server_cert, server_key


def one_case(directory, mode, measure=False, ca=None):
    secret = directory / "synthetic.env"
    if not secret.exists():
        secret.write_bytes(MARKER)
        os.chmod(secret, 0o600)
    payload = secret
    if mode == "noopen":
        payload = directory / "payload.bin"
        payload.write_bytes(MARKER)
        os.chmod(payload, 0o600)
    raw = mode == "connect"
    https = mode.startswith("https")
    status = 500 if mode in ("fail500", "https-fail") else 200
    server = None if mode == "refused" else Server(
        status=status, raw=raw, accept_timeout=30,
        tls_cert=str(ca[2]) if https else None, tls_key=str(ca[3]) if https else None)
    if mode == "refused":
        url = "http://127.0.0.1:1/upload"
    elif mode == "bypass":
        url = server.url("/bypass-gateway")
    elif https:
        url = server.url("/upload", "https")
    else:
        url = server.url("/upload")
    log = directory / f"{mode}.jsonl"
    env = os.environ.copy()
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("ALL_PROXY", None)
    env.pop("all_proxy", None)
    env.pop("no_proxy", None)
    env.pop("NO_PROXY", None)
    if measure:
        env["EGRESS_HOLD_MS"] = "2000"
    if https and mode != "https-pinned":
        env["TLS_CA"] = str(ca[0])
    extra = ["--tls-ca-cert", str(ca[0]), "--tls-ca-key", str(ca[1])] if https else None
    command = [sys.executable, str(CASE), mode, url, str(secret)]
    if mode == "noopen":
        command.append(str(payload))
    proc = run_proxy(log, secret, command, env, extra)
    cpu, rss = ([], [])
    if measure:
        cpu, rss = sample_process(proc.pid, 6)
    out, err = finish(proc)
    receipt = {"port": server.port, "data": b"", "error": None} if server else {"port": 1, "data": b"", "error": None}
    if server:
        server.join()
        receipt["data"] = server.box.get("data", b"")
        receipt["error"] = server.box.get("error")
        if mode in ("direct", "connect", "plaintext", "bypass", "fail500", "json", "base64", "gzip", "noopen", "https", "https-json", "https-fail") and not receipt["data"] and not receipt["error"]:
            raise SystemExit(f"{mode} receiver captured nothing\n{redact(err)}")
    records = load_records(log)
    try:
        kind = assert_case(mode, {
            "plaintext": "uploaded",
            "json": "uploaded",
            "base64": "uploaded",
            "gzip": "uploaded",
            "fail500": "attempted",
            "refused": "attempted",
            "bypass": "uploaded",
            "benign": "not_found",
            "direct": "not_visible",
            "connect": "not_visible",
            "noopen": None,
            "https": "uploaded",
            "https-json": "uploaded",
            "https-fail": "attempted",
            "https-pinned": "not_visible",
            "live-proxy": "uploaded",
            "live-direct": "not_visible",
            "live-udp": "not_visible",
        }[mode], records, receipt)
    except SystemExit:
        sys.stderr.write(redact(err))
        raise
    # weakly_canonical on macOS may add /private. Accept either path spelling.
    if mode != "noopen":
        closed = next(record for record in records if record["type"] == "sensitive_access_closed")
        if secret.name not in closed["target_resource"]:
            raise SystemExit(f"{mode} target {closed['target_resource']}")
    return kind, cpu, rss, err


def live_case(directory, mode, binary, secret):
    log = directory / f"{mode}.jsonl"
    server = None
    dummy = None
    host = "127.0.0.1"
    port = 0
    if mode == "live-udp":
        dummy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dummy.bind(("127.0.0.1", 0))
        port = dummy.getsockname()[1]
    elif mode == "live-attempt":
        host = "203.0.113.10"
        port = 443
    elif mode == "live-offhost":
        host = routable_ip()
        if not host:
            return "skipped"
        server = Server(accept_timeout=10, bind_host="0.0.0.0")
        port = server.port
    else:
        server = Server(accept_timeout=10)
        port = server.port
    port_file = directory / f"{mode}.port"
    duration = "8" if mode == "live-proxy" else "6"
    if mode == "live-proxy":
        agent = subprocess.Popen([str(binary), "proxy", str(secret), str(port_file), server.url("/upload")])
        time.sleep(0.3)
        proc = subprocess.Popen(
            [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--watch-live", "--duration", duration,
             "--sample-ms", "40", "--port-file", str(port_file)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        action = {"live-direct": "direct", "live-offhost": "direct", "live-udp": "udp", "live-attempt": "attempt"}[mode]
        agent = subprocess.Popen([str(binary), action, str(secret), host, str(port)])
        time.sleep(0.2)
        proc = subprocess.Popen(
            [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--watch-live", "--duration", duration,
             "--sample-ms", "40"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _out, err = finish(proc)
    try:
        agent.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent.kill()
    if dummy:
        dummy.close()
    receipt = {"port": port, "data": b"", "error": None}
    if server:
        server.join()
        receipt["data"] = server.box.get("data", b"")
        receipt["error"] = server.box.get("error")
    records = load_records(log)
    expected = {"live-proxy": "uploaded", "live-direct": "not_found", "live-udp": "not_visible",
                "live-offhost": "uploaded", "live-attempt": "attempted"}[mode]
    try:
        kind = assert_live_case(mode, expected, records, receipt, secret.name)
    except SystemExit:
        sys.stderr.write(redact(err))
        raise
    return kind


def main():
    if not PROXY.exists():
        raise SystemExit("agent-egress is not built")
    upload_tp = attempted_tp = tn = fp = fn = 0
    content_unseen = 0
    with tempfile.TemporaryDirectory(prefix="reins-egress-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        idle_log = directory / "idle.jsonl"
        secret = directory / "synthetic.env"
        secret.write_bytes(MARKER)
        os.chmod(secret, 0o600)
        ca = make_ca(directory)
        idle = subprocess.Popen(
            [str(PROXY), "--log", str(idle_log), "--sensitive-file", str(secret), "--watch-live", "--duration", "3",
             "--sample-ms", "50"],
            cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        idle_cpu, idle_rss = sample_process(idle.pid, 3.4)
        idle_out, idle_err = idle.communicate(timeout=10)
        if idle.returncode != 0:
            raise SystemExit(f"idle proxy failed\n{idle_out}\n{idle_err}")
        active_cpu, active_rss = [], []
        modes = ("plaintext", "json", "base64", "gzip", "fail500", "refused", "bypass", "benign", "direct", "connect",
                 "noopen", "https", "https-json", "https-fail", "https-pinned")
        for mode in modes:
            kind, cpu, rss, _err = one_case(directory, mode, measure=(mode == "https"), ca=ca)
            if mode == "https":
                active_cpu, active_rss = cpu, rss
            if kind == "uploaded":
                upload_tp += 1
            elif kind == "attempted":
                attempted_tp += 1
            elif kind in ("not_found", "not_visible"):
                tn += 1
                if kind == "not_visible":
                    content_unseen += 1
            elif kind != "transfer_only":
                fn += 1
        binary = directory / "codex"
        subprocess.check_call(["/usr/bin/clang", "-O2", "-o", str(binary), str(ROOT / "tests/live_agent.c")])
        for mode in ("live-proxy", "live-direct", "live-udp", "live-offhost", "live-attempt"):
            kind = live_case(directory, mode, binary, secret)
            if kind == "skipped":
                print(f"SKIP {mode} no routable address")
                continue
            if kind == "uploaded":
                upload_tp += 1
            elif kind == "attempted":
                attempted_tp += 1
            elif kind == "not_visible":
                tn += 1
                content_unseen += 1
            elif kind == "not_found":
                tn += 1
            else:
                fn += 1
    # False positives and false negatives are assertion failures above. A passed
    # run has none. not_visible is a true negative for the verdict and a content miss.
    print(
        "RESULT "
        f"upload_tp={upload_tp} attempted_tp={attempted_tp} tn={tn} fp={fp} fn={fn} "
        f"content_unseen={content_unseen} transfer_without_open=1 "
        f"idle_cpu_median={median(idle_cpu)} idle_rss_median_kb={median(idle_rss)} "
        f"idle_samples={len(idle_cpu)} active_cpu_median={median(active_cpu)} "
        f"active_rss_median_kb={median(active_rss)} active_samples={len(active_cpu)}"
    )
    if not idle_cpu or not active_cpu:
        raise SystemExit(f"missing cpu samples idle={len(idle_cpu)} active={len(active_cpu)}")
    if upload_tp != 8 or attempted_tp != 3 or tn != 6 or content_unseen != 5:
        raise SystemExit("verdict counts did not match the synthetic matrix")


if __name__ == "__main__":
    main()
