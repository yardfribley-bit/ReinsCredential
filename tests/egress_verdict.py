#!/usr/bin/env python3
"""Egress-proxy verdicts for a launched process tree.

The sensitive bytes are synthetic. This does not read real credentials and it
does not start the Unix content gateway.
"""
import gzip
import json
import os
import shlex
import shutil
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
# None is a transfer with no access close. It is not an access-level verdict.
LAUNCHED_VERDICTS = {
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
}
# Idle watch-live on a table that already has extra sleep processes.
# RSS is kilobytes from ps. CPU is one sample's percent of one core.
IDLE_RSS_KB_MAX = 150_000
IDLE_CPU_PERCENT_MAX = 150

LIVE_VERDICTS = {
    "live-proxy": "uploaded",
    "live-direct": "not_found",
    "live-udp": "not_found",
    "live-udp-large": "uploaded",
    "live-udp-small": "not_found",
    "live-compressed": "uploaded",
    "live-chunked": "uploaded",
    "live-partial": "not_visible",
    "live-short-post": "uploaded",
    "live-short-udp": "uploaded",
    "live-short-refused": "attempted",
    "live-short-unmeasured": "not_visible",
    "live-tls-hello": "not_visible",
    "live-offhost": "uploaded",
    "live-attempt": "attempted",
    "live-refused": "attempted",
    "live-unknown-app": "uploaded",
}


def matrix_counts(verdicts):
    uploaded = attempted = true_negative = unseen = 0
    for verdict in verdicts.values():
        if verdict == "uploaded":
            uploaded += 1
        elif verdict == "attempted":
            attempted += 1
        elif verdict == "not_found":
            true_negative += 1
        elif verdict == "not_visible":
            # Unresolved. Not a true negative and not a delivery pass.
            unseen += 1
    return uploaded, attempted, true_negative, unseen


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
    def __init__(self, status=200, raw=False, tls_cert=None, tls_key=None, accept_timeout=15, bind_host="127.0.0.1", accepts=1, bind_port=0):
        self.status = status
        self.raw = raw
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.bind_host = bind_host
        self.accepts = accepts
        self.box = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, bind_port))
        self.sock.listen(max(self.accepts, 1))
        self.sock.settimeout(accept_timeout)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def url(self, path, scheme="http"):
        return f"{scheme}://127.0.0.1:{self.port}{path}"

    def _run(self):
        collected = b""
        for index in range(self.accepts):
            try:
                conn, _addr = self.sock.accept()
            except Exception as error:
                self.box["error"] = str(error)
                self.box["data"] = collected
                return
            if index == 0:
                self._read_one(conn, first=True)
                collected = self.box.get("data", b"")
            else:
                collected += self._read_raw(conn)
        self.box["data"] = collected
        try:
            self.sock.close()
        except Exception:
            pass

    def _read_raw(self, conn):
        conn.settimeout(3)
        data = b""
        try:
            while len(data) < 2 * 1024 * 1024:
                block = conn.recv(8192)
                if not block:
                    break
                data += block
        except socket.timeout:
            pass
        try:
            conn.close()
        except Exception:
            pass
        return data

    def _read_one(self, conn, first=True):
        del first
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
    def close_rank(record):
        verdict = record.get("upload_verdict") or ""
        outcome = record.get("transfer_outcome") or ""
        # Provisional. A measured loopback 未发现 or a UDP 看不到 with a peer wins.
        if verdict == "not_visible" and outcome == "descriptors_or_flows_incomplete":
            return 0
        return {"uploaded": 4, "attempted": 3, "not_visible": 2, "not_found": 1}.get(verdict, 0)

    named.sort(key=close_rank)
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
    if mode == "live-udp":
        if record["evidence_basis"] != "live_agent_observed":
            raise SystemExit(f"loopback udp basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
        if record["upload_verdict"] != "not_found":
            raise SystemExit(f"measured loopback udp closed as {record['upload_verdict']}")
    if mode == "live-udp-large":
        if record["evidence_basis"] != "flow_txbytes_udp":
            raise SystemExit(f"udp large basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
        if "left_host" not in record["transfer_outcome"]:
            raise SystemExit(f"udp large outcome {record['transfer_outcome']}")
    if mode == "live-udp-small":
        if record["evidence_basis"] != "live_agent_observed" or "aggregate_below_lower_bound" not in record["detail"]:
            raise SystemExit(f"udp small basis {record['evidence_basis']} detail {record['detail']}")
        if record["upload_verdict"] != "not_found":
            raise SystemExit("fully measured small udp was not 未发现")
    if mode == "live-compressed":
        if record["evidence_basis"] != "flow_txbytes" or "lower_bound=" not in record["detail"]:
            raise SystemExit(f"compressed basis {record['evidence_basis']} detail {record['detail']}")
        detail = record["detail"]
        def field(name):
            token = name + "="
            start = detail.find(token)
            if start < 0:
                raise SystemExit(f"compressed detail missing {name}: {detail}")
            start += len(token)
            end = detail.find(";", start)
            return int(detail[start:end if end >= 0 else len(detail)])
        if not (field("lower_bound") <= field("tx_sum") < field("file_bytes")):
            raise SystemExit(f"compressed window {detail}")
    if mode == "live-chunked":
        if record["evidence_basis"] != "flow_txbytes" or "left_host" not in record["transfer_outcome"]:
            raise SystemExit(f"chunked basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
    if mode == "live-partial":
        if record["upload_verdict"] != "not_visible" or record["transfer_outcome"] != "off_host_measurement_incomplete":
            raise SystemExit(f"partial measurement closed as {record['upload_verdict']} {record['transfer_outcome']}")
        if "not_rewritten_as_not_found" not in record["detail"]:
            raise SystemExit(f"partial detail {record['detail']}")
    if mode == "live-short-post":
        if record["evidence_basis"] != "flow_txbytes" or "left_host" not in record["transfer_outcome"]:
            raise SystemExit(f"short post basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
        if MARKER not in receipt.get("data", b""):
            raise SystemExit("short post receiver did not get the synthetic bytes")
    if mode == "live-short-udp":
        if record["evidence_basis"] != "flow_txbytes_udp" or "left_host" not in record["transfer_outcome"]:
            raise SystemExit(f"short udp basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
        if MARKER not in receipt.get("data", b""):
            raise SystemExit("short udp receiver did not get the synthetic bytes")
    if mode == "live-short-refused":
        if record["evidence_basis"] != "flow_attempt":
            raise SystemExit(f"short refused basis {record['evidence_basis']} outcome {record['transfer_outcome']}")
    if mode == "live-short-unmeasured":
        if record["upload_verdict"] != "not_visible":
            raise SystemExit(f"short unmeasured closed as {record['upload_verdict']} {record['transfer_outcome']}")
        if record["upload_verdict"] == "not_found":
            raise SystemExit("short unmeasured connection was called 未发现")
    if mode == "live-tls-hello":
        if record["upload_verdict"] != "not_visible":
            raise SystemExit(f"tls handshake closed as {record['upload_verdict']} {record['transfer_outcome']}")
        if "tls_handshake_body_not_visible" not in record["transfer_outcome"]:
            raise SystemExit(f"tls handshake outcome {record['transfer_outcome']}")
        if record["evidence_basis"] == "flow_txbytes":
            raise SystemExit("tls handshake was counted as an upload")
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
    if mode == "live-refused":
        if record["evidence_basis"] != "flow_attempt":
            raise SystemExit(f"refused basis {record['evidence_basis']}")
        destination = record.get("destination") or ""
        if "[::" in destination:
            raise SystemExit(f"refused IPv4 was formatted as IPv6: {destination}")
        if destination.count(".") != 3:
            raise SystemExit(f"refused destination is not dotted IPv4: {destination}")
    if mode == "live-unknown-app":
        owner = ((record.get("actor_process") or {}).get("owning_agent") or {})
        if owner.get("bundle") != "UnknownAgent.app" or owner.get("name") != "UnknownAgent":
            raise SystemExit(f"unknown app owner {owner}")
        if record.get("evidence_basis") != "flow_txbytes":
            raise SystemExit(f"unknown app basis {record.get('evidence_basis')}")
        if "left_host" not in (record.get("transfer_outcome") or ""):
            raise SystemExit(f"unknown app outcome {record.get('transfer_outcome')}")
        if MARKER not in receipt.get("data", b""):
            raise SystemExit("unknown app receiver did not get the synthetic bytes")
    if expected == "uploaded" and mode not in ("live-offhost", "live-unknown-app", "live-udp-large", "live-compressed", "live-chunked", "live-short-post", "live-short-udp") and "upstream_http_2xx" not in record["transfer_outcome"]:
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
        kind = assert_case(mode, LAUNCHED_VERDICTS[mode], records, receipt)
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
    held = secret
    if mode == "live-compressed":
        held = directory / "compressible.env"
        held.write_bytes(MARKER + b"A" * 4000)
        os.chmod(held, 0o600)
        Path(str(held) + ".send").write_bytes(gzip.compress(held.read_bytes(), mtime=0))
    if mode == "live-udp":
        dummy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dummy.bind(("127.0.0.1", 0))
        port = dummy.getsockname()[1]
    elif mode in ("live-udp-large", "live-udp-small", "live-short-udp", "live-short-unmeasured"):
        host = routable_ip()
        if not host:
            return "skipped"
        dummy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dummy.bind((host, 0))
        port = dummy.getsockname()[1]
    elif mode == "live-attempt":
        host = "203.0.113.10"
        port = 443
    elif mode == "live-refused":
        host = routable_ip()
        if not host:
            return "skipped"
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, 0))
        except OSError:
            probe.close()
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("0.0.0.0", 0))
        port = probe.getsockname()[1]
        probe.close()
    elif mode == "live-chunked":
        host = routable_ip()
        if not host:
            return "skipped"
        server = Server(accept_timeout=10, bind_host="0.0.0.0", raw=True, accepts=3)
        port = server.port
    elif mode == "live-tls-hello":
        host = routable_ip()
        if not host:
            return "skipped"
        try:
            server = Server(accept_timeout=10, bind_host=host, raw=True, bind_port=443)
        except OSError:
            return "skipped"
        port = server.port
        if port != 443:
            return "skipped"
    elif mode == "live-short-refused":
        host = routable_ip()
        if not host:
            return "skipped"
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, 0))
        except OSError:
            probe.close()
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind(("0.0.0.0", 0))
        port = probe.getsockname()[1]
        probe.close()
    elif mode in ("live-offhost", "live-unknown-app", "live-compressed", "live-partial", "live-short-post"):
        host = routable_ip()
        if not host:
            return "skipped"
        server = Server(accept_timeout=10, bind_host="0.0.0.0", raw=(mode == "live-compressed"))
        port = server.port
    else:
        server = Server(accept_timeout=10)
        port = server.port
    port_file = directory / f"{mode}.port"
    duration = "8" if mode == "live-proxy" else "16" if mode == "live-refused" else "12"
    proxy_env = os.environ.copy()
    if mode in ("live-partial", "live-short-unmeasured"):
        proxy_env["REINS_DISABLE_NTSTAT"] = "1"
    if mode == "live-proxy":
        agent = subprocess.Popen([str(binary), "proxy", str(held), str(port_file), server.url("/upload")])
        time.sleep(0.3)
        proc = subprocess.Popen(
            [str(PROXY), "--log", str(log), "--sensitive-file", str(held), "--watch-live", "--duration", duration,
             "--sample-ms", "40", "--port-file", str(port_file)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=proxy_env)
    else:
        action = {
            "live-direct": "direct", "live-offhost": "direct", "live-unknown-app": "direct",
            "live-udp": "udp", "live-udp-small": "udp", "live-udp-large": "udp-file",
            "live-attempt": "attempt", "live-refused": "refused", "live-compressed": "payload",
            "live-chunked": "chunk3", "live-partial": "partial", "live-short-post": "short",
            "live-short-udp": "udp-short", "live-short-unmeasured": "udp-short",
            "live-short-refused": "refused-short", "live-tls-hello": "tls-hello",
        }[mode]
        ready = directory / f"{mode}.ready"
        agent = subprocess.Popen([str(binary), action, str(held), host, str(port), str(ready)])
        time.sleep(0.2)
        proc = subprocess.Popen(
            [str(PROXY), "--log", str(log), "--sensitive-file", str(held), "--watch-live", "--duration", duration,
             "--sample-ms", "40"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=proxy_env)
        time.sleep(1.0)
        ready.write_text("go\n")
        if mode in ("live-direct", "live-short-post", "live-tls-hello"):
            deadline = time.time() + 8
            while time.time() < deadline:
                if log.exists() and "sensitive_access_closed" in log.read_text():
                    break
                time.sleep(0.2)
            else:
                raise SystemExit(f"{mode} produced no sensitive_access_closed while the watch was still running")
    _out, err = finish(proc)
    try:
        agent.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent.kill()
    udp_payload = b""
    if dummy and mode in ("live-udp-large", "live-short-udp"):
        dummy.settimeout(1)
        try:
            udp_payload, _addr = dummy.recvfrom(65536)
        except socket.timeout:
            udp_payload = b""
    if dummy:
        dummy.close()
    receipt = {"port": port, "data": udp_payload, "error": None}
    if server:
        server.join()
        receipt["data"] = server.box.get("data", b"")
        receipt["error"] = server.box.get("error")
    records = load_records(log)
    expected = LIVE_VERDICTS[mode]
    try:
        kind = assert_live_case(mode, expected, records, receipt, held.name)
    except SystemExit:
        sys.stderr.write(redact(err))
        raise
    return kind


def live_after_canary(directory, unknown, secret):
    """A launched exact_bytes match must not swallow a later agent's own close."""
    host = routable_ip()
    if not host:
        return "skipped"
    log = directory / "live-after-canary.jsonl"
    canary_sink = Server(accept_timeout=20)
    offhost = Server(accept_timeout=20, bind_host="0.0.0.0")
    env = os.environ.copy()
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "no_proxy", "NO_PROXY"):
        env.pop(key, None)
    # The launched canary must stay alive. agent-egress stops when that child
    # exits, and the later agent would never be sampled.
    env["EGRESS_HOLD_MS"] = "12000"
    proc = subprocess.Popen(
        [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--watch-live", "--timeout-sec", "20",
         "--sample-ms", "40", "--launch", "--", sys.executable, str(CASE), "plaintext", canary_sink.url("/upload"), str(secret)],
        cwd=str(ROOT), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)
    ready = directory / "live-after-canary.ready"
    agent = subprocess.Popen([str(unknown), "direct", str(secret), host, str(offhost.port), str(ready)])
    time.sleep(2.0)
    ready.write_text("go\n")
    _out, err = finish(proc)
    try:
        agent.wait(timeout=8)
    except subprocess.TimeoutExpired:
        agent.kill()
    canary_sink.join()
    offhost.join()
    records = load_records(log)
    closes = [record for record in records if record["type"] == "sensitive_access_closed" and secret.name in (record.get("target_resource") or "")]
    canary = [record for record in closes if record.get("upload_verdict") == "uploaded" and "exact_bytes" in (record.get("detail") or "")]
    later = [record for record in closes if record.get("evidence_basis") == "flow_txbytes" and record.get("upload_verdict") == "uploaded"]
    if not canary or not later:
        sys.stderr.write(redact(err))
        raise SystemExit(
            "live-after-canary missing canary exact_bytes or later flow close: "
            + redact(json.dumps(closes)))
    owner = ((later[-1].get("actor_process") or {}).get("owning_agent") or {})
    if owner.get("bundle") != "UnknownAgent.app" or owner.get("name") != "UnknownAgent":
        raise SystemExit(f"later agent owner {owner}")
    if host not in (later[-1].get("destination") or ""):
        raise SystemExit(f"later destination {later[-1].get('destination')}")
    if MARKER not in offhost.box.get("data", b""):
        raise SystemExit("later receiver did not get the synthetic bytes")
    if MARKER.split(b"\n")[0] not in canary_sink.box.get("data", b""):
        raise SystemExit("canary receiver did not get the synthetic bytes")
    return "uploaded"


def xcode_python():
    roots = sorted(Path("/Applications").glob(
        "Xcode*.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/*/Resources/Python.app/Contents/MacOS/Python"))
    return roots[-1] if roots else None


def live_toolchain_chain(directory, secret):
    """A shell child under Grok Bot, with Xcode's Python in the middle, is owned by Grok Bot.app."""
    host = routable_ip()
    python = xcode_python()
    if not host:
        return "skipped"
    if python is None:
        raise SystemExit("live-toolchain-chain could not find Xcode's Python.app")
    chain = directory / "chain_wait"
    hold = directory / "hold-upload"
    subprocess.check_call(["/usr/bin/clang", "-O2", "-o", str(chain), str(ROOT / "tests/chain_wait.c")])
    subprocess.check_call(["/usr/bin/clang", "-O2", "-o", str(hold), str(ROOT / "tests/live_agent.c")])
    grok = directory / "Grok Bot.app" / "Contents" / "MacOS" / "Grok Bot"
    helper = directory / "Grok Bot.app" / "Contents" / "Frameworks" / "Grok Bot Helper.app" / "Contents" / "MacOS" / "Grok Bot Helper"
    grok.parent.mkdir(parents=True, exist_ok=True)
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(chain, grok)
    shutil.copy(chain, helper)
    os.chmod(grok, 0o755)
    os.chmod(helper, 0o755)
    server = Server(accept_timeout=20, bind_host="0.0.0.0")
    ready = directory / "toolchain.ready"
    log = directory / "live-toolchain.jsonl"
    hold_cmd = shlex.join([str(hold), "direct", str(secret), host, str(server.port), str(ready)])
    zsh_cmd = shlex.join([str(python), str(ROOT / "tests/toolchain_parent.py"), "/bin/bash", "-c", hold_cmd])
    proc = subprocess.Popen(
        [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--watch-live", "--duration", "16",
         "--sample-ms", "40"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3)
    agent = subprocess.Popen([str(grok), str(helper), "/bin/zsh", "-c", zsh_cmd])
    time.sleep(2.0)
    ready.write_text("go\n")
    _out, err = finish(proc)
    try:
        agent.wait(timeout=8)
    except subprocess.TimeoutExpired:
        agent.kill()
    server.join()
    records = load_records(log)
    closes = [record for record in records if record["type"] == "sensitive_access_closed"
              and secret.name in (record.get("target_resource") or "")
              and record.get("evidence_basis") == "flow_txbytes"
              and record.get("upload_verdict") == "uploaded"]
    if not closes:
        sys.stderr.write(redact(err))
        raise SystemExit("live-toolchain-chain missing uploaded flow close: " + redact(json.dumps(records)))
    owner = ((closes[-1].get("actor_process") or {}).get("owning_agent") or {})
    if owner.get("bundle") != "Grok Bot.app" or owner.get("name") != "Grok":
        raise SystemExit(f"toolchain chain owner {owner}")
    executable = (((closes[-1].get("actor_process") or {}).get("process") or {}).get("executable") or "")
    if not executable.endswith("/hold-upload"):
        raise SystemExit(f"toolchain chain actor {executable}")
    if host not in (closes[-1].get("destination") or ""):
        raise SystemExit(f"toolchain destination {closes[-1].get('destination')}")
    if MARKER not in server.box.get("data", b""):
        raise SystemExit("toolchain receiver did not get the synthetic bytes")
    return "uploaded"


def live_idle_reposts(directory, binary, secret):
    """Idle, then a short off-host POST, repeated cold and warm. Every one must upload."""
    host = routable_ip()
    if not host:
        return "skipped"
    server = Server(accept_timeout=40, bind_host="0.0.0.0", accepts=3)
    log = directory / "idle-reposts.jsonl"
    proc = subprocess.Popen(
        [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--watch-live", "--duration", "30",
         "--sample-ms", "40"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(1.2)
        for index in range(3):
            ready = directory / f"idle-repost-{index}.ready"
            if ready.exists():
                ready.unlink()
            before = log.read_text() if log.exists() else ""
            agent = subprocess.Popen([str(binary), "short", str(secret), host, str(server.port), str(ready)])
            time.sleep(0.05)
            ready.write_text("go\n")
            deadline = time.time() + 8
            while time.time() < deadline:
                text = log.read_text() if log.exists() else ""
                added = text[len(before):] if text.startswith(before) else text
                if '"upload_verdict":"uploaded"' in added.replace(" ", "") or '"upload_verdict": "uploaded"' in added:
                    break
                time.sleep(0.1)
            else:
                raise SystemExit(f"idle repost {index} produced no uploaded close\n{redact(text if log.exists() else '')}")
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
            time.sleep(1.2)
        records = load_records(log)
        uploads = [record for record in records
                   if record.get("type") == "sensitive_access_closed" and record.get("upload_verdict") == "uploaded"
                   and record.get("evidence_basis") == "flow_txbytes"]
        if len(uploads) < 3:
            raise SystemExit(f"idle reposts uploaded {len(uploads)} times, want 3")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    server.join()
    if server.box.get("data", b"").count(MARKER) < 3:
        raise SystemExit("idle reposts: the peer did not receive every 37-byte body")
    return "uploaded"


def main():
    if not PROXY.exists():
        raise SystemExit("agent-egress is not built")
    upload_tp = attempted_tp = tn = fp = fn = 0
    content_unseen = 0
    after_canary = "skipped"
    with tempfile.TemporaryDirectory(prefix="reins-egress-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        idle_log = directory / "idle.jsonl"
        secret = directory / "synthetic.env"
        secret.write_bytes(MARKER)
        os.chmod(secret, 0o600)
        ca = make_ca(directory)
        sleepers = [subprocess.Popen(["/bin/sleep", "8"]) for _ in range(40)]
        idle = subprocess.Popen(
            [str(PROXY), "--log", str(idle_log), "--sensitive-file", str(secret), "--watch-live", "--duration", "3",
             "--sample-ms", "50"],
            cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        idle_cpu, idle_rss = sample_process(idle.pid, 3.4)
        idle_out, idle_err = idle.communicate(timeout=10)
        for sleeper in sleepers:
            sleeper.kill()
        if idle.returncode != 0:
            raise SystemExit(f"idle proxy failed\n{idle_out}\n{idle_err}")
        idle_rss_median = median(idle_rss)
        idle_cpu_median = median(idle_cpu)
        if idle_rss_median is None or idle_rss_median > IDLE_RSS_KB_MAX or idle_cpu_median is None or idle_cpu_median > IDLE_CPU_PERCENT_MAX:
            raise SystemExit(
                f"idle watch exceeded the resource budget: rss_kb={idle_rss_median} cpu={idle_cpu_median} "
                f"caps rss_kb={IDLE_RSS_KB_MAX} cpu={IDLE_CPU_PERCENT_MAX}")
        active_cpu, active_rss = [], []
        for mode in LAUNCHED_VERDICTS:
            kind, cpu, rss, _err = one_case(directory, mode, measure=(mode == "https"), ca=ca)
            if mode == "https":
                active_cpu, active_rss = cpu, rss
            if kind == "uploaded":
                upload_tp += 1
            elif kind == "attempted":
                attempted_tp += 1
            elif kind == "not_found":
                tn += 1
            elif kind == "not_visible":
                content_unseen += 1
            elif kind != "transfer_only":
                fn += 1
        binary = directory / "codex"
        subprocess.check_call(["/usr/bin/clang", "-O2", "-o", str(binary), str(ROOT / "tests/live_agent.c")])
        unknown = directory / "UnknownAgent.app" / "Contents" / "MacOS" / "x"
        unknown.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(["/usr/bin/clang", "-O2", "-o", str(unknown), str(ROOT / "tests/live_agent.c")])
        os.chmod(unknown, 0o755)
        skipped = set()
        for mode in LIVE_VERDICTS:
            kind = live_case(directory, mode, unknown if mode == "live-unknown-app" else binary, secret)
            if kind == "skipped":
                skipped.add(mode)
                print(f"SKIP {mode} no routable address")
                continue
            if kind == "uploaded":
                upload_tp += 1
            elif kind == "attempted":
                attempted_tp += 1
            elif kind == "not_visible":
                content_unseen += 1
            elif kind == "not_found":
                tn += 1
            else:
                fn += 1
        reposts = live_idle_reposts(directory, binary, secret)
        if reposts == "skipped":
            print("SKIP live-idle-reposts no routable address")
        elif reposts == "uploaded":
            upload_tp += 3
        else:
            fn += 1
        after_canary = live_after_canary(directory, unknown, secret)
        if after_canary == "skipped":
            print("SKIP live-after-canary no routable address")
        elif after_canary == "uploaded":
            upload_tp += 1
        else:
            fn += 1
        toolchain = live_toolchain_chain(directory, secret)
        if toolchain == "skipped":
            print("SKIP live-toolchain-chain no routable address")
        elif toolchain == "uploaded":
            upload_tp += 1
        else:
            fn += 1
    # False positives and false negatives are assertion failures above. A passed
    # run has none. not_visible is unresolved, not a true negative and not a delivery pass.
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
    counted = dict(LAUNCHED_VERDICTS)
    counted.update({mode: verdict for mode, verdict in LIVE_VERDICTS.items() if mode not in skipped})
    if reposts == "uploaded":
        counted["live-idle-repost-1"] = "uploaded"
        counted["live-idle-repost-2"] = "uploaded"
        counted["live-idle-repost-3"] = "uploaded"
    if after_canary == "uploaded":
        counted["live-after-canary"] = "uploaded"
    if toolchain == "uploaded":
        counted["live-toolchain-chain"] = "uploaded"
    expect_upload, expect_attempted, expect_tn, expect_unseen = matrix_counts(counted)
    if (upload_tp, attempted_tp, tn, content_unseen, fp, fn) != (expect_upload, expect_attempted, expect_tn, expect_unseen, 0, 0):
        raise SystemExit(
            "verdict counts did not match the synthetic matrix: "
            f"got upload_tp={upload_tp} attempted_tp={attempted_tp} tn={tn} "
            f"content_unseen={content_unseen} fp={fp} fn={fn}; "
            f"expected upload_tp={expect_upload} attempted_tp={expect_attempted} tn={expect_tn} "
            f"content_unseen={expect_unseen} fp=0 fn=0"
        )


if __name__ == "__main__":
    main()
