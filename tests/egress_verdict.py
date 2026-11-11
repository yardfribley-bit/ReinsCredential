#!/usr/bin/env python3
"""Egress-proxy verdicts for a launched process tree.

The sensitive bytes are synthetic. This does not read real credentials and it
does not start the Unix content gateway.
"""
import gzip
import json
import os
import socket
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
    def __init__(self, status=200, raw=False):
        self.status = status
        self.raw = raw
        self.box = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(15)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _run(self):
        try:
            conn, _addr = self.sock.accept()
        except Exception as error:
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


def load_records(path):
    records = []
    text = path.read_text()
    if MARKER.decode() in text or MARKER.decode().strip() in text:
        raise SystemExit("evidence log contains the synthetic secret bytes")
    for line in text.splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def run_proxy(log, secret, command, env, timeout=25):
    proc = subprocess.Popen(
        [str(PROXY), "--log", str(log), "--sensitive-file", str(secret), "--sample-ms", "20", "--timeout-sec", "20",
         "--launch", "--", *command],
        cwd=str(ROOT), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc


def finish(proc):
    try:
        out, err = proc.communicate(timeout=30)
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
    if record["upload_verdict"] != expected:
        raise SystemExit(f"{mode} verdict {record['upload_verdict']} != {expected}\n{redact(json.dumps(record))}")
    if not record["destination"] or not record["transfer_outcome"]:
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
    if mode == "fail500" and not record["transfer_outcome"].startswith("upstream_http_500"):
        raise SystemExit(f"fail500 outcome {record['transfer_outcome']}")
    if mode == "refused" and record["transfer_outcome"] != "connect_failed":
        raise SystemExit(f"refused outcome {record['transfer_outcome']}")
    if expected == "uploaded" and "upstream_http_2xx" not in record["transfer_outcome"]:
        raise SystemExit(f"uploaded outcome {record['transfer_outcome']}")
    if mode in ("plaintext", "json", "base64", "gzip", "bypass", "fail500", "noopen"):
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


def one_case(directory, mode, measure=False):
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
    status = 500 if mode == "fail500" else 200
    server = None if mode == "refused" else Server(status=status, raw=raw)
    if mode == "refused":
        url = "http://127.0.0.1:1/upload"
    elif mode == "bypass":
        url = server.url("/bypass-gateway")
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
    command = [sys.executable, str(CASE), mode, url, str(secret)]
    if mode == "noopen":
        command.append(str(payload))
    proc = run_proxy(log, secret, command, env)
    cpu, rss = ([], [])
    if measure:
        cpu, rss = sample_process(proc.pid, 6)
    out, err = finish(proc)
    receipt = {"port": server.port, "data": b"", "error": None} if server else {"port": 1, "data": b"", "error": None}
    if server:
        server.join()
        receipt["data"] = server.box.get("data", b"")
        receipt["error"] = server.box.get("error")
        if mode in ("direct", "connect", "plaintext", "bypass", "fail500", "json", "base64", "gzip", "noopen") and not receipt["data"] and not receipt["error"]:
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
        idle = subprocess.Popen(
            [str(PROXY), "--log", str(idle_log), "--sensitive-file", str(secret), "--duration", "3", "--sample-ms", "50"],
            cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        idle_cpu, idle_rss = sample_process(idle.pid, 3.4)
        idle_out, idle_err = idle.communicate(timeout=10)
        if idle.returncode != 0:
            raise SystemExit(f"idle proxy failed\n{idle_out}\n{idle_err}")
        active_cpu, active_rss = [], []
        for mode in ("plaintext", "json", "base64", "gzip", "fail500", "refused", "bypass", "benign", "direct", "connect", "noopen"):
            kind, cpu, rss, _err = one_case(directory, mode, measure=(mode == "benign"))
            if mode == "benign":
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
    if upload_tp != 5 or attempted_tp != 2 or tn != 3 or content_unseen != 2:
        raise SystemExit("verdict counts did not match the synthetic matrix")


if __name__ == "__main__":
    main()
