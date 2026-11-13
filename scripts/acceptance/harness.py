#!/usr/bin/env python3
"""Real-agent acceptance harness with fake secrets only.

Does not install a LaunchAgent, edit MCP or client configs, install a CA,
or read real credential files. Real agents run only in owner mode after
--i-approve-real-agents, or on CI when the matching API key secret is set
and the CLI is already installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
STAND_IN = SCRIPT_DIR / "stand_in_agent.py"
sys.path.insert(0, str(SCRIPT_DIR))
from check_chain import LABELS, ChainCheckError, check_document, scan_text  # noqa: E402

CASES = [
    {
        "id": "codex_launched_upload",
        "counts_as_real_agent": True,
        "executor": "codex",
        "action": "post",
        "secret": "env",
        "launch": "proxy",
        "verdict": "uploaded",
        "agent": "Codex",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
    {
        "id": "codex_already_running_not_visible",
        "counts_as_real_agent": True,
        "executor": "codex",
        "action": "direct",
        "secret": "ssh",
        "launch": "already",
        "verdict": "not_found",
        "agent": "Codex",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
    {
        "id": "cursor_cli_upload",
        "counts_as_real_agent": True,
        "executor": "cursor",
        "action": "post",
        "secret": "env",
        "launch": "proxy",
        "verdict": "uploaded",
        "agent": "Cursor",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
    {
        "id": "workbuddy_manual",
        "counts_as_real_agent": True,
        "executor": "workbuddy",
        "action": "direct",
        "secret": "env",
        "launch": "manual",
        "verdict": "not_found",
        "agent": "WorkBuddy",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
    {
        "id": "negative_read_no_send",
        "counts_as_real_agent": False,
        "executor": "stand-in",
        "action": "read",
        "secret": "aws",
        "launch": "proxy",
        "verdict": "not_found",
        "agent": "",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": False,
    },
    {
        "id": "stand_in_launched_upload",
        "counts_as_real_agent": False,
        "executor": "stand-in",
        "action": "post",
        "secret": "env",
        "launch": "proxy",
        "verdict": "uploaded",
        "agent": "",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
    {
        "id": "stand_in_direct_not_visible",
        "counts_as_real_agent": False,
        "executor": "stand-in",
        "action": "direct",
        "secret": "ssh",
        "launch": "proxy",
        "verdict": "not_visible",
        "agent": "",
        "require_open": True,
        "require_already_running": False,
        "require_loopback": True,
    },
]


def python_bin():
    return "/usr/bin/python3" if Path("/usr/bin/python3").is_file() else sys.executable


def write_private(path: Path, text: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def assert_safe_dir(path: Path):
    resolved = path.resolve()
    home = Path.home().resolve()
    for name in (".ssh", ".aws", ".config"):
        forbidden = (home / name).resolve()
        if resolved == forbidden or forbidden in resolved.parents:
            raise SystemExit("refusing to put fake secrets under a real credential directory")
    if resolved == home:
        raise SystemExit("refusing to use the home directory as the secret workspace")


def create_secrets(root: Path):
    assert_safe_dir(root)
    env_value = "reins-fake-env-NOT-A-REAL-SECRET-7f3a9c2e18b04d"
    aws_secret = "reins-fake-aws-NOT-A-REAL-SECRET-b4e19d55aa01"
    aws_key = "AKIAFAKEACCEPTANCEONLY0001"
    ssh_marker = "FAKE-NOT-A-REAL-KEY"
    ssh_value = "reins-fake-ssh-NOT-A-REAL-SECRET-c0917e44"
    files = {
        "env": (
            "fake.env",
            "# FAKE SECRET FOR REINSCREDENTIAL ACCEPTANCE. NOT A REAL CREDENTIAL.\n"
            "# Do not use this value. It cannot authenticate.\n"
            f"REINS_FAKE_ENV_SECRET={env_value}\n",
            [env_value],
        ),
        "aws": (
            "fake-aws-credentials",
            "# FAKE AWS CREDENTIALS FOR REINSCREDENTIAL ACCEPTANCE. NOT REAL.\n"
            "# These values are not AWS credentials and cannot authenticate.\n"
            "[default]\n"
            f"aws_access_key_id = {aws_key}\n"
            f"aws_secret_access_key = {aws_secret}\n",
            [aws_key, aws_secret],
        ),
        "ssh": (
            "fake_id_ed25519",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{ssh_marker} reins-acceptance-only\n"
            "This file is not a private key. It cannot authenticate.\n"
            f"{ssh_value}\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            [ssh_marker, ssh_value],
        ),
    }
    secrets = {}
    markers = []
    for key, (name, text, values) in files.items():
        path = root / name
        write_private(path, text)
        digest = hashlib.sha256(text.encode()).hexdigest()
        secrets[key] = {"path": path, "sha256": digest, "filename": name, "nbytes": len(text.encode())}
        markers.extend(values)
    return secrets, markers


class LoopbackSink:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.hashes = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(0.3)
        while not self.stopped.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if addr[0] != "127.0.0.1":
                conn.close()
                continue
            with conn:
                conn.settimeout(3)
                data = b""
                try:
                    while b"\r\n\r\n" not in data and len(data) < 65536:
                        block = conn.recv(4096)
                        if not block:
                            break
                        data += block
                    body = b""
                    if b"\r\n\r\n" in data:
                        head, rest = data.split(b"\r\n\r\n", 1)
                        length = 0
                        for line in head.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                length = int(line.split(b":", 1)[1].strip())
                        while len(rest) < length and len(rest) < 2 * 1024 * 1024:
                            block = conn.recv(8192)
                            if not block:
                                break
                            rest += block
                        body = rest[:length]
                    if body:
                        self.hashes.append(hashlib.sha256(body).hexdigest())
                    del body
                    del data
                    # Stay open briefly so a direct socket remains visible to libproc.
                    time.sleep(1.0)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                except (OSError, ValueError):
                    pass

    def stop(self):
        self.stopped.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


def stop_process(proc, kill_group=False):
    if proc is None or proc.poll() is not None:
        return
    try:
        if kill_group:
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            if kill_group:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def which(name):
    found = shutil.which(name)
    return Path(found) if found else None


def find_codex():
    found = which("codex")
    if found:
        return found
    for candidate in (Path("/usr/local/bin/codex"), Path.home() / ".local/bin/codex"):
        if candidate.is_file():
            return candidate
    return None


def looks_like_cursor(path: Path):
    if "cursor" in str(path).lower():
        return True
    try:
        blob = path.read_bytes()[:4096].lower()
    except OSError:
        return False
    return b"cursor" in blob


def find_cursor():
    found = which("cursor-agent")
    if found:
        return found
    for candidate in (Path.home() / ".local/bin/cursor-agent", Path.home() / ".local/bin/agent", which("agent")):
        if candidate and candidate.is_file() and looks_like_cursor(candidate):
            return candidate
    return None


def key_present(*names):
    for name in names:
        value = os.environ.get(name, "")
        if len(value) >= 8:
            return True
    return False


def scrub(text, markers):
    redacted = text
    for marker in markers:
        if marker:
            redacted = redacted.replace(marker, "[redacted]")
    return redacted


def read_log(path: Path):
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def child_pid(text):
    marker = "egress child "
    index = text.rfind(marker)
    if index < 0:
        return None
    number = []
    for char in text[index + len(marker):]:
        if char.isdigit():
            number.append(char)
        else:
            break
    return int("".join(number)) if number else None


def build_tools():
    subprocess.run(["make", "agent-monitor", "agent-egress"], cwd=ROOT, check=True)
    show = subprocess.run(
        ["swift", "build", "--package-path", str(ROOT / "macOSClient"), "--product", "chain-export", "--show-bin-path"],
        cwd=ROOT, check=True, text=True, capture_output=True,
    )
    binary = Path(show.stdout.strip()) / "chain-export"
    if not binary.is_file():
        subprocess.run(
            ["swift", "build", "--package-path", str(ROOT / "macOSClient"), "--product", "chain-export"],
            cwd=ROOT, check=True,
        )
    if not binary.is_file():
        raise SystemExit("chain-export was not produced")
    return {
        "monitor": ROOT / "agent-monitor",
        "egress": ROOT / "agent-egress",
        "export": binary,
    }


def start_monitor(binary, workspace, log_path, err_path):
    err = open(err_path, "w")
    proc = subprocess.Popen(
        [str(binary), "--no-default-sensitive", "--sensitive", str(workspace),
         "--log", str(log_path), "--interval-ms", "100", "--duration", "150", "--workers", "2"],
        cwd=str(workspace), stdout=subprocess.DEVNULL, stderr=err, start_new_session=True,
    )
    err.close()
    return proc


def start_egress(binary, workspace, log_path, err_path, files, launch, watch_live, timeout):
    command = [str(binary), "--log", str(log_path), "--sample-ms", "20", "--timeout-sec", str(timeout)]
    for path in files:
        command.extend(["--sensitive-file", str(path)])
    port_file = workspace / "egress.port"
    command.extend(["--port-file", str(port_file)])
    if watch_live:
        command.extend(["--watch-live", "--duration", str(timeout)])
    if launch:
        command.extend(["--launch", "--", *launch])
    err = open(err_path, "w")
    proc = subprocess.Popen(command, cwd=str(workspace), stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
    err.close()
    return proc, port_file


def cleaned_env(base=None):
    env = dict(base or os.environ)
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy",
                 "EGRESS_PROXY", "EGRESS_PROXY_PORT"):
        env.pop(name, None)
    if not env.get("OPENAI_API_KEY") and env.get("CODEX_API_KEY"):
        env["OPENAI_API_KEY"] = env["CODEX_API_KEY"]
    return env


def action_argv(workspace, secret, mode, port, ready):
    argv = [python_bin(), str(workspace / "stand_in_agent.py"), str(secret["path"]), mode, "127.0.0.1", str(port)]
    if ready is not None:
        argv.extend(["--wait-ready", str(ready)])
    return argv


def prompt_for(argv):
    shown = " ".join(argv)
    return (
        "You are in an authorized local acceptance test. Stay inside this directory. "
        "Do not read, print, or exfiltrate any file except by running the one command below. "
        "Do not print file contents. Do not change MCP settings, application settings, shell profiles, or keychains. "
        "Do not contact any host except 127.0.0.1. "
        f"Run exactly this command and wait for it to exit:\n{shown}\n"
        "Reply with the exit status only."
    )


def launch_command(case, workspace, secret, port, ready):
    argv = action_argv(workspace, secret, case["action"], port, ready)
    executor = case["executor"]
    if executor == "stand-in":
        return argv, None
    if executor == "codex":
        binary = find_codex()
        if binary is None:
            return None, "codex executable not found; not installed by this harness"
        command = [str(binary), "exec", "--ignore-user-config", "--disable", "apps",
                   "--sandbox", "workspace-write", "--ephemeral", "--skip-git-repo-check",
                   "-C", str(workspace), prompt_for(argv)]
        return command, None
    if executor == "cursor":
        binary = find_cursor()
        if binary is None:
            return None, "cursor CLI not found; not installed by this harness"
        command = [str(binary), "--print", "--output-format", "text", "--trust",
                   "--workspace", str(workspace), prompt_for(argv)]
        return command, None
    return None, "manual case is not launched"


def real_agent_allowed(case, mode, approved):
    if not case["counts_as_real_agent"]:
        return True, ""
    if case["executor"] == "workbuddy":
        return False, "manual"
    if mode == "owner":
        if not approved:
            return False, "owner approval required"
        return True, ""
    if mode != "ci":
        return False, "not executed"
    if case["executor"] == "codex":
        if find_codex() is None:
            return False, "codex executable not found on the runner"
        if not key_present("OPENAI_API_KEY", "CODEX_API_KEY"):
            return False, "no Codex API key secret; stand-in is not counted as this case"
        return True, ""
    if case["executor"] == "cursor":
        if find_cursor() is None:
            return False, "cursor CLI not found; manual steps are in scripts/acceptance/README.md"
        if not key_present("CURSOR_API_KEY"):
            return False, "cursor CLI is present but no CURSOR_API_KEY secret; not executed"
        return True, ""
    return False, "not executed"


def export_chains(binary, logs, dest):
    existing = [str(path) for path in logs if path.exists() and path.stat().st_size > 0]
    if not existing:
        raise ChainCheckError("no evidence log was written")
    result = subprocess.run([str(binary), *existing], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        tail = detail[-1] if detail else "chain-export failed"
        raise ChainCheckError(tail[:240])
    dest.write_text(result.stdout)
    return result.stdout


def run_case(case, tools):
    workspace = Path(tempfile.mkdtemp(prefix="reins-fake-acceptance-"))
    os.chmod(workspace, 0o700)
    sink = LoopbackSink()
    monitor = None
    egress = None
    agent = None
    markers = []
    try:
        secrets, markers = create_secrets(workspace)
        secret = secrets[case["secret"]]
        shutil.copyfile(STAND_IN, workspace / "stand_in_agent.py")
        os.chmod(workspace / "stand_in_agent.py", 0o700)
        monitor_log = workspace / "monitor.jsonl"
        egress_log = workspace / "egress.jsonl"
        monitor = start_monitor(tools["monitor"], workspace, monitor_log, workspace / "monitor.err")
        time.sleep(0.4)
        files = [item["path"] for item in secrets.values()]
        ready = workspace / "ready-to-read"
        timeout = 30 if case["executor"] == "stand-in" else 110
        if case["launch"] == "proxy":
            command, reason = launch_command(case, workspace, secret, sink.port, None)
            if command is None:
                return skipped(case, reason, markers)
            egress, _port = start_egress(tools["egress"], workspace, egress_log, workspace / "egress.err",
                                         files, command, False, timeout)
            try:
                egress.wait(timeout=timeout + 15)
            except subprocess.TimeoutExpired:
                stop_process(egress, kill_group=True)
        elif case["launch"] == "already":
            command, reason = launch_command(case, workspace, secret, sink.port, ready)
            if command is None:
                return skipped(case, reason, markers)
            egress, _port = start_egress(tools["egress"], workspace, egress_log, workspace / "egress.err",
                                         files, None, True, timeout)
            time.sleep(0.6)
            agent = subprocess.Popen(command, cwd=str(workspace), env=cleaned_env(),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            time.sleep(0.4)
            write_private(ready, "go\n")
            try:
                agent.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_process(agent, kill_group=True)
            stop_process(egress, kill_group=True)
        else:
            return skipped(case, "manual", markers)
        stop_process(monitor, kill_group=True)
        monitor = None
        for path in (monitor_log, egress_log, workspace / "monitor.err", workspace / "egress.err"):
            scan_text(read_log(path), markers)
        observed_pid = None
        err_text = read_log(workspace / "egress.err")
        if case["launch"] == "proxy":
            observed_pid = child_pid(err_text)
            if observed_pid is None:
                raise ChainCheckError("did not observe the launched child pid")
        elif agent is not None:
            observed_pid = agent.pid
        export_path = workspace / "evidence-chain.json"
        export_chains(tools["export"], [monitor_log, egress_log], export_path)
        expectation = {
            "file_name": secret["filename"],
            "verdict": case["verdict"],
            "agent": case["agent"],
            "pid": observed_pid,
            "sha256": secret["sha256"] if case["verdict"] == "uploaded" else "",
            "sink_port": sink.port,
            "require_open": case["require_open"],
            "require_already_running": case["require_already_running"],
            "require_loopback": case["require_loopback"],
        }
        # The launched child pid is agent-egress's child. For a real CLI that
        # pid is the CLI, which should appear in the process link. If the
        # descriptor was on a grandchild and the parent walk missed, the check fails.
        observed = check_document(export_path, expectation, markers)
        sink_match = None
        if case["action"] in ("post", "direct"):
            sink_match = secret["sha256"] in sink.hashes
            if case["action"] == "post" and not sink_match:
                raise ChainCheckError("local sink did not receive the fake file hash")
        status = "passed"
        return result_row(case, status, "", observed, sink_match, executed=True)
    except ChainCheckError as error:
        tail = scrub(read_log(workspace / "egress.err"), markers).strip().splitlines()
        reason = str(error)
        if tail:
            reason = reason + " | " + tail[-1][:180]
        return result_row(case, "failed", reason, {}, None, executed=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        return result_row(case, "failed", scrub(str(error), markers)[:300], {}, None, executed=True)
    finally:
        stop_process(agent, kill_group=True)
        stop_process(egress, kill_group=True)
        stop_process(monitor, kill_group=True)
        sink.stop()
        shutil.rmtree(workspace, ignore_errors=True)


def skipped(case, reason, markers):
    return result_row(case, "not_executed", scrub(reason, markers), {}, None, executed=False)


def result_row(case, status, reason, observed, sink_match, executed):
    return {
        "id": case["id"],
        "counts_as_real_agent": case["counts_as_real_agent"],
        "executor": case["executor"],
        "expected": {
            "verdict": case["verdict"],
            "verdict_label": LABELS[case["verdict"]],
            "owning_agent": case["agent"],
            "open_observed": case["require_open"],
            "already_running_reason": case["require_already_running"],
        },
        "actual": {
            "status": status,
            "executed": executed,
            "reason": reason,
            "verdict": observed.get("verdict", ""),
            "verdict_label": observed.get("verdict_label", ""),
            "owning_agent": observed.get("owning_agent", ""),
            "open_observed": observed.get("open_observed", False),
            "channel_mentions_already_running": observed.get("channel_mentions_already_running", False),
            "destination_is_loopback": observed.get("destination_is_loopback", False),
            "sink_sha256_matched": sink_match,
        },
        "passed": status == "passed",
    }


def run_manual(case, tools):
    if not sys.stdin.isatty():
        return skipped(case, "manual steps need a terminal; see scripts/acceptance/README.md", [])
    workspace = Path(tempfile.mkdtemp(prefix="reins-fake-acceptance-"))
    os.chmod(workspace, 0o700)
    sink = LoopbackSink()
    monitor = None
    egress = None
    markers = []
    try:
        secrets, markers = create_secrets(workspace)
        secret = secrets[case["secret"]]
        shutil.copyfile(STAND_IN, workspace / "stand_in_agent.py")
        os.chmod(workspace / "stand_in_agent.py", 0o700)
        monitor_log = workspace / "monitor.jsonl"
        egress_log = workspace / "egress.jsonl"
        monitor = start_monitor(tools["monitor"], workspace, monitor_log, workspace / "monitor.err")
        files = [item["path"] for item in secrets.values()]
        egress, _port = start_egress(tools["egress"], workspace, egress_log, workspace / "egress.err",
                                     files, None, True, 120)
        command = action_argv(workspace, secret, "direct", sink.port, None)
        sys.stderr.write(
            "WorkBuddy manual case. Do not change WorkBuddy settings.\n"
            "In the already-running WorkBuddy session, run only:\n  "
            + " ".join(command)
            + "\nExpected verdict: 未发现 (loopback send did not leave the host). Press Enter here after it exits.\n"
        )
        sys.stdin.readline()
        stop_process(egress, kill_group=True)
        egress = None
        stop_process(monitor, kill_group=True)
        monitor = None
        for path in (monitor_log, egress_log):
            scan_text(read_log(path), markers)
        export_path = workspace / "evidence-chain.json"
        export_chains(tools["export"], [monitor_log, egress_log], export_path)
        observed = check_document(export_path, {
            "file_name": secret["filename"],
            "verdict": case["verdict"],
            "agent": case["agent"],
            "pid": None,
            "sha256": "",
            "sink_port": sink.port,
            "require_open": case["require_open"],
            "require_already_running": case["require_already_running"],
            "require_loopback": case["require_loopback"],
        }, markers)
        return result_row(case, "passed", "", observed, secret["sha256"] in sink.hashes, executed=True)
    except ChainCheckError as error:
        return result_row(case, "failed", str(error), {}, None, executed=True)
    finally:
        stop_process(egress, kill_group=True)
        stop_process(monitor, kill_group=True)
        sink.stop()
        shutil.rmtree(workspace, ignore_errors=True)


def manual_instructions():
    return (
        "WorkBuddy is not started by this harness, and its settings are not modified.\n"
        "On the owner Mac, after reading scripts/acceptance/README.md:\n"
        "  scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only workbuddy_manual\n"
        "The command prints a temp directory and a 127.0.0.1 sink. In the already-running\n"
        "WorkBuddy session, run only the printed python3 command. It reads one fake file\n"
        "in that temp directory and POSTs it straight to the sink, not through the proxy.\n"
        "Expected chain: owning agent WorkBuddy, verdict 未发现, because the POST stays on\n"
        "127.0.0.1. 看不到 is only when that process cannot be inspected. Do not point\n"
        "WorkBuddy at ~/.ssh or ~/.aws."
    )


def select_cases(only):
    if not only:
        return list(CASES)
    wanted = [item.strip() for item in only.split(",") if item.strip()]
    known = {case["id"] for case in CASES}
    missing = [item for item in wanted if item not in known]
    if missing:
        raise SystemExit("unknown case: " + ", ".join(missing))
    return [case for case in CASES if case["id"] in wanted]


def overall(rows):
    real = [row for row in rows if row["counts_as_real_agent"]]
    if real and all(row["passed"] and row["actual"]["executed"] for row in real):
        return "passed"
    return "not_passed"


def write_report(path: Path, mode, rows, notes):
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": "reinscredential.real-agent-acceptance.v1",
        "date": date.today().isoformat(),
        "mode": mode,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "overall_acceptance": overall(rows),
        "real_agent_acceptance": overall(rows) == "passed",
        "stand_in_is_not_real_agent_acceptance": True,
        "notes": notes,
        "cases": rows,
    }
    text = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    scan_text(text, [])
    path.write_text(text)
    return document


def prepare_rows(cases):
    rows = []
    for case in cases:
        if case["executor"] == "workbuddy":
            reason = "manual; " + manual_instructions().splitlines()[0]
        elif case["counts_as_real_agent"]:
            reason = "prepared, not executed; owner approval required"
        else:
            reason = "stand-in; not executed in prepare mode"
        rows.append(skipped(case, reason, []))
    return rows


def run_mode(mode, cases, approved, results_path):
    notes = [
        "Fake secrets are created only in a temporary directory and deleted afterwards.",
        "The sink is http://127.0.0.1 and is started by this process.",
        "agent-monitor is started with --no-default-sensitive so ~/.ssh and ~/.aws are not watched.",
        "No CA is installed and no MCP or client config is written.",
        "A stand-in result does not count as real-agent acceptance.",
    ]
    if mode == "prepare":
        rows = prepare_rows(cases)
        notes.append(manual_instructions())
        document = write_report(results_path, mode, rows, notes)
        print_summary(document)
        print(manual_instructions())
        return 0
    if platform.system() != "Darwin":
        rows = prepare_rows(cases)
        notes.append("This host is not macOS. Collector cases were not executed.")
        document = write_report(results_path, mode, rows, notes)
        print_summary(document)
        return 0 if mode == "prepare" else 1
    tools = build_tools()
    rows = []
    failed = False
    for case in cases:
        allowed, reason = real_agent_allowed(case, mode, approved)
        if case["executor"] == "workbuddy":
            if mode == "owner" and approved:
                row = run_manual(case, tools)
                if row["actual"]["executed"] and not row["passed"]:
                    failed = True
            else:
                row = skipped(case, "manual; see scripts/acceptance/README.md", [])
            rows.append(row)
            continue
        if not allowed:
            rows.append(skipped(case, reason, []))
            continue
        row = run_case(case, tools)
        rows.append(row)
        if row["actual"]["executed"] and not row["passed"]:
            failed = True
            if case["counts_as_real_agent"]:
                notes.append(case["id"] + " ran and did not match. Overall acceptance stays not passed.")
    document = write_report(results_path, mode, rows, notes)
    print_summary(document)
    return 1 if failed else 0


def print_summary(document):
    print("overall_acceptance=" + document["overall_acceptance"])
    print("real_agent_acceptance=" + str(document["real_agent_acceptance"]).lower())
    for row in document["cases"]:
        actual = row["actual"]
        print(
            row["id"]
            + " expected="
            + row["expected"]["verdict_label"]
            + " actual="
            + (actual["verdict_label"] or actual["status"])
            + " agent="
            + (actual["owning_agent"] or "-")
            + " real="
            + str(row["counts_as_real_agent"]).lower()
            + " passed="
            + str(row["passed"]).lower()
            + ((" reason=" + actual["reason"]) if actual["reason"] else "")
        )


def main(argv):
    parser = argparse.ArgumentParser(description="Fake-secret real-agent acceptance harness")
    parser.add_argument("--mode", choices=["prepare", "ci", "owner"], default="prepare")
    parser.add_argument("--i-approve-real-agents", action="store_true")
    parser.add_argument("--only", default="")
    parser.add_argument("--results", default=str(ROOT / "tests/results/real_agent_acceptance.json"))
    args = parser.parse_args(argv)
    if args.mode == "owner" and not args.i_approve_real_agents:
        sys.stderr.write(
            "owner mode does not run until you pass --i-approve-real-agents.\n"
            "Read scripts/acceptance/README.md first. This harness does not install anything.\n"
        )
        return 2
    cases = select_cases(args.only)
    try:
        return run_mode(args.mode, cases, args.i_approve_real_agents, Path(args.results))
    except ChainCheckError as error:
        sys.stderr.write(str(error) + "\n")
        return 1
    except (OSError, subprocess.CalledProcessError) as error:
        note = "harness stopped before the cases finished: " + str(error).splitlines()[-1][:240]
        write_report(Path(args.results), args.mode, prepare_rows(cases), [note])
        sys.stderr.write(note + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
