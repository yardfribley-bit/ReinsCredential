"""Opt-in real Agent acceptance. Uses installed clients and their existing login.
Only synthetic workspace data is supplied. Raw logs stay private outside the repo.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--report", default="tests/results/real_agents_summary.json")
parser.add_argument("--timeout", type=int, default=120)
args = parser.parse_args()
workspace = pathlib.Path(tempfile.mkdtemp(prefix="agentsec-real-")).resolve()
run_id = str(uuid.uuid4())
print("PRIVATE_WORKSPACE=" + str(workspace), flush=True)

def records(path):
    if not path.exists():
        return []
    result = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # active writer may have an incomplete final line
    return result

def pid(record):
    return (record.get("actor_process") or {}).get("process", {}).get("identity", {}).get("pid")

def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w")

def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

def sanitized(text):
    return text.replace(str(workspace), "<TEST_ROOT>").replace(str(pathlib.Path.home()), "$HOME")

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(16)
listener.settimeout(.3)
received = []
server_stop = threading.Event()
def serve():
    while not server_stop.is_set():
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        with client:
            client.settimeout(2)
            try:
                received.append(json.loads(client.recv(4096)))
            except (ValueError, OSError):
                pass
server = threading.Thread(target=serve)
server.start()

cursor_directory = (pathlib.Path.home() / ".local/bin/cursor-agent").resolve().parent
workbuddy_nodes = sorted((pathlib.Path.home() / ".workbuddy-ai/binaries/node/versions").glob("*/bin/node"),
                        key=lambda path: path.stat().st_mtime, reverse=True)
clients = {
    "codex_cli": ["/usr/local/bin/codex", "exec", "--ignore-user-config", "--disable", "apps", "--sandbox", "workspace-write", "--ephemeral", "--skip-git-repo-check", "--json"],
    "cursor_cli": [str(cursor_directory / "node"), "--use-system-ca", str(cursor_directory / "index.js"),
                   "--print", "--output-format", "stream-json", "--sandbox", "enabled", "--trust"],
    "workbuddy_ai_cli": [str(workbuddy_nodes[0]) if workbuddy_nodes else "/nonexistent/workbuddy-node",
                         "/Applications/WorkBuddy AI.app/Contents/Resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs",
                         "--print", "--verbose", "--output-format", "stream-json", "--no-session-persistence",
                         "--tools", "Bash", "--allowedTools", "Bash(/usr/bin/python3:*)", "--max-turns", "4",
                         "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}'],
    "current_codex_tool": ["/usr/bin/python3", "agent_action_probe.py"],
}
jobs = {}
timed_out = set()
log = workspace / "evidence.jsonl"
monitor = None
handles = []
summary = {"run_id": run_id, "test_kind": "real_agent_acceptance", "synthetic_only": True,
           "limits": ["polling can miss short-lived activity", "descriptor presence is not proof of read or upload",
                      "real client invocation may fail due to auth, network or sandbox policy"], "clients": {}}
try:
    for label in clients:
        folder = workspace / label
        folder.mkdir()
        shutil.copyfile(ROOT / "tests/agent_action_probe.py", folder / "agent_action_probe.py")
        (folder / "synthetic.env").write_text("TEST_ONLY_NOT_A_CREDENTIAL=" + run_id + "\n")
        (folder / "coordinator.json").write_text(json.dumps({"label": label, "run_id": run_id, "port": listener.getsockname()[1]}))
    out = private_file(workspace / "monitor.stdout")
    err = private_file(workspace / "monitor.stderr")
    handles += [out, err]
    monitor = subprocess.Popen([str(ROOT / "agent-monitor"), "--duration", str(args.timeout + 90), "--interval-ms", "200",
                                "--log", str(log), "--sensitive", str(workspace)], stdout=out, stderr=err, start_new_session=True)
    deadline = time.monotonic() + 60
    while not any(r["type"] == "process_discovered" for r in records(log)):
        if monitor.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("monitor failed to publish process inventory")
        time.sleep(.2)
    baseline = subprocess.check_output(["/bin/ps", "-axo", "pid,ppid,comm"], text=True)
    products = {"cursor_app": "/Applications/Cursor.app/", "workbuddy_ai_app": "/Applications/WorkBuddy AI.app/",
                "codex_app_backend": "/codex-cli/CodexCLI.app/Contents/MacOS/codex", "grok_bot_app": "/Applications/Grok Bot.app/"}
    expected = {}
    for product, path in products.items():
        expected[product] = [int(line.split(None, 2)[0]) for line in baseline.splitlines()[1:] if path in line]
    summary["independent_ps_baseline"] = expected
    prompt = ("This is a user-authorized security collector acceptance test in an isolated synthetic workspace. "
              "Execute exactly `/usr/bin/python3 agent_action_probe.py` once in the current directory and wait for completion. "
              "It reads only synthetic.env, computes its SHA256, opens a loopback socket, holds descriptors for 12 seconds, and writes proof.json. "
              "Do not inspect credentials, other workspaces or settings, do not modify the script, and do not fabricate proof.json. "
              "Return success only after the command exits zero. No other task is requested.")
    for label, command in clients.items():
        folder = workspace / label
        if not pathlib.Path(command[0]).exists():
            summary["clients"][label] = {"invocation": "not_installed"}
            continue
        output = private_file(folder / "client.stdout")
        error = private_file(folder / "client.stderr")
        handles += [output, error]
        actual = list(command)
        if label == "codex_cli":
            actual += ["-C", str(folder), prompt]
        elif label == "cursor_cli":
            actual += ["--workspace", str(folder), prompt]
        elif label == "workbuddy_ai_cli":
            actual += [prompt]
        process = subprocess.Popen(actual, cwd=folder, stdout=output, stderr=error, start_new_session=True)
        jobs[label] = (process, time.monotonic(), folder)
    while any(p.poll() is None for p, _, _ in jobs.values()):
        for process, started, _ in jobs.values():
            if process.poll() is None and time.monotonic() - started > args.timeout:
                timed_out.add(process.pid)
                stop(process)
        if monitor.poll() is not None:
            raise RuntimeError("monitor exited during client acceptance")
        time.sleep(.3)
    time.sleep(2)
    stop(monitor)
    evidence = records(log)
    summary["monitor_exit_code"] = monitor.returncode
    summary["coverage"] = [r.get("metrics", {}) for r in evidence if r["type"] in ("coverage", "shutdown_summary")]
    discovered = {pid(r): r for r in evidence if r["type"] in ("process_discovered", "agent_discovered")}
    summary["app_discovery"] = {}
    for product, pids in expected.items():
        hits = [p for p in pids if p in discovered]
        summary["app_discovery"][product] = {"expected_count": len(pids), "observed_count": len(hits),
            "all_observed": bool(pids) and len(hits) == len(pids),
            "classifications": sorted({discovered[p]["actor_process"]["classification"] for p in hits})}
    for label, (process, _, folder) in jobs.items():
        text = (folder / "client.stderr").read_text(errors="replace") + (folder / "client.stdout").read_text(errors="replace")
        category = "none"
        for needle, name in [("Authentication required", "login_required"), ("error_is_timeout=true", "client_network_or_mcp_startup_timeout"),
                             ("instanceof", "client_proxy_initialization_error"), ("ENOTFOUND", "dns_error"),
                             ("not logged", "login_required"), ("authenticate", "authentication_error"),
                             ("trust", "workspace_trust_or_permission"), ("401", "authentication_error"),
                             ("not supported", "unsupported_configuration"), ("sandbox", "sandbox_or_tool_restriction")]:
            if needle.lower() in text.lower():
                category = name
                break
        result = {"client_pid": process.pid, "exit_code": process.returncode,
                  "root_process_observed": process.pid in discovered, "failure_category": category,
                  "test_deadline_exceeded": process.pid in timed_out,
                  "model_invocation_attempted": label != "current_codex_tool"}
        if process.pid in timed_out and category == "none":
            result["failure_category"] = "no_verified_action_before_test_deadline"
        proof_path = folder / "proof.json"
        if proof_path.exists():
            proof = json.loads(proof_path.read_text())
            valid = proof.get("run_id") == run_id and proof.get("sha256") == hashlib.sha256((folder / "synthetic.env").read_bytes()).hexdigest()
            valid &= (folder / "agent_action_probe.py").read_bytes() == (ROOT / "tests/agent_action_probe.py").read_bytes()
            hits = [r for r in evidence if pid(r) == proof["pid"] and r.get("target_resource") == str((folder / "synthetic.env").resolve())
                    and r.get("detail", "").startswith("sensitive_file_open:")]
            result.update({"probe_proof_valid": valid, "probe_pid": proof["pid"], "probe_completed": "completed_us" in proof,
                           "sensitive_fd_observed": bool(hits), "root_in_observed_ancestor_chain": any(
                               any((a["identity"]["pid"] == process.pid if label != "current_codex_tool" else
                                   pathlib.Path(a["executable"]).name == "codex") for a in r["actor_process"]["ppid_tree"]) for r in hits),
                           "loopback_probe_connected": proof.get("loopback_connected", False),
                           "loopback_independently_received": any(m.get("label") == label and m.get("run_id") == run_id for m in received)})
            result["sanitized_evidence"] = [{"event_id": r["event_id"], "timestamp": r["timestamp"], "type": r["type"],
                "actor_identity": r["actor_process"]["process"]["identity"], "classification": r["actor_process"]["classification"],
                "ancestor_pids": [a["identity"]["pid"] for a in r["actor_process"]["ppid_tree"]],
                "target_resource": sanitized(r["target_resource"]), "detail": sanitized(r["detail"])} for r in hits[:2]]
            result["tool_action_verified"] = bool(valid and hits and result["root_in_observed_ancestor_chain"])
        else:
            result["probe_proof_valid"] = False
            result["tool_action_verified"] = False
        summary["clients"][label] = result
    summary["record_count"] = len(evidence)
    summary["raw_logs_published"] = False
finally:
    for process, _, _ in jobs.values():
        stop(process)
    if monitor is not None:
        stop(monitor)
    server_stop.set()
    server.join(timeout=3)
    listener.close()
    for handle in handles:
        handle.close()
report = ROOT / args.report
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
