"""Native regression: an unlisted, reparented interpreter still triggers policy."""
import hashlib
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid

root = pathlib.Path(__file__).resolve().parents[1]
workspace = pathlib.Path(tempfile.mkdtemp(prefix="agentsec-unknown-")).resolve()
shutil.copyfile(root / "tests/agent_action_probe.py", workspace / "agent_action_probe.py")
run_id = str(uuid.uuid4())
(workspace / "synthetic.env").write_text("SYNTHETIC_ONLY=" + run_id)
listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
(workspace / "coordinator.json").write_text(json.dumps({"label": "unlisted_process", "run_id": run_id, "port": listener.getsockname()[1]}))
launcher = "import os,time; child=os.fork();\nif child==0:\n os.setsid(); time.sleep(.5); os.execl('/usr/bin/python3','python3','agent_action_probe.py')\n"
subprocess.run(["/usr/bin/python3", "-c", launcher], cwd=workspace, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
deadline = time.monotonic() + 5
while not (workspace / "proof.json").exists():
    assert time.monotonic() < deadline
    time.sleep(.05)
proof = json.loads((workspace / "proof.json").read_text())
assert proof["ppid"] == 1, "probe must be independent of the launching Agent before collector startup"
log = workspace / "evidence.jsonl"
result = subprocess.run([str(root / "agent-monitor"), "--duration", "15", "--interval-ms", "100",
                         "--sensitive", str(workspace), "--log", str(log)], capture_output=True, text=True, timeout=45)
listener.close()
assert result.returncode == 0, result.stderr
rows = [json.loads(line) for line in log.read_text().splitlines()]
hits = [r for r in rows if (r.get("actor_process") or {}).get("process", {}).get("identity", {}).get("pid") == proof["pid"]]
assert any(r["type"] == "process_discovered" for r in hits)
assert all(r["actor_process"]["classification"] == "unclassified_process" for r in hits)
files = [r for r in hits if r["target_resource"] == str(workspace / "synthetic.env") and r["detail"].startswith("sensitive_file_open:")]
assert files, "unlisted process sensitive activity must not be filtered out"
assert any("socket_peer:127.0.0.1:" in r["detail"] for r in hits)
assert any("upload_unproven" in r["detail"] for r in hits)
summary = {"run_id": run_id, "test_kind": "unlisted_reparented_interpreter_not_real_ai_client", "passed": True,
           "probe_pid": proof["pid"], "probe_ppid": proof["ppid"], "classification": "unclassified_process",
           "agent_name_rule_used": False, "sensitive_fd_observed": True, "socket_peer_observed": True,
           "evidence_event_id": files[0]["event_id"], "target_resource": "<TEST_ROOT>/synthetic.env",
           "evidence_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "monitor_exit_code": result.returncode}
report = root / "tests/results/unknown_process_summary.json"
report.parent.mkdir(parents=True, exist_ok=True); report.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
