"""Local-only integration checks. Run after building both executables."""
import json
import pathlib
import subprocess
import tempfile
import time
import uuid
import stat
import os

root = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(os.environ.get("AGENT_MONITOR_BINARY", str(root / "agent-monitor")))
with tempfile.TemporaryDirectory(prefix="agent-monitor-test-") as temp:
    directory = pathlib.Path(temp)
    log = directory / "evidence.jsonl"
    sensitive = directory / "synthetic.env"
    output = directory / "stdout.jsonl"
    with output.open("w") as out:
        monitor = subprocess.Popen([str(binary), "--duration", "25",
            "--interval-ms", "100", "--match", "agent-probe", "--sensitive", str(sensitive),
            "--sensitive", str(directory),
            "--log", str(log)], stdout=out, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 45
            while not log.exists() or '"type":"coverage"' not in log.read_text():
                if monitor.poll() is not None or time.monotonic() > deadline:
                    monitor.terminate()
                    _, error = monitor.communicate(timeout=5)
                    raise AssertionError("monitor failed to become ready: " + error)
                time.sleep(.05)
            probe = subprocess.Popen([str(root / "agent-probe"), str(sensitive)], stdout=subprocess.PIPE, text=True)
            parent, child = map(int, probe.stdout.readline().split())
            assert probe.wait(timeout=15) == 0
            _, stderr = monitor.communicate(timeout=30)
            assert monitor.returncode == 0, stderr
        finally:
            if monitor.poll() is None:
                monitor.terminate()
                monitor.wait(timeout=5)
    records = [json.loads(line) for line in log.read_text().splitlines()]
    def actor_pid(record):
        return (record.get("actor_process") or {}).get("process", {}).get("identity", {}).get("pid")
    ours = [r for r in records if actor_pid(r) in (parent, child)]
    assert any(r["type"] == "agent_discovered" and actor_pid(r) == parent for r in ours), "parent discovery"
    children = [r for r in ours if r["type"] == "agent_discovered" and actor_pid(r) == child]
    assert children and children[0]["detail"] == "observed_ancestor", "child attribution"
    assert any(p["identity"]["pid"] == parent for p in children[0]["actor_process"]["ppid_tree"]), "identity-bound parent chain"
    assert any(r.get("detail", "").startswith("sensitive_file_open:") for r in ours), "open sensitive file"
    assert any(r.get("detail", "").startswith("socket_peer:127.0.0.1:") for r in ours), "loopback peer"
    assert any("upload_unproven" in r.get("detail", "") for r in ours), "co-observation signal"
    pairs = [r for r in ours if r['type'] == 'sensitive_network_cooccurrence']
    assert pairs and any(r['target_resource'] == str(sensitive.resolve()) and
                         r['destination'].startswith('127.0.0.1:') and
                         r['evidence_basis'] == 'same_identity_descriptor_snapshot' and
                         r['risk_level'] == 'Medium' and not r['transfer_outcome'] and
                         not r['content_sha256'] for r in pairs), 'typed file/peer co-observation'
    assert any(r["type"] == "agent_no_longer_observed" and actor_pid(r) == parent for r in ours), "disappearance"
    file_events = [r for r in records if r["type"] == "filesystem_change"]
    assert file_events and all(r["actor_process"] is None for r in file_events), "honest FSEvents attribution"
    assert all(pathlib.Path(r["target_resource"]).is_absolute() for r in file_events), "absolute resource path"
    assert not any(r["target_resource"] == str(log.resolve()) for r in file_events), "collector log must not create a feedback loop"
    assert output.read_text() == "", "daemon should not emit unstructured stdout"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600, "secure log permissions"
    identifiers = [str(uuid.UUID(r["event_id"])) for r in records]
    assert len(set(identifiers)) == len(records), "unique event UUIDs"
    assert [r["sequence"] for r in records] == list(range(1, len(records) + 1)), "single-writer sequence"
    assert all(isinstance(r["timestamp"], int) and r["timestamp"] > 1_000_000_000_000_000 for r in records)
    assert all(r["risk_level"] in ("High", "Medium", "Low") and r["schema_version"] == 2 for r in records)
    assert records[-1]["type"] == "shutdown_summary" and records[-1]["count"] == 0, "drain without loss"
    # A second run appends a separate session and never truncates existing evidence.
    before = log.read_bytes()
    again = subprocess.Popen([str(binary), "--duration", "30", "--log", str(log)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 45
        while b'"type":"coverage"' not in log.read_bytes()[len(before):]:
            if again.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("restart failed to become ready")
            time.sleep(.05)
        again.terminate()
        _, error = again.communicate(timeout=30)
        assert again.returncode == 0, error
    finally:
        if again.poll() is None:
            again.kill()
            again.wait(timeout=5)
    assert log.read_bytes().startswith(before) and len(log.read_bytes()) > len(before), "append across restarts"
    assert json.loads(log.read_text().splitlines()[-1])["type"] == "shutdown_summary", "SIGTERM drains and appends summary"
    print("PASS: discovery, parent identities, sensitive FD, socket peer, risk signal, disappearance, FSEvents, UUID/schema, ordered append, drain, restart")

for args in (["--interval-ms", "0"], ["--unknown", "x"], ["--duration"], ["--pid", "bad"]):
    result = subprocess.run([str(binary), *args], capture_output=True, timeout=5)
    assert result.returncode != 0, args
print("PASS: invalid CLI inputs rejected")
