"""Local-only integration checks. Run after building both executables."""
import json
import pathlib
import subprocess
import tempfile
import time

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="agent-monitor-test-") as temp:
    directory = pathlib.Path(temp)
    log = directory / "evidence.jsonl"
    sensitive = directory / "synthetic.env"
    output = directory / "stdout.jsonl"
    with output.open("w") as out:
        monitor = subprocess.Popen([str(root / "agent-monitor"), "--duration", "25",
            "--interval-ms", "100", "--match", "agent-probe", "--sensitive", str(sensitive),
            "--log", str(log)], stdout=out, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 15
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
    ours = [r for r in records if r.get("pid") in (parent, child)]
    assert any(r["type"] == "agent_discovered" and r["pid"] == parent for r in ours), "parent discovery"
    assert any(r["type"] == "agent_discovered" and r["pid"] == child and r["reason"] == "observed_ancestor" for r in ours), "child attribution"
    assert any(r.get("detail", "").startswith("sensitive_file_open:") for r in ours), "open sensitive file"
    assert any(r.get("detail", "").startswith("socket_peer:127.0.0.1:") for r in ours), "loopback peer"
    assert any("upload_unproven" in r.get("detail", "") for r in ours), "co-observation signal"
    assert any(r["type"] == "agent_no_longer_observed" and r["pid"] == parent for r in ours), "disappearance"
    assert any(r["type"] == "filesystem_change" and r["actor_pid"] is None for r in records), "FSEvents"
    assert [json.loads(line) for line in output.read_text().splitlines()] == records, "stdout/log parity"
    print("PASS: discovery, descendant, sensitive FD, socket peer, risk signal, disappearance, FSEvents, JSON append output")

for args in (["--interval-ms", "0"], ["--unknown", "x"], ["--duration"], ["--pid", "bad"]):
    result = subprocess.run([str(root / "agent-monitor"), *args], capture_output=True, timeout=5)
    assert result.returncode != 0, args
print("PASS: invalid CLI inputs rejected")
