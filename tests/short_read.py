"""Short-lived sensitive opens by a synthetic agent.

The credential is a fake file created in a temporary directory. This checks
owning-agent attribution and recall. It does not claim upload detection.
"""
import json
import os
import pathlib
import shutil
import statistics
import subprocess
import threading
import time

root = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(os.environ.get("AGENT_MONITOR_BINARY", str(root / "agent-monitor")))
fixture_src = root / "agent-short-read"


def sample(pid):
    try:
        out = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "%cpu=", "-o", "rss="], text=True).split()
        if len(out) < 2:
            return None
        return {"cpu_percent": float(out[0]), "rss_kb": int(out[1])}
    except (subprocess.CalledProcessError, ValueError, OSError):
        return None


def samples(pid, seconds):
    found = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        item = sample(pid)
        if item:
            found.append(item)
        time.sleep(0.25)
    return found


def actor_pid(record):
    return ((record.get("actor_process") or {}).get("process") or {}).get("identity", {}).get("pid")


def run_cohort(monitor_log, mode, iterations, hold_ms, app_binary, credential):
    child = subprocess.Popen([str(app_binary), str(credential), str(iterations), str(hold_ms), mode],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    parent = int(child.stdout.readline().strip())
    deadline = time.monotonic() + 20
    discovered = False
    while time.monotonic() < deadline:
        records = [json.loads(line) for line in monitor_log.read_text().splitlines() if line]
        if any(r.get("type") == "agent_discovered" and actor_pid(r) == parent for r in records):
            discovered = True
            break
        if child.poll() is not None:
            break
        time.sleep(0.05)
    if not discovered:
        child.kill()
        raise AssertionError(f"{mode} parent was not classified as an agent")
    # The discovery line can reach disk before the watcher is armed.
    time.sleep(1.5)
    child.stdin.write("x")
    child.stdin.flush()
    child.wait(timeout=30)
    records = [json.loads(line) for line in monitor_log.read_text().splitlines() if line]
    hits = []
    for record in records:
        if record.get("type") != "activity_observed" or record.get("evidence_basis") != "fd_observed":
            continue
        if record.get("target_resource") != str(credential.resolve()):
            continue
        actor = record.get("actor_process") or {}
        owner = actor.get("owning_agent") or {}
        tree = [actor.get("process", {}).get("identity", {}).get("pid")]
        tree += [item.get("identity", {}).get("pid") for item in actor.get("ppid_tree") or []]
        if parent not in tree:
            continue
        hits.append(record)
    # One event per reader identity.
    identities = {actor_pid(record) for record in hits}
    return {"parent": parent, "detected_identities": len(identities), "iterations": iterations,
            "hits": hits, "discovered": discovered}


def main():
    with tempfile_dir() as directory:
        credential = directory / "synthetic-credential"
        credential.write_text("SYNTHETIC_CREDENTIAL_NOT_A_SECRET\n")
        os.chmod(credential, 0o600)
        app = directory / "ChatGPT.app" / "Contents" / "MacOS" / "synthetic-agent"
        app.parent.mkdir(parents=True)
        shutil.copy(fixture_src, app)
        os.chmod(app, 0o755)
        log = directory / "evidence.jsonl"
        monitor = subprocess.Popen([str(binary), "--duration", "70", "--interval-ms", "500",
            "--no-default-sensitive", "--sensitive", str(credential), "--log", str(log)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 20
            while not log.exists() or '"type":"coverage"' not in log.read_text():
                if monitor.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError("monitor did not become ready: " + (monitor.stderr.read() if monitor.stderr else ""))
                time.sleep(0.05)
            idle = samples(monitor.pid, 3)
            held = run_cohort(log, "hold", 20, 30, app, credential)
            active = []
            sampler = threading.Thread(target=lambda: active.extend(samples(monitor.pid, 4)))
            sampler.start()
            cat = run_cohort(log, "cat", 20, 0, app, credential)
            sampler.join()
            deadline = time.monotonic() + 20
            while monitor.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if monitor.poll() is None:
                monitor.terminate()
            _, errors = monitor.communicate(timeout=15)
        finally:
            if monitor.poll() is None:
                monitor.kill()
                monitor.wait(timeout=5)
        records = [json.loads(line) for line in log.read_text().splitlines() if line]
        def recall(cohort):
            return cohort["detected_identities"] / cohort["iterations"]
        def check(cohort, label):
            for record in cohort["hits"]:
                actor = record["actor_process"]
                assert actor["chain_complete"] is True, actor.get("chain_status")
                assert actor["owning_agent"]["bundle"] == "ChatGPT.app"
                assert actor["owning_agent"]["root_identity"]["pid"] == cohort["parent"]
                assert record["evidence_basis"] == "fd_observed"
                assert "not an upload" in record["summary"]
                assert "ChatGPT read" in record["summary"]
                assert "synthetic-credential" in record["summary"]
                assert record["content_sha256"] == "" and record["transfer_outcome"] == ""
            if label == "cat":
                assert any("via cat" in record["summary"] for record in cohort["hits"]), "cat tool chain missing"
        check(held, "hold")
        if cat["hits"]:
            check(cat, "cat")
        held_recall = recall(held)
        cat_recall = recall(cat)
        assert held_recall >= 0.9, held
        assert cat_recall >= 0.4, cat
        coverage = [r for r in records if r["type"] == "coverage"]
        last = coverage[-1]["metrics"] if coverage else {}
        def median(items, key):
            values = [item[key] for item in items]
            return statistics.median(values) if values else None
        report = {
            "held_open_30ms": {"detected": held["detected_identities"], "attempts": held["iterations"],
                               "recall": held_recall},
            "cat_immediate": {"detected": cat["detected_identities"], "attempts": cat["iterations"],
                              "recall": cat_recall},
            "cpu_rss": {"idle_median_cpu_percent": median(idle, "cpu_percent"),
                        "idle_median_rss_kb": median(idle, "rss_kb"),
                        "active_median_cpu_percent": median(active, "cpu_percent"),
                        "active_median_rss_kb": median(active, "rss_kb"),
                        "samples_idle": len(idle), "samples_active": len(active)},
            "coverage_metrics": {key: last.get(key) for key in (
                "activity_scan_duration_ms", "fd_scans_partial", "subtree_focused", "subtree_bursts",
                "subtree_fd_hits", "subtree_fork_notes", "subtree_sweep_us", "fast_fd_hits")},
            "upload_detection_claimed": False,
        }
        print("SHORT_READ " + json.dumps(report, sort_keys=True))
        print("PASS: short-lived synthetic credential opens name ChatGPT, complete the chain, and do not claim upload")


class tempfile_dir:
    def __enter__(self):
        import tempfile
        self.path = pathlib.Path(tempfile.mkdtemp(prefix="reins-short-read-"))
        return self.path
    def __exit__(self, *_):
        shutil.rmtree(self.path, ignore_errors=True)


if __name__ == "__main__":
    main()
