"""Re-analyze private execution artifacts without invoking any client again."""
import argparse
import hashlib
import json
import pathlib

parser = argparse.ArgumentParser()
parser.add_argument("workspace", type=pathlib.Path)
parser.add_argument("--report", type=pathlib.Path, default=pathlib.Path("tests/results/real_agents_summary.json"))
args = parser.parse_args()
workspace = args.workspace.resolve()
summary = json.loads(args.report.read_text())
rows = [json.loads(line) for line in (workspace / "evidence.jsonl").read_text().splitlines()]
source = pathlib.Path(__file__).with_name("agent_action_probe.py").read_bytes()
def sanitized(text):
    return text.replace(str(workspace), "<TEST_ROOT>").replace(str(args.workspace), "<TEST_ROOT>").replace(str(pathlib.Path.home()), "$HOME")
for label, result in summary["clients"].items():
    result["model_invocation_attempted"] = result.pop("model_driven_invocation", result.get("model_invocation_attempted", False))
    folder = workspace / label
    output = (folder / "client.stderr").read_text(errors="replace") + (folder / "client.stdout").read_text(errors="replace")
    result["failure_categories"] = [name for needle, name in (("Authentication required", "login_required"),
        ("instanceof", "client_proxy_initialization_error"), ("error_is_timeout=true", "client_network_or_mcp_startup_timeout")) if needle in output]
    if "Authentication required" in output:
        result["failure_category"] = "login_required"
    elif "error_is_timeout=true" in output or "timed out handshaking" in output:
        result["failure_category"] = "client_network_or_mcp_startup_timeout"
    proof_path = folder / "proof.json"
    if not proof_path.exists():
        result["tool_action_verified"] = False
        continue
    proof = json.loads(proof_path.read_text())
    result["probe_proof_valid"] = proof["run_id"] == summary["run_id"] and (folder / "agent_action_probe.py").read_bytes() == source
    result["probe_proof_valid"] &= proof["sha256"] == hashlib.sha256((folder / "synthetic.env").read_bytes()).hexdigest()
    expected_path = str((folder / "synthetic.env").resolve())
    hits = [r for r in rows if (r.get("actor_process") or {}).get("process", {}).get("identity", {}).get("pid") == proof["pid"]
            and r["target_resource"] == expected_path and r["detail"].startswith("sensitive_file_open:")]
    activity = [r for r in rows if (r.get("actor_process") or {}).get("process", {}).get("identity", {}).get("pid") == proof["pid"]]
    result["socket_peer_observed"] = any(r["detail"].startswith("socket_peer:127.0.0.1:") for r in activity)
    result["risk_signal_observed"] = any("upload_unproven" in r["detail"] for r in activity)
    result["sensitive_fd_observed"] = bool(hits)
    result["root_in_observed_ancestor_chain"] = any(any(
        a["identity"]["pid"] == result["client_pid"] if label != "current_codex_tool" else pathlib.Path(a["executable"]).name == "codex"
        for a in r["actor_process"]["ppid_tree"]) for r in hits)
    result["tool_action_verified"] = result["probe_proof_valid"] and result["sensitive_fd_observed"] and result["root_in_observed_ancestor_chain"]
    result["sanitized_evidence"] = [{"event_id": r["event_id"], "timestamp": r["timestamp"], "type": r["type"],
        "actor_identity": r["actor_process"]["process"]["identity"], "classification": r["actor_process"]["classification"],
        "ancestor_pids": [a["identity"]["pid"] for a in r["actor_process"]["ppid_tree"]],
        "target_resource": sanitized(r["target_resource"]), "detail": sanitized(r["detail"])} for r in hits[:2]]
summary["coverage_summary"] = {key: {"min": min(m.get(key, 0) for m in summary["coverage"]), "max": max(m.get(key, 0) for m in summary["coverage"])}
    for key in ("visible", "unavailable", "activity_processes", "activity_scan_duration_ms", "fd_scans_partial", "raw_queue_dropped", "evidence_rejected", "source_gaps")}
summary["artifact_sha256"] = {"private_evidence_jsonl": hashlib.sha256((workspace / "evidence.jsonl").read_bytes()).hexdigest(),
                              "probe_source": hashlib.sha256(source).hexdigest()}
summary["baseline_scope"] = "path-identifiable ps baseline subset; not a census of all agents or every renamed helper"
args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"app_discovery": summary["app_discovery"], "clients": summary["clients"], "coverage_summary": summary["coverage_summary"]}, ensure_ascii=False, indent=2))
