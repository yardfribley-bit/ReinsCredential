#!/usr/bin/env python3
"""Checker tests that do not start a collector or an agent.

They create fake secrets in a temporary directory, then delete them.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from check_chain import ChainCheckError, check_document  # noqa: E402
from harness import assert_safe_dir, create_secrets  # noqa: E402

ROOT = SCRIPT_DIR.parents[1]


def expect_fail(fn, text):
    try:
        fn()
    except ChainCheckError as error:
        if text not in str(error):
            raise SystemExit("expected failure containing " + text + " but got " + str(error))
        return
    raise SystemExit("expected a chain check failure")


def sample(verdict, label, agent="Codex", extra=""):
    return {
        "schema": "reinscredential.evidence-chain.v1",
        "raw_secret_bytes": "omitted",
        "invented_events": "none",
        "chains": [{
            "file": "/tmp/reins-fake-acceptance/fake.env",
            "verdict": verdict,
            "verdict_label": label,
            "owning_agent": agent,
            "open_observed": True,
            "content_sha256": "abc" if verdict == "uploaded" else "",
            "destination": "http://127.0.0.1:9/ingest",
            "transfer_outcome": "upstream_http_2xx",
            "channel_reasons": ["这个 Agent 在采集开始前已经在运行。"] if "running" in extra else [],
            "links": [
                {"step": "process", "value": "python3（pid 4242） → codex（pid 100）"}
            ],
        }],
    }


def main():
    workspace = Path(tempfile.mkdtemp(prefix="reins-fake-acceptance-self-"))
    os.chmod(workspace, 0o700)
    try:
        assert_safe_dir(workspace)
        secrets, markers = create_secrets(workspace)
        for item in secrets.values():
            mode = stat.S_IMODE(item["path"].stat().st_mode)
            if mode != 0o600:
                raise SystemExit("fake secret mode is not 0600")
            text = item["path"].read_text()
            folded = text.upper()
            if "FAKE" not in folded or "NOT" not in folded:
                raise SystemExit("fake secret is not obviously fake")
            if any(len(line) > 80 and " " not in line for line in text.splitlines()):
                raise SystemExit("fake ssh file looks like a real key blob")
        joined = "\n".join(path.read_text() for path in workspace.iterdir() if path.is_file())
        for marker in markers:
            if marker not in joined:
                raise SystemExit("a marker was not written into its fake file")
        home_ssh = Path.home() / ".ssh"
        if home_ssh.exists() and any(home_ssh in path.parents for path in workspace.rglob("*")):
            raise SystemExit("workspace escaped into ~/.ssh")

        good = sample("uploaded", "已上传")
        observed = check_document(good, {
            "file_name": "fake.env", "verdict": "uploaded", "agent": "Codex", "pid": 100,
            "sha256": "abc", "sink_port": 9, "require_open": True,
            "require_already_running": False, "require_loopback": True,
        }, markers)
        if observed["owning_agent"] != "Codex" or observed["verdict_label"] != "已上传":
            raise SystemExit("good fixture was not accepted")
        expect_fail(
            lambda: check_document(good, {
                "file_name": "fake.env", "verdict": "not_found", "agent": "Codex", "pid": 100,
                "sha256": "", "sink_port": 9, "require_open": True,
                "require_already_running": False, "require_loopback": False,
            }, markers),
            "已上传",
        )
        hidden = sample("not_visible", "看不到", extra="running")
        expect_fail(
            lambda: check_document(hidden, {
                "file_name": "fake.env", "verdict": "not_found", "agent": "Codex", "pid": 100,
                "sha256": "", "sink_port": 9, "require_open": True,
                "require_already_running": False, "require_loopback": False,
            }, markers),
            "看不到",
        )
        leaked = json.loads(json.dumps(good))
        leaked["chains"][0]["destination"] += markers[0]
        expect_fail(lambda: check_document(leaked, {
            "file_name": "fake.env", "verdict": "uploaded", "agent": "Codex", "pid": 100,
            "sha256": "abc", "sink_port": 9, "require_open": True,
            "require_already_running": False, "require_loopback": True,
        }, markers), "marker")
        expect_fail(lambda: check_document(good, {
            "file_name": "fake.env", "verdict": "uploaded", "agent": "Cursor", "pid": 100,
            "sha256": "abc", "sink_port": 9, "require_open": True,
            "require_already_running": False, "require_loopback": True,
        }, markers), "owning_agent")
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    py = "/usr/bin/python3" if Path("/usr/bin/python3").is_file() else sys.executable
    prepared = subprocess.run([py, str(SCRIPT_DIR / "harness.py"), "--mode", "prepare"],
                              cwd=ROOT, check=False, text=True, capture_output=True)
    if prepared.returncode != 0:
        raise SystemExit("prepare mode failed: " + prepared.stderr[-400:])
    blob = prepared.stdout + prepared.stderr
    for marker in ("reins-fake-env-NOT-A-REAL-SECRET", "AKIAFAKEACCEPTANCEONLY", "FAKE-NOT-A-REAL-KEY"):
        if marker in blob:
            raise SystemExit("prepare output contained a fake-secret marker")
    if "overall_acceptance=not_passed" not in prepared.stdout:
        raise SystemExit("prepare mode did not keep acceptance not_passed")
    if "real_agent_acceptance=false" not in prepared.stdout:
        raise SystemExit("prepare mode counted itself as real-agent acceptance")
    print("self_check_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
