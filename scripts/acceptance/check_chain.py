#!/usr/bin/env python3
"""Check one evidence-chain JSON export against a case expectation.

The export is the dashboard document (schema reinscredential.evidence-chain.v1).
This module never prints the marker strings it is given.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


LABELS = {
    "uploaded": "已上传",
    "attempted": "已尝试未成功",
    "not_found": "未发现",
    "not_visible": "看不到",
}
PRODUCT_AGENTS = ("Codex", "Cursor", "WorkBuddy", "Claude")


class ChainCheckError(Exception):
    pass


def _load(export):
    if isinstance(export, (str, Path)):
        return json.loads(Path(export).read_text())
    return export


def _contains_marker(text, markers):
    return any(marker and marker in text for marker in markers)


def _process_text(chain):
    parts = []
    for link in chain.get("links") or []:
        if link.get("step") == "process":
            parts.append(link.get("value") or "")
    return " ".join(parts)


def _pid_present(text, pid):
    return re.search(r"(?<![0-9])" + str(int(pid)) + r"(?![0-9])", text) is not None


def check_document(export, expectation, markers):
    """Return the observed chain fields, or raise ChainCheckError.

    ``expectation`` keys: file_name, verdict, agent (or ""), pid, sha256,
    sink_port, require_open, require_already_running, require_loopback.
    An empty agent means a product name is not required. Stand-in cases use that.
    """
    document = _load(export)
    raw = json.dumps(document, ensure_ascii=False)
    if _contains_marker(raw, markers):
        raise ChainCheckError("evidence-chain export contains a registered fake-secret marker")
    if document.get("schema") != "reinscredential.evidence-chain.v1":
        raise ChainCheckError("export schema is not reinscredential.evidence-chain.v1")
    if document.get("raw_secret_bytes") != "omitted":
        raise ChainCheckError("export does not say raw secret bytes are omitted")

    verdict = expectation["verdict"]
    label = LABELS[verdict]
    file_name = expectation["file_name"]
    chains = document.get("chains") or []
    related = [chain for chain in chains if file_name and file_name in (chain.get("file") or "")]
    labels = sorted({chain.get("verdict_label") or "" for chain in related})
    matched = [chain for chain in related if chain.get("verdict") == verdict and chain.get("verdict_label") == label]
    if verdict == "not_visible":
        bad = [chain.get("verdict_label") for chain in related if chain.get("verdict_label") in ("未发现", "已上传", "已尝试未成功")]
        if bad:
            raise ChainCheckError("a not-visible case also produced " + ",".join(bad))
    if verdict == "not_found":
        bad = [chain.get("verdict_label") for chain in related if chain.get("verdict_label") in ("看不到", "已上传", "已尝试未成功")]
        if bad:
            raise ChainCheckError("a not-found case also produced " + ",".join(bad))
    if not matched:
        raise ChainCheckError(
            "no chain for "
            + file_name
            + " has verdict "
            + label
            + "; saw "
            + (",".join(labels) if labels else "no chain for that file")
        )
    chain = matched[0]
    agent = chain.get("owning_agent") or ""
    expected_agent = expectation.get("agent") or ""
    if expected_agent and agent != expected_agent:
        raise ChainCheckError("owning_agent is " + (agent or "empty") + "; expected " + expected_agent)
    if expectation.get("require_open") and not chain.get("open_observed"):
        raise ChainCheckError("the chain does not show an open descriptor")
    pid = expectation.get("pid")
    if pid is not None and not _pid_present(_process_text(chain), pid):
        raise ChainCheckError("process link does not include pid " + str(pid))
    if verdict == "uploaded":
        digest = (chain.get("content_sha256") or "").lower()
        if expectation.get("sha256") and digest != expectation["sha256"]:
            raise ChainCheckError("content hash does not match the fake file")
        destination = chain.get("destination") or ""
        port = expectation.get("sink_port")
        if port and ("127.0.0.1" not in destination or str(port) not in destination):
            raise ChainCheckError("uploaded chain destination is not the local sink")
    if verdict == "not_visible" and (chain.get("content_sha256") or ""):
        raise ChainCheckError("a not-visible chain still carries a content hash")
    blob = " ".join(chain.get("channel_reasons") or []) + " " + (chain.get("transfer_outcome") or "")
    if expectation.get("require_already_running") and "已经在运行" not in blob and "already_running" not in blob:
        raise ChainCheckError("already-running case is missing that channel reason")
    if expectation.get("require_loopback"):
        destination = chain.get("destination") or ""
        if "127.0.0.1" not in destination and "127.0.0.1" not in blob:
            raise ChainCheckError("chain does not mention the loopback sink")
    return {
        "verdict": chain.get("verdict") or "",
        "verdict_label": chain.get("verdict_label") or "",
        "owning_agent": agent,
        "open_observed": bool(chain.get("open_observed")),
        "file": Path(chain.get("file") or "").name,
        "destination_is_loopback": "127.0.0.1" in ((chain.get("destination") or "") + blob),
        "content_sha256_present": bool(chain.get("content_sha256")),
        "channel_mentions_already_running": "已经在运行" in blob or "already_running" in blob,
        "chain_count_for_file": len(related),
    }


def scan_text(text, markers):
    if _contains_marker(text, markers):
        raise ChainCheckError("a log or result contains a registered fake-secret marker")
