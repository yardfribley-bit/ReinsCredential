[English](CHANGELOG.md) · [简体中文](CHANGELOG.zh-CN.md)

# Changelog

## 0.2.0

- Evidence-chain closures stay on their own list, so a large `evidence.jsonl` cannot drop them from the chain page. A counted off-host send closes as uploaded with its destination. A TLS handshake with no application data closes as not visible. The owning app is the one that performed the access.
- Live detection follows a registered-file open, not a known-agent name list. The owner is the desktop `.app` around that process. Xcode and its `Python.app` are toolchain hops, not the owner, when a desktop app sits further up the parent chain.
- Each actor closes as uploaded, attempted, not found, or not visible. A startup-canary body match does not suppress a later actor on the same file.
- The dashboard exports a JSON evidence chain and a Markdown reading of the same chain. Neither contains raw secret bytes.
- Local builds sign ad-hoc. Developer ID signing and notarization run only when the corresponding environment variables are set.
- Uninstall removes this product's LaunchAgent and app, and keeps evidence unless `--delete-evidence` is passed.
