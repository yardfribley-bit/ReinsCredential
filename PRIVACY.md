[English](PRIVACY.md) · [简体中文](PRIVACY.zh-CN.md)

# Privacy

ReinsCredential runs on the Mac where it is installed. It does not upload evidence, configuration, or file contents.

What it stores locally, under `~/Library/Application Support/ReinsCredential`:

- Process identity (pid and start time), executable path, and parent chain for a process that opened a registered file.
- The path of that file, and a SHA-256 of a registered file the egress proxy fingerprinted.
- Destinations and transfer results the local proxy or a TCP byte counter actually observed.
- Verdict words and the reason string for each close.

What it does not store or show:

- Raw secret bytes. Logs, the dashboard, and both export formats omit them. Exports say `raw_secret_bytes: omitted` and redact assignment-style values.
- Login-keychain items. The app does not read or write the keychain.
- Other apps' MCP or client configuration. Those files are not edited.
- A certificate authority in the system or login keychain. An optional TLS CA is a file the operator passes in, and it is not installed.
- A system-wide proxy. The egress proxy listens on `127.0.0.1` and sets proxy variables only on a process tree it launched.

A flow verdict counts TCP send bytes on the same process that held the file. It is not a decrypted TLS body and not a receipt from the remote server. UDP and QUIC payloads are not read; those closes stay `not_visible`.
