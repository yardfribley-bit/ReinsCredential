[English](README.md) · [简体中文](README.zh-CN.md)

![ReinsCredential](brand/ReinsCredential-Wordmark-light.png)

# ReinsCredential

Detect which desktop agents access and upload sensitive files.

ReinsCredential shows which desktop app on your Mac opened a registered sensitive file, and whether that process uploaded it. The product name is ReinsCredential in every language.

A file-open sentence means the file was open in that process, or, when the sentence says so, that only the file's access time overlapped one short-lived tool. It does not by itself mean the file was uploaded.

## Verdicts

| Code | English | 中文 | Meaning |
| --- | --- | --- | --- |
| `uploaded` | Uploaded | 已上传 | Registered content was in a proxied request that succeeded, or the same process sent an off-host TCP byte span large enough for the file (`flow_txbytes`). |
| `attempted` | Attempted | 已尝试未成功 | The content matched and the transfer failed, or an off-host connect failed, including a refused connection. |
| `not_found` | Not found | 未发现 | The process was visible and no off-host upload of the file was observed. A loopback send stays here. |
| `not_visible` | Not visible | 看不到 | The descriptors or the channel could not be read. UDP and QUIC stay here. This is not a clean bill. |

Limits:

- TLS that did not enter the local proxy is not decrypted.
- A flow-byte match is a TCP send count on the same process. It is not a remote receipt.
- UDP and QUIC stay Not visible.

## Quick start

```sh
make
./agent-monitor --log ./evidence.jsonl
```

Needs Xcode Command Line Tools. The build uses the system CoreServices, libcurl, libbsm, and zlib. No extra packages are downloaded.

Default sensitive locations include `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.npmrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud`, `~/.azure`, and `.env` in the launch directory. `--sensitive` adds a path. `--no-default-sensitive` clears the defaults first.

Install the Mac app, upgrade, and uninstall: [macOSClient/INSTALL.md](macOSClient/INSTALL.md) ([中文](macOSClient/INSTALL.zh-CN.md)).

Privacy: [PRIVACY.md](PRIVACY.md). This version: [RELEASE_NOTES_0.2.0.md](RELEASE_NOTES_0.2.0.md), [CHANGELOG.md](CHANGELOG.md). The release gate is [RELEASE_CRITERIA.md](RELEASE_CRITERIA.md).

## What the app does

The collector is user-space. It does not install a system extension. It does not install a CA, set a system proxy, or edit other apps' MCP or client configuration. The app's own processes are never the suspected agent.

Any non-collector process that opens a registered sensitive file is tracked. The owner is that process's own `.app`. If the process is not inside an app, Xcode and the Python.app it ships are toolchain hops and the walk continues to the desktop app above them, including names with spaces such as `Grok Bot.app`. Known names are display labels, not a detection gate. A startup-canary body match covers only that launched process. A later actor on the same file still gets its own close.

`agent-egress` is a local HTTP proxy on `127.0.0.1`. `--launch` sets proxy environment variables only for the process tree it starts. `--watch-live` watches processes that already have a registered file open. Logs do not store raw secret bytes.

```sh
./agent-egress --log ./evidence.jsonl --sensitive-file ./synthetic.env \
  --launch -- python3 your-synthetic-case.py
make check
make integration
```

`make acceptance` stays a strict gate and can return non-zero while known misses remain. Do not weaken it to make a report green.

## Limits

FSEvents do not name the process that changed a file, and they do not report a pure read. A file-change record leaves the actor empty. An open descriptor is not a read. A socket peer is not a payload. Polling can miss a short-lived process. An optional TLS CA file is used only for CONNECT bodies that enter the proxy. It is not written to the login keychain.
