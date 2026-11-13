[English](RELEASE_NOTES_0.2.0.md) · [简体中文](RELEASE_NOTES_0.2.0.zh-CN.md)

# ReinsCredential 0.2.0

ReinsCredential 0.2.0 reports which desktop app opened a registered sensitive file, and whether that process uploaded it, tried and failed, showed no off-host send, or could not be seen.

## Install

Open `ReinsCredential-0.2.0-local.dmg` or unzip `ReinsCredential-0.2.0-local.zip`, and move `ReinsCredential.app` to the Applications folder. The first launch of an ad-hoc build registers a per-user LaunchAgent. A Developer ID build uses the system login-item service. Check `SHA256SUMS.txt` before opening the package.

## What the four verdicts mean

- **已上传 / uploaded.** The registered bytes were in a proxied HTTP body that returned success, or the process tree's measured off-host send, summed across TCP and UDP/QUIC for the hold and a short tail, falls between the compression lower bound and the raw size plus 64 KiB (`flow_txbytes`, or `flow_txbytes_udp`). A connection that lasts about 100 ms is included after it closes. The count is not a decrypted body and not a receipt from the far side.
- **已尝试未成功 / attempted.** A matching body was sent and the transfer failed, or an off-host connect failed before the file's bytes went out, including a short refused connect.
- **未发现 / not_found.** Every off-host channel in that window was measured, and the total is below the compression lower bound. A send that stays on `127.0.0.1` is this verdict (`loopback_not_off_host`).
- **看不到 / not_visible.** A channel closed before its byte count was captured, the descriptor list was incomplete, or the measured total is above the window. It is not a clean bill and it is not rewritten as 未发现.

## Limits

TLS that never entered the local proxy is not decrypted. A client handshake of at most 1024 sent bytes is not an upload. The peer name is reverse DNS when the resolver returns one, or a hostname already present in the network-statistics source. ClientHello bytes are not copied off the socket. The compression lower bound is gzip, zlib, or raw deflate, not zstd. The proxy is not system-wide. No CA is added to the keychain, and other apps' MCP settings are not changed. FSEvents still do not name the process that read a file. A connect the network-statistics control never reports can still be missed.

## Upgrade and uninstall

Quit the app and stop monitoring before replacing it. Evidence in `~/Library/Application Support/ReinsCredential` is kept. To remove the app and its LaunchAgent while keeping that evidence:

```sh
macOSClient/scripts/uninstall-local.sh
```

Add `--delete-evidence` only when the evidence directory should be removed as well.
