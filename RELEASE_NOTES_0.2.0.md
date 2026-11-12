# ReinsCredential 0.2.0

ReinsCredential 0.2.0 reports which desktop app opened a registered sensitive file, and whether that process uploaded it, tried and failed, showed no off-host send, or could not be seen.

## Install

Open `ReinsCredential-0.2.0-local.dmg` or unzip `ReinsCredential-0.2.0-local.zip`, and move `ReinsCredential.app` to the Applications folder. The first launch of an ad-hoc build registers a per-user LaunchAgent. A Developer ID build uses the system login-item service. Check `SHA256SUMS.txt` before opening the package.

## What the four verdicts mean

- **已上传 / uploaded.** The registered bytes were in a proxied HTTP body that returned success, or the same process sent an off-host TCP byte span large enough to hold the file (`flow_txbytes`). The flow count is not a decrypted body and not a receipt from the far side.
- **已尝试未成功 / attempted.** A matching body was sent and the transfer failed, or an off-host connect failed before the file's bytes went out.
- **未发现 / not_found.** The process and its TCP counters were visible, and no off-host upload of the file was observed. A send that stays on `127.0.0.1` is this verdict (`loopback_not_off_host`).
- **看不到 / not_visible.** The descriptor list or the channel could not be read. UDP and QUIC are this verdict. It is not a clean bill.

## Limits

TLS that never entered the local proxy is not decrypted. The proxy is not system-wide. No CA is added to the keychain, and other apps' MCP settings are not changed. FSEvents still do not name the process that read a file.

## Upgrade and uninstall

Quit the app and stop monitoring before replacing it. Evidence in `~/Library/Application Support/ReinsCredential` is kept. To remove the app and its LaunchAgent while keeping that evidence:

```sh
macOSClient/scripts/uninstall-local.sh
```

Add `--delete-evidence` only when the evidence directory should be removed as well.
