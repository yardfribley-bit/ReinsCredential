# ReinsCredential 0.2.0 release gate

Marketing version stays `0.2.0` (`CFBundleShortVersionString`). A build is releasable only when every item below is true. Each item names the automated check that locks it. Checks that need a Mac run in `.github/workflows/macos.yml`. The tag workflow in `.github/workflows/release.yml` does not run on pull requests.

Constraints for every item: no CA is installed, no system proxy is set, the login keychain is not modified, and no other app's MCP or client configuration is edited.

## 1. Behavior-based detection

Any non-collector process that opens a registered sensitive file is attributed to its owning desktop app and closed, per actor, as `uploaded`, `attempted`, `not_found`, or `not_visible`.

| Case | Required close | Check |
| --- | --- | --- |
| (a) Unlisted `.app` sends off-loopback | `uploaded`, owner `UnknownAgent.app` | `make integration` mode `live-unknown-app` |
| (b) Shell child of a desktop agent, with Xcode's Python between the shell and `Grok Bot.app` | `uploaded`, owner `Grok Bot.app`, actor `hold-upload` | `make integration` mode `live-toolchain-chain`; unit test `ApplyBehaviorOwner` on the same shape |
| (c) Loopback-only send | `not_found`, outcome `loopback_not_off_host` | `make integration` mode `live-direct` |
| (d) Failed connect | `attempted` | `make integration` mode `live-attempt` |
| (e) UDP | `not_visible` | `make integration` mode `live-udp` |
| (f) Later actor on a file the startup canary already matched | a new `uploaded` close with `flow_txbytes`, plus the canary's `exact_bytes` close | `make integration` mode `live-after-canary` |
| (g) Proxy-launched body match | `uploaded` with `exact_bytes` | `make integration` launched modes `plaintext`, `json`, `base64`, `gzip` |

Known-name matches are display labels. They are not the reason a process is tracked.

## 2. Evidence chain a person can read

The dashboard export, and `chain-export` / `chain-export --markdown`, show for each finding: the app, the process-chain status, the file, the open observation, the destination, the hash or flow basis, the verdict, and the reason. JSON and Markdown are both produced. Raw secret bytes are omitted; hashes and redacted display text remain.

Check: `macOSClient/scripts/check.sh` (`EvidenceChainTests`, including Markdown and JSON export) and the snapshot step in the macOS workflow.

## 3. Lifecycle

- One supervisor holds `RuntimeInstanceLock`. A second launch does not become a second collector. Check: `macOSClient/scripts/check.sh` (`RuntimeCore` lock tests).
- Quitting or stopping monitoring stops the owned monitor and egress children and removes this product's per-user LaunchAgent. Check: `LocalLaunchAgent.stopAndRemove` in `RuntimeCore` tests, and `macOSClient/scripts/uninstall-local.sh`.
- Uninstall removes that LaunchAgent and `ReinsCredential.app`. Evidence under `~/Library/Application Support/ReinsCredential` stays unless `--delete-evidence` is passed. Check: the packaging step in the macOS workflow runs the script `--dry-run` both ways.
- Upgrade replaces the app and does not delete that evidence directory. `install-local.sh` refuses to overwrite an existing app until the old one has been quit; it never deletes the support directory.
- The app does not install a CA, a system proxy, or a keychain item, so quit and reinstall are not blocked on those.

## 4. Resource limits

Evidence logs are mode `0600`. The monitor asks to rotate at 16 MiB and keeps a bounded set of archives. The dashboard keeps a bounded live window.

`make integration` starts 40 extra `sleep` processes and then runs `agent-egress --watch-live` against that table. The run fails if the proxy's median RSS exceeds 150000 KB or its median CPU sample exceeds 150 percent of one core. The same run prints `idle_rss_median_kb` and `idle_cpu_median`.

Measured on macOS CI run 43242914536 (2026-11-12): idle median CPU 1.6 percent, idle median RSS 6608 KB, with 12 samples. The active HTTPS sample in that run was median CPU 0.4 percent and median RSS 11888 KB.

## 5. Packaging

`macOSClient/scripts/build-app.sh` produces `ReinsCredential.app` at version 0.2.0. With `REINS_SIGNING_IDENTITY` unset or `-`, the signature is ad-hoc and the local LaunchAgent flag is set. A Developer ID value in that variable is used when a person provides it. `package-local.sh` writes `ReinsCredential-0.2.0-local.dmg`, `ReinsCredential-0.2.0-local.zip`, and `SHA256SUMS.txt`. `notarize-local.sh` notarizes only when `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_APP_SPECIFIC_PASSWORD` are set; otherwise it exits 0.

Check: `bash -n` on those scripts in the macOS workflow. The scripts do not need credentials to succeed.

## 6. Docs

- Quick start, verdict words, and the limits of each word: `README.md`
- Privacy: `PRIVACY.md`
- Install, upgrade, uninstall: `macOSClient/INSTALL.md` and `macOSClient/scripts/uninstall-local.sh`
- History and this version: `CHANGELOG.md`, `RELEASE_NOTES_0.2.0.md`

Limits that stay true in those docs: TLS bodies are not decrypted, a flow-byte match is not a remote receipt, and UDP/QUIC is `not_visible`.

## 7. CI and tagged release

Pull requests and branch pushes run `.github/workflows/macos.yml` only. `.github/workflows/release.yml` runs when a person pushes a `v*` tag. It builds the app, packages the dmg and zip, notarizes only if the secrets above exist, and attaches the artifacts to that tag. It does not run for an ordinary push or a pull request.
