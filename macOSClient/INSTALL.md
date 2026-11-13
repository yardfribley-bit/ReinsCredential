[English](INSTALL.md) · [简体中文](INSTALL.zh-CN.md)

# ReinsCredential 0.2 local build

Requires macOS 13 or later. This version samples in user space. It does not install a system extension, an Endpoint Security client, a root daemon, or a system-wide proxy. Marketing version stays `0.2.0`.

`package-local.sh` writes `ReinsCredential-0.2.0-local.dmg`, `ReinsCredential-0.2.0-local.zip`, and `SHA256SUMS.txt`. The tag workflow attaches those three files when someone pushes a `v*` tag. The [Releases](https://github.com/yardfribley-bit/ReinsCredential/releases) page has no published package yet. Until a tag exists, build from source below.

1. When a release is tagged, download the three files into one folder. The checksum file lists the disk image and the zip by file name. Check them before opening either archive:

   ```sh
   shasum -a 256 -c SHA256SUMS.txt
   ```

   Open `ReinsCredential-0.2.0-local.dmg` and drag `ReinsCredential.app` to `/Applications`. `~/Applications` is also fine. The zip contains the same app.
2. Launch the app from that location. A build without a Developer ID is ad-hoc signed and is not notarized. Gatekeeper can block the first open. Control-click (or right-click) the app, choose Open, then Open. After a blocked double-click, System Settings → Privacy & Security → Open Anyway is the same per-app exception. Do not turn off SIP, Gatekeeper, or any other system security control. An ad-hoc build installs this product's per-user LaunchAgent under `~/Library/LaunchAgents`. A Developer ID build uses SMAppService. System background controls still apply. If they block the app, check System Settings → General → Login Items & Extensions for ReinsCredential.
3. Wait until the status is Monitoring or Monitoring · coverage limited. Coverage limited means some processes or descriptors cannot be observed. It does not mean the app is off.
4. Open Watch scope and add directories that contain sensitive files. Defaults are `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.npmrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud`, and `~/.azure`. A project `.env` needs the project directory. Changing configuration restarts collection and leaves a short gap.
5. Run the self-test. It creates a synthetic file and a loopback connection so the collector can relate a process, a file, and a destination. It does not send anything off the Mac and it does not prove full exfiltration detection.
6. A "sensitive file and network connection both visible" row shows the file, the process chain, and the peer. Check that the activity is expected. The row is not a proven upload.

Closing the window leaves the background service running. Stop collection with Stop Monitoring. Risk notifications are sent only by the open interface. After you quit the interface, the service keeps recording and does not post notifications.

Data stays in `~/Library/Application Support/ReinsCredential` and is not uploaded. The runtime directory is mode 0700 and logs are 0600. The current log and the five newest archives are kept. 16 MiB is the rotation request. Draining the queue can exceed it, and older archives are deleted. The interface keeps the latest 2,000 live records. Older archives can be opened from the evidence log.

Uninstall stops this product's per-user LaunchAgent and removes both `~/Applications/ReinsCredential.app` and `/Applications/ReinsCredential.app`. The evidence directory stays:

```sh
macOSClient/scripts/uninstall-local.sh
macOSClient/scripts/uninstall-local.sh --delete-evidence
```

`uninstall-local.sh --dry-run` prints the actions and does not call `launchctl` or delete files. You can also stop monitoring in the app, quit, and move the app to the Trash. Do not delete another app's plist.

To upgrade, stop monitoring and quit the old app, then replace the app and launch it again. Replacing the app does not delete `~/Library/Application Support/ReinsCredential`. `install-local.sh` will not overwrite an app that is already at `~/Applications/ReinsCredential.app`. Quit the old app and replace or remove it in Finder, then run the script again.

A local build uses an ad-hoc signature when `REINS_SIGNING_IDENTITY` is unset or `-`. Set that variable to a Developer ID and `build-app.sh` signs with it. `notarize-local.sh` notarizes only when `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_APP_SPECIFIC_PASSWORD` are all set. Otherwise it returns success and leaves the current signature. Do not turn off system security.

Developer build and install, from the repository root:

```sh
macOSClient/scripts/build-app.sh
macOSClient/scripts/install-local.sh
```

`build-app.sh --arch arm64 --arch x86_64` passes both architectures to the Swift build and the C++ helpers. `package-local.sh` writes the disk image, the zip, and `SHA256SUMS.txt` under `macOSClient/dist/`. `install-local.sh` copies the built app only to `~/Applications/ReinsCredential.app` and opens it. It does not install into `/Applications`. Pass `--no-open` to skip the launch.

The Dock, Finder, and About icon is generated from [`brand/ReinsCredential-AppIcon-1024.png`](../brand/ReinsCredential-AppIcon-1024.png). The product name in the Dock and About window stays ReinsCredential.
