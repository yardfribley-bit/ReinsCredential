[English](INSTALL.md) · [简体中文](INSTALL.zh-CN.md)

# ReinsCredential 0.2 local build

Requires macOS 13 or later. This version samples in user space. It does not need ESF, an administrator daemon, or a system-wide proxy.

1. Open `ReinsCredential-0.2.0-local.dmg` and drag the app into Applications. `~/Applications` is also fine.
2. Launch the app from that location. An ad-hoc build installs this product's per-user LaunchAgent under `~/Library/LaunchAgents`. A Developer ID build uses SMAppService. System background controls still apply. If they block the app, check System Settings → General → Login Items & Extensions for ReinsCredential.
3. Wait until the status is Monitoring or coverage limited. Coverage limited means some processes or descriptors cannot be observed. It does not mean the app is off.
4. Open Watch scope and add directories that contain sensitive files. Defaults include `~/.ssh` and `~/.aws`. A project `.env` needs the project directory. Changing configuration restarts collection and leaves a short gap.
5. Run the self-test. It creates a synthetic file and a loopback connection so the collector can relate a process, a file, and a destination. It does not send anything off the Mac and it does not prove full exfiltration detection.
6. A "sensitive file and network connection both visible" row shows the file, the process chain, and the peer. Check that the activity is expected. The row is not a proven upload.

Closing the window leaves the background service running. Stop collection with Stop Monitoring. Risk notifications are sent only by the open interface. After you quit the interface, the service keeps recording and does not post notifications.

Data stays in `~/Library/Application Support/ReinsCredential` and is not uploaded. The runtime directory is mode 0700 and logs are 0600. The current log and the five newest archives are kept. 16 MiB is the rotation request. Draining the queue can exceed it, and older archives are deleted. The interface keeps the latest 2,000 live records. Older archives can be opened from the evidence log.

Uninstall stops this product's per-user LaunchAgent and removes the app. The evidence directory stays:

```sh
macOSClient/scripts/uninstall-local.sh
macOSClient/scripts/uninstall-local.sh --delete-evidence
```

You can also stop monitoring in the app, quit, and move the app to the Trash. Do not delete another app's plist.

To upgrade, stop monitoring and quit the old app, then replace the app and launch it again. Replacing the app does not delete `~/Library/Application Support/ReinsCredential`.

A local build uses an ad-hoc signature when `REINS_SIGNING_IDENTITY` is unset. Set that variable to a Developer ID and `build-app.sh` signs with it. `notarize-local.sh` notarizes only when `APPLE_ID`, `APPLE_TEAM_ID`, and `APPLE_APP_SPECIFIC_PASSWORD` are all set. Otherwise it returns success. Do not turn off system security.

Developer build and install:

```sh
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64
macOSClient/scripts/package-local.sh
macOSClient/scripts/install-local.sh
```

The Dock, Finder, and About icon is generated from `brand/ReinsCredential-AppIcon-1024.png`. The product name in the Dock and About window stays ReinsCredential.
