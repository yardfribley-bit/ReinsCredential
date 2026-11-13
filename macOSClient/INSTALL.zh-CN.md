[English](INSTALL.md) · [简体中文](INSTALL.zh-CN.md)

# ReinsCredential 0.2 本机版

需要 macOS 13 或更新版本。本版本使用用户态采样，不安装系统扩展，不使用 Endpoint Security，不以 root 运行守护进程，也不设置全局网络代理。对外版本号保持 `0.2.0`。产品名在程序坞和关于窗口里都是 ReinsCredential。

`package-local.sh` 写出 `ReinsCredential-0.2.0-local.dmg`、`ReinsCredential-0.2.0-local.zip` 和 `SHA256SUMS.txt`。有人推送 `v*` 标签时，标签工作流会附上这三个文件。[Releases](https://github.com/yardfribley-bit/ReinsCredential/releases) 上目前还没有已发布的安装包。在打上标签之前，按下面的源码步骤构建。

1. 有发行标签之后，把三个文件下载到同一个文件夹。校验文件里的磁盘映像和 zip 都是文件名。打开之前先核对：

   ```sh
   shasum -a 256 -c SHA256SUMS.txt
   ```

   打开 `ReinsCredential-0.2.0-local.dmg`，把 `ReinsCredential.app` 拖入 `/Applications`；也可放入 `~/Applications`。zip 里是同一个 App。
2. 从安装位置启动 App。没有 Developer ID 的构建是 ad-hoc 签名，也未公证。Gatekeeper 可能拦住第一次打开。按住 Control 点（或右键）这个 App，选择“打开”，再选“打开”。双击被拦之后，“系统设置 → 隐私与安全性 → 仍要打开”是同一条针对这个 App 的例外。不要关闭 SIP、Gatekeeper 或其它系统安全开关。本地临时签名版在 `~/Library/LaunchAgents` 安装本产品的用户服务。正式签名构建使用 SMAppService。系统的后台运行控制仍有效；若受限制，到“系统设置 → 通用 → 登录项与扩展”检查 ReinsCredential。
3. 等待状态变成“监控中”或“监控运行中 · 覆盖受限”。“覆盖受限”表示部分进程或描述符无法观察，不代表完全失效。
4. 打开“监控范围”，添加含敏感文件的目录。默认是 `~/.ssh`、`~/.aws`、`~/.config/gh`、`~/.netrc`、`~/.npmrc`、`~/.git-credentials`、`~/.docker/config.json`、`~/.kube/config`、`~/.config/gcloud` 和 `~/.azure`。项目 `.env` 需要添加项目目录。配置改变会重启采集，有短暂覆盖间隙。
5. 运行检测自检。它创建合成文件和回环连接，验证采集器能关联进程、文件与目的地。不发送到外网，也不证明完整的数据外泄检测。
6. “敏感文件与网络连接同时可见”会显示文件、进程链与对端。核对活动是否符合预期。这不是已经证明的上传。

关闭窗口后，后台服务继续采集。停止采集请点“停止监控”。风险通知只由打开的界面发送。退出界面后，服务继续记录，不再发系统通知。

数据保存在 `~/Library/Application Support/ReinsCredential`，不会自动上传。运行目录 0700、日志 0600。保留当前日志与最近 5 个归档。16 MiB 是请求轮转阈值，队列排空可能超量，旧归档会删除。界面保留最近 2,000 条实时记录。更早的归档可以从证据日志打开。

卸载会停掉本产品的用户 LaunchAgent，并删除 `~/Applications/ReinsCredential.app` 和 `/Applications/ReinsCredential.app`。证据目录默认留下：

```sh
macOSClient/scripts/uninstall-local.sh
macOSClient/scripts/uninstall-local.sh --delete-evidence
```

`uninstall-local.sh --dry-run` 只打印将要做的事，不调用 `launchctl`，也不删除文件。也可以先在 App 中停止监控，再退出并把 App 移到废纸篓。不要删除其它应用的 plist。

升级时先停止监控并退出旧版，再替换 App、重新启动。替换 App 不会删除 `~/Library/Application Support/ReinsCredential`。`install-local.sh` 不会覆盖已经位于 `~/Applications/ReinsCredential.app` 的 App。先退出旧版，在访达里替换或删除它，再运行脚本。

本地构建在未设置 `REINS_SIGNING_IDENTITY`、或该值为 `-` 时使用 ad-hoc 签名。把该变量设为 Developer ID 后，`build-app.sh` 改用该身份。`notarize-local.sh` 只在 `APPLE_ID`、`APPLE_TEAM_ID` 和 `APPLE_APP_SPECIFIC_PASSWORD` 都存在时公证，否则直接成功返回并保留当前签名。不要关闭系统安全设置。

开发者构建与安装，在仓库根目录执行：

```sh
macOSClient/scripts/build-app.sh
macOSClient/scripts/install-local.sh
```

`build-app.sh --arch arm64 --arch x86_64` 把两种架构同时传给 Swift 构建和 C++ 辅助程序。`package-local.sh` 在 `macOSClient/dist/` 写出磁盘映像、zip 和 `SHA256SUMS.txt`。`install-local.sh` 只把构建好的 App 复制到 `~/Applications/ReinsCredential.app` 并打开。它不会安装到 `/Applications`。加上 `--no-open` 则不自动打开。

程序坞、访达和关于窗口的图标由 [`brand/ReinsCredential-AppIcon-1024.png`](../brand/ReinsCredential-AppIcon-1024.png) 生成。
