[English](INSTALL.md) · [简体中文](INSTALL.zh-CN.md)

# ReinsCredential 0.2 本机版

需要 macOS 13 或更新版本。本版本使用用户态采样，不要求 ESF、管理员守护进程或全局网络代理。产品名在程序坞和关于窗口里都是 ReinsCredential。

1. 打开 `ReinsCredential-0.2.0-local.dmg`，把 App 拖入“应用程序”；也可放入个人的 `~/Applications`。
2. 从安装位置启动 App。本地临时签名版在 `~/Library/LaunchAgents` 安装本产品的用户服务。正式签名构建使用 SMAppService。系统的后台运行控制仍有效；若受限制，到“系统设置 → 通用 → 登录项与扩展”检查 ReinsCredential。
3. 等待状态变成“监控中”或“覆盖受限”。“覆盖受限”表示部分进程或描述符无法观察，不代表完全失效。
4. 打开“监控范围”，添加含敏感文件的目录。默认包含 `~/.ssh`、`~/.aws`；项目 `.env` 需要添加项目目录。配置改变会重启采集，有短暂覆盖间隙。
5. 运行检测自检。它创建合成文件和回环连接，验证采集器能关联进程、文件与目的地。不发送到外网，也不证明完整的数据外泄检测。
6. “敏感文件与网络连接同时可见”会显示文件、进程链与对端。核对活动是否符合预期。这不是已经证明的上传。

关闭窗口后，后台服务继续采集。停止采集请点“停止监控”。风险通知只由打开的界面发送。退出界面后，服务继续记录，不再发系统通知。

数据保存在 `~/Library/Application Support/ReinsCredential`，不会自动上传。运行目录 0700、日志 0600。保留当前日志与最近 5 个归档。16 MiB 是请求轮转阈值，队列排空可能超量，旧归档会删除。界面保留最近 2,000 条实时记录。更早的归档可以从证据日志打开。

卸载会停掉本产品的用户 LaunchAgent 并删除 App。证据目录默认留下：

```sh
macOSClient/scripts/uninstall-local.sh
macOSClient/scripts/uninstall-local.sh --delete-evidence
```

也可以先在 App 中停止监控，再退出并把 App 移到废纸篓。不要删除其它应用的 plist。

升级时先停止监控并退出旧版，再替换 App、重新启动。替换 App 不会删除 `~/Library/Application Support/ReinsCredential`。

本地构建在未设置 `REINS_SIGNING_IDENTITY` 时使用 ad-hoc 签名。把该变量设为 Developer ID 后，`build-app.sh` 改用该身份。`notarize-local.sh` 只在 `APPLE_ID`、`APPLE_TEAM_ID` 和 `APPLE_APP_SPECIFIC_PASSWORD` 都存在时公证，否则直接成功返回。不要关闭系统安全设置。

开发者构建与安装：

```sh
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64
macOSClient/scripts/package-local.sh
macOSClient/scripts/install-local.sh
```

程序坞、访达和关于窗口的图标由 `brand/ReinsCredential-AppIcon-1024.png` 生成。
