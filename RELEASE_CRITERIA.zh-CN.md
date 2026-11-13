[English](RELEASE_CRITERIA.md) · [简体中文](RELEASE_CRITERIA.zh-CN.md)

# ReinsCredential 0.2.0 发布门槛

市场版本保持 `0.2.0`（`CFBundleShortVersionString`）。下面每一项都成立，构建才可以发布。每一项都写明锁定它的自动检查。需要 Mac 的检查在 `.github/workflows/macos.yml`。`.github/workflows/release.yml` 只在有人推送 `v*` 标签时运行，拉取请求不会触发它。

每一项的约束相同：不安装 CA，不设置系统代理，不修改登录钥匙串，不修改其它应用的 MCP 或客户端配置。

## 1. 按行为检测

任何非采集器进程打开已登记敏感文件，都归到所属桌面应用，并按行为者收口为 `uploaded`（已上传）、`attempted`（已尝试未成功）、`not_found`（未发现）或 `not_visible`（看不到）。

| 情形 | 要求的收口 | 检查 |
| --- | --- | --- |
| (a) 未列入名单的 `.app` 向非回环地址发送 | `uploaded`，属主 `UnknownAgent.app` | `make integration` 的 `live-unknown-app` |
| (b) 桌面 Agent 的 shell 子进程，中间有 Xcode 的 Python，上面是 `Grok Bot.app` | `uploaded`，属主 `Grok Bot.app`，行为者 `hold-upload` | `make integration` 的 `live-toolchain-chain`；同一形状的 `ApplyBehaviorOwner` 单元测试 |
| (c) 只向回环发送 | `not_found`，结果 `loopback_not_off_host` | `make integration` 的 `live-direct` |
| (d) 连接失败 | `attempted` | `live-attempt`（向 TEST-NET 停在 SYN_SENT）和 `live-refused`（对本机地址上已关闭的端口做阻塞 `connect`） |
| (e) 测到的 UDP 大到能装下文件，包括只开约 100 毫秒的套接字 | `uploaded`，`flow_txbytes_udp` | `live-udp-large` 和 `live-short-udp` |
| (f) 离机 UDP 已完整测到，且小于压缩下界 | `not_found` | `live-udp-small` |
| (g) 约 100 毫秒的 HTTP POST，发往可路由地址 | `uploaded`，`flow_txbytes` | `live-short-post` |
| (h) 短的被拒绝连接 | `attempted`，`flow_attempt` | `live-short-refused` |
| (i) 短的离机数据报，字节数没有拿到 | `not_visible`，不是 `not_found` | `live-short-unmeasured` |
| (j) 启动自检已经证明过的文件上，后来又有一个行为者 | 新的 `uploaded` / `flow_txbytes`，同时保留自检的 `exact_bytes` | `live-after-canary` |
| (k) 代理启动的进程做正文匹配 | `uploaded` 且为 `exact_bytes` | 启动模式 `plaintext`、`json`、`base64`、`gzip` |

已知名称只是显示标签，不是跟踪的原因。

## 2. 人能读的证据链

仪表盘导出，以及 `chain-export` / `chain-export --markdown`，对每条发现给出：应用、进程链状态、文件、打开观察、目的地、哈希或流量依据、结论和原因。JSON 和 Markdown 都会生成。密钥原文省略，哈希和遮盖后的显示文本保留。

检查：`macOSClient/scripts/check.sh`（含 Markdown 和 JSON 导出的 `EvidenceChainTests`），以及 macOS 工作流里的快照步骤。

## 3. 生命周期

- 一个监督进程持有 `RuntimeInstanceLock`。第二次启动不会变成第二个采集器。检查：`RuntimeCore` 锁测试。
- 退出或停止监控会停掉它拥有的 monitor 和 egress 子进程，并移除本产品的用户 LaunchAgent。检查：`LocalLaunchAgent.stopAndRemove` 和 `uninstall-local.sh`。
- 卸载移除该 LaunchAgent 和 `ReinsCredential.app`。除非传入 `--delete-evidence`，`~/Library/Application Support/ReinsCredential` 留下。检查：工作流对脚本做两种 `--dry-run`。
- 升级替换 App，不删除证据目录。已有安装时 `install-local.sh` 拒绝覆盖，直到旧应用退出；它从不删除支持目录。
- 应用不安装 CA、系统代理或钥匙串项目，所以退出和重装不会被这些东西挡住。

## 4. 资源限制

证据日志权限是 `0600`。采集器在 16 MiB 请求轮转，并保留有限个归档。仪表盘保留有限的实时窗口。

`make integration` 先启动 40 个额外的 `sleep` 进程，再对这张进程表运行 `agent-egress --watch-live`。代理的 RSS 中位数超过 150000 KB，或 CPU 采样中位数超过单核的 150%，运行就失败。同一次运行会打印 `idle_rss_median_kb` 和 `idle_cpu_median`。

2026-11-12 的 macOS CI 运行 43242914536 测得：空闲 CPU 中位数 1.6%，空闲 RSS 中位数 6608 KB，共 12 个样本。同一次运行里活跃的 HTTPS 样本是 CPU 中位数 0.4%、RSS 中位数 11888 KB。

## 5. 打包

`build-app.sh` 生成版本 0.2.0 的 `ReinsCredential.app`。`REINS_SIGNING_IDENTITY` 未设置或为 `-` 时使用 ad-hoc 签名，并设置本地 LaunchAgent 标志。有人提供 Developer ID 时使用该身份。`package-local.sh` 写出 dmg、zip 和 `SHA256SUMS.txt`。只有 `APPLE_ID`、`APPLE_TEAM_ID` 和 `APPLE_APP_SPECIFIC_PASSWORD` 都设置时才公证，否则 `notarize-local.sh` 以 0 退出。

检查：工作流对这些脚本做 `bash -n`，并用 `make-icon.sh` 从 `brand/ReinsCredential-AppIcon-1024.png` 生成非空的 `ReinsCredential.icns`。`CFBundleIconFile` 必须设置。脚本不需要凭据也能成功。

## 6. 文档

- 快速开始、结论用词和限制：`README.md` 与 `README.zh-CN.md`
- 隐私：`PRIVACY.md` 与 `PRIVACY.zh-CN.md`
- 安装、升级、卸载：`macOSClient/INSTALL.md`、`INSTALL.zh-CN.md` 和 `uninstall-local.sh`
- 历史和本版本：`CHANGELOG.md`、`CHANGELOG.zh-CN.md`、`RELEASE_NOTES_0.2.0.md`、`RELEASE_NOTES_0.2.0.zh-CN.md`

这些文档里保持的限制：TLS 正文不解密，流量字节匹配不是远端回执，看不到是尚未解决的盲区，不是验收通过。子进程扫描之前就结束的短打开，不写成已经覆盖所有读取。大于文件窗口的发送保持看不到。压缩下界不包含 zstd。

## 7. CI 和带标签的发布

拉取请求和分支推送只跑 `.github/workflows/macos.yml`。有人推送 `v*` 标签时才跑 `.github/workflows/release.yml`。它构建应用、打包 dmg 和 zip，仅在上述密钥存在时公证，并把产物附到该标签。普通推送和拉取请求不会跑它。
