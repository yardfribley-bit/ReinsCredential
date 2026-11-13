[English](README.md) · [简体中文](README.zh-CN.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="brand/ReinsCredential-Wordmark-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="brand/ReinsCredential-Wordmark-light.png">
  <img alt="ReinsCredential" src="brand/ReinsCredential-Wordmark-light.png" width="960">
</picture>

# ReinsCredential

ReinsCredential 显示这台 Mac 上哪个桌面应用打开了已登记的敏感文件——Claude、Cursor、Codex、Grok、Kiro、WorkBuddy，或任何不在这份名单上的应用——以及现有证据把这次访问收成已上传、已尝试未成功、未发现，还是看不到。它把这条记录做成可以阅读和导出的证据链，并且不安装系统扩展、不以 root 运行守护进程、不安装证书颁发机构、不修改钥匙串，也不改其它应用的配置。

两种语言里产品名都是 ReinsCredential，不另起中文产品名。文件打开的句子表示文件曾在该进程中打开；如果句子写明，则只是访问时间与一个短生命周期工具重合。打开本身不是上传。

## 使用 Mac 应用（macOS 13+）

日常使用走这个 App。系统需要 macOS 13 或更新版本。只有自己从源码构建时才需要 Xcode 命令行工具。对外版本号保持 `0.2.0`。

### 选项 A：下载发行版（打上标签之后）

只有有人推送 `v*` 标签时，发行包才会附在该标签上。[`.github/workflows/release.yml`](.github/workflows/release.yml) 上传：

- `ReinsCredential-0.2.0-local.dmg`
- `ReinsCredential-0.2.0-local.zip`
- `SHA256SUMS.txt`

[Releases](https://github.com/yardfribley-bit/ReinsCredential/releases) 上目前还没有已发布的版本。在打上标签之前，请用下面的选项 B。

有标签之后，把这三个文件下载到同一个文件夹，先核对再打开安装包。校验文件里的磁盘映像和 zip 都是文件名：

```sh
shasum -a 256 -c SHA256SUMS.txt
```

打开磁盘映像，或解压 zip，把 `ReinsCredential.app` 拖到 `/Applications` 或 `~/Applications`。

没有 Developer ID 的包是 ad-hoc 签名。标签工作流只在设置了 `REINS_SIGNING_IDENTITY` 时使用 Developer ID，并且只在 `APPLE_ID`、`APPLE_TEAM_ID` 和 `APPLE_APP_SPECIFIC_PASSWORD` 都存在时公证。否则附上的 App 保持 ad-hoc，也未公证。Gatekeeper 会把它当成身份不明的应用，第一次打开可能被拦住。按住 Control 点（或右键）这个 App，选择**打开**，再选**打开**。双击被拦之后，**系统设置 → 隐私与安全性 → 仍要打开**是同一条针对这个 App 的例外。不要关闭 SIP、Gatekeeper 或其它系统安全开关。在本机按选项 B 构建，是把 App 装到这台 Mac 上的另一条路。

### 选项 B：从源码构建并安装

需要 Xcode 命令行工具（`swift`、`clang++`）。在仓库根目录执行：

```sh
git clone https://github.com/yardfribley-bit/ReinsCredential.git
cd ReinsCredential
macOSClient/scripts/build-app.sh
macOSClient/scripts/install-local.sh
```

`build-app.sh --arch arm64 --arch x86_64` 会把两种架构同时传给 Swift 构建和 C++ 辅助程序。通用二进制在每种架构上能否运行，要各自验证。本仓库不把“编译通过”写成“两种架构都已经跑过”。

`install-local.sh` 把 `macOSClient/dist/ReinsCredential.app` 复制到 `~/Applications/ReinsCredential.app` 并打开它。它不会安装到 `/Applications`。如果 `~/Applications/ReinsCredential.app` 已经存在，脚本会停下来，旧 App 留在原地。先退出旧版，在访达里替换或删掉它，再重新运行脚本。加上 `--no-open` 则不自动打开。脚本不会删除 `~/Library/Application Support/ReinsCredential`。

未设置 `REINS_SIGNING_IDENTITY` 时，构建是 ad-hoc 签名，Gatekeeper 的路径和未公证的下载相同。有 Developer ID 时，在运行 `build-app.sh` 之前把该变量设成这个身份。`notarize-local.sh` 只在上面三个 Apple 凭据变量都设置时才公证打包好的磁盘映像；否则以 0 退出，并保留当前签名。

### 首次启动与日常使用

1. 打开 **ReinsCredential**，等到状态变成**监控中**。**监控运行中 · 覆盖受限**表示采集器开着，但有些进程或描述符看不到。**需要允许后台运行**表示还要到“系统设置 → 通用 → 登录项与扩展”允许这个 App。ad-hoc 构建第一次启动会登记本用户的 LaunchAgent。Developer ID 构建使用 SMAppService。两者都不是 root 守护进程。
2. 打开**监控范围**，添加放有敏感文件的文件夹。新安装默认监视 `~/.ssh`、`~/.aws`、`~/.config/gh`、`~/.netrc`、`~/.npmrc`、`~/.git-credentials`、`~/.docker/config.json`、`~/.kube/config`、`~/.config/gcloud` 和 `~/.azure`。项目里的 `.env` 不在这份名单里，需要把项目文件夹加进去。保存配置会重启采集，中间有一段短的空隙。
3. 用工具栏的**检测自检**，或**监控**菜单里的**运行检测自检**。它创建合成文件和一条回环连接，让采集器把进程、文件和目的地关联起来。它不读取真实凭据，也不向 Mac 以外发送任何东西。自检通过的那一行不是上传。
4. 在**监控**菜单里切换语言：**Follow System**、**简体中文**、**English**。英文界面里这个菜单叫 **Monitor**，简体中文界面里叫**监控**。界面已经是中文时，同样三项显示为**跟随系统**、**简体中文**和 **English**。
5. 选中一条证据链，从链上或工具栏**更多**菜单导出 JSON 或 Markdown（**导出选中的链为 JSON** / **导出选中的链为 Markdown**）。**导出时间窗口…**导出当前筛选里的链。原始密钥字节不会写入。对一份已经写完的 JSONL，同一份导出是：

```sh
swift run --package-path macOSClient chain-export evidence.jsonl
swift run --package-path macOSClient chain-export --markdown evidence.jsonl
```

`chain-export` 只读已完成的日志，不会启动采集器。

关掉窗口后，本用户的后台服务继续运行。**停止监控**才会停采集。风险通知只在界面打开时发送。证据留在这台 Mac 的 `~/Library/Application Support/ReinsCredential`。

### 升级与卸载

替换之前先停止监控并退出旧版。替换 App 不会删除证据目录。`install-local.sh` 不会覆盖已经位于 `~/Applications/ReinsCredential.app` 的 App。

卸载会停掉本产品的用户 LaunchAgent，并删除 `~/Applications/ReinsCredential.app` 和 `/Applications/ReinsCredential.app`。除非加上 `--delete-evidence`，证据会留下：

```sh
macOSClient/scripts/uninstall-local.sh
macOSClient/scripts/uninstall-local.sh --delete-evidence
```

完整步骤，包括 `--dry-run`：[macOSClient/INSTALL.zh-CN.md](macOSClient/INSTALL.zh-CN.md)（[English](macOSClient/INSTALL.md)）。

## 四句结论

| 代码 | English | 中文 | 含义 |
| --- | --- | --- | --- |
| `uploaded` | Uploaded | 已上传 | 已登记内容出现在成功的代理请求里，或进程树在持有文件和短暂收尾窗口里测到的离机发送（TCP 与 UDP/QUIC 合计）落在压缩下界和原始大小加 64 KiB 之间。依据是 `flow_txbytes`；当 UDP/QUIC 字节把合计推进这个窗口、而仅有的 TCP 应用字节仍低于下界时，依据是 `flow_txbytes_udp`。 |
| `attempted` | Attempted | 已尝试未成功 | 内容匹配但传输失败，或离机连接在送出不少于下界的字节之前失败，包括连接被拒绝（`flow_attempt`）。 |
| `not_found` | Not found | 未发现 | 持有文件期间和收尾窗口里，每条离机通道都测到了字节数，并且合计低于压缩下界。只发到本机回环的发送留在这里（`loopback_not_off_host`）。 |
| `not_visible` | Not visible | 看不到 | 有通道没测到、连接在拿到字节数之前就关了，或测到的合计超过文件大小加 64 KiB。这是未决状态，不是清白结论，也不会改写成未发现。 |

任何非采集器进程打开已登记敏感文件就会被跟踪。属主是该进程自己的 `.app`。进程不在应用里时，Xcode 和它自带的 Python.app 是工具链，继续往上找到桌面应用，名字可以有空格，例如 `Grok Bot.app`。已知名称只用于显示，不是检测门槛。启动自检的正文匹配只覆盖那次启动的进程。之后另一个进程打开同一文件，仍然单独收口。应用自己的进程不会被当成可疑 Agent。

## 命令行与开发者快速开始

在仓库根目录、装有 Xcode 命令行工具时构建。构建使用系统自带的 CoreServices、libcurl、libbsm 和 zlib，不额外下载依赖。

```sh
make
./agent-monitor --log ./evidence.jsonl
```

命令行的默认路径和 App 相同，另外加上启动 `agent-monitor` 的那个目录里的 `.env`。`--sensitive` 增加路径。`--no-default-sensitive` 先清掉默认值。

`agent-egress` 是 `127.0.0.1` 上的本地 HTTP 代理。`--launch` 只给它启动的那棵进程树设置代理环境变量。`--watch-live` 观察已经打开已登记文件的进程，不按名称名单挑选。日志不保存密钥原文。请使用合成文件：

```sh
./agent-egress --log ./evidence.jsonl --sensitive-file ./synthetic.env \
  --launch -- python3 your-synthetic-case.py
make check
make integration
```

`make acceptance` 仍是严格门槛，已知漏报存在时会返回非零。不要为了让报告变绿而放宽它。

## 隐私与安全保证

ReinsCredential 只在安装它的这台 Mac 上运行。它不上传证据、配置或文件内容。本地数据在 `~/Library/Application Support/ReinsCredential`（目录 `0700`，日志 `0600`）。

- 日志、仪表盘和两种导出都不包含密钥原文。导出写明 `raw_secret_bytes: omitted`。
- 应用不读、不写登录钥匙串，也不在那里安装证书颁发机构。可选的 TLS CA 只是操作者传给代理的文件，不会被安装。
- 它不修改其它应用的 MCP 或客户端配置，也不设置系统级代理。
- 出口代理只监听 `127.0.0.1`。`--launch` 只给它启动的进程树设置代理变量。没有进入这个代理的 TLS 不会被解密。
- `flow_txbytes` 或 `flow_txbytes_udp` 的收口，是持有该文件的进程树上的本机发送字节数。它不是解密后的正文，也不是远端服务器的回执。UDP 和 QUIC 的载荷不会被读取。测到的数据报字节数如果落在大小窗口里，仍然可以收成 `uploaded`。没测到字节数的 UDP 或 QUIC 通道保持 `not_visible`。

细节：[PRIVACY.zh-CN.md](PRIVACY.zh-CN.md)（[English](PRIVACY.md)）。

## 已知限制

- 没有 Endpoint Security 客户端。子进程扫描可能漏掉在下一次扫描之前就结束的打开。立刻退出的 `cat` 和其它短生命周期打开，召回不完整，不能写成已经覆盖所有读取。
- FSEvents 不提供修改文件的进程，也不报告纯读取。文件变化记录的行为者留空。打开的描述符不能证明字节已被读取。套接字对端不是载荷。
- 没有进入本地代理的 TLS 不会被解密。客户端握手发送不超过 1024 字节时，不能证明文件已经离开。记录的名字是反向 DNS，或网络统计源里已经有的主机名。不从套接字上抄 ClientHello。
- `flow_txbytes` 和 `flow_txbytes_udp` 统计的是进程树发出的字节，不是对端回执。发送量大于文件加 64 KiB 时保持 `not_visible`。文件可能混在这些流量里，计数本身分不出来。
- 压缩下界是原始大小、gzip、zlib 和 raw deflate 中的较小值。不计算 zstd。比这个下界更小的 zstd 载荷仍可能被收成 `not_found`。
- `not_visible` 是未决状态，不会改写成 `not_found`。
- 短离机发送会在套接字关闭后保留，来源是 `com.apple.network.statistics` 的通知（该内核控制可用时）。该控制没有报告的连接仍然可能漏掉。
- 可选的 TLS CA 文件只用于进入代理的 CONNECT 正文。

## 文档

| 主题 | English | 简体中文 |
| --- | --- | --- |
| 安装、升级、卸载 | [INSTALL.md](macOSClient/INSTALL.md) | [INSTALL.zh-CN.md](macOSClient/INSTALL.zh-CN.md) |
| 隐私 | [PRIVACY.md](PRIVACY.md) | [PRIVACY.zh-CN.md](PRIVACY.zh-CN.md) |
| 0.2.0 发行说明 | [RELEASE_NOTES_0.2.0.md](RELEASE_NOTES_0.2.0.md) | [RELEASE_NOTES_0.2.0.zh-CN.md](RELEASE_NOTES_0.2.0.zh-CN.md) |
| 更新记录 | [CHANGELOG.md](CHANGELOG.md) | [CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md) |
| 架构 | [ARCHITECTURE.md](ARCHITECTURE.md) | [ARCHITECTURE.md](ARCHITECTURE.md) |
| 发布门槛 | [RELEASE_CRITERIA.md](RELEASE_CRITERIA.md) | [RELEASE_CRITERIA.zh-CN.md](RELEASE_CRITERIA.zh-CN.md) |

架构只有一份文档，用中文写。卸载脚本是 `macOSClient/scripts/uninstall-local.sh`，安装指南里有说明。发布门槛写明上面每条结论对应哪项检查。
