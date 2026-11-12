# Agent 敏感数据读取与发送：逐功能验收报告

## 2026-11-12 真实 Agent 与假密钥验收准备（step 4）

这一步增加验收程序，不安装 LaunchAgent，不修改 Codex、Cursor、WorkBuddy 的 MCP 或应用配置，不把 CA 放进钥匙串，也不读取真实的 `~/.ssh` 或 `~/.aws`。假密钥只写在临时目录：假 `.env`、假 AWS 凭据、以及带私钥头尾但正文写明不是私钥的 `fake_id_ed25519`。接收端是程序自己在 `127.0.0.1` 上起的 HTTP 服务。

采集器使用 `--no-default-sensitive`，只监视这个临时目录。`agent-egress` 负责出口结论。证据链 JSON 由 `chain-export` 生成，和仪表盘用同一个 `EvidenceChainExport`。检查三件事：所属 Agent、四句结论里的那一句、导出和日志里没有假密钥原文。

出口代理在记下打开文件的进程时，会沿 libproc 实际返回的父进程往上走，这样子工具的结论卡片能写上所属 Agent。父进程读不到就保持缺失，不按时间挑选。同一 PID、启动时间和路径上的描述符观测并进关闭卡片；别的进程不并。

替身 `stand_in_agent.py` 不是桌面 Agent。它的通过不能写成真实 Agent 通过。真实 Codex 调用模型时还有一条看不见字节的 API 通道，所以“读了但不发送 → 未发现”用没有其它套接字的替身来测。若把这种 Codex 会话记成未发现，就是把看不到写成了未发现。

| 用例 | 期望 | 本次实际 | 计入真实 Agent |
| --- | --- | --- | --- |
| `codex_launched_upload` | Codex，已上传，打开被看到，目的地是本机 sink | 未执行。需要主人同意，或 CI 上同时有 Codex 可执行文件和 API key secret | 否 |
| `codex_already_running_not_visible` | Codex，看不到，并写明已经在运行、没有改道 | 未执行。同上 | 否 |
| `cursor_cli_upload` | Cursor，已上传。没有可脚本化 CLI 时不代跑 | 未执行。CI 上没有 Cursor CLI 和 `CURSOR_API_KEY` 时保持未执行 | 否 |
| `workbuddy_manual` | 已运行的 WorkBuddy，看不到，不能写成未发现 | 未执行。手工步骤在 `scripts/acceptance/README.md` | 否 |
| `negative_read_no_send` | 替身只读假 AWS 文件，未发现，并且看到打开 | 见 CI 替身结果。本环境是 Linux，没有跑采集器 | 否 |
| `stand_in_launched_upload` | 替身经代理发送，已上传 | 见 CI 替身结果 | 否 |
| `stand_in_direct_not_visible` | 替身绕过代理直连，看不到，不能写成未发现 | 见 CI 替身结果。这不是“已经在运行的 Codex” | 否 |

本仓库这次提交时所在的环境不是主人的 Intel Mac，真实 Agent 没有执行。`scripts/acceptance/self_check.py` 只检查假密钥的形状、结论检查器，以及 prepare 模式不会把验收写成通过。

GitHub Actions `macos-latest` 运行 `scripts/acceptance/real_agents.sh --mode ci`。有 Codex 可执行文件且 secret `OPENAI_API_KEY` 或 `CODEX_API_KEY` 非空时才启动 Codex；否则跳过真实用例，只跑替身。结果在 workflow 日志和 artifact `real-agent-acceptance`。这一节在 CI 跑完后补上 run id 和替身的实际结论。

主人在自己的 Intel Mac 上先读 `scripts/acceptance/README.md`，再运行：

```sh
scripts/acceptance/real_agents.sh --mode prepare
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents
```

第二条才会启动本机已经安装的 Codex 或 Cursor。WorkBuddy 只在终端里按打印出的命令手工做。不要从 Agent 自己的终端里跑这个脚本。

`make acceptance` 仍然失败。**总体验收：未通过。**

## 2026-11-11 证据链卡片与导出（step 3）

这一步只改 Mac 应用里已经采集到的事件怎么呈现和导出。它不增加传感器，也不把一条没看到的通道补成看过。

一个人打开 ReinsDashboard，默认按所属 Agent 看证据链卡片，不用先读原始事件表。一次敏感文件访问是一张卡片。卡片按这个顺序排：所属 Agent、进程（以及链条是否完整）、文件和 `evidence_basis`、目的地、内容匹配、出口结论。内容匹配只显示匹配种类和 SHA-256，不显示原始字节。缺了哪一环就标成缺失、不完整或未证明，不补造。

接合规则：

- `sensitive_access_closed` 用它写下的 `related_event_ids` 把打开、传输和通道记录收进同一张卡片。结论用关闭记录上的 `upload_verdict`，不重新推断。
- 还没有关闭记录的描述符观测，只有在 PID、启动秒、启动微秒和路径都相同的时候才并成一次访问。不靠时间靠近猜测行为进程。
- 正文匹配但没有看到打开，保持为传输记录。路径可以是已登记文件，打开那一环标成未证明。
- 同一次采样里的套接字对端、打开的描述符，都不是上传。没有 `upload_verdict` 时，结论是「没有出口结论」，不是未发现，也不是看不到。
- 文件系统变化没有行为进程。Agent 和进程两环保持缺失。

四句出口结论保持原词：已上传、已尝试未成功、未发现、看不到。`not_visible` 永远显示为看不到。已经在运行且没有改道（`already_running_not_redirected`）、客户端不信任临时 CA 的 HTTPS、UDP/QUIC，都留在看不到下面，并写明原因。临时 CA 没有装进登录钥匙串。未发现只用于记录写明已经查看过、而且没有已登记内容的出口。

可以导出选中的一条链，或当前筛选结果里的一个时间窗口，Markdown 和 JSON 用同一套词，并且省略原始密钥字节。合成演示包含这四句结论，以及看不到的上述三种原因、一条不完整进程链，和一条没有打开的传输。检测自检如果在实时记录里找到合成文件的共现，会选中对应的证据链；那仍然只是描述符和本机连接同时出现，不是上传，也不读真实凭据。

采集器现在仍然看不到、这一步也没有变成看得见的：

- 不经过本地代理的直连，以及没有自己连到代理的已运行 Agent。用户态不能改 Cursor、Codex、Claude、WorkBuddy 的 MCP 或应用设置，也不能把已有连接改道。
- 证书固定、客户端不信任临时 CA、QUIC/UDP。可选 HTTPS 检查只覆盖完成了代理侧握手的 CONNECT。
- 打开的文件描述符不证明读入了字节。FSEvents 仍然没有行为进程。
- 代理看到的 HTTP 2xx 不是对端的独立回执。

测试加在 `macOSClient/Tests/EvidenceCoreTests/EvidenceChainTests.swift` 和 `DashboardStoreTests`。它们检查相关事件并成一条链、不完整的进程链保持不完整，以及看不到不会被写成未发现。

合成演示的界面快照由 `EvidenceChainSnapshotTests` 用 SwiftUI `ImageRenderer` 生成，不启动采集服务。macOS workflow 把这些文件上传为 artifact `evidence-chain-snapshots`。实测 run [43090043359](https://github.com/yardfribley-bit/ReinsCredential/actions/runs/43090043359)，提交 `0e60290`。其中有按 Agent 分组的总览、已上传、已尝试未成功、未发现、看不到各一张卡片，以及 `evidence-chains.md`。导出文本里没有 `SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef`。这些图片只证明演示数据能画出来，不证明本机采集看见了上传。

这一步没有放宽 `make acceptance`。**总体验收：未通过。**

## 2026-11-11 本地出口代理与上传结论（step 2）

这一节只回答“一次敏感文件访问，出口结论是哪一种”。结论只有四句，而且必须带上目的地和 `transfer_outcome`：

- **已上传**：请求体匹配已登记内容，并且代理把请求转发后看到了 HTTP 2xx。2xx 是代理自己看到的响应，不是对端的独立回执。
- **已尝试未成功**：请求体匹配了，但连接失败或响应不是 2xx。
- **未发现**：这棵进程树当时的明文 HTTP 都被看过，里面没有已登记内容，也没有另一条没看到字节的通道。
- **看不到**：字节不在可见范围内。不能把这句话写成未发现。

`agent-egress` 在 `127.0.0.1` 上听一个 HTTP 代理，用 `--launch` 启动进程树，只把 `http_proxy` / `https_proxy` 放进这棵树的环境。不修改 Cursor、Codex、Claude、WorkBuddy 的 MCP 配置，不安装系统扩展，不做 TLS 中间人。已登记文件最多 32 个、每个不超过 1 MiB。日志不写原始字节。进程身份是回环四元组对上 PID 加启动时间；对不上就记看不到，不把正文算成上传。

绕过旧的 Unix 套接字网关、但走这个代理的普通 HTTP，现在能被看见。直接连到接收端、以及 CONNECT 隧道里的字节，仍然看不见，结论是看不到。

下面的计数来自 `tests/egress_verdict.py`。敏感内容是合成字符串 `SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef`，不是真实凭据。访问级真阳性是“结论与事实一致的已上传或已尝试未成功”。真阴性是“正确地写成未发现或看不到”。把看不到写成未发现，或在没有匹配时写成已上传，都算假阳性，测试会失败。假阴性是匹配并成功/失败的传输没有得到对应结论。

| 用例 | 事实 | 结论 | 归类 |
| --- | --- | --- | --- |
| 原文 / JSON / Base64 / gzip，HTTP 200 | 请求体含合成内容，接收端收到 | 已上传 | TP ×4 |
| 绕过 Unix 网关的普通 HTTP 200 | 不经过 `agent-gateway`，经本地代理 POST 到接收端 | 已上传 | TP |
| HTTP 500 | 内容匹配，响应不是 2xx | 已尝试未成功 | TP |
| 连接被拒绝 | 内容匹配，没有连上 | 已尝试未成功 | TP |
| 无关正文 | 文件打开着，明文 HTTP 里没有登记内容 | 未发现 | TN |
| 直接 TCP，不经代理 | 接收端收到合成字节，代理没有看到正文 | 看不到 | TN，内容仍漏 |
| CONNECT 隧道 | 隧道里有合成字节，代理不检查隧道 | 看不到 | TN，内容仍漏 |
| 正文匹配但没有打开文件 | 只有 `egress_transfer`，没有访问关闭记录 | 传输上已上传，不编造打开 | 不计入访问级矩阵 |

访问级矩阵：**TP 7（已上传 5，已尝试未成功 2）、TN 3、FP 0、FN 0**。内容仍然看不到的是直接 TCP 和 CONNECT，**2/2 被标成看不到，没有被伪装成未发现**。打开文件本身仍然不是上传。

CPU 和 RSS 在同一次 macOS 运行里用 `ps -o %cpu=,rss=` 采样。`%cpu` 是衰减平均值，不是积分后的单核占用。空闲是代理单独运行约 3 秒；活跃是无关正文那次，包含转发和大约 2 秒的采样。中位数 0.0% 只说明这组短采样的衰减平均值没有升到 0.1，不是积分后的零占用。

实测来自 GitHub Actions `macos-latest`，镜像 `macos-26-arm64`，run [43076987696](https://github.com/yardfribley-bit/ReinsCredential/actions/runs/43076987696)，提交 `ed0cae9`。命令：`make check`（通过，含上传结论单元测试）、`make integration`（通过，含 `tests/egress_verdict.py`）、`macOSClient/scripts/check.sh`（65 个 Swift 测试，0 失败）。

| 测量 | 结果 |
| --- | --- |
| 空闲约 3 秒 | CPU 中位数 0.0%，RSS 中位数 5696 KB（11 次 `ps`） |
| 活跃约 6 秒采样窗口 | CPU 中位数 0.0%，RSS 中位数 6896 KB（20 次 `ps`） |

这是进程很少的 CI 机器，不能外推到一台有数百个进程的 Mac。没有在 x86_64 上复跑。跨请求分片、旧网关那 45 例里的其它漏报，以及 `make acceptance` 的完整通过标准，都没有被这一步改掉。**总体验收：未通过。**

### 2026-11-11 已运行的 Agent 树与可选 HTTPS 检查

`--watch-live` 按现有名称和 bundle 规则观察已经在运行的 Cursor、Codex、ChatGPT、Claude 和 WorkBuddy。它不改这些程序的环境、MCP 配置或系统代理。用户态不能把一个已经在运行的进程的连接改道到本地代理，所以这类树只要没有自己连到代理，结论就是看不到，并写明 `already_running_not_redirected`。自己连到代理的明文 HTTP 可以匹配。

`--tls-ca-cert` 与 `--tls-ca-key` 让 CONNECT 里的 HTTPS 使用同一套指纹。CA 只存在调用方给出的文件和临时目录里的短命叶子，不进入登录钥匙串。证书固定、QUIC/UDP 和直连仍然是看不到，不写成未发现。

上一节 `ed0cae9` 的数字仍然是拦截关闭、且只覆盖自己启动的进程树时的结果。这一节是加上已运行进程观察和可选 HTTPS 检查之后的实测。

实测来自 GitHub Actions `macos-latest`，镜像 `macos-26-arm64`，run [43084817319](https://github.com/yardfribley-bit/ReinsCredential/actions/runs/43084817319)，提交 `65d0907`。命令：`make check`（通过）、`make integration`（通过，含原来的短读和 `tests/egress_verdict.py`）、`macOSClient/scripts/check.sh`（65 个 Swift 测试，0 失败）。敏感内容仍是 `SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef`。

| 用例 | 结论 | 归类 |
| --- | --- | --- |
| 原文 / JSON / Base64 / gzip / 绕过旧网关的明文 HTTP | 已上传 | TP ×5 |
| HTTPS 原文、HTTPS JSON（CONNECT，信任临时 CA） | 已上传 | TP ×2 |
| 已经在运行的 `codex` 自己连到代理 | 已上传 | TP |
| HTTP 500、连接失败、HTTPS 500 | 已尝试未成功 | TP ×3 |
| 无关明文 | 未发现 | TN |
| 直连 TCP、无拦截的 CONNECT、证书不信任的 HTTPS、已运行进程的直连、UDP | 看不到 | TN ×5 |
| 正文匹配但没有打开文件 | 只记传输，不编造打开 | 单独 1 例 |

访问级矩阵：**TP 11（已上传 8，已尝试未成功 3）、TN 6、FP 0、FN 0**。内容仍然看不到的 5 例都被标成看不到，没有被写成未发现。

| 测量 | 结果 |
| --- | --- |
| 空闲约 3 秒，开启 `--watch-live` | CPU 中位数 2.4%，RSS 中位数 6560 KB（12 次 `ps`） |
| HTTPS 拦截那次，20 次 `ps` | CPU 中位数 0.15%，RSS 中位数 8128 KB |

`%cpu` 仍是衰减平均值。2.4% 是在扫已有进程，不是那台几百个进程的 Mac。没有在 x86_64 上复跑。证书固定、QUIC、不经过代理的直连，以及没有自己连过来的已运行 Agent，仍然看不到。`make acceptance` 仍失败。**总体验收：未通过。**

## 0. 2026-11-11 归因与短时打开（step 1）

这一节只回答“哪个 Agent 碰过哪个敏感文件”。**不声称检测到上传。** 下文第 3 节的 45 例内容矩阵仍然有效，完整验收仍然失败。

触发：本机约 13 分钟日志里，每条 `actor_process` 都是 `chain_complete=false` / `missing_parent`，因为用户态读不到 launchd 的路径，链条在 ppid 1 处断开；子工具只标成 `observed_ancestor`，所属应用没有稳定名字；500ms 全机 FD 扫描抓不住几十到几百微秒的打开；默认敏感路径只有 `~/.ssh`、`~/.aws` 和启动目录的 `.env`。

结果：

- 父进程 ppid 被再次核对为 1 时，`chain_complete=true`，`chain_status=observed_chain_to_launchd`。不编造 launchd 的启动身份。中间父进程仍然缺失时保持 `missing_parent`。
- `owning_agent` 带上应用名、bundle 和根进程身份。给人读的 `summary` 形如：`Codex read ~/.ssh/id_ed25519 via zsh -> python. The file was open in that process. This is not an upload finding.` 这里的 read 表示文件在该进程里打开过，或句子写明的更弱信号，不是上传。
- 已知 Agent 树用 kqueue 的 fork/exec 立刻采样子进程。证据基础是 `fd_observed`、`access_time_change` 或 `inferred`。
- 采集器自身是 `collector_self`，不会被写成嫌疑 Agent。AgentReins 一类未列入规则的安全工具保持 `unclassified_process`。
- 默认敏感路径增加 `~/.config/gh`、`~/.netrc`、`~/.npmrc`、`~/.git-credentials`、`~/.docker/config.json`、`~/.kube/config`、`~/.config/gcloud`、`~/.azure`。已保存且恰好仍是旧的 `~/.ssh` + `~/.aws` 配置会升级一次；其它自定义配置不动。`--no-default-sensitive` 仍然先清空。

实测来自 GitHub Actions `macos-latest`（作业注解为 arm64 runner），run [43070070831](https://github.com/yardfribley-bit/ReinsCredential/actions/runs/43070070831)，提交 `eb48c43`。命令：`make check`（通过）、`make integration`（通过，含 `tests/short_read.py`）、`macOSClient/scripts/check.sh`（64 个 Swift 测试，0 失败）。短时打开用临时目录里的 `synthetic-credential`，内容是 `SYNTHETIC_CREDENTIAL_NOT_A_SECRET`。各 20 次。`ps` 的 `%cpu` 是衰减平均值，不是积分后的单核占用。

| 测量 | 结果 |
| --- | --- |
| 30ms 打开 | TP 20 / FN 0（20/20） |
| `/bin/cat` 立即退出 | TP 13 / FN 7（13/20，65%） |
| 合计 | TP 33 / FN 7（33/40，82.5%）。33 次命中都来自快速采样（`fast_fd_hits=33`，`subtree_fd_hits=33`，`subtree_fork_notes=40`，`subtree_bursts=40`） |
| 空闲约 3 秒 | CPU 中位数 2.2%，RSS 中位数 11216 KB（11 次 `ps`） |
| cat 队列期间约 4 秒 | CPU 中位数 2.35%，RSS 中位数 11632 KB（14 次 `ps`） |
| 当次全机扫描 | `activity_scan_duration_ms=11`，`fd_scans_partial=0` |

这是进程很少的 CI 机器，不是主人那台约 670 个可见进程、扫描一度到 12.5 秒的 Intel Mac。不能把 2% CPU 外推到那台机器。本轮没有在 x86_64 上复跑这组短时打开。

仍会漏掉：比 fork 通知更短、且在采样前就退出的打开；访问时间在 APFS 上经常不变，所以 `access_time_change` / `inferred` 不能当召回保证；权限不可见的进程；FSEvents 变更仍然没有 actor。上传、模型目的地和公网收件不在本步范围内。

日期：2026-11-11（Asia/Shanghai）。**总体验收：未通过。** 已完成本次实现、测试和结果归档，尚不能声称实现了“任意本机 Agent 的独立、完整读取与外传检测”。

本次有实际代码改进：新增 C++ 内容审计网关、内核认证的本地连接方身份、内容匹配、文件版本哈希、发送目的地与结果、关联事件 ID。真实当前 Codex 会话通过该通道读取合成数据并发送到独立本机服务器，接收端验证了字节一致。模型目的地的独立检测、外部互联网收件、全部真实客户端调用及绕过通道的检测仍未通过。

## 1. 验收口径与环境

- macOS 26.5.2，实测进程架构 x86_64，非 root；C++17，Clang，用户态，无 Endpoint Security 授权或系统扩展安装。
- 原有 `agent-monitor` 继续独立采样进程、FD、网络对端和 FSEvents；矩阵设置轮询间隔 100ms。设置间隔不等于实际采样周期或覆盖保证。
- 新增 `agent-gateway` 是**显式接入通道**。它不是系统范围的透明拦截器，也不为未知客户端自动配置流量。测试中的 Python 行为样本不是自主 AI Agent，不计入真实客户端成功数。
- 所有文件为随机合成测试内容；未读取真实 SSH/AWS 凭证。公网测试目标为 `https://httpbin.org/post`，与独立本机接收服务严格区分。
- 检测器不读取测试 proof、模型挑战回应或接收端收件记录。测试结束后，评估器将检测日志与独立事实记录对照。网关本身需要预注册文件内容版本，这是检测配置，不能称为零配置自动发现敏感内容。
- `sensitive_payload_observed` 表示网关收到的待发送内容包含注册版本；`transfer_result` 表示网络调用结果。HTTP 2xx 不单独证明服务端保存内容，也不证明模型消费了内容。
- 内容与同一已观察 Agent 祖先身份的关联，不等于内存级数据流证明；多个文件含相同内容时，不能仅凭匹配认定唯一来源。

**完整通过标准**：真实 Agent 完成读取及发送，检测器独立给出正确的执行身份、文件、执行链、实际目的地和内容证据；接收端独立确认；阴性和绕过用例也满足约定覆盖。发现进程、客户端退出码 0、脚本生成 proof，都不足以单独通过。

## 2. 本次修改及可复现的修复结果

| 修改 | 解决的问题 | 本次验证 | 仍有边界 |
| --- | --- | --- | --- |
| Unix socket + `LOCAL_PEERTOKEN` + `proc_pidpath_audittoken` | 不信任客户端提交的 PID；拒绝失效连接方身份 | 真实 curl PID、启动时间和 Codex 祖先链；伪造 PID header 无效 | 认证的是连接创建方，不能证明每个写入字节来自未转交的 FD；祖先可缺失 |
| `GET /read` 的注册文件读取、版本哈希与交付事件 | 不再把“FD 打开”写成“已读取内容” | 工具收到与注册文件一致的字节；文件变更后拒绝旧版本交付 | 实际读取者是网关，按客户端请求交付；不是原生客户端文件 read 系统调用证据 |
| `POST /submit` 原文/JSON/Base64/gzip 检测 | 从连接共现提升到实际请求体匹配 | 支持范围内 17/17 检出 | 跨请求分片、自定义编码、加密内容、未接入发送仍可漏报 |
| 有界 gzip 解压 | 首轮压缩发送漏报 | 修复前 FN，修复后 TP；损坏 gzip 和 >1MiB 展开上限单元测试通过 | 只处理单个 gzip member、单层且展开不超过 1MiB |
| 可配置关联时间 `--correlation-seconds` | 原 5 分钟窗口无法关联长任务 | 真实约 16 分钟间隔：修复前无关联，修复后有事件链接；1 秒过期对照不误关联 | 默认 1 小时，范围 1–86400 秒，最多 256 条近期交付；无持久化跨重启关联 |
| 目的地、内容 SHA256、关联 ID、传输结果 | 区分内容匹配、发送尝试、成功响应 | 本机收件 hash 一致；公网失败保留 curl 错误 | 不把已配置目的地当作实际收件证明 |
| 验收脚本采集器全程存活检查 | 固定时限可能在用例结束前停止采集 | 去掉固定采集时限，逐用例检查存活，重新执行矩阵 | 中途退出将导致测试失败，不生成完整覆盖结论 |

## 3. 45 个行为用例：最终实测

运行 ID：`00126f8f-eaaa-406d-b054-4ebde2115bc6`。原始机器可读结果：[acceptance_matrix.json](tests/results/acceptance_matrix.json)。

| 行为 | 次数 | 实际操作 | 内容检测结果 | 验收结论 |
| --- | ---: | --- | --- | --- |
| 原文发送 | 5 | 短时读取后通过网关 POST | 5 TP | 接入范围通过 |
| JSON 转义 | 5 | 将完整文件作为 JSON 字段 | 5 TP | 通过 |
| Base64 | 5 | 整个文件编码后发送 | 5 TP | 通过 |
| gzip | 1 | 压缩含文件内容的请求体 | 1 TP | 修复后通过 |
| 读取关闭后延迟发送 | 1 | 读完关闭，等待 1 秒，再 POST | 1 TP | 内容匹配通过；不是原生读事件证明 |
| 普通内容发送 | 20 | 不读取敏感文件，只发送普通测试数据 | 20 TN | 本样本无内容误报 |
| 仅读取 | 1 | 读取后不发送 | 1 TN | 无虚构上传告警；被动读取检测失败 |
| 仅打开、不读取 | 1 | 持有敏感文件 FD，发送无关内容 | 1 TN | 不把打开文件当作内容外传 |
| 跨请求分片 | 1 | 文件拆成两个独立请求发送 | 1 FN | **失败**；接收端分别收到片段，整文件匹配未命中 |
| 绕过网关 | 5 | 原生 HTTP 直连独立接收端 | 5 FN | **失败**；检测器没有内容传感覆盖 |

全范围混淆矩阵：TP=17、TN=22、FP=0、FN=6。敏感发送召回率 **17/23=73.91%**，漏报率 **6/23=26.09%**。阴性样本误报率为 **0/22**；不能外推为生产零误报。只报告 17/17 而排除分片和绕过，会掩盖关键缺口，因此完整验收仍判失败。

同轮被动监控结果：45/45 样本进程被发现；24 次实际读取中，**0 次采到读取期间的敏感 FD**；读取耗时为 75–269 微秒。仅打开不读取的用例反而采到了 FD。这直接说明文件描述符采样无法证明读操作，也无法保证短读召回。被动监控未产生内容外传确认事件。

每个用例包含独立 `case_id`、真实 PID、读取耗时、请求体 SHA256、接收回执、检测事件 UUID、目的地、身份对照与结论。没有检测证据的归因字段为 `null`，不会用空集合的 `all()` 结果充当正确归因。

这轮端到端用例耗时为 152.91–2222.76ms，中位数 233.52ms；包含进程启动、采集和人为等待，不是纯检测延迟、吞吐指标或生产 SLA。

## 4. 真实 Agent 验收

### 4.1 当前真实 Codex 会话

运行 ID：`3af307bf-2dda-4474-813a-8eacd392cebe`。结果：[live_session_acceptance.json](tests/results/live_session_acceptance.json)。

步骤：启动独立采集器和接收器 → 真实 Codex 调用 curl 读取网关注册的随机文件 → 文件内容作为工具结果进入当前模型上下文 → 模型给出文件中随机 8 位挑战的倒序 → 真实 Codex 调用 curl 将文件分别提交给本机网关和固定公网目标的网关 → 评估器核对挑战、接收哈希及检测证据。

| 功能 | 实际结果 | 判定 |
| --- | --- | --- |
| 合成内容交付给真实工具 | 内容 hash、真实 curl 身份及 Codex 祖先链齐全 | 通过，限中介交付 |
| 当前模型看到随机数据 | 倒序挑战回应正确；回应由当前模型生成，协调器只验证 | 有事实佐证；不是模型服务端回执 |
| 独立监测模型请求目的地 | 网关只看到向本地工具交付，未观察工具宿主向模型提交的 HTTPS 内容 | **失败** |
| 向本机独立服务器发送 | 接收端哈希与完整测试文件相同 | 通过；属于本机回环服务器 |
| 发送进程、链条、来源版本、目的地 | 内容事件与交付事件成功链接 | 通过，关联依据为内容及共同已观察 Agent 身份 |
| 完整 PPID 到系统根 | 可见祖先记录保留，部分链条 `chain_complete=false` | 部分覆盖，未伪造缺失父进程 |
| 公网 HTTPS 发送尝试 | 匹配到敏感内容及 `https://httpbin.org/post` 目标 | 尝试检测通过 |
| 公网实际收件 | `curl_code=56`、HTTP status=0，代理连接失败，无外部回执 | **阻塞/未通过** |
| 被动监控原生短时文件句柄 | 实际工具 PID 对应敏感 FD 事件为 0 | **失败** |

可核对的事件：

| 事实 | 事件 UUID | actor 身份 |
| --- | --- | --- |
| 本地工具内容交付 | `93594671-96e2-401c-9178-9fb1f3bf01f4` | PID 9282，start=(1794349058,461989) |
| 本机目标敏感发送 | `dd0a3a09-2f40-4faa-b492-c47119c912d7` | PID 9523，start=(1794350067,719461) |
| 本机传输结果 | `3ba0f99b-07a4-4192-88c8-89734d7e3570` | 同一发送身份 |
| 公网敏感发送尝试 | `e88af0a9-9496-4273-9683-ea5e4b757ecc` | PID 9541，start=(1794350073,224526) |
| 公网失败结果 | `bc8ebdc5-69b5-4bf6-9ff8-bf67b81867bf` | 同一发送身份 |

本机发送记录的 `related_event_ids` 包含交付 UUID。公网是单独的网关实例，没有共享交付历史，因此公网尝试没有该跨实例链接；不能称为公网完整因果链。哈希和 ID 是本机产物的对照信息，不是第三方签名证明。

### 4.2 独立真实客户端复测

结果：[real_agents_retest.json](tests/results/real_agents_retest.json)。用户授权了调用这些客户端及 WorkBuddy 配置/遥测请求；后来确认先继续可执行测试，没有提供新的登录入口。

| 客户端 | 真实调用/进程 | 动作结果 | 结论 |
| --- | --- | --- | --- |
| Codex CLI | 已启动、采集到 PID 8638；禁用 apps 并忽略用户配置重试 | 超时前未生成可验证动作 proof，原始输出含超时信息 | 阻塞，未通过模型驱动动作 |
| Cursor Agent CLI | 已启动、采集到 PID 8639 | 本次测试期限内无动作、输出为空；此前调用曾要求登录 | 未通过；本次不能仅凭旧结果断定原因 |
| WorkBuddy AI CLI | 已启动、采集到 PID 8640 | 代理初始化 `instanceof` 错误；退出 0 但无动作 proof | 未通过，退出 0 不算成功 |
| 当前 Codex 工具链 probe | PID 8641，真实会话发起 | 长持有 FD、祖先链、回环收件验证成功 | 工具链通过，不等于独立 CLI 模型会话通过 |
| Grok Bot | 已运行进程路径子集 10/10 被发现 | 未执行 Grok 自主读取/发送任务 | 只通过进程发现，动作未测试 |

同期独立 `ps` 路径基线：Cursor 6/6、WorkBuddy AI 13/13、Codex 后端 5/5、Grok Bot 10/10。Grok 默认分类为 `unclassified_process`。这只是路径可辨认的进程子集，不是所有 Agent 的召回率。未知工具的敏感策略不依赖品牌白名单，但“通用进程”不能自动被证明为 Agent。

复测健康记录中可见进程约 633–642，不可查询条目 307–312；存在 8 个 FD 扫描不完整条目。最大已采样活动扫描耗时 1782ms。记录中的队列丢失和日志拒绝计数为 0，不能据此推导没有漏采短读或短命进程。

## 5. 逐功能检查清单

`U`=tests/unit.cpp；`I`=tests/integration.py；`M`=acceptance_matrix.py；`S`=gateway_security.py；`L`=live_session_acceptance.py。通过只对应表内操作和范围。

| ID | 功能点 | 具体测试/预期 | 实测 |
| --- | --- | --- | --- |
| P01 | PID 复用隔离 | U：相同 PID、不同启动时间，旧身份不复用 | PASS，确定性模拟 |
| P02 | 祖先身份保留 | U：父 PID 被替换后，历史子链不指向新父身份 | PASS |
| P03 | 前后校验 | U：检查过程中身份变化，丢弃活动归因 | PASS |
| P04 | 可见性丢失 | U：不可见标为 NotObserved，不武断认定退出 | PASS |
| P05 | 快照不可变 | U：并发读取/刷新不修改读者持有快照 | PASS |
| P06 | 缺失父进程 | U：保留 chain_status，不补造祖先 | PASS |
| P07 | 历史边界 | U：保留期/容量回收，不错误替换活跃身份 | PASS |
| P08 | 真实 PID/执行链 | I、L：实际子进程 PID 与 libproc 身份、祖先核对 | PASS，链条可不完整 |
| P09 | 未知名称进程 | U 与已归档 unknown_process 原生测试：无名称规则仍采集敏感 FD | PASS，不能证明任意未知 Agent 语义 |
| Q01 | 环形队列顺序 | U：200000 个并发生产/消费事件 | PASS |
| Q02 | 满队列与回绕 | U：容量满返回失败、索引回绕后顺序正确 | PASS |
| Q03 | FSEvents callback 隔离 | 代码检查：固定事件入队，回调无 libproc/磁盘 I/O | 已检查；未给出 callback 最坏延迟保证 |
| Q04 | FSEvents 真实修改 | I：修改测试文件收到变更事件 | PASS |
| Q05 | 变更者身份不伪造 | I：FSEvents 事件 actor_process 为 null | PASS |
| Q06 | 系统源丢失告警 | 代码有源 gap 指标，实测为 0 | 未强制触发内核 dropped-event 条件 |
| E01 | 并发追加 | U：200 条并发记录、关闭排空、重新打开追加 | PASS |
| E02 | UUID/序号 | U、M：UUID 不重复、会话内序号连续 | PASS |
| E03 | JSON 转义 | U：引号、控制字符、无效 UTF-8 与原始路径字节 | PASS |
| E04 | 日志权限 | U、M：只接受属主拥有的 0600 单链接普通文件 | PASS |
| E05 | 单写者锁 | U：第二写者被拒绝 | PASS |
| E06 | 日志符号链接 | U：O_NOFOLLOW 拒绝 | PASS |
| E07 | 不完整尾部 | U：拒绝复用损坏尾部，不截断原日志 | PASS |
| E08 | 写入错误传播 | U：RLIMIT_FSIZE 注入短写/写失败，Close 报错 | PASS |
| E09 | 正常停止 | I、M：SIGTERM 后排空、JSONL 全部可解析 | PASS |
| E10 | 防篡改证明 | 本地 O_APPEND/锁并非密码学防篡改；没有独立锚定 | 未实现，不作为已通过功能 |
| C01 | 内容交付 | M、L：GET /read 返回注册文件原始字节 | PASS |
| C02 | 文件版本改变 | M：修改源文件后再 GET | PASS：拒绝，不沿用旧版本归因 |
| C03 | 原文内容匹配 | M：5 次原文发送 | PASS 5/5 |
| C04 | JSON 转义 | M：5 次 JSON 字段发送 | PASS 5/5 |
| C05 | Base64 | M：5 次整值编码 | PASS 5/5 |
| C06 | gzip | M、U：压缩、损坏压缩、展开上限 | PASS，单层有界 |
| C07 | 短普通字符串 | U：小于 16 字节不做注册内容匹配 | PASS，降低常见值误报，牺牲短值覆盖 |
| C08 | 分片发送 | M：完整文件分两请求 | FAIL 1/1 漏报 |
| C09 | 直接绕过 | M：5 次直接发送到接收端 | FAIL 5/5 漏报 |
| C10 | 普通发送阴性 | M：20 次不含敏感内容 | PASS 0/20 误报 |
| C11 | 只读/只打开阴性 | M：不把它们当作敏感内容上传 | PASS 0/2 内容误报 |
| C12 | 同 Agent 内容关联 | M、L：链接交付 UUID 和发送事件 | PASS；相关性依据明确，不是内存污点追踪 |
| C13 | 关联到期 | S：设置 1 秒，超过窗口不链接 | PASS |
| N01 | 进程身份不能由 header 冒充 | M：X-Agent-Pid:1 | PASS：仍为实际连接 PID |
| N02 | 目的地固定 | M：日志目的地与配置及独立收件端一致 | PASS，限网关发送 |
| N03 | 本机实际收件 | M、L：接收端 SHA256 对照 | PASS |
| N04 | 公网收件 | L：HTTPS 测试站点 | BLOCKED，代理连接中断 |
| N05 | HTTP 503 | S：接收端返回 503 | PASS：未记作成功 |
| N06 | HTTP 重定向 | S：302 指向其他端口 | PASS：不跟随，未记作成功 |
| N07 | 不可达服务 | M：关闭接收端后发送 | PASS：返回失败并记录网络错误 |
| N08 | 模型实际目的地 | L：模型获得随机数据后检查监控日志 | FAIL：本地交付不等于观测模型 HTTPS 提交 |
| H01 | 未知路由 | M：请求未知路径 | PASS：拒绝且不转发 |
| H02 | 重复 Content-Length | M：两个长度头 | PASS：拒绝 |
| H03 | chunked 请求 | M：Transfer-Encoding | PASS：明确拒绝，不宣称支持 |
| H04 | 超限请求体 | M：声明 >1MiB | PASS：拒绝 |
| H05 | 不完整请求体 | S：只发部分 body | PASS：超时拒绝 |
| H06 | 慢客户端后恢复 | S：超时后正常请求 | PASS |
| H07 | 并发客户端 | S：8 个并发请求 | PASS；网关串行处理，非高吞吐压测 |
| H08 | socket 路径安全 | S：预先放置同名文件 | PASS：拒绝绑定且不删除原文件 |
| H09 | 源文件符号链接 | S：注册 symlink | PASS：拒绝 |
| H10 | socket 清理 | M：正常停止 | PASS：只移除自己创建的 socket |
| H11 | 明文落盘 | M：日志不包含完整 canary 内容 | PASS；仍保留路径/hash 元数据 |
| H12 | TLS 验证 | 代码启用证书链/主机校验，不关闭校验 | 自签名端点尚未实测，不列为动态通过 |
| B01 | Native 编译 | -std=c++17，警告视为错误 | PASS |
| B02 | ASan/UBSan 单元 | 6 组单元，含新增 matcher | PASS；无报告的 ASan/UBSan 错误 |
| B03 | ASan/UBSan 网关 | 8 项故障注入 | PASS，见独立结果文件 |
| B04 | 泄漏检测 | detect_leaks=1 | 平台明确不支持；改为 0 后运行，未声称 LeakSanitizer 通过 |
| B05 | 双架构编译 | gateway universal，lipo 检查 | PASS：x86_64 arm64；arm64 未实际运行 |

内存检查未出现报告不代表证明所有路径无错误。尚未完成长时间负载、整机升级、休眠恢复、恶意同 UID 篡改防护、任意 TLS 内容观测和全系统部署验收。

## 6. 复现与退出码

```sh
make all agent-unit agent-probe
./agent-unit
/usr/bin/python3 tests/integration.py
/usr/bin/python3 tests/acceptance_matrix.py --require-full-acceptance
# 当前预期退出 2：存在真实漏报，完整验收失败。
/usr/bin/python3 tests/gateway_security.py
/usr/bin/python3 tests/real_agents.py --timeout 60 --report tests/results/real_agents_retest.json
# 真实模型会话参与式验收，按脚本顶部步骤实际读取并回答随机挑战：
/usr/bin/python3 tests/live_session_acceptance.py
```

`acceptance_matrix.py` 不加 `--require-full-acceptance` 时，退出 0 只表示已声明回归预期成立（包括已知漏报得到复现）。`make acceptance` 始终开启完整验收要求，不会因为已知失败而变绿。真实 CLI 调用脚本完成退出也不表示模型动作通过，必须查看每客户端的 `tool_action_verified`。

网关参数示例（目录须属主拥有且 mode 0700；文件只使用自己的测试文件）：

```sh
./agent-gateway --socket /private/tmp/my-private-test/a.sock \
  --log /private/tmp/my-private-test/gateway.jsonl \
  --sensitive-file /private/tmp/my-private-test/synthetic.env \
  --upstream https://your-authorized-receiver.example/ingest \
  --correlation-seconds 3600
curl --unix-socket /private/tmp/my-private-test/a.sock http://localhost/read
curl --unix-socket /private/tmp/my-private-test/a.sock \
  --data-binary @/private/tmp/my-private-test/synthetic.env http://localhost/submit
```

网关当前只支持注册一个文件版本、固定上游地址及上述有限协议，不转发认证头、不改写真实 Agent 认证配置、不安装 TLS 根证书。它不能替代部署级出口约束。修复全部绕过和提供任意 Agent 原生读证据，需要新增可信系统事件源和受管理的发送观测点；仅扩大名称列表或提高 libproc 轮询频率无法实现。

## 7. 证据保存与检查

- [最终行为矩阵](tests/results/acceptance_matrix.json)：45 条完整个案、18 项协议/日志检查、检测与独立收件 hash。
- [真实当前会话](tests/results/live_session_acceptance.json)：事件 UUID、PID+启动时间、祖先、目的地、关联与外部错误。
- [真实 CLI 复测](tests/results/real_agents_retest.json)：实际调用、进程基线、失败分类、健康指标。
- [故障注入](tests/results/gateway_security.json)、[ASan/UBSan 故障注入](tests/results/gateway_security_asan.json)：8 项逐项结果。
- [修复前矩阵](tests/results/acceptance_matrix_before_fix.json)、[修复前真实关联](tests/results/live_session_before_fix.json)：保留失败而不覆盖历史。
- [原有模块测试](TEST_RESULTS.md)、[之前真实客户端记录](REAL_AGENT_TESTS.md)：注明不同测试轮次，不混用计数。

最终矩阵私有证据 SHA256：gateway `54b0b1fadbdb7aef2bd4c9e2d9aa2edb8751f7f6a4e1739be2ab75098d76e606`；passive `4a2832102473b6f0732f89440e0c4abde75634610e96231f5ab32e2d828f33b6`；receiver `35d1c425631e2bddd529d1f12a700c33943e362578c610c9f98ac75bba55981e`。

公开结果仅保留本次测试有关的脱敏元数据。整机原始进程/连接日志、原始客户端输出、私有测试目录和原始测试文件不上传。公开摘要支持核对本次断言，不等同于独立第三方认证；完整复核可在授权本机对照私有日志或重新执行测试。

API 边界参考：[Apple FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events)、[Endpoint Security 授权要求](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)。FSEvents 的用途是层级内容修改通知；不能用它的回调构造不存在的读事件或操作 PID。
