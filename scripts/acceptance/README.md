# 真实 Agent 验收（假密钥）

这个目录是验收程序，不是安装程序。它不调用 `install-local.sh`，不注册 LaunchAgent，不修改 Codex、Cursor、WorkBuddy 的 MCP 或应用配置，不把 CA 写进任何钥匙串，也不读取 `~/.ssh`、`~/.aws` 或其它真实凭据。

假密钥只出现在临时目录里，跑完就删掉。三种文件都带有明显的假标记：

- `fake.env`
- `fake-aws-credentials`（访问密钥以 `AKIAFAKE` 开头，长度也不是真实 AWS 密钥）
- `fake_id_ed25519`（有私钥文件的头尾，正文写明这不是私钥）

接收端是程序自己监听的 `http://127.0.0.1`，不是外部服务。采集器带 `--no-default-sensitive`，只监视这个临时目录。证据链 JSON 由 `chain-export` 生成，和仪表盘用的是同一个导出。

替身进程 `stand_in_agent.py` 不是 Codex、Cursor 或 WorkBuddy。它的结果不能写成真实 Agent 通过。

## 在主人的 Intel Mac 上

先阅读本文件。下面两条命令都不会在未同意时启动真实 Agent。第一条只打印用例和手工步骤：

```sh
scripts/acceptance/real_agents.sh --mode prepare
```

同意在这台 Mac 上做真实 Agent 验收之后再运行。需要本机已经装好 Xcode 命令行工具、Swift，以及要测的 CLI。脚本会编译 `agent-monitor`、`agent-egress` 和 `chain-export`，不会安装它们。

```sh
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents
```

只跑某一个用例：

```sh
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only codex_launched_upload
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only codex_already_running_not_visible
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only cursor_cli_upload
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only negative_read_no_send
scripts/acceptance/real_agents.sh --mode owner --i-approve-real-agents --only workbuddy_manual
```

请从 Terminal 运行，不要从 Codex、Cursor 或 WorkBuddy 的终端里运行。否则父进程链会把替身算进那个 Agent。

Codex 需要 `codex` 已在 `PATH` 里，并且环境里已有 `OPENAI_API_KEY` 或 `CODEX_API_KEY`。脚本不安装 Codex，也不把密钥写进命令行。Cursor 只在已经存在 `cursor-agent`（或路径里带 cursor 的 `agent`）时尝试；没有 `CURSOR_API_KEY` 时，CI 不启动它。

### WorkBuddy（不能代跑）

`workbuddy_manual` 在终端里才会等待。程序先起采集器和 `agent-egress --watch-live`，然后打印一条只访问临时目录、并且直连 `127.0.0.1` 的 `python3` 命令。

在已经打开的 WorkBuddy 里只运行那一条命令。不要改它的 MCP、代理或证书设置。采集器不把这个进程改道。它看文件描述符和 TCP 发送字节数。发往 `127.0.0.1` 的字节没有离开本机，期望结论是 **未发现**。若描述符读不全，或文件打开期间只有 UDP/QUIC、没有可计数的 TCP，结论才是 **看不到**。不要把看不到写成未发现，也不要因为“已经在运行”就直接写成看不到。

### 用例期望

| 用例 | 谁来做 | 期望结论 | 期望所属 Agent |
| --- | --- | --- | --- |
| `codex_launched_upload` | 由代理启动的 Codex CLI | 已上传 | Codex |
| `codex_already_running_not_visible` | 先启动、不走代理的 Codex CLI，直连本机 | 未发现（回环，没有离开本机） | Codex |
| `cursor_cli_upload` | 可脚本化的 Cursor CLI；否则按上面的手工方式 | 已上传 | Cursor |
| `workbuddy_manual` | 你在已运行的 WorkBuddy 里执行打印出的命令 | 未发现（回环，没有离开本机） | WorkBuddy |
| `negative_read_no_send` | 替身只读假 AWS 文件，不发送 | 未发现 | 不要求产品名 |
| `stand_in_launched_upload` | 替身，经代理发送 | 已上传 | 不要求产品名 |
| `stand_in_direct_not_visible` | 替身，绕过代理直连 | 看不到 | 不要求产品名 |

真实 Codex 在调用模型时还可能有 UDP/QUIC。文件打开期间如果只有这种数不出字节的通道、没有可计数的 TCP，结论是看不到，不能改记成未发现。已经数出 TCP 发送字节、而且没有离开本机的上传时，结论是未发现。所以“读了但不发送 → 未发现”这一例用没有其它套接字的替身，并且不算真实 Agent 通过。

`make acceptance` 的失败标准没有放宽。替身通过也不等于总体验收通过。
