# ReinsCredential

ReinsCredential shows which desktop AI agent touched a sensitive file on your Mac, and through which tools.

A normal result reads like this:

> Codex read ~/.ssh/id_ed25519 via zsh -> python. The file was open in that process. This is not an upload finding.

That sentence means the file was open inside that process, or, when the sentence says so, that only the file's access time overlapped one short-lived tool. It does not by itself mean the file was uploaded.

An upload sentence is separate, and it is written only by the local egress proxy. The closing words are **已上传** (the registered content was in the request and the destination returned success), **已尝试未成功** (the content matched and the transfer failed), **未发现** (the proxy watched that tree's plaintext HTTP and the content was not in it), and **看不到** (that channel's bytes were not visible). 看不到 is not a clean bill. A socket peer or a TLS tunnel is not an upload.

The collector is a user-space Mac app. It does not install a system extension and it does not decrypt TLS. The app's own processes are never the suspected agent. Other security tools stay unlabeled programs, not agents.

```sh
make
./agent-monitor --log ./evidence.jsonl
```

Default sensitive locations are `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.npmrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud`, `~/.azure`, and `.env` in the launch directory. `--sensitive` adds a path. `--no-default-sensitive` clears the defaults first, which is how a saved configuration replaces them. An existing saved list that is still exactly `~/.ssh` and `~/.aws` is upgraded once; any other saved list is left as you set it.

## Collector details

C++17 用户态 Agent 候选监测与结构化证据收集器，使用 libproc 和 FSEvents。

原生 macOS 客户端位于 [macOSClient](macOSClient/README.md)：可安装 App 包含 C++ 采集器、登录后台服务、实时风险列表、目录配置、独立健康检查和检测自检。按用户选择坚持无 ESF，接受采样覆盖限制。[安装说明](macOSClient/INSTALL.md) · [本机产品逐功能验收](macOSClient/PRODUCT_TEST_REPORT.md) · [后端整改报告](BACKEND_AUDIT_REPORT.md)。开发 Agent 请先读 [AGENTS.md](AGENTS.md)；后端证据契约见 [Schema 2](schemas/README.md)。

**完整读取/外传验收尚未通过。** 最新实测、逐功能检查和真实 Agent 证据见 [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md)：45 个行为用例为 17 TP、22 TN、0 FP、6 FN；已接入内容通道的真实 Codex 本机发送验证通过，模型目的地、未接入发送和公网收件仍未通过。

```sh
make
./agent-monitor --log ./evidence.jsonl
```

需 Xcode Command Line Tools；使用系统自带 CoreServices、libcurl、libbsm、zlib，无需下载依赖。被动采集器等价编译命令：

```sh
clang++ -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread \
  main.cpp ProcessCache.cpp DarwinProcessSource.cpp FileMonitor.cpp \
  AgentMonitor.cpp EvidenceStore.cpp ContentMatcher.cpp -framework CoreServices -lz -o agent-monitor
```

```sh
./agent-monitor --duration 30 --interval-ms 200 --workers 2 --log ./evidence.jsonl
./agent-monitor --match my-agent --sensitive /path/to/secrets
./agent-monitor --agent-bundle 'Grok Bot.app' --log ./grok-evidence.jsonl
./agent-monitor --include-runtimes
./agent-monitor --pid 1234
make check
make integration
make acceptance # 当前返回非零：完整验收存在漏报
```

CLI 默认敏感路径为 ~/.ssh、~/.aws、启动目录的 .env。日志模式强制要求 0600，目录应由本人控制；默认输出到 evidence.jsonl，正常监控不向 stdout 输出。--pid 返回 JSON 元数据与已观察祖先链。--match 和 --sensitive 可以重复增加规则；`--no-default-sensitive` 清除之前的路径，App 在参数开头使用它以严格应用保存的配置。--include-runtimes 会把普通解释器也列为候选，增加误报。SIGINT/SIGTERM 排空已接收事件，但不保证尚未交付的 FSEvents。退出码 0 为正常，1 为致命错误，2 为覆盖/队列丢失，3 为请求日志轮转；轮转仍需检查汇总中的丢失指标。

现在默认记录所有可见进程的清单，并对它们采样敏感文件描述符，不依赖 Agent 名称白名单。未识别工具标注为 unclassified_process；已知程序标注为 known_agent_candidate。未知进程持有敏感文件时也会采样 socket 对端并输出风险线索。--agent-bundle 可重复配置应用目录标签，无需重新编译；标签不是身份认证或 Agent 语义证明。

核心实现：[FileMonitor.cpp](FileMonitor.cpp)、[ProcessCache.cpp](ProcessCache.cpp)、[EvidenceStore.cpp](EvidenceStore.cpp)。完整类图、状态机、资源所有权、Schema 和故障语义见 [ARCHITECTURE.md](ARCHITECTURE.md)。测试结果见 [TEST_RESULTS.md](TEST_RESULTS.md)。

真实 Cursor、WorkBuddy AI、Codex、Grok Bot 的进程对照结果，以及未完成的 CLI 动作验收见 [REAL_AGENT_TESTS.md](REAL_AGENT_TESTS.md)。该报告明确区分程序发现、实际工具执行、登录/网络阻塞，不以客户端退出码或 AI 自述代替证据。

FSEvents 不提供修改者 PID，也不监测纯读取。文件变更的 actor_process 必须为空；敏感文件描述符与网络对端共现只提示风险，不能证明数据上传。缓存使用 PID+启动时间防止常见复用误关联，但轮询不能保证观测所有 Agent 或彻底消除竞态。本项目尚未完成长期生产负载与部署验收。

新增实验性 `agent-gateway` 提供显式接入的文件内容交付与发送审计。它以 Unix socket audit token 验证连接方身份，记录来源版本 hash、内容匹配、目的地、传输结果及关联事件。原文、JSON、Base64 和有界 gzip 已测试；跨请求分片和未进入该套接字的发送仍会漏报。它不是透明 HTTPS 监控，也不会自动接入已安装 Agent。

`agent-egress` 在 `127.0.0.1` 上提供本地 HTTP 代理。`--launch` 只给它自己启动的那棵进程树设置代理环境变量。`--watch-live` 观察已经在运行的 Cursor、Codex、ChatGPT、Claude 和 WorkBuddy，但不改它们的环境、MCP 配置或系统代理；那些进程如果没有自己连到代理，结论是看不到。可选的 `--tls-ca-cert` 与 `--tls-ca-key` 让 CONNECT 里的 HTTPS 正文参加同一套指纹匹配。CA 只作为文件使用，不写入登录钥匙串。证书固定、QUIC 和直连仍然是看不到。成功的检查过的传输记为已上传，失败记为已尝试未成功，看过且没有指纹记为未发现。日志不写原始字节。用法和实测见最新验收报告。

```sh
./agent-egress --log ./evidence.jsonl --sensitive-file ./synthetic.env \
  --launch -- python3 your-synthetic-case.py
```
