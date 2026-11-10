# macOS Agent Runtime Security Collector

C++17 用户态 Agent 候选监测与结构化证据收集器，使用 libproc 和 FSEvents。

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

默认敏感路径为 ~/.ssh、~/.aws、启动目录的 .env。日志模式强制要求 0600，目录应由本人控制；默认输出到 evidence.jsonl，正常监控不向 stdout 输出。--pid 返回 JSON 元数据与已观察祖先链。--match 和 --sensitive 可以重复增加规则。--include-runtimes 会把普通解释器也列为候选，增加误报。SIGINT/SIGTERM 正常排空关闭。退出码 0 为正常，1 为致命错误，2 为存在覆盖/队列丢失。

现在默认记录所有可见进程的清单，并对它们采样敏感文件描述符，不依赖 Agent 名称白名单。未识别工具标注为 unclassified_process；已知程序标注为 known_agent_candidate。未知进程持有敏感文件时也会采样 socket 对端并输出风险线索。--agent-bundle 可重复配置应用目录标签，无需重新编译；标签不是身份认证或 Agent 语义证明。

核心实现：[FileMonitor.cpp](FileMonitor.cpp)、[ProcessCache.cpp](ProcessCache.cpp)、[EvidenceStore.cpp](EvidenceStore.cpp)。完整类图、状态机、资源所有权、Schema 和故障语义见 [ARCHITECTURE.md](ARCHITECTURE.md)。测试结果见 [TEST_RESULTS.md](TEST_RESULTS.md)。

真实 Cursor、WorkBuddy AI、Codex、Grok Bot 的进程对照结果，以及未完成的 CLI 动作验收见 [REAL_AGENT_TESTS.md](REAL_AGENT_TESTS.md)。该报告明确区分程序发现、实际工具执行、登录/网络阻塞，不以客户端退出码或 AI 自述代替证据。

FSEvents 不提供修改者 PID，也不监测纯读取。文件变更的 actor_process 必须为空；敏感文件描述符与网络对端共现只提示风险，不能证明数据上传。缓存使用 PID+启动时间防止常见复用误关联，但轮询不能保证观测所有 Agent 或彻底消除竞态。本项目尚未完成长期生产负载与部署验收。

新增实验性 `agent-gateway` 提供显式接入的文件内容交付与发送审计。它以 Unix socket audit token 验证连接方身份，记录来源版本 hash、内容匹配、目的地、传输结果及关联事件。原文、JSON、Base64 和有界 gzip 已测试；跨请求分片和绕过仍漏报。它不是透明 HTTPS 监控，也不会自动接入已安装 Agent。用法、边界、真实会话与故障测试均见最新验收报告。
