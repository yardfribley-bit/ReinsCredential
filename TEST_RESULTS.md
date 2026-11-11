# v2 重构验证结果

## 2026-11-11 所属 Agent、完整父链与短时打开

本轮在原有模块结果之上增加所属 Agent、`observed_chain_to_launchd` 和短时打开采样。上传检测没有实现，也不在本轮声称之内。确定性单元测试覆盖合成树：ChatGPT.app → codex → zsh → 未进入慢扫描快照的 python，句子为 `Codex read /synthetic/secret via zsh -> python. The file was open in that process. This is not an upload finding.` 采集器自身不是 Agent，AgentReins 保持未分类。

macOS 上的召回和 CPU/RSS 以 `make integration` 里的 `tests/short_read.py` 输出的 `SHORT_READ` 一行为准，并记在 [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md) 第 0 节。下面的历史 PASS 不是这组短时打开的召回率。

## 历史模块结果

本文件保留基础模块重构轮次的结果。后续内容审计、最终行为矩阵和逐功能验收以 [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md) 为准；其中完整验收失败，不应与本文件的基础模块 PASS 混为一谈。

2026-11-11，在本机 macOS 使用 Clang 验证。

## 本次重构解决的问题

| 问题 | 实现与验证边界 |
| --- | --- |
| PID 复用导致旧记录关联到新进程 | 身份键采用 PID+启动时间，历史父链绑定到身份；前后校验失败则拒绝活动归因。轮询仍不等于内核原子事件。 |
| 高频回调同步查询/写入 | 回调只复制固定大小事件到预分配 SPSC 环形队列，后台线程处理。队列满有显式损失计数。 |
| 资源与关闭竞态 | CF/FSEvents/dispatch/FD 采用 RAII；先停源并排空回调，再排空消费者和落盘线程。 |
| 纯文本日志难以关联，写入失败不可见 | Schema v2、UUID、微秒观测时间、身份父链、单写入线程追加、fsync、短写与故障传播。 |
| 采集器日志触发自身监控形成反馈 | IgnoreSelf 排除采集器自身变更；集成测试将日志置于受监控目录验证。 |

仍不能确定 FSEvents 文件修改者、保证发现所有 Agent、证明敏感文件已经读取或上传。

## 编译

- 主程序及单元测试：C++17，`-Wall -Wextra -Wpedantic -Werror -pthread`，编译成功，无警告。
- arm64+x86_64 通用二进制交叉编译成功。此项只验证编译/链接，不代表 Intel 实机验证。
- 独立构建 AddressSanitizer + UndefinedBehaviorSanitizer 版本进行运行验证。

## 确定性单元测试

- 同 PID 不同启动身份的替换、旧身份保留、历史父链接不重绑。
- 不可变旧快照、并发发布/读取、可见性丢失状态、失败快照不发布。
- 描述符扫描期间注入 PID 复用，拒绝该次活动归因。
- 缺失祖先与历史淘汰显式标记不完整。
- 环形队列满载、回绕，以及 200000 条并发事件顺序。
- 4 个并发生产者追加 200 条记录，排空后重启追加，总行数/UUID 唯一性。
- 0600 权限、排他写锁、符号链接拒绝、不完整尾行拒绝且不截断。
- JSON 控制字符与非法 UTF-8 处理，原始目标路径字节保留。
- 子进程内设置文件大小限制，确定性触发短写后 EFBIG，验证异步写入错误由 Close 传播，破损尾部不自动修复。
- 名称/入口分类、提示词误报排除、解释器 opt-in、目录边界。

正常构建与 ASan/UBSan 构建的上述测试通过。

后续新增全机未知进程策略：默认清点所有可见进程，以四路有界并发检查敏感文件，已知名称仅用于标签。新增确定性测试证明未注册名称仍会生成 process_discovered 和敏感文件/连接风险记录；新增原生测试将未注册解释器先归属 PID 1 再启动采集器，验证不依赖已知 Agent 祖先或 include-runtimes。具体结果见 [REAL_AGENT_TESTS.md](REAL_AGENT_TESTS.md) 和 tests/results/unknown_process_summary.json。

## 原生集成测试

合成 Agent 仅持有临时文件并建立 127.0.0.1 TCP 连接，派生 sleep 子进程。测试通过：

- 候选发现、带启动身份的父链、敏感 FD、socket 对端与共现风险提示。
- 进程不再可见通知。
- FSEvents 文件变更记录的 actor_process 为空，目标路径为绝对路径。
- 日志位于受监控目录内时 IgnoreSelf 避免自身追加反馈。
- Schema v2、UUID、微秒时间戳、单写入顺序、0600 文件权限。
- 正常定时退出及 SIGTERM 的排空关闭摘要，重启追加且不截断旧内容。
- 非法 CLI 参数拒绝。

ASan/UBSan 版本执行上述集成测试成功，未报告 AddressSanitizer 或 UndefinedBehaviorSanitizer 错误。普通工具沙箱无法启动 FSEvents，原生集成测试经批准在沙箱外执行；不读取真实凭证，不向外部服务发送测试数据。

## 复现与终端结果

常规构建及测试：

```sh
make all agent-unit agent-probe
./agent-unit
/usr/bin/python3 tests/integration.py
```

检测器构建对主程序和单元测试均使用 `-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`；集成测试可通过 `AGENT_MONITOR_BINARY=/绝对路径/检测器版主程序` 选择该构建。

本次终端成功输出：

```text
PASS: PID reuse, immutable snapshots, retained parent identity, visibility loss, failed samples, mid-scan reuse, missing lineage, bounded history
PASS: bounded overflow, wraparound, concurrent ordering of 200000 ring events
PASS: concurrent append, drain/reopen, UUID uniqueness, 0600 permissions, writer lock, symlink refusal, partial-tail refusal, JSON escaping, short-write failure propagation
PASS: classification, prompt false-positive exclusion, runtime opt-in, directory boundary
PASS: discovery, parent identities, sensitive FD, socket peer, risk signal, disappearance, FSEvents, UUID/schema, ordered append, drain, restart
PASS: invalid CLI inputs rejected
```

编译与上述测试进程退出码均为 0。`lipo -archs` 对通用构建输出 `x86_64 arm64`。

## 未验证

未运行 ThreadSanitizer、Intel 实机、长时间负载/压力测试、掉电故障测试、磁盘耗尽/断连矩阵、launchd 部署验收、自动轮转或防篡改验证。测试通过不等于证明完全无竞态、无泄漏、完整捕获所有 Agent 或能够检测真实数据上传。

真实应用已进行独立 ps 基线核对与调用尝试：进程发现通过，但新 Cursor/WorkBuddy CLI 因登录问题、WorkBuddy 代理错误和新 Codex CLI 网络/MCP 超时未完成模型驱动动作验收。当前 Codex 会话的工具执行链验证通过。不得将这些部分成功结果描述为三个新 CLI 的端到端全部通过；详见真实 Agent 报告。
