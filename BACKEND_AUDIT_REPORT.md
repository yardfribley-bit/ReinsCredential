# 后端整改与产品接口验收 — 2026-11-11

本次完成了进程历史身份、异步证据持久化、结构化风险提示和日志轮转接口的整改。**组件与常规原生集成通过；立即停止前的文件变更完整交付验收未通过。** 此报告没有将已知失败改为通过，也没有改变历史 [完整行为验收](ACCEPTANCE_REPORT.md) 的结论。无 ESF 采样仍不能保证发现所有 Agent 的短暂读取或证明任意 HTTPS 上传。

## 实际测试环境

- macOS 26.5.2，build 25F84，Darwin 25.5.0；执行架构 x86_64。
- Apple Clang 21.0.0，`-std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Werror -pthread`。
- 本报告的原生进程/FSEvents/Unix socket/回环 HTTP 测试在开发沙箱外执行，只使用合成文件和本机接收端。未调用真实 Agent、未上传真实敏感内容、未测试公网发送。
- ASan/UBSan 使用 `-O1 -fsanitize=address,undefined -fno-omit-frame-pointer` 和 `ASAN_OPTIONS=detect_leaks=0`。macOS 上本轮没有 LSan 验证；不得把通过 ASan 写成“已证明无泄漏”。

## 每个整改点和验证结果

| 功能点 | 已确认的缺陷/风险 | 实现与测试证据 | 结果 |
|---|---|---|---|
| PID 世代身份 | 只用 PID 会把已退出进程拼接到新实例 | 保持 PID+启动秒/微秒身份，元数据和 FD 采样前后校验。原有单元测试覆盖 PID 重用、采样中重用、历史淘汰及可见性丢失 | 通过 |
| 同世代 exec 历史 | 父进程后来 exec 为 Cursor 会把原本普通子进程追溯成 Cursor；exec 离开后标签残留 | 父边绑定时保存不可变的进程镜像/祖先观察；从当前镜像和冻结祖先重新分类。覆盖 PID 排序反转、父 exec 进入/离开、解释器入口变化、迟到祖先、循环与深链 | 新增 2 组通过 |
| 去重与入队失败 | Full 时仍推进去重状态，导致后续持续活动永久不再上报 | 只有 Accepted 才推进发现/镜像/活动去重；消失事件最多重试 8 次、最多 1024 个待重试身份，耗尽累计进健康记录 | 新增 1 组通过 |
| 精确资源提示 | 共现提示未直接携带对应文件和对端 | 新类型 `sensitive_network_cooccurrence` 携带同次验证后的 FD 样本中的文件和对端；每进程每轮最多 32 对，超出计数累计。包括无已知品牌标签的进程 | 新增 1 组通过；原生集成也核对文件和对端 |
| 共现误报边界 | 文件打开或套接字单独出现不能推导上传 | 文件单独、网络单独、身份验证失败均不生成新共现事件；重复扫描去重，Full 后重试，PID 新世代重新报告 | 通过；事件保持 Medium 和 `upload_unproven` |
| 回调与有界队列 | 高频事件、超长路径、OS 丢失/挂载变化可能静默缺失 | 实际生产回调注入测试：1023 槽满后准确丢弃 2 条，排空后恢复；PATH_MAX−1 保留，PATH_MAX 拒绝；七种 gap/topology 标志，包括 mount/unmount | 新增 3 组通过 |
| RAII 与错误清理 | CF/dispatch/stream 的异常路径需要一致释放 | owned 句柄均使用 unique_ptr+deleter；回调参数为借用指针。构造 CFArray 后的文件系统异常能清理，失败实例不能重启，Stop 可重复；异步落盘仍保留缺失 actor | 新增 2 组通过；未注入 OS Start 失败/部分线程创建失败 |
| 异步证据内存预算 | 仅按条数有界仍可保留大量未序列化参数 | 队列只持有已编码字段，默认每条 ≤1 MiB、待写编码字节合计 ≤16 MiB；预算包含 writer 手上尚未完成的条目。16 MiB 不输出的 argv 不保留在队列中 | 通过；预算是编码载荷，不是整个进程 RSS 上限 |
| 持久化确认 | 入队成功不能当作落盘成功 | 新 `SubmitDurable` 等待该记录 write+fsync，普通 `SubmitCritical` 仍只保证入队。64 次并发 durable 请求逐条核对独立 FD 可读记录/UUID；关闭可顺序重复 | 通过 |
| 写入/同步故障 | 发内容后才得知证据未持久化 | 测试二进制中注入真实 fsync EIO，另用子进程 RLIMIT_FSIZE 产生短写 EFBIG；两种故障都传回 durable 调用并阻止后续副作用。持久化组共 5 组 | 通过 |
| 内容网关失败关闭 | `/read` 和 `/submit` 原先可能先传内容再发现审计失败 | 敏感内容交付/外发前等待 admission 记录 durable 确认。独立本机服务器核对到达时 admission 已可读；两种短写路径均退出 1、上游收到 0 次、客户端未收到敏感正文 | 3 个独立场景通过 |
| 网关既有安全行为 | 新持久化路径可能影响并发、截止和错误处理 | 过期关联不补造、8 并发、503、302 不跟随、不完整 body 截止、服务恢复、已存在路径保护、敏感源 symlink 拒绝 | 8 个场景通过 |
| 日志轮转接口 | 持续运行的单文件会无限增长 | `--max-log-bytes N` 检查已打开 inode 的大小；达到阈值排空并退出 3，由客户端负责封存/重启。已有超限日志不截断；拒绝 0、负数、非法及溢出输入 | 6 个场景通过 |
| 关闭时队列排空 | 已交付的回调需要先排空再释放上下文 | 请求 FlushSync，再 stop/invalidate/dispatch barrier，最后排空消费者和 writer；常规集成验证 SIGTERM、追加重启和最后 shutdown_summary | 通过 |
| 立即停止前的文件交付 | 独立进程 write/fsync/close 完成不代表监控已经收到该变更 | 原生子进程经管道确认写完，主进程立即 Stop：**6/6 次目标文件事件缺失**。相同操作等待 500 ms 的诊断对照：6/6 捕获 | **严格能力验收失败，未修复成无损边界** |

## 新的产品接口

`agent-monitor --log PATH --max-log-bytes 33554432 --interval-ms 250 --sensitive PATH`

- 退出 0：正常结束且本轮未记录所计量的队列/gap 丢失，不代表系统活动完整覆盖。
- 退出 1：启动、查询、写入、同步等致命错误；stderr 为结构化 `fatal_error`。
- 退出 2：正常排空，但记录了覆盖损失或重试耗尽。
- 退出 3：要求轮转；优先于退出 2，客户端仍需读取 `shutdown_summary.count` 和各项损失计数。后端不会 rename/delete/truncate 日志。

阈值每 250 ms 在主线程扫描之间检查，不是硬文件上限。一轮正在进行的扫描、已接收队列和关闭汇总都可能造成超量。本次 2048 字节测试最终约 803 KiB；不能以此机制承诺“文件绝不超过配置大小”。最后汇总的 `log_bytes` 是提交汇总时的观测值，不是排空后最终大小。

健康记录新增整数指标：`retirement_pending`、累计 `retirement_retry_exhausted`、累计 `cooccurrence_pairs_truncated`、`log_bytes`、`log_limit_bytes`、`log_rotation_required`。`shutdown_flush_not_filesystem_barrier=1` 明确说明关闭不能当作所有此前文件操作的完整交付屏障。历史 `source_gaps` 是 OS 已报告的缺口；它为 0 也不能证明没有尚未交付的事件。

结构化共现记录的字段契约：

```json
{
  "type": "sensitive_network_cooccurrence",
  "risk_level": "Medium",
  "target_resource": "/absolute/synthetic.env",
  "destination": "127.0.0.1:1234/protocol=6",
  "attribution": "identity_validated_descriptor_snapshot",
  "evidence_basis": "same_identity_descriptor_snapshot",
  "detail": "Sensitive file descriptor and socket peer observed in the same sample; upload_unproven",
  "content_sha256": "",
  "transfer_outcome": ""
}
```

该片段是字段示意，完整记录包含 schema/session/sequence/UUID/时间和经验证的 `actor_process`。destination 是已观察的套接字对端，不证明它实际接收了该文件的内容。原来的低级 FD/peer 和 generic 风险观察仍保留以兼容历史分析。

## 复现命令与计数

```sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin make -j2 all check agent-probe agent-shutdown-probe
PATH=/usr/bin:/bin:/usr/sbin:/sbin make audit-native integration
AGENTSEC_REPORT=tests/results/gateway_security_audit.json /usr/bin/python3 tests/gateway_security.py
make shutdown-probe                  # 本次退出非零，6/6 缺失，必须保留失败
./agent-shutdown-probe 500            # 诊断对照，本次 6/6 通过；不是生产修复
```

`make check`：原有 6 组 + 新增 14 组，全部通过；native integration 2 组通过；rotation 6 场景通过；gateway durability 3 场景通过；gateway security 8 场景通过。新增 14 组在 ASan/UBSan 下再运行全部通过。这里的“组”和“场景”不是同一计量单位，没有合并为虚假的单一覆盖率。

ASan/UBSan 分别编译 `tests/process_generations.cpp`、`tests/callback_unit.cpp` 与全部 CORE，以及 `tests/store_durability.cpp` 与 `EvidenceStore.cpp`，随后以 `ASAN_OPTIONS=detect_leaks=0` 执行。11 月 12 日产品集成阶段又复跑组件、原生集成及严格停止探针，结果见 [复跑摘要](macOSClient/tests-results/component-summary.json)、[轮转](tests/results/rotation.json)、[持久化网关](tests/results/gateway_durability.json)、[网关回归](tests/results/gateway_security_audit.json)。公开结果只保留合成测试元数据及私有日志摘要哈希，不包含整机进程清单。

## 尚未证明的范围

未执行 arm64 原生运行、长时间 soak/高真实工作负载、断电/内核崩溃、F_FULLFSYNC 硬盘缓存保障、日志所有者/root 篡改防护或法律证据认定。远端接收与本地结果日志仍不是原子事务；admission durable 不代表远端完成。全系统纯读取、短暂 FD、未知 Agent 的语义身份、任意 TLS/分片/编码绕过都没有因本轮整改自动获得覆盖。测试通过只支撑表格中的具体行为。
