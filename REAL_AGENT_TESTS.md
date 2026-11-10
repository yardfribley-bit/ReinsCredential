# 真实 Agent 与未知进程验收

这是早期轮次的历史记录。最新真实调用、内容交付/发送验证、修复前后对照与最终失败项见 [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md)，不要混用各轮的 PID 或进程数量。

日期：2026-11-11。结论为**进程发现通过，真实工具动作验收部分通过**，不能声称所有 Agent 已完成端到端验收。

## 独立基线与发现结果

独立执行 `/bin/ps -axo pid,ppid,comm`，提取目标应用路径可辨识的 PID，再与采集日志中的 PID/启动身份记录对照。ps 中改写了进程标题的 Helper 可能不落入路径筛选，因此这是基线子集，不是所有 Agent 或全部 Helper 的清点。

| 应用 | 路径基线 PID 数 | 日志命中 | 默认分类 |
| --- | ---: | ---: | --- |
| Cursor | 6 | 6 | known_agent_candidate |
| WorkBuddy AI | 15 | 15 | known_agent_candidate |
| Codex 应用后端 | 5 | 5 | known_agent_candidate |
| Grok Bot | 10 | 10 | unclassified_process |

Grok Bot 主进程为 PID 475。本次没有内置 Grok 品牌规则，仍能在通用清单中找到它和基线中的 Helper。若要标注为用户认可的 Agent，可使用 `--agent-bundle 'Grok Bot.app'`；标签不会改变是否执行敏感资源采集。

## 实际动作测试

隔离目录包含合成 synthetic.env、固定 probe 脚本和回环服务端配置。脚本读取合成文件并计算 SHA256，保留文件描述符 12 秒，尝试连接 127.0.0.1，然后写入包含 run_id、PID、PPID 和完成时间的 proof.json。校验脚本未被修改，文件 hash 与原始合成数据一致，并将实际 PID 与日志身份和祖先链核对。

| 调用对象 | 启动进程被观察 | 合成动作证据 | 结论 |
| --- | --- | --- | --- |
| 当前 Codex 会话发起的工具执行 | 是 | proof、敏感 FD、Codex 祖先链、回环收件均有 | 工具执行链验证通过；不是新 CLI 模型会话的验证 |
| 新 Codex CLI 模型调用 | 是 | 未生成 proof | 网络/MCP 初始化超时，120 秒后终止测试会话 |
| Cursor Agent CLI 模型调用 | 是 | 未生成 proof | Authentication required，CLI 未登录 |
| WorkBuddy AI 内置 CLI 模型调用 | 是 | 未生成 proof | CLI 要求登录，并出现代理初始化 TypeError；退出码 0 仍判为未通过动作验收 |

Cursor 与 WorkBuddy 的 GUI 进程已运行，不代表独立 CLI 已登录。本次没有提取 GUI 凭证、改写认证配置、绕过工具审批或强行开启任意执行权限。WorkBuddy 配置/遥测请求经用户额外批准后才继续尝试。需要有效 CLI 登录及可用网络后再做模型驱动复测。

当前 Codex 工具执行的证据示例：

- event_id：`0bff272c-5cf6-4c44-a652-5b008480c79b`
- actor：PID `96305`，启动身份为 `(1794339818, 298612)`。
- 已观察祖先 PID：`96257 → 96254 → 814 → 466`。
- 目标：`<TEST_ROOT>/current_codex_tool/synthetic.env`。
- 回环收件由测试服务端独立确认。此例不证明任何敏感内容上传到模型。

## 不靠名字的资源策略回归

另行启动一个未注册解释器，待其父进程退出并归属 PID 1 后再启动采集器，避免因继承当前 Codex 祖先而被当成已知 Agent。该测试没有任何品牌名称规则，也未开启 include-runtimes。

结果：实际 PID 98095、PPID 1，分类 unclassified_process；采集到合成敏感文件描述符、回环 socket 和共现风险提示。事件 UUID 为 `839a6a1d-09ac-4aa1-a9a0-a9dd039c0573`。这验证未知进程不会被策略过滤，不冒充真实 AI 产品验收。

## 覆盖与证据保存

真实采样期间可见进程为 632–648，查询不可用条目为 307–310，部分轮次有 8 个描述符扫描不完整。健康记录中已完成活动扫描耗时最大采样值为 91ms，这不是所有轮次的性能上限或负载 SLA。raw_queue_dropped、evidence_rejected 和 source_gaps 均为 0，正常关闭退出码为 0。

公开机器可读结果：[real_agents_summary.json](tests/results/real_agents_summary.json)、[unknown_process_summary.json](tests/results/unknown_process_summary.json)。结果保留测试事件 UUID、身份、脱敏目标和私有证据文件 SHA256。整机原始进程/连接日志和客户端原始输出仅存本机临时目录，不上传 GitHub。

复现入口：

```sh
make all agent-unit agent-probe
./agent-unit
/usr/bin/python3 tests/integration.py
/usr/bin/python3 tests/unknown_process.py
# 需相应工具已安装/登录，且用户允许调用真实模型：
/usr/bin/python3 tests/real_agents.py --timeout 120
```

真实调用脚本从现有客户端分发目录运行，不安装或更新客户端。重分析私有执行产物可用 `tests/reconcile_real_agent_evidence.py PRIVATE_WORKSPACE`，不重新调用模型。

12 秒文件句柄是为了验证轮询链路，不能证明短时读取都能检测。FSEvents 不提供读取事件或操作 PID；连接元数据不能证明请求内容。尚未证明“发现所有 Agent”或“检测所有敏感数据外传”。
