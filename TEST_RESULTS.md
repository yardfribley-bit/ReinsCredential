# 本机验证结果

本轮在 macOS 上使用 Clang 完成编译与运行验证。

## 编译

主程序、合成进程夹具、单元测试均使用 C++17、`-Wall -Wextra -Wpedantic -Werror` 编译成功，无编译警告。可执行文件分别为 agent-monitor、agent-probe、agent-unit。

## 已通过

- 单元检查：Agent 规则、普通解释器默认排除、解释器可选纳入、提示词中出现包名不触发规则、PID+启动时间身份、JSON 控制字符转义、非法数值拒绝。
- 本地集成：已配置的测试 Agent 发现，sleep 后代归属，持有合成敏感文件，127.0.0.1 TCP 对端，文件/socket 共现风险提示，进程消失通知，FSEvents 通知，stdout 与追加 JSONL 一致，非法 CLI 输入拒绝。
- 真实本机两秒冒烟运行：发现 Cursor、Codex 和部分后代，观察到 socket 对端。该次快照有 638 个可见进程、307 个不可查询条目、48 个候选；这些数字是一次采样结果，不代表机器上 Agent 的准确数量。

集成测试终端结果：

```text
PASS: discovery, descendant, sensitive FD, socket peer, risk signal, disappearance, FSEvents, JSON append output
PASS: invalid CLI inputs rejected
```

## 测试环境与限制

普通工具沙箱中 FSEvents 启动失败，PID 1 查询受限；原生运行测试在获准的沙箱外执行。测试仅使用临时合成文件和本地回环连接，不访问真实凭证、不发起外网传输。

初次短存活夹具暴露全机查询 argv 导致扫描过慢的问题；修复为只对解释器查询 argv，并记录 scan_duration_ms，重新运行集成测试通过。

未验证 Intel 实机、后台 launchd 部署、长期负载、压力下事件丢失率、任意未知 Agent 覆盖率、敏感数据实际上传检测或阻断。这些不属于当前测试通过的结论。
