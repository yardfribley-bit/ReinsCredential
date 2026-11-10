# 持续 Agent 候选监测

## 编译运行

```sh
clang++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -pthread main.cpp -framework CoreServices -o agent-monitor
umask 077
./agent-monitor --log ./evidence.jsonl
./agent-monitor --duration 30 --interval-ms 200
./agent-monitor --match my-agent --sensitive /path/to/secrets
./agent-monitor --include-runtimes
./agent-monitor --pid 1234
```

默认每 500ms 扫描全机可见进程。启发式匹配常见 Agent 名称、应用安装路径、Node 包入口和 Python 模块，再追踪可见的后代。`--match` 是额外可执行 basename 的精确不区分大小写匹配，可重复。`--include-runtimes` 会把 Node/Bun/Python 列为候选，显著增加误报；它们默认不被当成 Agent。

间隔指扫描完成后的等待时间，不保证 500ms 内完成一轮；`coverage.scan_duration_ms` 提供实际扫描耗时。只为通用解释器读取 argv 来识别包入口，其他进程仅查询必要元数据。

默认敏感路径为 ~/.ssh、~/.aws 和启动目录/.env；`--sensitive` 可重复增加路径。不会读取文件内容。正常日志不输出命令行；显式 `--pid` 调试会输出 argv，其中可能有敏感内容。

## 证据含义

- `agent_discovered`：启发式候选及匹配原因、PID/PPID、可执行路径、PID+启动时间身份和已观察的根进程身份。
- `sensitive_file_open:`：轮询看到敏感文件描述符，不证明执行过读取或写入。
- `socket_peer:`：轮询看到 IPv4/IPv6 TCP/UDP 对端，包括本地地址，不证明上传。不解析 TLS、域名或请求内容；未连接 UDP sendto 和短命连接可能遗漏。
- `risk_signal:file_and_socket_coobserved;upload_unproven`：同次扫描出现文件描述符和 socket，仅为风险线索。
- `filesystem_change`：FSEvents 创建、修改、重命名通知，actor_pid 为 null，时间是观测时间。不能监测纯读取，不能给出修改者 PID。
- `agent_no_longer_observed`：退出或可见性丢失，不证明一定退出。
- `coverage`：可见进程数、查询失败数、候选数和枚举可能截断情况。

JSONL 同时写 stdout 和可选追加文件，由后台有界队列隔离输出。日志不是防篡改存储；请使用用户控制的目录和 `umask 077`，日志包含路径与网络对端。SIGINT/SIGTERM 排空队列。队列满或 FSEvents 丢失/根目录变化时 stderr 警告；不会自动重扫恢复证据。

## 覆盖边界

用户态无法保证发现所有 Agent。隐藏/改名/自定义 Agent、两次轮询之间结束的进程、启动前已脱离祖先的进程、exec 细节、权限不可见进程和共享应用进程内部会话都可能遗漏。名称和路径可伪造，不是身份认证。已观察后代在祖先进程退出后保持归属。使用 PID+启动时间防常见 PID 复用，并在 FD 扫描前后校验；逐进程查询仍不是原子快照。

FSEvents 使用串行 dispatch 队列，监控缺失路径的已存在祖先后进行路径过滤。未安装系统服务、未调整隐私权限、未实现阻断。完整生命周期/文件观测需评估 Endpoint Security 的授权条件；敏感数据上传判断需工具集成或受控请求出口的内容检查。

## 本地测试

```sh
clang++ -std=c++17 -Wall -Wextra -Wpedantic -Werror tests/fixture.cpp -o agent-probe
python3 tests/integration.py
clang++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -pthread tests/unit.cpp -framework CoreServices -o agent-unit
./agent-unit
```

测试只创建合成临时文件和 loopback TCP 连接，检查发现、子进程归属、FD、对端、风险提示、消失、FSEvents、JSONL 一致性和参数错误，不访问真实凭证或外部服务器。

Apple 参考：[libproc](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.h)、[FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events)。
