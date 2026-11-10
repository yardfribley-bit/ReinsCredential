# macOS Agent Monitor

当前版本已增加持续 Agent 候选发现与文件/网络描述符观测。完整运行方式、测试和能力边界见 [RUNTIME.md](RUNTIME.md)。

C++17 原型：ProcessMonitor、FileMonitor 在 main.cpp，持续进程观测和证据输出在 Runtime.h。

```sh
clang++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -pthread main.cpp -framework CoreServices -o agent-monitor
umask 077
./agent-monitor --log ./evidence.jsonl
./agent-monitor --pid 1234
```

默认监控 ~/.ssh、~/.aws、启动目录的 .env。可传入自定义敏感路径：

```sh
mkdir -p /tmp/agent-monitor-demo
./agent-monitor --sensitive /tmp/agent-monitor-demo
```

另一终端执行 `touch /tmp/agent-monitor-demo/example`，然后修改该文件。Ctrl-C 正常退出。

FSEvents 仅提供变更通知，不提供操作进程 PID、纯读取事件或精确操作时间。因此输出进程为 unknown；不能据此建立文件操作的完整因果链。进程祖先链是查询时的快照，短命进程、退出祖先、权限限制和重设父进程都会造成缺失；argv 读取失败时 argumentsAvailable 为 false。名称匹配仅为筛选，不是身份认证。

队列上限 4096，溢出时警告。FSEvents 丢失事件或根目录变更时提示需要重新扫描，本 MVP 不自动恢复证据。额外处理 renamed 以覆盖部分编辑器原子保存通知。部分目录需要授予启动终端相应的 macOS 隐私访问权限。

本阶段提供轮询式进程发现/消失通知和追加 JSONL 输出，不安装后台服务，不默认写 /var/log。文件与 socket 同时可见仅为风险提示，不能证明数据上传。命令行可能包含敏感信息，--pid 仅用于显式调试。
