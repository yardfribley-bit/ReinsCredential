# Runtime v2

当前版本已拆分为独立编译模块，旧的单文件编译命令不再适用。使用 `make`、`make check` 和 `make integration`。

运行参数与示例见 [README.md](README.md)。架构设计、PPID 链语义、Append-only 的实际保证、队列丢失、关闭时序和覆盖边界见 [ARCHITECTURE.md](ARCHITECTURE.md)。

证据 schema_version 已升级为 2：timestamp 使用 Unix 微秒，actor_process 是带身份及历史父链的对象或 null。消费者应按 schema_version 迁移；不再把字段 detail 中的说明当作可靠文件归因。已有 JSONL 文件只检查末尾换行，不自动迁移或验证历史 schema，建议 v2 使用新的日志路径。

v2 增加可选内容证据字段：destination、content_sha256、correlation_id、evidence_basis、transfer_outcome、related_event_ids。旧事件对应字段为空。只有显式内容网关填写内容匹配依据；被动 FD/socket 事件不会被升级为内容外传确认。内容事件、网络结果及独立收件必须分别解释，详见最新验收报告。
