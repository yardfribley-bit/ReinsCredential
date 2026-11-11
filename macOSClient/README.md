# ReinsCredential · macOS 本机监控客户端

SwiftUI 客户端：可安装 App、当前用户后台采集、实时风险筛选、搜索、证据详情、进程链、监控范围配置、自检和本地 JSONL 导入。最低部署目标为 macOS 13；跟随系统浅色/暗色外观，侧栏和详情采用 `.ultraThinMaterial`。

启动时显示真实实时数据，未启动服务时为空。完整 App 注册用户后台服务，自动采集；本机 ad-hoc 版采用用户 LaunchAgent，正式签名构建使用 SMAppService。界面以有界增量方式读取私有 JSONL。导入快照、合成演示和实时模式互相隔离。用户态采样可能漏过短暂活动，共现不证明内容上传。

[安装与卸载](INSTALL.md) · [本次逐功能测试报告](PRODUCT_TEST_REPORT.md)。

实际运行截图（合成数据）：[浅色](Documentation/dashboard-light.png) · [暗色](Documentation/dashboard-dark.png)。

## 构建与运行

需要 Xcode 或兼容的 macOS Swift 工具链，无第三方 Swift 包依赖。

```sh
# 在仓库根目录运行；C++ 后端可独立构建
swift run --package-path macOSClient ReinsDashboard

# 生成可双击的本地 .app
macOSClient/scripts/build-app.sh
open macOSClient/dist/ReinsCredential.app

# 同时编译 Apple Silicon 与 Intel
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64

# 63 项测试，含真实 C++ ToJson → Swift 解码
macOSClient/scripts/check.sh
macOSClient/scripts/package-local.sh
macOSClient/scripts/install-local.sh
```

`dist/ReinsCredential.app` 与本地 DMG 使用 ad-hoc 签名，未做 Developer ID 签名/公证。构建产物不提交 Git。`swift run` / Xcode 直接运行可开发界面，但只有完整 App 包包含后台注册所需 plist 和二进制。

使用工具栏「导入日志」或 `⌘O` 选择 C++ 监控器产生的 JSONL 文件。导入只读，不修改证据、不启动采集、不发送网络请求。文件权限仍由系统控制，客户端不会提升权限读取 `/var/log`。

## 模块与数据契约

```text
ReinsDashboardApp
  ├─ RuntimeController → 用户 LaunchAgent / SMAppService → ReinsRuntime → agent-monitor
  │     ├─ RuntimeCore: 私有配置、状态心跳、单实例锁、归档
  │     └─ LiveEvidenceReader: 增量 JSONL → 独立采集健康 + 实时记录
  └─ DashboardStore → DashboardView / EvidenceDetailView
        └─ EvidenceLogReader: 只读快照导入 → EvidenceCore 模型
```

模型实现：[Models/Evidence.swift](Sources/EvidenceCore/Models/Evidence.swift)。保留请求的 `ProcessNode`、`RiskLevel`、`EvidenceRecord` 基础字段，并扩展可选世代信息与证据语义。

| 客户端字段 | C++ Schema 2 来源 / 语义 |
| --- | --- |
| `id: UUID` | `event_id`，非法 UUID 拒绝导入 |
| `timestamp: Date` | `timestamp` + `timestamp_unit=unix_microseconds`，换算为 Unix 秒；详情按毫秒显示 |
| `riskLevel` | 接受 `High/Medium/Low` 与大写；客户端编码使用 `HIGH/MEDIUM/LOW` |
| `targetResource` | `target_resource` |
| `processTree` | `actor_process.process`，再接 `ppid_tree`，行为进程在前、最近父进程其次 |
| `ProcessNode.path` | `executable`；后端节点 UUID 由 PID + 两个启动时间字段稳定派生 |
| `actionType` | FSEvents 为 `CHANGE`，FD/进程观测为 `OBSERVE`；内容通道分别保留 `DELIVER/SUBMIT/TRANSFER` |
| 关联字段 | 保留 `sourceType`、`attribution`、`destination`、`chainComplete`、`evidenceBasis`、`transferOutcome`、`classification` |
| 健康字段 | 保留 `metrics`、`count`、`sessionID`；采集心跳必须晚于本轮 monitor 启动且足够新鲜 |

`ProcessNode` 显式解码保存的 UUID，避免 `let id = UUID()` 配合合成 Codable 时每次解码丢失原 ID。没有身份的 FSEvents 记录显示「未归因」，不会补造进程。PID + 启动时间的 UUID 只用于稳定显示，不是身份认证。

客户端 `JSONEncoder` 输出 camelCase 格式；默认 `Date` 编码遵循 Foundation 的参考纪元策略。后端 snake_case Schema 2 是另一份输入契约，不应把客户端编码结果回写为后端原始证据。权威后端格式见 [schema](../schemas/evidence-v2.schema.json)。

## 导入边界与失败行为

- 每次读取打开时的文件长度，后台处理，最多 32 MiB、100,000 行、单行 1 MiB。
- 只接受普通本地文件；以非阻塞方式打开后检查类型，拒绝 FIFO、目录和远程 URL。
- 只接受换行结束的记录；未完成尾行忽略并显示提示。
- 损坏/超大/未知 Schema/重复事件 ID 的完整行被跳过，显示行号；重复 ID 保留首次出现记录。
- 全部记录无效、读取失败或权限拒绝时，保留之前的数据并报错。有效空日志可显示空状态。
- 风险筛选、PID/进程/路径/目的地搜索和选择状态仅作用于当前快照。

## 验证与 AI 协作入口

当前逐项结果见 [PRODUCT_TEST_REPORT.md](PRODUCT_TEST_REPORT.md)，旧快照版本保留在 [TEST_REPORT.md](TEST_REPORT.md)。`scripts/check.sh` 编译 C++ 合成样例生成器并传入测试；单独 `swift test` 时 C++ 互操作项会明确跳过。`scripts/runtime-check.py` 验证隔离后台服务，只有本机合成文件/回环连接。

Debug 版包含只针对本应用合成窗口的渲染探针：

```sh
swift build --package-path macOSClient
macOSClient/.build/debug/ReinsDashboard --smoke-test /tmp/reins-dashboard-smoke
```

探针不属于 Release 构建，也不替代真实鼠标/键盘交互或 VoiceOver 验收。

维护入口为仓库根目录 [AGENTS.md](../AGENTS.md)：先查模块地图、证据边界、契约和验证命令，再进行局部修改。界面结构参考 Apple 的 [macOS 设计指南](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos/) 与 [NavigationSplitView](https://developer.apple.com/documentation/swiftui/navigationsplitview)。
