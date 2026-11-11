# SwiftUI 第一阶段测试报告

测试日期：2026-11-11（Asia/Shanghai）。范围：客户端模型、C++ 日志适配、JSONL 导入、界面状态、原生窗口渲染及应用构建。

## 环境与结论

- 本机 macOS 26.5.2（25F84），实际测试进程架构 x86_64。
- Apple Swift 6.3.2，Xcode 工具链，Package 使用 Swift tools 5.9，应用最低部署目标 macOS 13。
- XCTest：**26 项通过，0 失败，0 跳过**。最终模型/状态测试运行于 13:20:56。
- Debug 客户端编译通过；Release `x86_64 + arm64` 通用应用构建通过。
- `lipo -archs` 返回 `x86_64 arm64`；本地 ad-hoc 签名与 `Info.plist` 校验通过。
- 未在 Apple Silicon 或 macOS 13 真机运行；双架构编译不能替代双架构运行测试。

## 测试输入与复现

所有输入均为合成进程、路径和目的地。未读取个人敏感文件、未调用真实 Agent、未上传测试内容。

常规命令：

```sh
macOSClient/scripts/check.sh
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64
```

此次首次完整检查使用 `--scratch-path /private/tmp/reins-native-build`。还额外从已发布提交 `ec742a46ad3b541e7a1c315f7971a44902223e52` 提取 `EvidenceStore.cpp/.h`、`Types.h`、`SystemResources.h`，编译同一 `Tests/Interop/emit_evidence.cpp`，将输出通过 `REINS_BACKEND_FIXTURE` 传给 Swift 测试；26 项再次通过。这验证客户端不依赖工作区尚未提交的 C++ 审计改动。

测试位于 `Tests/EvidenceCoreTests/` 和 `Tests/DashboardAppTests/`。直接运行 `swift test`、未设置互操作样本时，`testCppSerializerFixture` 会明确跳过；因此验收使用 `scripts/check.sh`。

## 模型与后端互操作：9/9

| 测试方法（EvidenceModelTests） | 断言 | 结果 |
| --- | --- | --- |
| `testCanonicalRoundTripPreservesEveryFieldAndProcessUUID` | 全字段 Codable 往返、保存 ProcessNode UUID、中文/路径转义、大写风险编码 | PASS |
| `testBackendRiskCasingAndMicrosecondTimestamp` | 三种 C++ 风险值、Unix 微秒换算，测试时间误差不超过 1 微秒 | PASS |
| `testBackendTreeIsActorFirstWithNearestParentFirst` | actor→父→祖先顺序、PID/PPID、可执行路径、世代及完整性标志 | PASS |
| `testBackendIdentityStableAcrossEventsAndDistinctAfterPIDReuse` | 同一 PID/启动时间保持显示 UUID；复用 PID 后 UUID 改变 | PASS |
| `testPassiveEventsNeverInventReadWriteOrActor` | 空 actor 不补造进程；FSEvents、FD、未知类型不推断读取/写入 | PASS |
| `testGatewayActionsPreserveEvidenceStrength` | 内容通道动作映射；保留失败结果、目的地和证据来源 | PASS |
| `testInvalidBackendIdentityAndMetadataAreRejected` | 不支持的 Schema、错误时间单位、负数/小数/越界时间、未知风险、非法 UUID 拒绝 | PASS |
| `testInvalidCanonicalProcessUUIDIsRejected` | 不接受损坏的已保存 ProcessNode UUID | PASS |
| `testCppSerializerFixture` | 实际 C++ `ToJson` 的有 actor/无 actor 两条记录解码；路径引号/换行保真 | PASS |

`Date` 是浮点时间。上述微秒误差断言针对明确的现代时间样本，不代表所有年份均精确保留每个微秒。界面详情显示毫秒。

## JSONL 输入：10/10

| 测试方法（EvidenceLogReaderTests） | 断言 | 结果 |
| --- | --- | --- |
| `testAsyncReadImportsRegularFileWithoutModifyingIt` | 异步读取普通文件，输入字节保持不变 | PASS |
| `testCancelledEmptyReadStillThrowsCancellation` | 空文件也遵守取消 | PASS |
| `testCancelledReadDoesNotReturnPartialImport` | 取消读取不得作为成功快照返回 | PASS |
| `testDirectoryAndRemoteURLAreRejected` | 拒绝目录、远程 URL | PASS |
| `testEmptyInputAndIncompleteOnlyInput` | 区分空日志和仅有未完成尾行 | PASS |
| `testEqualTimestampSortingIsDeterministicByEventUUID` | 相同时间按事件 UUID 稳定排序 | PASS |
| `testFIFOIsRejectedWithoutWaitingForWriter` | FIFO 无写者时立即拒绝，不挂起读取 | PASS |
| `testImportLimitsRejectExcessiveSizeAndLineCount` | 32 MiB 文件与 100,000 行上限 | PASS |
| `testJSONLRejectsInvalidDuplicateAndOversizedRowsWithoutLosingGoodRows` | 损坏/重复/超大行报告行号，保留有效记录 | PASS |
| `testUnterminatedTailIsNotAcceptedEvenWhenItContainsValidJSON` | 没有换行提交标记的尾行不作为完整证据展示 | PASS |

## 界面状态：7/7

| 测试方法（DashboardStoreTests） | 断言 | 结果 |
| --- | --- | --- |
| `testRiskFiltersSearchAndSelectionUseImportedEvidence` | 三档风险、PID/路径/进程/目的地搜索、无结果清空选择 | PASS |
| `testSuccessfulImportReplacesDemoAndResetsFilters` | 导入替换演示数据，重置搜索、风险及选择 | PASS |
| `testPartialImportRetainsWarningsAndShowSamplesClearsThem` | 部分有效日志展示损坏行/尾行提示；切换演示清除旧状态 | PASS |
| `testMalformedOnlyImportPreservesPreviousDataset` | 全损坏文件报错并保留上次快照 | PASS |
| `testMissingFileImportPreservesPreviousDataset` | 文件不存在时保留上次快照 | PASS |
| `testPermissionFailurePreservesPreviousDataset` | 真实 chmod 000 权限拒绝；非 root 运行，无跳过 | PASS |
| `testEmptyValidLogIsImportedAsEmptySnapshot` | 合法空文件进入明确的空快照状态 | PASS |

这些是状态与文件导入测试，不是模拟鼠标点击系统文件选择器。

## Schema 2 契约校验

使用本机已有的 Python `jsonschema` 的 `Draft202012Validator`，未安装依赖：

| 校验 | 结果 |
| --- | --- |
| JSON Schema 自身符合元 Schema | PASS |
| 实际 C++ 序列化的两条合成记录 | 2/2 PASS |
| 逐个删除全部 23 个必填顶层字段 | 23/23 被拒绝 |
| 11 个错误类型/范围/枚举样本 | 11/11 被拒绝 |
| 嵌套扩展字段兼容性 | PASS |

Schema 校验只证明结构符合契约，不证明内容可信、事件真实或因果关系成立。Schema 复现说明见 `../schemas/README.md`。

## 原生界面渲染与范围

Debug `--smoke-test` 探针对本应用合成数据窗口分别设置浅色和暗色，按自身 window ID 捕获 PNG，检查 JSON 结果并逐张查看。早期 `NSView.cacheDisplay` 截图漏掉了系统材质侧栏，已改为完整窗口捕获；未使用该不完整截图作为通过证据。

渲染结果：**PASS（浅色、暗色各一张，2448 × 1634）**。实际附件：[浅色窗口](Documentation/dashboard-light.png)、[暗色窗口](Documentation/dashboard-dark.png)、[探针结果](Documentation/ui-smoke.json)。已核对原生工具栏/侧栏、演示标识、风险文本、表格列、详情和进程链首项，以及主题切换后的文字可读性。材质层下增加系统窗口底色，并修复选中行风险标签的颜色，以保证暗色与选择状态下可读。进程链容器为 ScrollView，滚动交互未做自动化验收。捕获只针对自身窗口，没有整屏回退。

尚未执行完整的 UI 点击自动化、VoiceOver、系统「减少透明度」、多屏/极端缩放以及长时间运行验收。当前是第一阶段证据浏览器，未实现实时守护进程连接。此报告不改变后端完整读取/外传验收仍有漏报的结论，也不包含尚未完成的后端审计修复验收。
