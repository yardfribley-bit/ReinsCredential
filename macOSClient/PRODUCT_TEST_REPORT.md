# 本机可安装版逐功能验收 — 2026-11-12

本轮目标是用户选择的“无 ESF、接受采样覆盖限制、先完成本机可安装版”。已实现完整 App、后台采集、实时证据、目录配置、独立健康检查、合成自检、停止/卸载入口和 DMG。**实际安装后的合成检测通过；完整任意 Agent 读取/外传验收仍未通过。** 不把文件描述符与 socket 共现当作已证明上传。

## 环境与可复核材料

- macOS 26.5.2 / 25F84；本轮执行架构 x86_64，Swift 6.3.2 / Apple Clang 21，部署目标 macOS 13。
- Dashboard、Runtime、agent-monitor 三个发行二进制均含 arm64 与 x86_64。arm64 仅编译验证，没有宣称实际执行通过。
- App 安装至当前用户 `~/Applications/ReinsCredential.app`，本地 ad-hoc 签名；签名完整性校验通过，不等同于 Developer ID、Apple 公证或 Gatekeeper 互联网发行验收。
- [组件摘要](tests-results/component-summary.json)、[后台集成 14 项](tests-results/runtime.json)、[实际安装与合成证据](tests-results/installed-product.json)、[停用检查](tests-results/installed-stop.json)、[安装包检查](tests-results/package.json)。只公开合成证据子集和摘要，不公开个人原始进程清单或环境变量。
- 首次启动空白界面：[浅色](Documentation/onboarding-light.png) / [暗色](Documentation/onboarding-dark.png)。截图探针不注册服务；真实安装检测依据独立安装报告。
- 早期快照界面的 [TEST_REPORT.md](TEST_REPORT.md) 是历史版本；不能用它替代本轮安装、运行结果。

## 逐功能测试

| 功能点 | 方法与断言 | 结果与实际边界 |
|---|---|---|
| 编译/包装 | Release 双架构构建；嵌入 Runtime、C++ collector、后台 plist；逐个签名，再深度验证 App | 通过；非正式签名/公证 |
| 当前用户安装 | 从构建 App 安装到 `~/Applications`，用 `open` 从安装位置启动 | 通过，不需要 root |
| 系统后台注册 | 本机版生成仅属于本产品的 0600 LaunchAgent；通过 launchctl 引导当前 GUI 用户域 | 通过；launchd 的 PID 与私有状态中的 supervisorPID 一致 |
| SMAppService 路径 | 实际安装、注册及启动测试；注册可用但 helper 启动失败，出现 EX_CONFIG 与 ad-hoc 信任诊断 | **本机未通过**。本地构建明确采用用户 LaunchAgent；正式签名构建保留 SMAppService，尚待持证环境验收。没有重置全机后台登记或关闭系统安全控制 |
| 自动采集 | 安装 App 自动创建私有配置，启动真实 C++ 采集器，不需要用户另开终端运行 daemon | 通过 |
| 退出界面继续采集 | 安装诊断退出 App 后，独立读取新鲜 heartbeat，并与 launchd PID 核对 | 通过。重登/整机重启尚未实测；plist 已配置 RunAtLoad/KeepAlive |
| 检测自检 | App 创建随机合成 `.env`，独立 helper 持有 FD 与回环 TCP 连接；生产采集器独立发现，UI 只读取日志 | 通过；目标路径、probe PID、世代时间、父进程链、127.0.0.1 对端齐备，事件类型 `sensitive_network_cooccurrence` |
| 自检证据语义 | 核对 `same_identity_descriptor_snapshot`、空 transfer_outcome、空 content hash；没有向外网发送 | 通过；自检不读取真实凭据，不证明内容读入或发送到模型 |
| 非品牌进程覆盖 | 后台集成使用 ReinsRuntime probe，没有给它增加 Agent 名称匹配；仍能发现敏感 FD/peer | 通过。这支持无白名单风险观察，不证明可识别所有未知 Agent 的语义身份 |
| 祖先与世代 | 实际 probe 记录包含启动时间；后台集成核对 Python 测试父进程，安装自检核对 ReinsDashboard 父进程 | 通过；未观察到的祖先仍保留不完整标志 |
| 实时日志接入 | 按 inode/offset 增量读取，每轮默认最多 1 MiB；界面保留最近 2,000 条 | 通过。7 个 LiveEvidenceReader 测试涵盖部分行、分块追赶、轮转、坏行/重复、超长行恢复、非普通文件及缺失文件 |
| 健康不是进程存活 | 独立核对 supervisor 新鲜度、当前 monitor 启动时刻、backend coverage 新鲜度；旧 session 或过期健康不能显示监控正常 | 6 个 RuntimeController 测试通过。实际本机显示 degraded，原因是部分进程/FD 不可见，未伪装成完整覆盖 |
| 敏感路径配置 | 私有原子 plist 保存；默认 SSH/AWS，可添加项目目录；C++ 通过 `--no-default-sensitive` 严格使用保存配置 | 通过。真实集成修改间隔触发新 PID/session，旧进程退出、旧日志归档。每次配置重载有采样间隙 |
| 单实例 | 同一私有数据目录再启动 supervisor，第二个拒绝且不覆盖第一份状态 | 通过；使用持有期 flock，不以 PID 文件代替锁 |
| 关闭/停止 | SIGTERM 下 owned child 清理；安装 App 停止操作移除本产品 LaunchAgent，核对相关进程及服务消失 | 通过；已有日志和配置保留 |
| 配置/状态文件安全 | 拒绝 symlink、FIFO、硬链接、非私有文件、组可写服务目录及外来同名 plist；不覆盖无关文件 | RuntimeCore 共 20 项通过，其中本地 LaunchAgent 新增 4 项 |
| 日志轮转 | C++ 达到阈值退出 3；supervisor 封存后重启，保留 5 个归档 | 6 个真实后端阈值场景 + 合成退出 3 的 supervisor 控制测试通过。16 MiB 是请求阈值，不是硬上限；轮转会产生覆盖间隙 |
| 崩溃重试 | 合成 monitor 连续退出，5 次失败/5 分钟预算后保持 failed，避免无限快速重启 | 通过。此项是故障注入控制测试，不冒充真实采集能力测试 |
| 实时/快照/演示隔离 | 启动为空实时模式；导入或演示期间后台记录不能替换当前数据集；返回实时恢复最新记录 | DashboardStore 11 项通过 |
| C++/Swift 契约 | 实际编译 C++ ToJson 生成样例，Swift 解码世代、时间、风险、缺失 actor 与证据强度 | 模型 9 项通过，未跳过跨语言项 |
| 只读快照导入 | 上限、普通文件、半行、错误、重复、取消及排序 | 10 项通过；导入不回写原始日志 |
| 原生外观 | 运行真实空白窗口，分别捕获浅色/暗色；修复最初状态区被裁切的问题 | 基础渲染与人工图像检查通过。未完成全部窗口尺寸、鼠标键盘交互和 VoiceOver 验收 |
| 系统通知 | 界面提供显式授权入口与风险通知节流 | 已实现，**未计为通过**：本轮未授权/实测通知送达。退出 App 后后台继续记录，但不发送通知 |
| 完整 Agent 外泄检测 | 任意真实 Agent 读取后发往模型/其他公网服务器 | **未通过，也未在本轮重新宣称通过**。历史验收仍为 17 TP / 22 TN / 0 FP / 6 FN |

## 后端整改与漏报/误报检查

[后端整改报告](../BACKEND_AUDIT_REPORT.md) 逐条说明 PID/exec 历史冻结、队列拒绝后的重试、编码字节预算、持久化确认及网关失败关闭。最终复跑原有 6 组、新增 14 组全部通过；原生集成 2 组、轮转 6 场景、网关持久化 3 场景通过。组、场景、XCTest 函数不能相加得到“检测准确率”。

共现测试包含文件单独、网络单独、世代验证失败和无已知 Agent 标签；这些不会被升级成“文件已上传”。它们验证具体误归因防线，不等于对真实用户工作负载测得零误报。

**严格停止边界仍失败：**独立子进程完成 write/fsync/close 后立即停止 FSEvents，6/6 次未捕获该目标变化；500 ms 等待的诊断对照为 6/6 捕获。生产代码没有用等待时间伪造保证。FlushSync 只能请求交付，不是文件系统操作的完整屏障；配置重启/轮转也受此限制。`make shutdown-probe` 保留非零失败。

## 本轮确实发现并修复的问题

1. 已存在的 `/private/tmp` 路径被 Foundation standardization 改写到 `/tmp` 符号链接，安全校验拒绝启动。保留原始绝对路径，并增加既有目录重开回归。
2. launchd 可提供相对 argv[0]，不能以它拼接 collector 路径。改为从已加载 Mach-O 获取 executable 路径。
3. 系统状态“已注册”不代表 monitor 健康；增加独立 coverage 时效/启动轮次校验。
4. 安装环境的 SMAppService 启动没有通过。明确区分本地用户 LaunchAgent 与正式签名部署；实测本机版后台与检测均通过。
5. 首次窗口状态区域裁切；显式约束根视图窗口边界，复核真实截图。

## 复现

```sh
PATH=/usr/bin:/bin:/usr/sbin:/sbin make check audit-native integration
macOSClient/scripts/check.sh
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64
macOSClient/scripts/package-local.sh
macOSClient/scripts/install-local.sh
python3 macOSClient/scripts/runtime-check.py \
  --runtime "$HOME/Applications/ReinsCredential.app/Contents/MacOS/ReinsRuntime" \
  --monitor "$HOME/Applications/ReinsCredential.app/Contents/Helpers/agent-monitor"
open -n "$HOME/Applications/ReinsCredential.app" --args \
  --verify-installation /private/tmp/reins-installed-check.json
# 使用与 UI 相同的停用路径；保留证据
open -n "$HOME/Applications/ReinsCredential.app" --args \
  --stop-monitoring /private/tmp/reins-stopped-check.json
make shutdown-probe # 本次明确失败；不得降低条件改成绿色
```

安装诊断会启动服务并创建合成数据，完成后退出界面、保留后台运行。它没有向生产日志插入虚构观察。诊断输出路径应由测试者控制。`runtime-check.py` 使用独立临时数据目录，不安装服务，真实采集与合成故障场景分别标明。

本轮没有进行多日运行、高负载 soak、断电恢复、不同账号/权限矩阵、arm64 真机运行、重新登录/重启、签名公证发行、任意 TLS 内容证明或对抗规避验收。追加日志仍可被同一账号或 root 篡改。当前交付是可使用且经本机验收的采样监控版本，不是已证明全面防泄漏的企业成品。

系统集成依据为 Apple 的 [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice)、[register](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) 与 [unregister](https://developer.apple.com/documentation/servicemanagement/smappservice/unregister%28%29) 文档；本报告的通过/失败结论来自上述本机测试。
