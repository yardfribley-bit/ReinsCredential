# Agent 敏感数据读取与发送：逐功能验收报告

## 0. 2026-11-11 归因与短时打开（step 1）

这一节只回答“哪个 Agent 碰过哪个敏感文件”。**不声称检测到上传。** 下文第 3 节的 45 例内容矩阵仍然有效，完整验收仍然失败。

触发：本机约 13 分钟日志里，每条 `actor_process` 都是 `chain_complete=false` / `missing_parent`，因为用户态读不到 launchd 的路径，链条在 ppid 1 处断开；子工具只标成 `observed_ancestor`，所属应用没有稳定名字；500ms 全机 FD 扫描抓不住几十到几百微秒的打开；默认敏感路径只有 `~/.ssh`、`~/.aws` 和启动目录的 `.env`。

结果：

- 父进程 ppid 被再次核对为 1 时，`chain_complete=true`，`chain_status=observed_chain_to_launchd`。不编造 launchd 的启动身份。中间父进程仍然缺失时保持 `missing_parent`。
- `owning_agent` 带上应用名、bundle 和根进程身份。给人读的 `summary` 形如：`Codex read ~/.ssh/id_ed25519 via zsh -> python. The file was open in that process. This is not an upload finding.` 这里的 read 表示文件在该进程里打开过，或句子写明的更弱信号，不是上传。
- 已知 Agent 树用 kqueue 的 fork/exec 立刻采样子进程。证据基础是 `fd_observed`、`access_time_change` 或 `inferred`。
- 采集器自身是 `collector_self`，不会被写成嫌疑 Agent。AgentReins 一类未列入规则的安全工具保持 `unclassified_process`。
- 默认敏感路径增加 `~/.config/gh`、`~/.netrc`、`~/.npmrc`、`~/.git-credentials`、`~/.docker/config.json`、`~/.kube/config`、`~/.config/gcloud`、`~/.azure`。已保存且恰好仍是旧的 `~/.ssh` + `~/.aws` 配置会升级一次；其它自定义配置不动。`--no-default-sensitive` 仍然先清空。

实测数字来自 GitHub Actions `macos-latest` 上的 `make check`、`make integration`（含 `tests/short_read.py`）和 `macOSClient/scripts/check.sh`。短时打开用临时目录里的 `synthetic-credential`，内容是 `SYNTHETIC_CREDENTIAL_NOT_A_SECRET`。30ms 持有与 `/bin/cat` 立即退出各 20 次。下表在该次运行日志写入后填入；在填入前不要把单元测试当成召回率。

| 测量 | 结果 |
| --- | --- |
| 30ms 打开 TP/FN | 待 CI |
| cat 立即退出 TP/FN | 待 CI |
| 空闲 CPU / RSS | 待 CI |
| 活动 CPU / RSS | 待 CI |

仍会漏掉：比 fork 通知更短、且在采样前就退出的打开；访问时间在 APFS 上经常不变，所以 `access_time_change` / `inferred` 不能当召回保证；权限不可见的进程；FSEvents 变更仍然没有 actor。上传、模型目的地和公网收件不在本步范围内。

日期：2026-11-11（Asia/Shanghai）。**总体验收：未通过。** 已完成本次实现、测试和结果归档，尚不能声称实现了“任意本机 Agent 的独立、完整读取与外传检测”。

本次有实际代码改进：新增 C++ 内容审计网关、内核认证的本地连接方身份、内容匹配、文件版本哈希、发送目的地与结果、关联事件 ID。真实当前 Codex 会话通过该通道读取合成数据并发送到独立本机服务器，接收端验证了字节一致。模型目的地的独立检测、外部互联网收件、全部真实客户端调用及绕过通道的检测仍未通过。

## 1. 验收口径与环境

- macOS 26.5.2，实测进程架构 x86_64，非 root；C++17，Clang，用户态，无 Endpoint Security 授权或系统扩展安装。
- 原有 `agent-monitor` 继续独立采样进程、FD、网络对端和 FSEvents；矩阵设置轮询间隔 100ms。设置间隔不等于实际采样周期或覆盖保证。
- 新增 `agent-gateway` 是**显式接入通道**。它不是系统范围的透明拦截器，也不为未知客户端自动配置流量。测试中的 Python 行为样本不是自主 AI Agent，不计入真实客户端成功数。
- 所有文件为随机合成测试内容；未读取真实 SSH/AWS 凭证。公网测试目标为 `https://httpbin.org/post`，与独立本机接收服务严格区分。
- 检测器不读取测试 proof、模型挑战回应或接收端收件记录。测试结束后，评估器将检测日志与独立事实记录对照。网关本身需要预注册文件内容版本，这是检测配置，不能称为零配置自动发现敏感内容。
- `sensitive_payload_observed` 表示网关收到的待发送内容包含注册版本；`transfer_result` 表示网络调用结果。HTTP 2xx 不单独证明服务端保存内容，也不证明模型消费了内容。
- 内容与同一已观察 Agent 祖先身份的关联，不等于内存级数据流证明；多个文件含相同内容时，不能仅凭匹配认定唯一来源。

**完整通过标准**：真实 Agent 完成读取及发送，检测器独立给出正确的执行身份、文件、执行链、实际目的地和内容证据；接收端独立确认；阴性和绕过用例也满足约定覆盖。发现进程、客户端退出码 0、脚本生成 proof，都不足以单独通过。

## 2. 本次修改及可复现的修复结果

| 修改 | 解决的问题 | 本次验证 | 仍有边界 |
| --- | --- | --- | --- |
| Unix socket + `LOCAL_PEERTOKEN` + `proc_pidpath_audittoken` | 不信任客户端提交的 PID；拒绝失效连接方身份 | 真实 curl PID、启动时间和 Codex 祖先链；伪造 PID header 无效 | 认证的是连接创建方，不能证明每个写入字节来自未转交的 FD；祖先可缺失 |
| `GET /read` 的注册文件读取、版本哈希与交付事件 | 不再把“FD 打开”写成“已读取内容” | 工具收到与注册文件一致的字节；文件变更后拒绝旧版本交付 | 实际读取者是网关，按客户端请求交付；不是原生客户端文件 read 系统调用证据 |
| `POST /submit` 原文/JSON/Base64/gzip 检测 | 从连接共现提升到实际请求体匹配 | 支持范围内 17/17 检出 | 跨请求分片、自定义编码、加密内容、未接入发送仍可漏报 |
| 有界 gzip 解压 | 首轮压缩发送漏报 | 修复前 FN，修复后 TP；损坏 gzip 和 >1MiB 展开上限单元测试通过 | 只处理单个 gzip member、单层且展开不超过 1MiB |
| 可配置关联时间 `--correlation-seconds` | 原 5 分钟窗口无法关联长任务 | 真实约 16 分钟间隔：修复前无关联，修复后有事件链接；1 秒过期对照不误关联 | 默认 1 小时，范围 1–86400 秒，最多 256 条近期交付；无持久化跨重启关联 |
| 目的地、内容 SHA256、关联 ID、传输结果 | 区分内容匹配、发送尝试、成功响应 | 本机收件 hash 一致；公网失败保留 curl 错误 | 不把已配置目的地当作实际收件证明 |
| 验收脚本采集器全程存活检查 | 固定时限可能在用例结束前停止采集 | 去掉固定采集时限，逐用例检查存活，重新执行矩阵 | 中途退出将导致测试失败，不生成完整覆盖结论 |

## 3. 45 个行为用例：最终实测

运行 ID：`00126f8f-eaaa-406d-b054-4ebde2115bc6`。原始机器可读结果：[acceptance_matrix.json](tests/results/acceptance_matrix.json)。

| 行为 | 次数 | 实际操作 | 内容检测结果 | 验收结论 |
| --- | ---: | --- | --- | --- |
| 原文发送 | 5 | 短时读取后通过网关 POST | 5 TP | 接入范围通过 |
| JSON 转义 | 5 | 将完整文件作为 JSON 字段 | 5 TP | 通过 |
| Base64 | 5 | 整个文件编码后发送 | 5 TP | 通过 |
| gzip | 1 | 压缩含文件内容的请求体 | 1 TP | 修复后通过 |
| 读取关闭后延迟发送 | 1 | 读完关闭，等待 1 秒，再 POST | 1 TP | 内容匹配通过；不是原生读事件证明 |
| 普通内容发送 | 20 | 不读取敏感文件，只发送普通测试数据 | 20 TN | 本样本无内容误报 |
| 仅读取 | 1 | 读取后不发送 | 1 TN | 无虚构上传告警；被动读取检测失败 |
| 仅打开、不读取 | 1 | 持有敏感文件 FD，发送无关内容 | 1 TN | 不把打开文件当作内容外传 |
| 跨请求分片 | 1 | 文件拆成两个独立请求发送 | 1 FN | **失败**；接收端分别收到片段，整文件匹配未命中 |
| 绕过网关 | 5 | 原生 HTTP 直连独立接收端 | 5 FN | **失败**；检测器没有内容传感覆盖 |

全范围混淆矩阵：TP=17、TN=22、FP=0、FN=6。敏感发送召回率 **17/23=73.91%**，漏报率 **6/23=26.09%**。阴性样本误报率为 **0/22**；不能外推为生产零误报。只报告 17/17 而排除分片和绕过，会掩盖关键缺口，因此完整验收仍判失败。

同轮被动监控结果：45/45 样本进程被发现；24 次实际读取中，**0 次采到读取期间的敏感 FD**；读取耗时为 75–269 微秒。仅打开不读取的用例反而采到了 FD。这直接说明文件描述符采样无法证明读操作，也无法保证短读召回。被动监控未产生内容外传确认事件。

每个用例包含独立 `case_id`、真实 PID、读取耗时、请求体 SHA256、接收回执、检测事件 UUID、目的地、身份对照与结论。没有检测证据的归因字段为 `null`，不会用空集合的 `all()` 结果充当正确归因。

这轮端到端用例耗时为 152.91–2222.76ms，中位数 233.52ms；包含进程启动、采集和人为等待，不是纯检测延迟、吞吐指标或生产 SLA。

## 4. 真实 Agent 验收

### 4.1 当前真实 Codex 会话

运行 ID：`3af307bf-2dda-4474-813a-8eacd392cebe`。结果：[live_session_acceptance.json](tests/results/live_session_acceptance.json)。

步骤：启动独立采集器和接收器 → 真实 Codex 调用 curl 读取网关注册的随机文件 → 文件内容作为工具结果进入当前模型上下文 → 模型给出文件中随机 8 位挑战的倒序 → 真实 Codex 调用 curl 将文件分别提交给本机网关和固定公网目标的网关 → 评估器核对挑战、接收哈希及检测证据。

| 功能 | 实际结果 | 判定 |
| --- | --- | --- |
| 合成内容交付给真实工具 | 内容 hash、真实 curl 身份及 Codex 祖先链齐全 | 通过，限中介交付 |
| 当前模型看到随机数据 | 倒序挑战回应正确；回应由当前模型生成，协调器只验证 | 有事实佐证；不是模型服务端回执 |
| 独立监测模型请求目的地 | 网关只看到向本地工具交付，未观察工具宿主向模型提交的 HTTPS 内容 | **失败** |
| 向本机独立服务器发送 | 接收端哈希与完整测试文件相同 | 通过；属于本机回环服务器 |
| 发送进程、链条、来源版本、目的地 | 内容事件与交付事件成功链接 | 通过，关联依据为内容及共同已观察 Agent 身份 |
| 完整 PPID 到系统根 | 可见祖先记录保留，部分链条 `chain_complete=false` | 部分覆盖，未伪造缺失父进程 |
| 公网 HTTPS 发送尝试 | 匹配到敏感内容及 `https://httpbin.org/post` 目标 | 尝试检测通过 |
| 公网实际收件 | `curl_code=56`、HTTP status=0，代理连接失败，无外部回执 | **阻塞/未通过** |
| 被动监控原生短时文件句柄 | 实际工具 PID 对应敏感 FD 事件为 0 | **失败** |

可核对的事件：

| 事实 | 事件 UUID | actor 身份 |
| --- | --- | --- |
| 本地工具内容交付 | `93594671-96e2-401c-9178-9fb1f3bf01f4` | PID 9282，start=(1794349058,461989) |
| 本机目标敏感发送 | `dd0a3a09-2f40-4faa-b492-c47119c912d7` | PID 9523，start=(1794350067,719461) |
| 本机传输结果 | `3ba0f99b-07a4-4192-88c8-89734d7e3570` | 同一发送身份 |
| 公网敏感发送尝试 | `e88af0a9-9496-4273-9683-ea5e4b757ecc` | PID 9541，start=(1794350073,224526) |
| 公网失败结果 | `bc8ebdc5-69b5-4bf6-9ff8-bf67b81867bf` | 同一发送身份 |

本机发送记录的 `related_event_ids` 包含交付 UUID。公网是单独的网关实例，没有共享交付历史，因此公网尝试没有该跨实例链接；不能称为公网完整因果链。哈希和 ID 是本机产物的对照信息，不是第三方签名证明。

### 4.2 独立真实客户端复测

结果：[real_agents_retest.json](tests/results/real_agents_retest.json)。用户授权了调用这些客户端及 WorkBuddy 配置/遥测请求；后来确认先继续可执行测试，没有提供新的登录入口。

| 客户端 | 真实调用/进程 | 动作结果 | 结论 |
| --- | --- | --- | --- |
| Codex CLI | 已启动、采集到 PID 8638；禁用 apps 并忽略用户配置重试 | 超时前未生成可验证动作 proof，原始输出含超时信息 | 阻塞，未通过模型驱动动作 |
| Cursor Agent CLI | 已启动、采集到 PID 8639 | 本次测试期限内无动作、输出为空；此前调用曾要求登录 | 未通过；本次不能仅凭旧结果断定原因 |
| WorkBuddy AI CLI | 已启动、采集到 PID 8640 | 代理初始化 `instanceof` 错误；退出 0 但无动作 proof | 未通过，退出 0 不算成功 |
| 当前 Codex 工具链 probe | PID 8641，真实会话发起 | 长持有 FD、祖先链、回环收件验证成功 | 工具链通过，不等于独立 CLI 模型会话通过 |
| Grok Bot | 已运行进程路径子集 10/10 被发现 | 未执行 Grok 自主读取/发送任务 | 只通过进程发现，动作未测试 |

同期独立 `ps` 路径基线：Cursor 6/6、WorkBuddy AI 13/13、Codex 后端 5/5、Grok Bot 10/10。Grok 默认分类为 `unclassified_process`。这只是路径可辨认的进程子集，不是所有 Agent 的召回率。未知工具的敏感策略不依赖品牌白名单，但“通用进程”不能自动被证明为 Agent。

复测健康记录中可见进程约 633–642，不可查询条目 307–312；存在 8 个 FD 扫描不完整条目。最大已采样活动扫描耗时 1782ms。记录中的队列丢失和日志拒绝计数为 0，不能据此推导没有漏采短读或短命进程。

## 5. 逐功能检查清单

`U`=tests/unit.cpp；`I`=tests/integration.py；`M`=acceptance_matrix.py；`S`=gateway_security.py；`L`=live_session_acceptance.py。通过只对应表内操作和范围。

| ID | 功能点 | 具体测试/预期 | 实测 |
| --- | --- | --- | --- |
| P01 | PID 复用隔离 | U：相同 PID、不同启动时间，旧身份不复用 | PASS，确定性模拟 |
| P02 | 祖先身份保留 | U：父 PID 被替换后，历史子链不指向新父身份 | PASS |
| P03 | 前后校验 | U：检查过程中身份变化，丢弃活动归因 | PASS |
| P04 | 可见性丢失 | U：不可见标为 NotObserved，不武断认定退出 | PASS |
| P05 | 快照不可变 | U：并发读取/刷新不修改读者持有快照 | PASS |
| P06 | 缺失父进程 | U：保留 chain_status，不补造祖先 | PASS |
| P07 | 历史边界 | U：保留期/容量回收，不错误替换活跃身份 | PASS |
| P08 | 真实 PID/执行链 | I、L：实际子进程 PID 与 libproc 身份、祖先核对 | PASS，链条可不完整 |
| P09 | 未知名称进程 | U 与已归档 unknown_process 原生测试：无名称规则仍采集敏感 FD | PASS，不能证明任意未知 Agent 语义 |
| Q01 | 环形队列顺序 | U：200000 个并发生产/消费事件 | PASS |
| Q02 | 满队列与回绕 | U：容量满返回失败、索引回绕后顺序正确 | PASS |
| Q03 | FSEvents callback 隔离 | 代码检查：固定事件入队，回调无 libproc/磁盘 I/O | 已检查；未给出 callback 最坏延迟保证 |
| Q04 | FSEvents 真实修改 | I：修改测试文件收到变更事件 | PASS |
| Q05 | 变更者身份不伪造 | I：FSEvents 事件 actor_process 为 null | PASS |
| Q06 | 系统源丢失告警 | 代码有源 gap 指标，实测为 0 | 未强制触发内核 dropped-event 条件 |
| E01 | 并发追加 | U：200 条并发记录、关闭排空、重新打开追加 | PASS |
| E02 | UUID/序号 | U、M：UUID 不重复、会话内序号连续 | PASS |
| E03 | JSON 转义 | U：引号、控制字符、无效 UTF-8 与原始路径字节 | PASS |
| E04 | 日志权限 | U、M：只接受属主拥有的 0600 单链接普通文件 | PASS |
| E05 | 单写者锁 | U：第二写者被拒绝 | PASS |
| E06 | 日志符号链接 | U：O_NOFOLLOW 拒绝 | PASS |
| E07 | 不完整尾部 | U：拒绝复用损坏尾部，不截断原日志 | PASS |
| E08 | 写入错误传播 | U：RLIMIT_FSIZE 注入短写/写失败，Close 报错 | PASS |
| E09 | 正常停止 | I、M：SIGTERM 后排空、JSONL 全部可解析 | PASS |
| E10 | 防篡改证明 | 本地 O_APPEND/锁并非密码学防篡改；没有独立锚定 | 未实现，不作为已通过功能 |
| C01 | 内容交付 | M、L：GET /read 返回注册文件原始字节 | PASS |
| C02 | 文件版本改变 | M：修改源文件后再 GET | PASS：拒绝，不沿用旧版本归因 |
| C03 | 原文内容匹配 | M：5 次原文发送 | PASS 5/5 |
| C04 | JSON 转义 | M：5 次 JSON 字段发送 | PASS 5/5 |
| C05 | Base64 | M：5 次整值编码 | PASS 5/5 |
| C06 | gzip | M、U：压缩、损坏压缩、展开上限 | PASS，单层有界 |
| C07 | 短普通字符串 | U：小于 16 字节不做注册内容匹配 | PASS，降低常见值误报，牺牲短值覆盖 |
| C08 | 分片发送 | M：完整文件分两请求 | FAIL 1/1 漏报 |
| C09 | 直接绕过 | M：5 次直接发送到接收端 | FAIL 5/5 漏报 |
| C10 | 普通发送阴性 | M：20 次不含敏感内容 | PASS 0/20 误报 |
| C11 | 只读/只打开阴性 | M：不把它们当作敏感内容上传 | PASS 0/2 内容误报 |
| C12 | 同 Agent 内容关联 | M、L：链接交付 UUID 和发送事件 | PASS；相关性依据明确，不是内存污点追踪 |
| C13 | 关联到期 | S：设置 1 秒，超过窗口不链接 | PASS |
| N01 | 进程身份不能由 header 冒充 | M：X-Agent-Pid:1 | PASS：仍为实际连接 PID |
| N02 | 目的地固定 | M：日志目的地与配置及独立收件端一致 | PASS，限网关发送 |
| N03 | 本机实际收件 | M、L：接收端 SHA256 对照 | PASS |
| N04 | 公网收件 | L：HTTPS 测试站点 | BLOCKED，代理连接中断 |
| N05 | HTTP 503 | S：接收端返回 503 | PASS：未记作成功 |
| N06 | HTTP 重定向 | S：302 指向其他端口 | PASS：不跟随，未记作成功 |
| N07 | 不可达服务 | M：关闭接收端后发送 | PASS：返回失败并记录网络错误 |
| N08 | 模型实际目的地 | L：模型获得随机数据后检查监控日志 | FAIL：本地交付不等于观测模型 HTTPS 提交 |
| H01 | 未知路由 | M：请求未知路径 | PASS：拒绝且不转发 |
| H02 | 重复 Content-Length | M：两个长度头 | PASS：拒绝 |
| H03 | chunked 请求 | M：Transfer-Encoding | PASS：明确拒绝，不宣称支持 |
| H04 | 超限请求体 | M：声明 >1MiB | PASS：拒绝 |
| H05 | 不完整请求体 | S：只发部分 body | PASS：超时拒绝 |
| H06 | 慢客户端后恢复 | S：超时后正常请求 | PASS |
| H07 | 并发客户端 | S：8 个并发请求 | PASS；网关串行处理，非高吞吐压测 |
| H08 | socket 路径安全 | S：预先放置同名文件 | PASS：拒绝绑定且不删除原文件 |
| H09 | 源文件符号链接 | S：注册 symlink | PASS：拒绝 |
| H10 | socket 清理 | M：正常停止 | PASS：只移除自己创建的 socket |
| H11 | 明文落盘 | M：日志不包含完整 canary 内容 | PASS；仍保留路径/hash 元数据 |
| H12 | TLS 验证 | 代码启用证书链/主机校验，不关闭校验 | 自签名端点尚未实测，不列为动态通过 |
| B01 | Native 编译 | -std=c++17，警告视为错误 | PASS |
| B02 | ASan/UBSan 单元 | 6 组单元，含新增 matcher | PASS；无报告的 ASan/UBSan 错误 |
| B03 | ASan/UBSan 网关 | 8 项故障注入 | PASS，见独立结果文件 |
| B04 | 泄漏检测 | detect_leaks=1 | 平台明确不支持；改为 0 后运行，未声称 LeakSanitizer 通过 |
| B05 | 双架构编译 | gateway universal，lipo 检查 | PASS：x86_64 arm64；arm64 未实际运行 |

内存检查未出现报告不代表证明所有路径无错误。尚未完成长时间负载、整机升级、休眠恢复、恶意同 UID 篡改防护、任意 TLS 内容观测和全系统部署验收。

## 6. 复现与退出码

```sh
make all agent-unit agent-probe
./agent-unit
/usr/bin/python3 tests/integration.py
/usr/bin/python3 tests/acceptance_matrix.py --require-full-acceptance
# 当前预期退出 2：存在真实漏报，完整验收失败。
/usr/bin/python3 tests/gateway_security.py
/usr/bin/python3 tests/real_agents.py --timeout 60 --report tests/results/real_agents_retest.json
# 真实模型会话参与式验收，按脚本顶部步骤实际读取并回答随机挑战：
/usr/bin/python3 tests/live_session_acceptance.py
```

`acceptance_matrix.py` 不加 `--require-full-acceptance` 时，退出 0 只表示已声明回归预期成立（包括已知漏报得到复现）。`make acceptance` 始终开启完整验收要求，不会因为已知失败而变绿。真实 CLI 调用脚本完成退出也不表示模型动作通过，必须查看每客户端的 `tool_action_verified`。

网关参数示例（目录须属主拥有且 mode 0700；文件只使用自己的测试文件）：

```sh
./agent-gateway --socket /private/tmp/my-private-test/a.sock \
  --log /private/tmp/my-private-test/gateway.jsonl \
  --sensitive-file /private/tmp/my-private-test/synthetic.env \
  --upstream https://your-authorized-receiver.example/ingest \
  --correlation-seconds 3600
curl --unix-socket /private/tmp/my-private-test/a.sock http://localhost/read
curl --unix-socket /private/tmp/my-private-test/a.sock \
  --data-binary @/private/tmp/my-private-test/synthetic.env http://localhost/submit
```

网关当前只支持注册一个文件版本、固定上游地址及上述有限协议，不转发认证头、不改写真实 Agent 认证配置、不安装 TLS 根证书。它不能替代部署级出口约束。修复全部绕过和提供任意 Agent 原生读证据，需要新增可信系统事件源和受管理的发送观测点；仅扩大名称列表或提高 libproc 轮询频率无法实现。

## 7. 证据保存与检查

- [最终行为矩阵](tests/results/acceptance_matrix.json)：45 条完整个案、18 项协议/日志检查、检测与独立收件 hash。
- [真实当前会话](tests/results/live_session_acceptance.json)：事件 UUID、PID+启动时间、祖先、目的地、关联与外部错误。
- [真实 CLI 复测](tests/results/real_agents_retest.json)：实际调用、进程基线、失败分类、健康指标。
- [故障注入](tests/results/gateway_security.json)、[ASan/UBSan 故障注入](tests/results/gateway_security_asan.json)：8 项逐项结果。
- [修复前矩阵](tests/results/acceptance_matrix_before_fix.json)、[修复前真实关联](tests/results/live_session_before_fix.json)：保留失败而不覆盖历史。
- [原有模块测试](TEST_RESULTS.md)、[之前真实客户端记录](REAL_AGENT_TESTS.md)：注明不同测试轮次，不混用计数。

最终矩阵私有证据 SHA256：gateway `54b0b1fadbdb7aef2bd4c9e2d9aa2edb8751f7f6a4e1739be2ab75098d76e606`；passive `4a2832102473b6f0732f89440e0c4abde75634610e96231f5ab32e2d828f33b6`；receiver `35d1c425631e2bddd529d1f12a700c33943e362578c610c9f98ac75bba55981e`。

公开结果仅保留本次测试有关的脱敏元数据。整机原始进程/连接日志、原始客户端输出、私有测试目录和原始测试文件不上传。公开摘要支持核对本次断言，不等同于独立第三方认证；完整复核可在授权本机对照私有日志或重新执行测试。

API 边界参考：[Apple FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events)、[Endpoint Security 授权要求](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)。FSEvents 的用途是层级内容修改通知；不能用它的回调构造不存在的读事件或操作 PID。
