# 证据链

schema: reinscredential.evidence-chain.v1
原始密钥字节：已省略
没有补造缺失的事件。

结论用词：已上传、已尝试未成功、未发现、看不到。看不到不能写成未发现。没有出口结论表示记录里没有这四句。打开的描述符、同时出现的连接，都不是上传。原始密钥字节不包含在导出里。

导出范围：全部给出的证据链
条数：8

## 1. Codex · /synthetic/demo/uploaded.env · 已上传

- 时间：2026-11-11T00:00:00.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：Codex（Codex.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：codex（pid 5101） → Codex（pid 5100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000100.000000。
- 文件：/synthetic/demo/uploaded.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：http://example.invalid/demo-upload
  - 状态：已记录
- 内容匹配：exact_bytes · SHA-256 abababababababababababababababababababababababababababababababab
  - 状态：已记录
  - 说明：原始字节不在记录里。 请求体长度 48 字节。
- 出口结论：已上传
  - 状态：已记录
  - 说明：请求体与已登记内容匹配，并且代理看到了成功的 HTTP 结果。这不是对端的独立回执。传输结果：upstream_http_2xx;application_receipt_requires_independent_verification。
- 采集原句：已上传。codex 向 http://example.invalid/demo-upload 发送的请求体与已登记文件 /synthetic/demo/uploaded.env 匹配，传输结果：upstream_http_2xx。这是代理观察到的 HTTP 结果，不是对端的独立回执。
- 结论代码：uploaded
- 出口结论：已上传
- 关联事件：00000000-0000-4000-8000-000000000003, 00000000-0000-4000-8000-000000000001, 00000000-0000-4000-8000-000000000002
- 快照中缺少的关联：0

## 2. Codex · /synthetic/demo/matched-without-open.env · 已上传

- 时间：2026-11-10T23:59:30.000Z
- 种类：transfer_without_open
- 打开是否被看到：没有看到
- 所属 Agent：Codex（Codex.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：codex（pid 5101） → Codex（pid 5100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000100.000000。
- 文件：/synthetic/demo/matched-without-open.env
  - 状态：未证明
  - 说明：正文匹配指向这个已登记路径，但没有看到打开。这里不补造打开记录。
- 目的地：http://example.invalid/demo-unopened
  - 状态：已记录
- 内容匹配：exact_bytes · SHA-256 efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef
  - 状态：已记录
  - 说明：原始字节不在记录里。 请求体长度 32 字节。
- 出口结论：已上传
  - 状态：已记录
  - 说明：请求体与已登记内容匹配，并且代理看到了成功的 HTTP 结果。这不是对端的独立回执。传输结果：upstream_http_2xx;application_receipt_requires_independent_verification。
- 采集原句：已上传。请求体匹配已登记文件，但这次传输记录没有看到打开。
- 结论代码：uploaded
- 出口结论：已上传
- 关联事件：00000000-0000-4000-8000-000000000020
- 快照中缺少的关联：0

## 3. Claude · /synthetic/demo/attempted.env · 已尝试未成功

- 时间：2026-11-10T23:59:00.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：Claude（Claude.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：claude-helper（pid 6101） → Claude（pid 6100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000210.000000。
- 文件：/synthetic/demo/attempted.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：https://example.invalid/demo-attempt
  - 状态：已记录
  - 说明：这次 HTTPS 用调用方提供的临时 CA 检查了正文。CA 没有装进登录钥匙串。
- 内容匹配：exact_bytes · SHA-256 cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
  - 状态：已记录
  - 说明：原始字节不在记录里。 请求体长度 40 字节。
- 出口结论：已尝试未成功
  - 状态：已记录
  - 说明：请求体与已登记内容匹配，但这次传输没有成功。传输结果：upstream_http_500。
- 通道说明：这次 HTTPS 用调用方提供的临时 CA 检查了正文。CA 没有装进登录钥匙串。
- 采集原句：已尝试未成功。claude-helper 向 https://example.invalid/demo-attempt 发送的请求体匹配，但传输没有成功：upstream_http_500。
- 结论代码：attempted
- 出口结论：已尝试未成功
- 关联事件：00000000-0000-4000-8000-000000000006, 00000000-0000-4000-8000-000000000004, 00000000-0000-4000-8000-000000000005
- 快照中缺少的关联：0

## 4. Claude · /synthetic/demo/partial.env · 没有出口结论

- 时间：2026-11-10T23:58:30.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：Claude（Claude.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：claude-helper（pid 6102）
  - 状态：不完整
  - 说明：进程链不完整：没有观察到父进程。 行为进程在前。 启动世代 1700000220.000000。
- 文件：/synthetic/demo/partial.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：缺失
  - 状态：缺失
  - 说明：没有观察到目的地。
- 内容匹配：缺失
  - 状态：缺失
  - 说明：没有内容匹配。打开的描述符或同时出现的连接不是上传。
- 出口结论：没有出口结论
  - 状态：缺失
  - 说明：没有出口结论。打开的描述符或同时出现的连接不是上传。这不是未发现，也不是看不到。
- 采集原句：Claude 的子进程打开了 /synthetic/demo/partial.env。父进程没有观察到。这不是上传结论。
- 结论代码：（空）
- 出口结论：没有出口结论
- 关联事件：00000000-0000-4000-8000-000000000021
- 快照中缺少的关联：0

## 5. Cursor · /synthetic/demo/clean.env · 未发现

- 时间：2026-11-10T23:58:00.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：Cursor（Cursor.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：Cursor Helper（pid 7101） → Cursor（pid 7100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000310.000000。
- 文件：/synthetic/demo/clean.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：http://example.invalid/demo-clean
  - 状态：已记录
- 内容匹配：没有匹配到已登记内容
  - 状态：已记录
  - 说明：这是看过的出口里没有内容，不是看不到。
- 出口结论：未发现
  - 状态：已记录
  - 说明：已查看的出口里没有已登记内容。这句话不覆盖没有被检查的通道。传输结果：watched_http_no_registered_content。
- 采集原句：未发现。已查看 Cursor Helper 的明文 HTTP 出口（http://example.invalid/demo-clean），没有看到已登记文件 /synthetic/demo/clean.env 的内容。
- 结论代码：not_found
- 出口结论：未发现
- 关联事件：00000000-0000-4000-8000-000000000009, 00000000-0000-4000-8000-000000000007, 00000000-0000-4000-8000-000000000008
- 快照中缺少的关联：0

## 6. WorkBuddy · /synthetic/demo/hidden.env · 看不到

- 时间：2026-11-10T23:57:00.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：WorkBuddy（WorkBuddy.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：WorkBuddy Helper（pid 8101） → WorkBuddy（pid 8100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000410.000000。
- 文件：/synthetic/demo/hidden.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：203.0.113.50:443/protocol=17
  - 状态：已记录
  - 说明：这个 Agent 在采集开始前已经在运行。没有修改它的 MCP 或应用设置，用户态不能把已有连接改道到本地代理。 这是 UDP 或 QUIC。正文看不到。
- 内容匹配：缺失
  - 状态：缺失
  - 说明：这个通道的字节看不到，不能写成没有匹配，也不能写成未发现。
- 出口结论：看不到
  - 状态：已记录
  - 说明：看不到。不能把它写成未发现。传输结果：udp_or_quic_body_not_visible。
- 通道说明：这个 Agent 在采集开始前已经在运行。没有修改它的 MCP 或应用设置，用户态不能把已有连接改道到本地代理。 这是 UDP 或 QUIC。正文看不到。
- 采集原句：看不到。看不到 WorkBuddy Helper 发往 203.0.113.50:443 的通道内容，因此不能判断已登记文件 /synthetic/demo/hidden.env 有没有发出去。
- 结论代码：not_visible
- 出口结论：看不到
- 关联事件：00000000-0000-4000-8000-000000000013, 00000000-0000-4000-8000-000000000010, 00000000-0000-4000-8000-000000000011, 00000000-0000-4000-8000-000000000012
- 快照中缺少的关联：0

## 7. ChatGPT · /synthetic/demo/pinned.env · 看不到

- 时间：2026-11-10T23:56:00.000Z
- 种类：file_access
- 打开是否被看到：看到
- 所属 Agent：ChatGPT（ChatGPT.app）
  - 状态：已记录
  - 说明：名称或 bundle 匹配是候选分类，不是身份认证。
- 进程：ChatGPT Helper（pid 9101） → ChatGPT（pid 9100）
  - 状态：已记录
  - 说明：进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。 行为进程在前。 启动世代 1700000510.000000。
- 文件：/synthetic/demo/pinned.env
  - 状态：已记录
  - 说明：看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：fd_observed，看到描述符。
- 目的地：https://example.invalid:443
  - 状态：已记录
  - 说明：HTTPS 没有完成代理侧握手。证书固定，或客户端不信任临时 CA。这个 CA 不会装进登录钥匙串。
- 内容匹配：缺失
  - 状态：缺失
  - 说明：这个通道的字节看不到，不能写成没有匹配，也不能写成未发现。
- 出口结论：看不到
  - 状态：已记录
  - 说明：看不到。不能把它写成未发现。传输结果：tls_intercept_handshake_failed。
- 通道说明：HTTPS 没有完成代理侧握手。证书固定，或客户端不信任临时 CA。这个 CA 不会装进登录钥匙串。
- 采集原句：看不到。到 https://example.invalid:443 的 TLS 没有完成代理侧握手，正文没有被检查。证书固定、客户端不信任临时 CA，或 QUIC 都会是这个结果。
- 结论代码：not_visible
- 出口结论：看不到
- 关联事件：00000000-0000-4000-8000-000000000016, 00000000-0000-4000-8000-000000000014, 00000000-0000-4000-8000-000000000015
- 快照中缺少的关联：0

## 8. 未归属 · /synthetic/demo/changed.env · 没有出口结论

- 时间：2026-11-10T23:55:00.000Z
- 种类：file_access
- 打开是否被看到：没有看到
- 所属 Agent：缺失
  - 状态：缺失
  - 说明：没有识别到所属 Agent。不会用进程名补一个。
- 进程：缺失
  - 状态：缺失
  - 说明：没有可归因的进程。
- 文件：/synthetic/demo/changed.env
  - 状态：已记录
  - 说明：文件系统报告了变化。没有行为进程，也不是打开或上传。
- 目的地：缺失
  - 状态：缺失
  - 说明：没有观察到目的地。
- 内容匹配：缺失
  - 状态：缺失
  - 说明：没有内容匹配。打开的描述符或同时出现的连接不是上传。
- 出口结论：没有出口结论
  - 状态：缺失
  - 说明：没有出口结论。打开的描述符或同时出现的连接不是上传。这不是未发现，也不是看不到。
- 采集原句：合成演示：敏感路径发生了变化。文件系统事件没有行为进程。
- 结论代码：（空）
- 出口结论：没有出口结论
- 关联事件：00000000-0000-4000-8000-000000000030
- 快照中缺少的关联：0
