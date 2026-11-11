import Foundation

public extension EvidenceRecord {
    /// Entirely synthetic. Never merge these records into an imported log.
    /// The set includes every upload verdict, an incomplete process chain,
    /// a body match with no open, an already-running agent, untrusted HTTPS,
    /// and UDP. None of the strings are real credentials.
    static var sampleRecords: [EvidenceRecord] {
        let now = Date(timeIntervalSince1970: 1_794_355_200)
        let uploadedHash = String(repeating: "ab", count: 32)
        let attemptedHash = String(repeating: "cd", count: 32)
        let unmatchedOpenHash = String(repeating: "ef", count: 32)
        let codex = demoTree(actor: 5101, parent: 5100, actorName: "codex", parentName: "Codex",
                             actorPath: "/synthetic/Codex.app/Contents/MacOS/codex",
                             parentPath: "/synthetic/Codex.app/Contents/MacOS/Codex",
                             actorStart: 1_700_000_100, parentStart: 1_700_000_000)
        let claude = demoTree(actor: 6101, parent: 6100, actorName: "claude-helper", parentName: "Claude",
                              actorPath: "/synthetic/Claude.app/Contents/MacOS/claude-helper",
                              parentPath: "/synthetic/Claude.app/Contents/MacOS/Claude",
                              actorStart: 1_700_000_210, parentStart: 1_700_000_200)
        let cursor = demoTree(actor: 7101, parent: 7100, actorName: "Cursor Helper", parentName: "Cursor",
                              actorPath: "/synthetic/Cursor.app/Contents/MacOS/Cursor Helper",
                              parentPath: "/synthetic/Cursor.app/Contents/MacOS/Cursor",
                              actorStart: 1_700_000_310, parentStart: 1_700_000_300)
        let workbuddy = demoTree(actor: 8101, parent: 8100, actorName: "WorkBuddy Helper", parentName: "WorkBuddy",
                                 actorPath: "/synthetic/WorkBuddy.app/Contents/MacOS/WorkBuddy Helper",
                                 parentPath: "/synthetic/WorkBuddy.app/Contents/MacOS/WorkBuddy",
                                 actorStart: 1_700_000_410, parentStart: 1_700_000_400)
        let chatgpt = demoTree(actor: 9101, parent: 9100, actorName: "ChatGPT Helper", parentName: "ChatGPT",
                               actorPath: "/synthetic/ChatGPT.app/Contents/MacOS/ChatGPT Helper",
                               parentPath: "/synthetic/ChatGPT.app/Contents/MacOS/ChatGPT",
                               actorStart: 1_700_000_510, parentStart: 1_700_000_500)
        let uploadedOpen = demoID(1)
        let uploadedTransfer = demoID(2)
        let uploadedClose = demoID(3)
        let attemptedOpen = demoID(4)
        let attemptedTransfer = demoID(5)
        let attemptedClose = demoID(6)
        let cleanOpen = demoID(7)
        let cleanTransfer = demoID(8)
        let cleanClose = demoID(9)
        let hiddenOpen = demoID(10)
        let hiddenUDP = demoID(11)
        let hiddenLive = demoID(12)
        let hiddenClose = demoID(13)
        let tlsOpen = demoID(14)
        let tlsUnseen = demoID(15)
        let tlsClose = demoID(16)

        return [
            demo(id: uploadedClose, at: now, risk: .high, path: "/synthetic/demo/uploaded.env", action: "VERDICT",
                 source: "sensitive_access_closed", tree: codex, agent: "Codex", bundle: "Codex.app",
                 destination: "http://example.invalid/demo-upload", basis: "egress_proxy_http_body_match",
                 outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                 verdict: "uploaded", hash: uploadedHash, complete: true, status: "observed_chain_to_launchd",
                 detail: "match=exact_bytes;raw_bytes_not_stored;synthetic_demo",
                 summary: "已上传。codex 向 http://example.invalid/demo-upload 发送的请求体与已登记文件 /synthetic/demo/uploaded.env 匹配，传输结果：upstream_http_2xx。这是代理观察到的 HTTP 结果，不是对端的独立回执。",
                 related: [uploadedOpen, uploadedTransfer], count: 48),
            demo(id: uploadedTransfer, at: now.addingTimeInterval(-2), risk: .high, path: "/synthetic/demo/uploaded.env",
                 action: "TRANSFER", source: "egress_transfer", tree: codex, agent: "Codex", bundle: "Codex.app",
                 destination: "http://example.invalid/demo-upload", basis: "exact_bytes",
                 outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                 verdict: "uploaded", hash: uploadedHash, complete: true, status: "observed_chain_to_launchd",
                 detail: "match=exact_bytes;raw_bytes_not_stored;open_of_source_file_not_proven_by_this_record;synthetic_demo",
                 summary: "已上传。合成演示中的明文 HTTP 匹配。原始字节没有保存。", count: 48),
            demo(id: uploadedOpen, at: now.addingTimeInterval(-4), risk: .medium, path: "/synthetic/demo/uploaded.env",
                 action: "OBSERVE", source: "sensitive_fd_observed", tree: codex, agent: "Codex", bundle: "Codex.app",
                 basis: "fd_observed", complete: true, status: "observed_chain_to_launchd",
                 detail: "descriptor_observed;bytes_read_unproven;not_an_upload;synthetic_demo",
                 summary: "Codex 的进程打开了 /synthetic/demo/uploaded.env。文件在该进程中处于打开状态。这不是上传结论。"),

            demo(id: demoID(20), at: now.addingTimeInterval(-30), risk: .high, path: "/synthetic/demo/matched-without-open.env",
                 action: "TRANSFER", source: "egress_transfer", tree: codex, agent: "Codex", bundle: "Codex.app",
                 destination: "http://example.invalid/demo-unopened", basis: "exact_bytes",
                 outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                 verdict: "uploaded", hash: unmatchedOpenHash, complete: true, status: "observed_chain_to_launchd",
                 detail: "match=exact_bytes;raw_bytes_not_stored;open_of_source_file_not_proven_by_this_record;synthetic_demo",
                 summary: "已上传。请求体匹配已登记文件，但这次传输记录没有看到打开。", count: 32),

            demo(id: attemptedClose, at: now.addingTimeInterval(-60), risk: .high, path: "/synthetic/demo/attempted.env",
                 action: "VERDICT", source: "sensitive_access_closed", tree: claude, agent: "Claude", bundle: "Claude.app",
                 destination: "https://example.invalid/demo-attempt", basis: "egress_proxy_http_body_match",
                 outcome: "upstream_http_500", verdict: "attempted", hash: attemptedHash, complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "match=exact_bytes;raw_bytes_not_stored;tls_intercept;synthetic_demo",
                 summary: "已尝试未成功。claude-helper 向 https://example.invalid/demo-attempt 发送的请求体匹配，但传输没有成功：upstream_http_500。",
                 related: [attemptedOpen, attemptedTransfer], count: 40),
            demo(id: attemptedTransfer, at: now.addingTimeInterval(-62), risk: .high, path: "/synthetic/demo/attempted.env",
                 action: "TRANSFER", source: "egress_transfer", tree: claude, agent: "Claude", bundle: "Claude.app",
                 destination: "https://example.invalid/demo-attempt", basis: "exact_bytes",
                 outcome: "upstream_http_500", verdict: "attempted", hash: attemptedHash, complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "match=exact_bytes;raw_bytes_not_stored;tls_intercept;synthetic_demo",
                 summary: "已尝试未成功。HTTPS 正文匹配，响应不是成功。临时 CA 没有装进登录钥匙串。", count: 40),
            demo(id: attemptedOpen, at: now.addingTimeInterval(-64), risk: .medium, path: "/synthetic/demo/attempted.env",
                 action: "OBSERVE", source: "sensitive_fd_observed", tree: claude, agent: "Claude", bundle: "Claude.app",
                 basis: "fd_observed", complete: true, status: "observed_chain_to_launchd",
                 detail: "descriptor_observed;bytes_read_unproven;not_an_upload;synthetic_demo",
                 summary: "Claude 的进程打开了 /synthetic/demo/attempted.env。这不是上传结论。"),

            demo(id: demoID(21), at: now.addingTimeInterval(-90), risk: .medium, path: "/synthetic/demo/partial.env",
                 action: "OBSERVE", source: "activity_observed",
                 tree: [demoNode(pid: 6102, ppid: 6199, name: "claude-helper", path: "/synthetic/Claude.app/Contents/Helpers/claude-helper", start: 1_700_000_220)],
                 agent: "Claude", bundle: "Claude.app", basis: "fd_observed", complete: false, status: "missing_parent",
                 detail: "sensitive_file_open:/synthetic/demo/partial.env;synthetic_demo",
                 summary: "Claude 的子进程打开了 /synthetic/demo/partial.env。父进程没有观察到。这不是上传结论。"),

            demo(id: cleanClose, at: now.addingTimeInterval(-120), risk: .low, path: "/synthetic/demo/clean.env",
                 action: "VERDICT", source: "sensitive_access_closed", tree: cursor, agent: "Cursor", bundle: "Cursor.app",
                 destination: "http://example.invalid/demo-clean", basis: "egress_proxy_watched_http_no_match",
                 outcome: "watched_http_no_registered_content", verdict: "not_found", complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "no_registered_content_in_inspected_body_or_channel_not_visible;synthetic_demo",
                 summary: "未发现。已查看 Cursor Helper 的明文 HTTP 出口（http://example.invalid/demo-clean），没有看到已登记文件 /synthetic/demo/clean.env 的内容。",
                 related: [cleanOpen, cleanTransfer]),
            demo(id: cleanTransfer, at: now.addingTimeInterval(-122), risk: .low, path: "",
                 action: "TRANSFER", source: "egress_transfer", tree: cursor, agent: "Cursor", bundle: "Cursor.app",
                 destination: "http://example.invalid/demo-clean", basis: "no_registered_whole_version_match",
                 outcome: "watched_http_no_registered_content", complete: true, status: "observed_chain_to_launchd",
                 detail: "inspected_http_body;registered_content_absent;raw_bytes_not_stored;synthetic_demo",
                 summary: "明文 HTTP 已查看，请求体里没有已登记文件的内容。"),
            demo(id: cleanOpen, at: now.addingTimeInterval(-124), risk: .medium, path: "/synthetic/demo/clean.env",
                 action: "OBSERVE", source: "sensitive_fd_observed", tree: cursor, agent: "Cursor", bundle: "Cursor.app",
                 basis: "fd_observed", complete: true, status: "observed_chain_to_launchd",
                 detail: "descriptor_observed;bytes_read_unproven;not_an_upload;synthetic_demo",
                 summary: "Cursor 的进程打开了 /synthetic/demo/clean.env。这不是上传结论。"),

            demo(id: hiddenClose, at: now.addingTimeInterval(-180), risk: .low, path: "/synthetic/demo/hidden.env",
                 action: "VERDICT", source: "sensitive_access_closed", tree: workbuddy, agent: "WorkBuddy", bundle: "WorkBuddy.app",
                 destination: "203.0.113.50:443/protocol=17", basis: "egress_channel_not_visible",
                 outcome: "udp_or_quic_body_not_visible", verdict: "not_visible", complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "no_registered_content_in_inspected_body_or_channel_not_visible;already_running_not_redirected;app_settings_not_modified;synthetic_demo",
                 summary: "看不到。看不到 WorkBuddy Helper 发往 203.0.113.50:443 的通道内容，因此不能判断已登记文件 /synthetic/demo/hidden.env 有没有发出去。",
                 related: [hiddenOpen, hiddenUDP, hiddenLive]),
            demo(id: hiddenUDP, at: now.addingTimeInterval(-182), risk: .medium, path: "",
                 action: "UNSEEN", source: "egress_channel_unseen", tree: workbuddy, agent: "WorkBuddy", bundle: "WorkBuddy.app",
                 destination: "203.0.113.50:443/protocol=17", basis: "socket_peer_without_payload",
                 outcome: "udp_or_quic_body_not_visible", verdict: "not_visible", complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "synthetic_demo",
                 summary: "看不到。只看到了 UDP 或 QUIC 对端，没有看到发送的字节。"),
            demo(id: hiddenLive, at: now.addingTimeInterval(-183), risk: .medium, path: "",
                 action: "UNSEEN", source: "egress_channel_unseen", tree: workbuddy, agent: "WorkBuddy", bundle: "WorkBuddy.app",
                 basis: "live_agent_tree_not_attached",
                 outcome: "live_agent_tree_not_proxied;already_running;app_settings_not_modified;user_space_cannot_redirect",
                 verdict: "not_visible", complete: true, status: "observed_chain_to_launchd",
                 detail: "already_running_not_redirected;app_settings_not_modified;synthetic_demo",
                 summary: "看不到。这个 Agent 在采集开始前已经在运行。没有修改它的 MCP 或应用设置，用户态也不能把已有进程的连接改道到本地代理。"),
            demo(id: hiddenOpen, at: now.addingTimeInterval(-184), risk: .medium, path: "/synthetic/demo/hidden.env",
                 action: "OBSERVE", source: "sensitive_fd_observed", tree: workbuddy, agent: "WorkBuddy", bundle: "WorkBuddy.app",
                 basis: "fd_observed", complete: true, status: "observed_chain_to_launchd",
                 detail: "descriptor_observed;bytes_read_unproven;not_an_upload;synthetic_demo",
                 summary: "WorkBuddy 的进程打开了 /synthetic/demo/hidden.env。这不是上传结论。"),

            demo(id: tlsClose, at: now.addingTimeInterval(-240), risk: .low, path: "/synthetic/demo/pinned.env",
                 action: "VERDICT", source: "sensitive_access_closed", tree: chatgpt, agent: "ChatGPT", bundle: "ChatGPT.app",
                 destination: "https://example.invalid:443", basis: "egress_channel_not_visible",
                 outcome: "tls_intercept_handshake_failed", verdict: "not_visible", complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "synthetic_demo",
                 summary: "看不到。到 https://example.invalid:443 的 TLS 没有完成代理侧握手，正文没有被检查。证书固定、客户端不信任临时 CA，或 QUIC 都会是这个结果。",
                 related: [tlsOpen, tlsUnseen]),
            demo(id: tlsUnseen, at: now.addingTimeInterval(-242), risk: .medium, path: "",
                 action: "UNSEEN", source: "egress_channel_unseen", tree: chatgpt, agent: "ChatGPT", bundle: "ChatGPT.app",
                 destination: "https://example.invalid:443", basis: "tls_intercept_handshake_failed",
                 outcome: "tls_intercept_handshake_failed", verdict: "not_visible", complete: true,
                 status: "observed_chain_to_launchd",
                 detail: "synthetic_demo",
                 summary: "看不到。到 https://example.invalid:443 的 TLS 没有完成代理侧握手，正文没有被检查。证书固定、客户端不信任临时 CA，或 QUIC 都会是这个结果。临时 CA 不会装进登录钥匙串。"),
            demo(id: tlsOpen, at: now.addingTimeInterval(-244), risk: .medium, path: "/synthetic/demo/pinned.env",
                 action: "OBSERVE", source: "sensitive_fd_observed", tree: chatgpt, agent: "ChatGPT", bundle: "ChatGPT.app",
                 basis: "fd_observed", complete: true, status: "observed_chain_to_launchd",
                 detail: "descriptor_observed;bytes_read_unproven;not_an_upload;synthetic_demo",
                 summary: "ChatGPT 的进程打开了 /synthetic/demo/pinned.env。这不是上传结论。"),

            demo(id: demoID(30), at: now.addingTimeInterval(-300), risk: .low, path: "/synthetic/demo/changed.env",
                 action: "CHANGE", source: "filesystem_change", attribution: "unavailable",
                 detail: "synthetic_demo;filesystem_change_without_actor",
                 summary: "合成演示：敏感路径发生了变化。文件系统事件没有行为进程。")
        ]
    }
}

private func demoID(_ n: Int) -> UUID {
    let digits = String(n)
    let suffix = String(repeating: "0", count: max(0, 12 - digits.count)) + digits
    return UUID(uuidString: "00000000-0000-4000-8000-\(suffix)")!
}

private func demoNode(pid: Int32, ppid: Int32, name: String, path: String, start: UInt64) -> ProcessNode {
    ProcessNode(pid: pid, ppid: ppid, name: name, path: path, startSeconds: start, startMicroseconds: 0)
}

private func demoTree(actor: Int32, parent: Int32, actorName: String, parentName: String,
                      actorPath: String, parentPath: String, actorStart: UInt64, parentStart: UInt64) -> [ProcessNode] {
    [
        demoNode(pid: actor, ppid: parent, name: actorName, path: actorPath, start: actorStart),
        demoNode(pid: parent, ppid: 1, name: parentName, path: parentPath, start: parentStart)
    ]
}

private func demo(id: UUID, at time: Date, risk: RiskLevel, path: String, action: String, source: String,
                  tree: [ProcessNode] = [], agent: String = "", bundle: String = "",
                  attribution: String = "synthetic_demo", destination: String = "", basis: String = "",
                  outcome: String = "", verdict: String = "", hash: String = "", complete: Bool? = nil,
                  status: String = "", detail: String = "", summary: String = "", related: [UUID] = [],
                  count: UInt64 = 0) -> EvidenceRecord {
    EvidenceRecord(
        id: id, timestamp: time, riskLevel: risk, targetResource: path, actionType: action, processTree: tree,
        sourceType: source, attribution: attribution, detail: detail, destination: destination,
        chainComplete: complete, evidenceBasis: basis, transferOutcome: outcome, classification: "synthetic_demo",
        count: count, summary: summary, uploadVerdict: verdict, owningAgentName: agent, owningAgentBundle: bundle,
        chainStatus: status, contentSHA256: hash, relatedEventIDs: related.map(\.uuidString)
    )
}
