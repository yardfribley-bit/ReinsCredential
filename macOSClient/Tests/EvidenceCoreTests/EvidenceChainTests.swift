import Foundation
import XCTest
@testable import EvidenceCore

final class EvidenceChainTests: XCTestCase {
    func testVerdictCodesNeverCollapseHiddenIntoNotFound() {
        let cases: [(String, UploadVerdictWord, String)] = [
            ("uploaded", .uploaded, "已上传"),
            ("attempted", .attempted, "已尝试未成功"),
            ("not_found", .notFound, "未发现"),
            ("not_visible", .notVisible, "看不到"),
            ("", .absent, "没有出口结论"),
            ("not_visible ", .unrecognized, "未识别的结论"),
            ("NOT_VISIBLE", .unrecognized, "未识别的结论"),
            ("未发现", .unrecognized, "未识别的结论"),
            ("看不到", .unrecognized, "未识别的结论")
        ]
        for (raw, word, label) in cases {
            let parsed = UploadVerdictWord.parse(raw)
            XCTAssertEqual(parsed, word, raw)
            XCTAssertEqual(parsed.chineseLabel, label, raw)
            if raw != "not_found" {
                XCTAssertNotEqual(parsed.chineseLabel, "未发现", raw)
            }
        }
        XCTAssertNotEqual(UploadVerdictWord.notVisible.chineseLabel, UploadVerdictWord.notFound.chineseLabel)
    }

    func testRelatedEventsBecomeOneChain() throws {
        let open = event(id: 1, type: "sensitive_fd_observed", path: "/synthetic/demo/uploaded.env",
                         tree: codexTree, agent: "Codex", bundle: "Codex.app", basis: "fd_observed",
                         complete: true, status: "observed_chain_to_launchd",
                         detail: "descriptor_observed;bytes_read_unproven;not_an_upload")
        let transfer = event(id: 2, type: "egress_transfer", path: "/synthetic/demo/uploaded.env",
                             tree: codexTree, agent: "Codex", bundle: "Codex.app", basis: "exact_bytes",
                             destination: "http://example.invalid/demo-upload",
                             outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                             verdict: "uploaded", hash: hash("ab"), complete: true,
                             status: "observed_chain_to_launchd",
                             detail: "match=exact_bytes;raw_bytes_not_stored", count: 48,
                             at: open.timestamp.addingTimeInterval(1))
        let close = event(id: 3, type: "sensitive_access_closed", path: "/synthetic/demo/uploaded.env",
                          tree: codexTree, agent: "Codex", bundle: "Codex.app",
                          basis: "egress_proxy_http_body_match",
                          destination: "http://example.invalid/demo-upload",
                          outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                          verdict: "uploaded", hash: hash("ab"), complete: true,
                          status: "observed_chain_to_launchd",
                          detail: "match=exact_bytes;raw_bytes_not_stored",
                          related: [open.id, transfer.id],
                          at: open.timestamp.addingTimeInterval(2))
        let chains = EvidenceChainBuilder.chains(from: [close, transfer, open])
        XCTAssertEqual(chains.count, 1)
        let chain = try XCTUnwrap(chains.first)
        XCTAssertEqual(Set(chain.memberIDs), Set([open.id, transfer.id, close.id]))
        XCTAssertEqual(chain.links.map(\.kind), ChainLinkKind.allCases)
        XCTAssertEqual(chain.owningAgentName, "Codex")
        XCTAssertEqual(chain.link(.agent)?.presence, .present)
        XCTAssertEqual(chain.link(.process)?.presence, .present)
        XCTAssertTrue(chain.link(.process)?.note.contains("进程链完整") == true)
        XCTAssertEqual(chain.openObserved, true)
        XCTAssertEqual(chain.link(.file)?.presence, .present)
        XCTAssertEqual(chain.link(.file)?.value, "/synthetic/demo/uploaded.env")
        XCTAssertEqual(chain.destination, "http://example.invalid/demo-upload")
        XCTAssertEqual(chain.payloadSHA256, hash("ab"))
        XCTAssertEqual(chain.matchKind, "exact_bytes")
        XCTAssertEqual(chain.verdict, .uploaded)
        XCTAssertEqual(chain.verdictLabel, "已上传")
        XCTAssertFalse(chain.payloadSHA256.contains("synthetic-value"))
    }

    func testBackendRelatedIDsJoinWithoutInventingAMissingOpen() throws {
        let openID = UUID(uuidString: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAA1")!
        let closeID = UUID(uuidString: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAA2")!
        let missing = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"
        let open = try decode(backend(id: openID, type: "sensitive_fd_observed", path: "/synthetic/demo/wire.env",
                                       basis: "fd_observed", verdict: ""))
        var closeFixture = backend(id: closeID, type: "sensitive_access_closed", path: "/synthetic/demo/wire.env",
                                    basis: "egress_channel_not_visible", verdict: "not_visible")
        closeFixture["related_event_ids"] = [openID.uuidString, missing]
        closeFixture["destination"] = "203.0.113.50:443/protocol=17"
        closeFixture["transfer_outcome"] = "udp_or_quic_body_not_visible"
        closeFixture["detail"] = "already_running_not_redirected;app_settings_not_modified"
        let close = try decode(closeFixture)
        XCTAssertEqual(close.relatedEventIDs, [openID.uuidString, missing])
        let chains = EvidenceChainBuilder.chains(from: [open, close])
        XCTAssertEqual(chains.count, 1)
        let chain = try XCTUnwrap(chains.first)
        XCTAssertEqual(chain.missingReferenceCount, 1)
        XCTAssertEqual(Set(chain.memberIDs), Set([open.id, close.id]))
        XCTAssertEqual(chain.verdict, .notVisible)
        XCTAssertEqual(chain.verdictLabel, "看不到")
        XCTAssertNotEqual(chain.verdict, .notFound)
        XCTAssertTrue(chain.channelReasons.contains { $0.contains("已经在运行") })
        XCTAssertTrue(chain.channelReasons.contains { $0.contains("UDP") || $0.contains("QUIC") })
        XCTAssertFalse(chain.reasonLine.contains("未发现。"))
    }

    func testIncompleteChainStaysIncomplete() throws {
        let record = event(id: 4, type: "activity_observed", path: "/synthetic/demo/partial.env",
                           tree: [node(pid: 6102, ppid: 6199, name: "claude-helper", path: "/synthetic/Claude.app/Contents/Helpers/claude-helper", start: 1_700_000_220)],
                           agent: "Claude", bundle: "Claude.app", basis: "fd_observed",
                           complete: false, status: "missing_parent",
                           detail: "sensitive_file_open:/synthetic/demo/partial.env")
        let chain = try XCTUnwrap(EvidenceChainBuilder.chains(from: [record]).first)
        XCTAssertEqual(chain.chainComplete, false)
        XCTAssertEqual(chain.link(.process)?.presence, .incomplete)
        XCTAssertNotEqual(chain.link(.process)?.presence, .present)
        XCTAssertFalse(chain.link(.process)?.value.contains("6199") == true)
        XCTAssertEqual(chain.verdict, .absent)
        XCTAssertNotEqual(chain.verdict, .notFound)
        XCTAssertNotEqual(chain.verdict, .notVisible)
        XCTAssertEqual(chain.link(.destination)?.presence, .missing)
        let markdown = EvidenceChainExport.markdown([chain])
        XCTAssertTrue(markdown.contains("进程链不完整"))
        XCTAssertFalse(markdown.contains("进程链完整"))
        XCTAssertEqual(chain.verdictLabel, "没有出口结论")
    }

    func testHiddenChannelsStayHiddenAcrossTheNewLabels() throws {
        let running = hidden(id: 11, basis: "live_agent_tree_not_attached",
                             outcome: "live_agent_tree_not_proxied;already_running;app_settings_not_modified;user_space_cannot_redirect",
                             detail: "already_running_not_redirected;app_settings_not_modified",
                             destination: "")
        let udp = hidden(id: 12, basis: "socket_peer_without_payload", outcome: "udp_or_quic_body_not_visible",
                         detail: "", destination: "203.0.113.50:443/protocol=17")
        let https = hidden(id: 13, basis: "tls_intercept_handshake_failed", outcome: "tls_intercept_handshake_failed",
                           detail: "", destination: "https://example.invalid:443")
        let clean = event(id: 14, type: "sensitive_access_closed", path: "/synthetic/demo/clean.env",
                          tree: cursorTree, agent: "Cursor", bundle: "Cursor.app",
                          basis: "egress_proxy_watched_http_no_match",
                          destination: "http://example.invalid/demo-clean",
                          outcome: "watched_http_no_registered_content", verdict: "not_found",
                          complete: true, status: "observed_chain_to_launchd")
        let chains = EvidenceChainBuilder.chains(from: [running, udp, https, clean])
        let hiddenChains = chains.filter { $0.verdictCode == "not_visible" }
        XCTAssertEqual(hiddenChains.count, 3)
        for chain in hiddenChains {
            XCTAssertEqual(chain.verdict, .notVisible)
            XCTAssertEqual(chain.verdictLabel, "看不到")
            XCTAssertNotEqual(chain.verdict, .notFound)
            XCTAssertNotEqual(chain.verdictLabel, "未发现")
            XCTAssertEqual(chain.link(.payload)?.presence, .missing)
            XCTAssertNotEqual(chain.link(.payload)?.value, "没有匹配到已登记内容")
            let markdown = EvidenceChainExport.markdown([chain])
            XCTAssertTrue(markdown.contains("出口结论：看不到"))
            XCTAssertFalse(markdown.contains("出口结论：未发现"))
            let document = try decodeExport(markdown: false, chains: [chain])
            XCTAssertEqual(document.chains.first?.verdict, "not_visible")
            XCTAssertEqual(document.chains.first?.verdictLabel, "看不到")
        }
        XCTAssertTrue(hiddenChains.contains { $0.channelReasons.contains { $0.contains("已经在运行") } })
        XCTAssertTrue(hiddenChains.contains { $0.channelReasons.contains { $0.contains("UDP") || $0.contains("QUIC") } })
        XCTAssertTrue(hiddenChains.contains { $0.channelReasons.contains { $0.contains("不信任临时 CA") || $0.contains("登录钥匙串") } })
        let found = try XCTUnwrap(chains.first { $0.verdictCode == "not_found" })
        XCTAssertEqual(found.verdict, .notFound)
        XCTAssertEqual(found.verdictLabel, "未发现")
        XCTAssertNotEqual(found.verdict, .notVisible)
    }

    func testBodyMatchWithoutOpenDoesNotInventAnOpen() throws {
        let secret = "synthetic-value-not-real-0123456789"
        let transfer = event(id: 20, type: "egress_transfer", path: "/synthetic/demo/matched-without-open.env",
                             tree: codexTree, agent: "Codex", bundle: "Codex.app", basis: "exact_bytes",
                             destination: "http://example.invalid/demo-unopened",
                             outcome: "upstream_http_2xx;application_receipt_requires_independent_verification",
                             verdict: "uploaded", hash: hash("ef"), complete: true,
                             status: "observed_chain_to_launchd",
                             detail: "match=exact_bytes;raw_bytes_not_stored;open_of_source_file_not_proven_by_this_record;token=\(secret)",
                             summary: "password=\(secret) SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef")
        let chain = try XCTUnwrap(EvidenceChainBuilder.chains(from: [transfer]).first)
        XCTAssertEqual(chain.kind, .transferWithoutOpen)
        XCTAssertFalse(chain.openObserved)
        XCTAssertEqual(chain.link(.file)?.presence, .unproven)
        XCTAssertEqual(chain.memberIDs, [transfer.id])
        XCTAssertEqual(chain.verdict, .uploaded)
        XCTAssertEqual(chain.payloadSHA256, hash("ef"))
        let markdown = EvidenceChainExport.markdown([chain])
        let json = EvidenceChainExport.json([chain])
        XCTAssertFalse(markdown.contains(secret))
        XCTAssertFalse(json.contains(secret))
        XCTAssertFalse(markdown.contains("SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef"))
        XCTAssertFalse(json.contains("SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef"))
        XCTAssertTrue(markdown.contains(hash("ef")))
        XCTAssertTrue(json.contains(hash("ef")))
        XCTAssertTrue(markdown.contains("没有看到打开") || chain.link(.file)?.note.contains("没有看到打开") == true)
    }

    func testCooccurrenceIsNotAnUploadAndFilesystemDoesNotInventAnActor() throws {
        let peer = event(id: 30, type: "sensitive_network_cooccurrence", path: "/synthetic/demo/co.env",
                         tree: codexTree, agent: "Codex", bundle: "Codex.app",
                         basis: "same_identity_descriptor_snapshot",
                         destination: "203.0.113.10:443/protocol=6",
                         detail: "Sensitive file descriptor and socket peer observed in the same sample; upload_unproven",
                         complete: true, status: "observed_chain_to_launchd")
        let change = event(id: 31, type: "filesystem_change", path: "/synthetic/demo/changed.env",
                           detail: "synthetic change")
        let chains = EvidenceChainBuilder.chains(from: [peer, change])
        let co = try XCTUnwrap(chains.first { $0.filePath == "/synthetic/demo/co.env" })
        XCTAssertEqual(co.verdict, .absent)
        XCTAssertNotEqual(co.verdict, .uploaded)
        XCTAssertNotEqual(co.verdict, .notFound)
        XCTAssertNotEqual(co.verdict, .notVisible)
        XCTAssertEqual(co.destination, "203.0.113.10:443/protocol=6")
        XCTAssertTrue(co.link(.destination)?.note.contains("不是上传") == true)
        XCTAssertEqual(co.link(.payload)?.presence, .missing)
        let file = try XCTUnwrap(chains.first { $0.filePath == "/synthetic/demo/changed.env" })
        XCTAssertEqual(file.link(.agent)?.presence, .missing)
        XCTAssertEqual(file.link(.process)?.presence, .missing)
        XCTAssertTrue(file.owningAgentName.isEmpty)
        XCTAssertTrue(file.link(.process)?.value == "缺失")
    }

    func testSamplesCoverFourVerdictsAndDoNotRelabelHiddenChannels() throws {
        let chains = EvidenceChainBuilder.chains(from: EvidenceRecord.sampleRecords)
        for word in [UploadVerdictWord.uploaded, .attempted, .notFound, .notVisible] {
            XCTAssertTrue(chains.contains { $0.verdict == word }, word.rawValue)
        }
        let hidden = chains.filter { $0.verdictCode == "not_visible" }
        XCTAssertGreaterThanOrEqual(hidden.count, 2)
        for chain in hidden {
            XCTAssertEqual(chain.verdictLabel, "看不到")
            XCTAssertNotEqual(chain.verdict, .notFound)
            let exported = try decodeExport(markdown: false, chains: [chain])
            XCTAssertEqual(exported.chains.first?.verdictLabel, "看不到")
            XCTAssertEqual(exported.chains.first?.verdict, "not_visible")
        }
        XCTAssertTrue(chains.contains { $0.chainComplete == false && $0.link(.process)?.presence == .incomplete })
        XCTAssertTrue(chains.contains { $0.kind == .transferWithoutOpen && $0.openObserved == false })
        XCTAssertTrue(chains.contains { $0.channelReasons.contains { $0.contains("已经在运行") } })
        XCTAssertTrue(chains.contains { $0.channelReasons.contains { $0.contains("UDP") || $0.contains("QUIC") } })
        XCTAssertTrue(chains.contains { $0.channelReasons.contains { $0.contains("不信任临时 CA") } })
        XCTAssertTrue(chains.contains { $0.verdict == .attempted && $0.channelReasons.contains { $0.contains("临时 CA") } })
        let sections = chains.groupedByOwningAgent()
        XCTAssertTrue(sections.contains { $0.title == "Codex" })
        XCTAssertEqual(sections.last?.title, "未归属")
    }

    func testExportWindowKeepsLabelsAndDropsChainsOutsideIt() throws {
        let early = event(id: 40, type: "sensitive_access_closed", path: "/synthetic/demo/early.env",
                          verdict: "not_visible", basis: "egress_channel_not_visible",
                          outcome: "udp_or_quic_body_not_visible", destination: "203.0.113.8:53/protocol=17",
                          at: Date(timeIntervalSince1970: 1_700_000_000))
        let late = event(id: 41, type: "sensitive_access_closed", path: "/synthetic/demo/late.env",
                         verdict: "not_found", basis: "egress_proxy_watched_http_no_match",
                         outcome: "watched_http_no_registered_content",
                         at: Date(timeIntervalSince1970: 1_700_000_100))
        let chains = EvidenceChainBuilder.chains(from: [early, late])
        let window = early.timestamp...early.timestamp
        let markdown = EvidenceChainExport.markdown(chains, window: window)
        XCTAssertTrue(markdown.contains("/synthetic/demo/early.env"))
        XCTAssertFalse(markdown.contains("/synthetic/demo/late.env"))
        XCTAssertTrue(markdown.contains("出口结论：看不到"))
        XCTAssertFalse(markdown.contains("出口结论：未发现"))
        let document = try decodeExport(markdown: false, chains: chains, window: window)
        XCTAssertEqual(document.chains.count, 1)
        XCTAssertEqual(document.chains.first?.verdictLabel, "看不到")
        XCTAssertEqual(document.rawSecretBytes, "omitted")
        XCTAssertEqual(document.inventedEvents, "none")
        XCTAssertEqual(document.verdictGlossary["not_visible"], "看不到")
        XCTAssertEqual(document.verdictGlossary["not_found"], "未发现")
    }

    private func decodeExport(markdown: Bool, chains: [EvidenceChain], window: ClosedRange<Date>? = nil) throws -> EvidenceChainDocument {
        _ = markdown
        let data = Data(EvidenceChainExport.json(chains, window: window).utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(EvidenceChainDocument.self, from: data)
    }

    private func hash(_ unit: String) -> String { String(repeating: unit, count: 32) }

    private func hidden(id: Int, basis: String, outcome: String, detail: String, destination: String) -> EvidenceRecord {
        event(id: id, type: "egress_channel_unseen", path: "", basis: basis, destination: destination,
              outcome: outcome, verdict: "not_visible", detail: detail, complete: true,
              status: "observed_chain_to_launchd", tree: workbuddyTree, agent: "WorkBuddy", bundle: "WorkBuddy.app")
    }

    private func event(id: Int, type: String, path: String, tree: [ProcessNode] = [], agent: String = "",
                       bundle: String = "", basis: String = "", destination: String = "", outcome: String = "",
                       verdict: String = "", hash: String = "", complete: Bool? = nil, status: String = "",
                       detail: String = "", summary: String = "", related: [UUID] = [], count: UInt64 = 0,
                       at: Date = Date(timeIntervalSince1970: 1_794_355_200)) -> EvidenceRecord {
        EvidenceRecord(
            id: demoID(id), timestamp: at, riskLevel: .medium, targetResource: path, actionType: "OBSERVE",
            processTree: tree, sourceType: type, attribution: "synthetic_demo", detail: detail,
            destination: destination, chainComplete: complete, evidenceBasis: basis, transferOutcome: outcome,
            summary: summary, uploadVerdict: verdict, owningAgentName: agent, owningAgentBundle: bundle,
            chainStatus: status, contentSHA256: hash, relatedEventIDs: related.map(\.uuidString), count: count
        )
    }

    private func demoID(_ n: Int) -> UUID {
        let digits = String(n)
        let suffix = String(repeating: "0", count: max(0, 12 - digits.count)) + digits
        return UUID(uuidString: "10000000-0000-4000-8000-\(suffix)")!
    }

    private var codexTree: [ProcessNode] {
        [node(pid: 5101, ppid: 5100, name: "codex", path: "/synthetic/Codex.app/Contents/MacOS/codex", start: 1_700_000_100),
         node(pid: 5100, ppid: 1, name: "Codex", path: "/synthetic/Codex.app/Contents/MacOS/Codex", start: 1_700_000_000)]
    }
    private var cursorTree: [ProcessNode] {
        [node(pid: 7101, ppid: 7100, name: "Cursor Helper", path: "/synthetic/Cursor.app/Contents/MacOS/Cursor Helper", start: 1_700_000_310)]
    }
    private var workbuddyTree: [ProcessNode] {
        [node(pid: 8101, ppid: 8100, name: "WorkBuddy Helper", path: "/synthetic/WorkBuddy.app/Contents/MacOS/WorkBuddy", start: 1_700_000_410)]
    }
    private func node(pid: Int32, ppid: Int32, name: String, path: String, start: UInt64) -> ProcessNode {
        ProcessNode(pid: pid, ppid: ppid, name: name, path: path, startSeconds: start, startMicroseconds: 0)
    }

    private func decode(_ fixture: [String: Any]) throws -> EvidenceRecord {
        try JSONDecoder().decode(EvidenceRecord.self, from: JSONSerialization.data(withJSONObject: fixture))
    }

    private func backend(id: UUID, type: String, path: String, basis: String, verdict: String) -> [String: Any] {
        ["schema_version": 2, "event_id": id.uuidString, "timestamp": UInt64(1_794_355_200_000_000),
         "timestamp_unit": "unix_microseconds", "risk_level": "Medium", "target_resource": path,
         "type": type, "attribution": "synthetic_demo", "evidence_basis": basis, "upload_verdict": verdict,
         "actor_process": ["process": entry(pid: 42, ppid: 40, name: "codex", path: "/synthetic/Codex.app/Contents/MacOS/codex", start: 1_700_000_100),
                           "ppid_tree": [entry(pid: 40, ppid: 1, name: "Codex", path: "/synthetic/Codex.app/Contents/MacOS/Codex", start: 1_700_000_000)],
                           "chain_complete": true, "chain_status": "observed_chain_to_launchd",
                           "classification": "known_agent_candidate",
                           "owning_agent": ["name": "Codex", "bundle": "Codex.app"]]]
    }

    private func entry(pid: Int, ppid: Int, name: String, path: String, start: UInt64) -> [String: Any] {
        ["identity": ["pid": pid, "start_seconds": start, "start_microseconds": 0],
         "ppid": ppid, "name": name, "executable": path]
    }
}
