import XCTest
@testable import EvidenceCore

final class ClosurePresentationTests: XCTestCase {
    func testEmptyLaunchSummaryIsZero() {
        let counts = ClosureListing.counts(of: [])
        XCTAssertEqual(counts.uploaded, 0)
        XCTAssertEqual(counts.attempted, 0)
        XCTAssertEqual(counts.notFound, 0)
        XCTAssertEqual(counts.notVisible, 0)
        XCTAssertTrue(counts.notVisibleReasonKeys.isEmpty)
    }

    func testWindowFrameIsClampedOntoTheVisibleScreen() {
        let visible = CGRect(x: 0, y: 0, width: 1_440, height: 900)
        let saved = CGRect(x: -228, y: 40, width: 164, height: 164)
        let frame = WindowPlacement.clamped(saved: saved, visible: visible)
        XCTAssertGreaterThanOrEqual(frame.minX, visible.minX)
        XCTAssertGreaterThanOrEqual(frame.minY, visible.minY)
        XCTAssertLessThanOrEqual(frame.maxX, visible.maxX)
        XCTAssertLessThanOrEqual(frame.maxY, visible.maxY)
        XCTAssertGreaterThanOrEqual(frame.width, WindowPlacement.minimum.width)
        XCTAssertGreaterThanOrEqual(frame.height, WindowPlacement.minimum.height)
        XCTAssertNotEqual(frame.origin.x, -228)
    }

    func testCurrentRunIsNewestFirstAndHistoryKeepsOlderDaysApart() {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        let older = close(verdict: "uploaded", at: start.addingTimeInterval(-86_400), name: "RCQAUpload",
                          destination: "192.168.1.11:53429", basis: "flow_txbytes", outcome: "flow_txbytes;left_host")
        let yesterdayLater = close(verdict: "not_visible", at: start.addingTimeInterval(-86_000), name: "RCQATLSHello",
                                   destination: "192.168.1.11:53431", basis: "observation_impossible",
                                   outcome: "tls_handshake_body_not_visible")
        let first = close(verdict: "attempted", at: start.addingTimeInterval(10), name: "RCQARefused",
                          destination: "192.168.1.11:54630", basis: "flow_attempt", outcome: "flow_attempt")
        let second = close(verdict: "uploaded", at: start.addingTimeInterval(40), name: "RCQAUpload",
                           destination: "192.168.1.11:54629", basis: "flow_txbytes", outcome: "flow_txbytes;left_host")
        let split = ClosureListing.partition([older, second, first, yesterdayLater], runStartedAt: start)
        XCTAssertEqual(split.current.map(\.id), [second.id, first.id])
        XCTAssertEqual(split.history.map(\.id), [yesterdayLater.id, older.id])
        XCTAssertTrue(split.current.allSatisfy { $0.timestamp >= start.addingTimeInterval(-2) })
        XCTAssertTrue(split.history.allSatisfy { $0.timestamp < start.addingTimeInterval(-2) })
        let days = ClosureListing.historyDays(split.history, calendar: Calendar(identifier: .gregorian))
        XCTAssertEqual(days.count, 1)
        XCTAssertEqual(days[0].chains.map(\.id), [yesterdayLater.id, older.id])
        XCTAssertFalse(days[0].chains.contains { split.current.map(\.id).contains($0.id) })
    }

    func testSelfCheckIsExcludedFromUploadedCounts() {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        let real = close(verdict: "uploaded", at: start, name: "RCQAUpload", bundle: "RCQAUpload.app",
                         destination: "192.168.1.11:54629", basis: "flow_txbytes", outcome: "flow_txbytes;left_host")
        let canary = close(verdict: "uploaded", at: start.addingTimeInterval(1), name: "ReinsRuntime", bundle: "ReinsRuntime",
                           destination: "http://127.0.0.1:53978/upload", basis: "egress_proxy_http_body_match",
                           outcome: "upstream_http_2xx")
        let loopback = close(verdict: "not_found", at: start.addingTimeInterval(2), name: "RCQALoop", bundle: "RCQALoop.app",
                             destination: "127.0.0.1:54628", basis: "live_agent_observed",
                             outcome: "live_agent_observed_loopback_not_off_host")
        let hidden = close(verdict: "not_visible", at: start.addingTimeInterval(3), name: "RCQATLSHello", bundle: "RCQATLSHello.app",
                           destination: "192.168.1.11:54631", basis: "observation_impossible",
                           outcome: "tls_handshake_body_not_visible")
        XCTAssertTrue(ClosureListing.isSelfCheck(canary))
        XCTAssertFalse(ClosureListing.isSelfCheck(real))
        XCTAssertFalse(ClosureListing.isSelfCheck(loopback))
        let counts = ClosureListing.counts(of: [real, canary, loopback, hidden])
        XCTAssertEqual(counts.uploaded, 1)
        XCTAssertEqual(counts.notFound, 1)
        XCTAssertEqual(counts.notVisible, 1)
        XCTAssertEqual(counts.notVisibleReasonKeys, ["basis.tlsHandshake"])
    }

    func testEveryBasisMapsToAStableKeyAndHostPortDropsTheProtocolSuffix() {
        for (basis, expected) in ClosureExplanation.basisKeys {
            XCTAssertEqual(ClosureExplanation.key(basis: basis, outcome: ""), expected, basis)
            XCTAssertFalse(expected.isEmpty)
            XCTAssertNotEqual(expected, basis)
        }
        XCTAssertEqual(ClosureExplanation.key(basis: "", outcome: "flow_txbytes;left_host;tx_sum=1646"), "basis.flowTxbytes")
        XCTAssertEqual(ClosureExplanation.key(basis: "", outcome: "tls_handshake_body_not_visible"), "basis.tlsHandshake")
        XCTAssertEqual(ClosureExplanation.key(basis: "flow_txbytes", outcome: "flow_txbytes_udp;left_host"), "basis.flowTxbytesUdp")
        XCTAssertEqual(ClosureExplanation.key(basis: "gzip:exact_bytes", outcome: ""), "basis.gzip")
        XCTAssertEqual(ClosureListing.hostPort("192.168.1.11:54629/protocol=6"), "192.168.1.11:54629")
        XCTAssertEqual(ClosureListing.hostPort("http://127.0.0.1:53978/upload"), "127.0.0.1:53978")
        let gaps = CoverageNotice.keys(partialDescriptors: 2, validationFailed: 0, unavailable: 1, enumerationIncomplete: true, droppedEvents: false)
        XCTAssertEqual(gaps, ["coverage.descriptors", "coverage.unreadable", "coverage.enumeration"])
    }

    private func close(verdict: String, at: Date, name: String, bundle: String? = nil, destination: String, basis: String, outcome: String) -> EvidenceChain {
        let record = EvidenceRecord(
            timestamp: at, riskLevel: .high, targetResource: "/tmp/canary.txt", actionType: "OBSERVE",
            processTree: [ProcessNode(pid: 42, ppid: 1, name: name, path: "/tmp/\(name).app/Contents/MacOS/\(name)", startSeconds: 10, startMicroseconds: 1)],
            sourceType: "sensitive_access_closed", destination: destination, evidenceBasis: basis, transferOutcome: outcome,
            uploadVerdict: verdict, owningAgentName: name, owningAgentBundle: bundle ?? "\(name).app"
        )
        let chains = EvidenceChainBuilder.chains(from: [record])
        XCTAssertEqual(chains.count, 1)
        return chains[0]
    }
}
