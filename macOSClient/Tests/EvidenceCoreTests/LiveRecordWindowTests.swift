import Foundation
import XCTest
@testable import EvidenceCore

final class LiveRecordWindowTests: XCTestCase {
    func testCoverageFloodCannotEvictClosuresFromTheChainList() {
        let close = record("sensitive_access_closed", path: "/tmp/canary.txt", verdict: "uploaded",
                           destination: "192.168.1.11:53429", basis: "flow_txbytes",
                           outcome: "flow_txbytes;left_host;tx_sum=180")
        let transfer = record("egress_transfer", path: "/tmp/canary.txt", verdict: "uploaded",
                              destination: "192.168.1.11:53429", basis: "flow_txbytes")
        let open = record("sensitive_fd_observed", path: "/tmp/canary.txt", basis: "fd_observed")
        var sets = LiveRecordWindow.merge(events: [], chain: [], incoming: [open, transfer, close])
        var stamp = Date(timeIntervalSince1970: 1_700_000_000)
        for chunk in 0..<8 {
            var flood: [EvidenceRecord] = []
            flood.reserveCapacity(2_000)
            for index in 0..<2_000 {
                stamp = stamp.addingTimeInterval(0.01)
                let coverage = chunk.isMultiple(of: 2) && index.isMultiple(of: 5)
                flood.append(record(coverage ? "coverage" : "activity_observed",
                                    path: "",
                                    at: stamp,
                                    name: "inventory-\(chunk)-\(index)"))
            }
            sets = LiveRecordWindow.merge(events: sets.events, chain: sets.chain, incoming: flood)
        }
        XCTAssertLessThanOrEqual(sets.events.count, LiveRecordWindow.eventCapacity)
        XCTAssertFalse(sets.events.contains { $0.id == close.id })
        XCTAssertTrue(sets.chain.contains { $0.id == close.id })
        XCTAssertTrue(sets.chain.contains { $0.id == transfer.id })
        XCTAssertTrue(sets.chain.contains { $0.id == open.id })
        XCTAssertFalse(sets.chain.contains { $0.sourceType == "coverage" })
        XCTAssertFalse(sets.chain.contains { $0.sourceType == "activity_observed" && $0.targetResource.isEmpty })
        let chains = EvidenceChainBuilder.chains(from: sets.chain)
        XCTAssertFalse(chains.isEmpty)
        let chain = chains.first { $0.filePath == "/tmp/canary.txt" }
        XCTAssertEqual(chain?.verdict, .uploaded)
        XCTAssertEqual(chain?.destination, "192.168.1.11:53429")
        XCTAssertEqual(chain?.verdictCode, "uploaded")
        XCTAssertNotEqual(chain?.verdict, .notFound)
        XCTAssertNotEqual(chain?.verdict, .notVisible)
    }

    private func record(_ type: String, path: String, verdict: String = "", destination: String = "",
                        basis: String = "", outcome: String = "", at: Date = Date(timeIntervalSince1970: 1_700_000_000),
                        name: String = "RCQAUpload") -> EvidenceRecord {
        EvidenceRecord(
            timestamp: at, riskLevel: .high, targetResource: path, actionType: "OBSERVE",
            processTree: [ProcessNode(pid: 42, ppid: 1, name: name,
                                      path: "/tmp/RCQAUpload.app/Contents/MacOS/RCQAUpload",
                                      startSeconds: 10, startMicroseconds: 1)],
            sourceType: type, destination: destination, evidenceBasis: basis, transferOutcome: outcome,
            uploadVerdict: verdict, owningAgentName: "RCQAUpload", owningAgentBundle: "RCQAUpload.app"
        )
    }
}
