import Foundation
import XCTest
@testable import EvidenceCore

final class EvidenceModelTests: XCTestCase {
    func testCanonicalRoundTripPreservesEveryFieldAndProcessUUID() throws {
        let node = ProcessNode(id: UUID(uuidString: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")!,
                               pid: 200, ppid: 100, name: "synthetic-agent", path: "/synthetic/agent",
                               startSeconds: 1_735_689_000, startMicroseconds: 123)
        let original = EvidenceRecord(id: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
            timestamp: Date(timeIntervalSince1970: 1_735_689_600.123456), riskLevel: .high,
            targetResource: "/synthetic/secret\n\"key", actionType: "READ", processTree: [node],
            sourceType: "explicit_action", attribution: "synthetic", detail: "测试详情",
            destination: "https://example.invalid/receiver", chainComplete: false,
            evidenceBasis: "synthetic_fixture", transferOutcome: "not_sent", classification: "candidate")
        let bytes = try JSONEncoder().encode(original)
        let first = try JSONDecoder().decode(EvidenceRecord.self, from: bytes)
        let second = try JSONDecoder().decode(EvidenceRecord.self, from: bytes)
        XCTAssertEqual(first, original)
        XCTAssertEqual(second.processTree.first?.id, node.id)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(object["riskLevel"] as? String, "HIGH")
        XCTAssertNil(object["schema_version"], "Client encoding must not impersonate the backend schema")
    }

    func testBackendRiskCasingAndMicrosecondTimestamp() throws {
        for (raw, expected) in [("High", RiskLevel.high), ("Medium", .medium), ("Low", .low)] {
            var fixture = backendFixture()
            fixture["risk_level"] = raw
            let record = try decode(fixture)
            XCTAssertEqual(record.riskLevel, expected)
            XCTAssertEqual(record.timestamp.timeIntervalSince1970, 1_735_689_600.123456,
                           accuracy: 0.000001)
        }
    }

    func testBackendTreeIsActorFirstWithNearestParentFirst() throws {
        let record = try decode(backendFixture())
        XCTAssertEqual(record.processTree.map(\.pid), [42, 40, 1])
        XCTAssertEqual(record.processTree.map(\.ppid), [40, 1, 0])
        XCTAssertEqual(record.processTree.map(\.name), ["synthetic-agent", "launcher", "init"])
        XCTAssertEqual(record.processTree.map(\.path), ["/synthetic/agent", "/synthetic/launcher", "/synthetic/init"])
        XCTAssertEqual(record.chainComplete, false)
        XCTAssertEqual(record.classification, "agent_candidate")
        XCTAssertEqual(record.processTree[0].startSeconds, 1_735_689_500)
        XCTAssertEqual(record.processTree[0].startMicroseconds, 42)
    }

    func testBackendIdentityStableAcrossEventsAndDistinctAfterPIDReuse() throws {
        let original = try decode(backendFixture())
        var anotherEvent = backendFixture()
        anotherEvent["event_id"] = "22222222-2222-4222-8222-222222222222"
        let repeatObservation = try decode(anotherEvent)
        XCTAssertEqual(original.processTree.map(\.id), repeatObservation.processTree.map(\.id))

        var replacement = backendFixture()
        var actor = try XCTUnwrap(replacement["actor_process"] as? [String: Any])
        var process = try XCTUnwrap(actor["process"] as? [String: Any])
        var identity = try XCTUnwrap(process["identity"] as? [String: Any])
        identity["start_microseconds"] = 43
        process["identity"] = identity
        actor["process"] = process
        replacement["actor_process"] = actor
        let reusedPID = try decode(replacement)
        XCTAssertEqual(original.processTree[0].pid, reusedPID.processTree[0].pid)
        XCTAssertNotEqual(original.processTree[0].id, reusedPID.processTree[0].id)
        XCTAssertEqual(original.processTree[1].id, reusedPID.processTree[1].id)
    }

    func testPassiveEventsNeverInventReadWriteOrActor() throws {
        for (source, expectedAction) in [("filesystem_change", "CHANGE"),
                                         ("sensitive_fd_observed", "OBSERVE"),
                                         ("process_discovered", "OBSERVE"),
                                         ("unknown_future_type", "OBSERVE")] {
            var fixture = backendFixture()
            fixture["type"] = source
            fixture["actor_process"] = NSNull()
            fixture.removeValue(forKey: "attribution")
            let record = try decode(fixture)
            XCTAssertEqual(record.actionType, expectedAction)
            XCTAssertTrue(record.processTree.isEmpty)
            XCTAssertNil(record.chainComplete)
            XCTAssertEqual(record.attribution, "unavailable")
        }
    }

    func testGatewayActionsPreserveEvidenceStrength() throws {
        for (source, action) in [("sensitive_content_delivered", "DELIVER"),
                                 ("sensitive_payload_observed", "SUBMIT"),
                                 ("payload_observed", "SUBMIT"),
                                 ("transfer_result", "TRANSFER"), ("sensor_gap", "GAP")] {
            var fixture = backendFixture()
            fixture["type"] = source
            fixture["evidence_basis"] = "synthetic_hash_match"
            fixture["transfer_outcome"] = "failed"
            fixture["destination"] = "https://example.invalid/receiver"
            let record = try decode(fixture)
            XCTAssertEqual(record.actionType, action)
            XCTAssertEqual(record.evidenceBasis, "synthetic_hash_match")
            XCTAssertEqual(record.transferOutcome, "failed")
            XCTAssertEqual(record.destination, "https://example.invalid/receiver")
        }
    }

    func testInvalidBackendIdentityAndMetadataAreRejected() throws {
        let invalid: [(String, Any)] = [
            ("schema_version", 1), ("schema_version", 3),
            ("timestamp_unit", "unix_seconds"), ("timestamp", -1),
            ("timestamp", 1.5), ("timestamp", "1735689600123456"),
            ("timestamp", UInt64(253_402_300_800_000_000)),
            ("risk_level", "CRITICAL"), ("event_id", "not-a-uuid")
        ]
        for (key, value) in invalid {
            var fixture = backendFixture()
            fixture[key] = value
            XCTAssertThrowsError(try decode(fixture), "Invalid \(key)=\(value) must fail")
        }
        var missingUnit = backendFixture()
        missingUnit.removeValue(forKey: "timestamp_unit")
        XCTAssertThrowsError(try decode(missingUnit))
    }

    func testInvalidCanonicalProcessUUIDIsRejected() throws {
        let data = Data(#"{"id":"not-a-uuid","pid":42,"ppid":1,"name":"test","path":"/synthetic/agent"}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ProcessNode.self, from: data))
    }

    func testCppSerializerFixture() async throws {
        guard let path = ProcessInfo.processInfo.environment["REINS_BACKEND_FIXTURE"] else {
            throw XCTSkip("Run scripts/check.sh to generate the fixture with the actual C++ ToJson serializer")
        }
        let imported = try await EvidenceLogReader.read(url: URL(fileURLWithPath: path))
        XCTAssertEqual(imported.records.count, 2)
        XCTAssertTrue(imported.rejectedLines.isEmpty)
        XCTAssertFalse(imported.incompleteTail)
        let event = try XCTUnwrap(imported.records.first {
            $0.id == UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        })
        XCTAssertEqual(event.riskLevel, .medium)
        XCTAssertEqual(event.sourceType, "sensitive_fd_observed")
        XCTAssertEqual(event.actionType, "OBSERVE")
        XCTAssertEqual(event.timestamp.timeIntervalSince1970, 1_735_689_600.123456, accuracy: 0.000001)
        XCTAssertEqual(event.targetResource, "/synthetic/secret\n\"key")
        XCTAssertEqual(event.processTree.map(\.pid), [4202, 4201])
        XCTAssertEqual(event.processTree.map(\.ppid), [4201, 1])
        XCTAssertEqual(event.processTree.map(\.name), ["demo-agent", "launcher"])
        XCTAssertEqual(event.processTree.map(\.path), ["/synthetic/agent", "/synthetic/launcher"])
        XCTAssertEqual(event.attribution, "observed_fd_only")
        XCTAssertEqual(event.chainComplete, false)

        let change = try XCTUnwrap(imported.records.first {
            $0.id == UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
        })
        XCTAssertEqual(change.riskLevel, .low)
        XCTAssertEqual(change.timestamp.timeIntervalSince1970, 1_735_689_600.123457, accuracy: 0.000001)
        XCTAssertEqual(change.actionType, "CHANGE")
        XCTAssertEqual(change.targetResource, "/synthetic/.env")
        XCTAssertTrue(change.processTree.isEmpty)
    }

    private func decode(_ fixture: [String: Any]) throws -> EvidenceRecord {
        try JSONDecoder().decode(EvidenceRecord.self, from: JSONSerialization.data(withJSONObject: fixture))
    }

    private func backendFixture() -> [String: Any] {
        ["schema_version": 2, "event_id": "11111111-1111-4111-8111-111111111111",
         "timestamp": UInt64(1_735_689_600_123_456), "timestamp_unit": "unix_microseconds",
         "risk_level": "Medium", "target_resource": "/synthetic/.env",
         "type": "sensitive_fd_observed", "attribution": "observed_fd_only",
         "actor_process": ["process": entry(pid: 42, ppid: 40, name: "synthetic-agent", path: "/synthetic/agent", start: 1_735_689_500),
                           "ppid_tree": [entry(pid: 40, ppid: 1, name: "launcher", path: "/synthetic/launcher", start: 1_735_689_400),
                                         entry(pid: 1, ppid: 0, name: "init", path: "/synthetic/init", start: 1_735_689_000)],
                           "chain_complete": false, "classification": "agent_candidate"]]
    }

    private func entry(pid: Int, ppid: Int, name: String, path: String, start: UInt64) -> [String: Any] {
        ["identity": ["pid": pid, "start_seconds": start, "start_microseconds": 42],
         "ppid": ppid, "name": name, "executable": path]
    }
}
