import CryptoKit
import Foundation

/// PID alone is not a process identity. Backend records include the start time.
public struct ProcessNode: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public let pid: Int32
    public let ppid: Int32
    public let name: String
    public let path: String
    public let startSeconds: UInt64?
    public let startMicroseconds: UInt64?

    public init(id: UUID = UUID(), pid: Int32, ppid: Int32, name: String, path: String,
                startSeconds: UInt64? = nil, startMicroseconds: UInt64? = nil) {
        self.id = id
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.path = path
        self.startSeconds = startSeconds
        self.startMicroseconds = startMicroseconds
    }

    enum CodingKeys: String, CodingKey {
        case id, pid, ppid, name, path, startSeconds, startMicroseconds
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Decode the stored UUID rather than using an immutable default that
        // synthesized Codable silently replaces on every decode.
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        pid = try c.decode(Int32.self, forKey: .pid)
        ppid = try c.decode(Int32.self, forKey: .ppid)
        name = try c.decode(String.self, forKey: .name)
        path = try c.decode(String.self, forKey: .path)
        startSeconds = try c.decodeIfPresent(UInt64.self, forKey: .startSeconds)
        startMicroseconds = try c.decodeIfPresent(UInt64.self, forKey: .startMicroseconds)
    }
}

public enum RiskLevel: String, Codable, CaseIterable, Sendable {
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let value = try c.decode(String.self)
        guard let risk = Self(rawValue: value.uppercased()) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unknown risk level: \(value)")
        }
        self = risk
    }
}

public struct EvidenceRecord: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let riskLevel: RiskLevel
    public let targetResource: String
    /// READ / WRITE / EXEC for explicit action records. Passive observations use
    /// OBSERVE / CHANGE, because an open descriptor does not prove a read.
    public let actionType: String
    /// Actor first, then nearest parent through oldest observed ancestor.
    public let processTree: [ProcessNode]
    public let sourceType: String
    public let attribution: String
    public let detail: String
    public let destination: String
    public let chainComplete: Bool?
    public let evidenceBasis: String
    public let transferOutcome: String
    public let classification: String
    public let metrics: [String: UInt64]
    public let count: UInt64
    public let sessionID: String?

    public init(id: UUID = UUID(), timestamp: Date, riskLevel: RiskLevel,
                targetResource: String, actionType: String, processTree: [ProcessNode],
                sourceType: String = "", attribution: String = "", detail: String = "",
                destination: String = "", chainComplete: Bool? = nil,
                evidenceBasis: String = "", transferOutcome: String = "", classification: String = "",
                metrics: [String: UInt64] = [:], count: UInt64 = 0, sessionID: String? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.riskLevel = riskLevel
        self.targetResource = targetResource
        self.actionType = actionType
        self.processTree = processTree
        self.sourceType = sourceType
        self.attribution = attribution
        self.detail = detail
        self.destination = destination
        self.chainComplete = chainComplete
        self.evidenceBasis = evidenceBasis
        self.transferOutcome = transferOutcome
        self.classification = classification
        self.metrics = metrics
        self.count = count
        self.sessionID = sessionID
    }

    enum CodingKeys: String, CodingKey {
        case id, timestamp, riskLevel, targetResource, actionType, processTree
        case sourceType, attribution, detail, destination, chainComplete
        case evidenceBasis, transferOutcome, classification
        case metrics, count, sessionID, backendSession = "session_id"
        case schemaVersion = "schema_version", eventID = "event_id"
        case timestampUnit = "timestamp_unit", backendRisk = "risk_level"
        case backendTarget = "target_resource", type, actor = "actor_process"
        case backendBasis = "evidence_basis", backendOutcome = "transfer_outcome"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if c.contains(.schemaVersion) {
            let version = try c.decode(Int.self, forKey: .schemaVersion)
            guard version == 2 else {
                throw DecodingError.dataCorruptedError(forKey: .schemaVersion, in: c,
                    debugDescription: "Unsupported evidence schema \(version)")
            }
            guard try c.decode(String.self, forKey: .timestampUnit) == "unix_microseconds" else {
                throw DecodingError.dataCorruptedError(forKey: .timestampUnit, in: c,
                    debugDescription: "Expected Unix microseconds")
            }
            id = try c.decode(UUID.self, forKey: .eventID)
            let micros = try c.decode(UInt64.self, forKey: .timestamp)
            guard micros <= 253_402_300_799_999_999 else {
                throw DecodingError.dataCorruptedError(forKey: .timestamp, in: c,
                    debugDescription: "Timestamp exceeds supported calendar range")
            }
            timestamp = Date(timeIntervalSince1970: Double(micros) / 1_000_000)
            riskLevel = try c.decode(RiskLevel.self, forKey: .backendRisk)
            targetResource = try c.decode(String.self, forKey: .backendTarget)
            sourceType = try c.decode(String.self, forKey: .type)
            // Preserve evidence strength instead of guessing READ/EXEC from a name.
            switch sourceType {
            case "filesystem_change": actionType = "CHANGE"
            case "sensitive_content_delivered": actionType = "DELIVER"
            case "sensitive_payload_observed", "payload_observed": actionType = "SUBMIT"
            case "transfer_result": actionType = "TRANSFER"
            case "sensor_gap": actionType = "GAP"
            case "sensitive_network_cooccurrence": actionType = "CORRELATE"
            default: actionType = "OBSERVE"
            }
            let actor = try c.decodeIfPresent(BackendActor.self, forKey: .actor)
            processTree = actor.map { [$0.process.node] + $0.parents.map(\.node) } ?? []
            chainComplete = actor?.chainComplete
            classification = actor?.classification ?? ""
            evidenceBasis = try c.decodeIfPresent(String.self, forKey: .backendBasis) ?? ""
            transferOutcome = try c.decodeIfPresent(String.self, forKey: .backendOutcome) ?? ""
        } else {
            id = try c.decode(UUID.self, forKey: .id)
            timestamp = try c.decode(Date.self, forKey: .timestamp)
            riskLevel = try c.decode(RiskLevel.self, forKey: .riskLevel)
            targetResource = try c.decode(String.self, forKey: .targetResource)
            actionType = try c.decode(String.self, forKey: .actionType)
            processTree = try c.decode([ProcessNode].self, forKey: .processTree)
            sourceType = try c.decodeIfPresent(String.self, forKey: .sourceType) ?? ""
            chainComplete = try c.decodeIfPresent(Bool.self, forKey: .chainComplete)
            evidenceBasis = try c.decodeIfPresent(String.self, forKey: .evidenceBasis) ?? ""
            transferOutcome = try c.decodeIfPresent(String.self, forKey: .transferOutcome) ?? ""
            classification = try c.decodeIfPresent(String.self, forKey: .classification) ?? ""
        }
        attribution = try c.decodeIfPresent(String.self, forKey: .attribution) ?? "unavailable"
        detail = try c.decodeIfPresent(String.self, forKey: .detail) ?? ""
        destination = try c.decodeIfPresent(String.self, forKey: .destination) ?? ""
        metrics = try c.decodeIfPresent([String: UInt64].self, forKey: .metrics) ?? [:]
        count = try c.decodeIfPresent(UInt64.self, forKey: .count) ?? 0
        sessionID = try c.decodeIfPresent(String.self, forKey: c.contains(.schemaVersion) ? .backendSession : .sessionID)
    }

    /// The client format has camelCase keys. This does not rewrite backend logs.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(timestamp, forKey: .timestamp)
        try c.encode(riskLevel, forKey: .riskLevel)
        try c.encode(targetResource, forKey: .targetResource)
        try c.encode(actionType, forKey: .actionType)
        try c.encode(processTree, forKey: .processTree)
        try c.encode(sourceType, forKey: .sourceType)
        try c.encode(attribution, forKey: .attribution)
        try c.encode(detail, forKey: .detail)
        try c.encode(destination, forKey: .destination)
        try c.encodeIfPresent(chainComplete, forKey: .chainComplete)
        try c.encode(evidenceBasis, forKey: .evidenceBasis)
        try c.encode(transferOutcome, forKey: .transferOutcome)
        try c.encode(classification, forKey: .classification)
        try c.encode(metrics, forKey: .metrics)
        try c.encode(count, forKey: .count)
        try c.encodeIfPresent(sessionID, forKey: .sessionID)
    }
}

private struct BackendActor: Decodable {
    let process: BackendEntry
    let parents: [BackendEntry]
    let chainComplete: Bool
    let classification: String
    enum CodingKeys: String, CodingKey {
        case process, parents = "ppid_tree", chainComplete = "chain_complete", classification
    }
}

private struct BackendEntry: Decodable {
    let identity: BackendIdentity
    let ppid: Int32
    let name: String
    let executable: String

    var node: ProcessNode {
        // A display UUID derived from PID + start time stays stable across reloads.
        // It is not an attestation; backend attribution is kept separately.
        let key = "\(identity.pid):\(identity.seconds):\(identity.microseconds)"
        let bytes = Array(SHA256.hash(data: Data(key.utf8)).prefix(16))
        let id = UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                            bytes[12], bytes[13], bytes[14], bytes[15]))
        return ProcessNode(id: id, pid: identity.pid, ppid: ppid, name: name, path: executable,
                           startSeconds: identity.seconds, startMicroseconds: identity.microseconds)
    }
}

private struct BackendIdentity: Decodable {
    let pid: Int32
    let seconds: UInt64
    let microseconds: UInt64
    enum CodingKeys: String, CodingKey {
        case pid, seconds = "start_seconds", microseconds = "start_microseconds"
    }
}
