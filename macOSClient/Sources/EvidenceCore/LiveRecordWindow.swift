import Foundation

public struct LiveRecordSets: Equatable, Sendable {
    public var events: [EvidenceRecord]
    public var chain: [EvidenceRecord]

    public init(events: [EvidenceRecord], chain: [EvidenceRecord]) {
        self.events = events
        self.chain = chain
    }
}

/// The events list is a newest-first sliding window. Chain records do not
/// compete for those slots: closures and the records a chain is built from
/// stay on their own list, so a flood of coverage or empty activity rows
/// cannot erase them.
public enum LiveRecordWindow {
    public static let eventCapacity = 2_000
    public static let chainCapacity = 2_000

    public static func protectsChain(_ record: EvidenceRecord) -> Bool {
        switch record.sourceType {
        case "sensitive_access_closed", "egress_transfer", "transfer_result",
             "sensitive_payload_observed", "egress_channel_unseen",
             "sensitive_fd_observed", "sensitive_access_observed",
             "sensitive_content_delivered", "sensitive_content_delivery_attempt",
             "sensitive_network_cooccurrence":
            return true
        case "activity_observed":
            return !record.targetResource.isEmpty
        default:
            return false
        }
    }

    /// `events` and `chain` are newest-first. `incoming` is oldest-first, as the reader returns it.
    public static func merge(events: [EvidenceRecord], chain: [EvidenceRecord], incoming: [EvidenceRecord],
                             eventCapacity: Int = eventCapacity, chainCapacity: Int = chainCapacity) -> LiveRecordSets {
        let eventLimit = max(1, eventCapacity)
        let chainLimit = max(1, chainCapacity)
        var seen = Set<UUID>()
        var combined: [EvidenceRecord] = []
        combined.reserveCapacity(incoming.count + events.count)
        for record in incoming.reversed() where seen.insert(record.id).inserted {
            combined.append(record)
        }
        for record in events where seen.insert(record.id).inserted {
            combined.append(record)
        }
        var chainSeen = Set<UUID>()
        var chainCombined: [EvidenceRecord] = []
        chainCombined.reserveCapacity(chain.count + incoming.count)
        for record in incoming.reversed() where protectsChain(record) && chainSeen.insert(record.id).inserted {
            chainCombined.append(record)
        }
        for record in chain where protectsChain(record) && chainSeen.insert(record.id).inserted {
            chainCombined.append(record)
        }
        return LiveRecordSets(events: Array(combined.prefix(eventLimit)),
                              chain: Array(chainCombined.prefix(chainLimit)))
    }
}
