import CoreGraphics
import Foundation

/// Where a saved window is allowed to sit. Coordinates match AppKit: origin is the bottom left.
public enum WindowPlacement {
    public static let minimum = CGSize(width: 1_050, height: 640)
    public static let preferred = CGSize(width: 1_360, height: 840)

    /// Pulls a restored frame onto `visible`. The result is at least `minimum` when the
    /// screen is large enough, and its origin is never outside `visible`.
    public static func clamped(saved: CGRect, visible: CGRect, minimum: CGSize = minimum) -> CGRect {
        guard visible.size.width > 1, visible.size.height > 1 else {
            return CGRect(origin: CGPoint(x: 0, y: 0), size: preferred)
        }
        let width = min(max(saved.size.width, min(minimum.width, visible.size.width)), visible.size.width)
        let height = min(max(saved.size.height, min(minimum.height, visible.size.height)), visible.size.height)
        let savedMaxX = saved.origin.x + saved.size.width
        let savedMaxY = saved.origin.y + saved.size.height
        let visibleMaxX = visible.origin.x + visible.size.width
        let visibleMaxY = visible.origin.y + visible.size.height
        let overlaps = saved.origin.x < visibleMaxX && savedMaxX > visible.origin.x && saved.origin.y < visibleMaxY && savedMaxY > visible.origin.y
        var x = saved.origin.x
        var y = saved.origin.y
        if x < visible.origin.x || x + width > visibleMaxX || y < visible.origin.y || y + height > visibleMaxY || !overlaps {
            x = min(max(x, visible.origin.x), visibleMaxX - width)
            y = min(max(y, visible.origin.y), visibleMaxY - height)
        }
        return CGRect(origin: CGPoint(x: x, y: y), size: CGSize(width: width, height: height))
    }
}

public enum ClosureScope: String, CaseIterable, Identifiable, Sendable {
    case currentRun
    case history
    public var id: String { rawValue }
}

public struct ClosureCounts: Equatable, Sendable {
    public var uploaded = 0
    public var attempted = 0
    public var notFound = 0
    public var notVisible = 0
    public var notVisibleReasonKeys: [String] = []
}

public struct HistoryDay: Identifiable, Equatable, Sendable {
    public let id: String
    public let start: Date
    public let chains: [EvidenceChain]
}

public enum ClosureListing {
    /// Current-run rows are newest first. Older rows are history, also newest first.
    /// Without a monitor start, every chain stays in the current list.
    public static func partition(_ chains: [EvidenceChain], runStartedAt: Date?, margin: TimeInterval = 2) -> (current: [EvidenceChain], history: [EvidenceChain]) {
        let newestFirst = chains.sorted { lhs, rhs in
            if lhs.timestamp != rhs.timestamp { return lhs.timestamp > rhs.timestamp }
            return lhs.id.uuidString < rhs.id.uuidString
        }
        guard let runStartedAt else { return (newestFirst, []) }
        let cutoff = runStartedAt.addingTimeInterval(-margin)
        return (newestFirst.filter { $0.timestamp >= cutoff }, newestFirst.filter { $0.timestamp < cutoff })
    }

    public static func isSelfCheck(_ chain: EvidenceChain) -> Bool {
        let agent = (chain.owningAgentName + " " + chain.owningAgentBundle).lowercased()
        if agent.contains("reinsruntime") { return true }
        let destination = chain.destination.lowercased()
        let basis = chain.evidenceBasis.lowercased()
        return destination.contains("127.0.0.1") && (destination.contains("/upload") || basis.contains("egress_proxy"))
    }

    public static func counts(of chains: [EvidenceChain]) -> ClosureCounts {
        var counts = ClosureCounts()
        var reasons: [String] = []
        for chain in chains where !isSelfCheck(chain) {
            switch chain.verdict {
            case .uploaded: counts.uploaded += 1
            case .attempted: counts.attempted += 1
            case .notFound: counts.notFound += 1
            case .notVisible:
                counts.notVisible += 1
                let key = ClosureExplanation.key(basis: chain.evidenceBasis, outcome: chain.transferOutcome)
                if !reasons.contains(key) { reasons.append(key) }
            case .absent, .unrecognized: break
            }
        }
        counts.notVisibleReasonKeys = reasons
        return counts
    }

    /// Newest day first. Chains inside a day are newest first.
    public static func historyDays(_ chains: [EvidenceChain], calendar: Calendar = .current) -> [HistoryDay] {
        let groups = Dictionary(grouping: chains) { chain -> Date in
            calendar.startOfDay(for: chain.timestamp)
        }
        return groups.keys.sorted(by: >).map { day in
            let items = (groups[day] ?? []).sorted { $0.timestamp > $1.timestamp }
            let formatter = DateFormatter()
            formatter.calendar = calendar
            formatter.dateFormat = "yyyy-MM-dd"
            return HistoryDay(id: formatter.string(from: day), start: day, chains: items)
        }
    }

    /// `192.168.1.11:54629` from a peer string, a URL, or a `/protocol=` suffix.
    public static func hostPort(_ destination: String) -> String {
        var text = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return "" }
        if let range = text.range(of: "/protocol=") { text = String(text[..<range.lowerBound]) }
        if let url = URL(string: text), let host = url.host, let port = url.port {
            return "\(host):\(port)"
        }
        if text.hasPrefix("http://") || text.hasPrefix("https://") {
            text = String(text.drop { $0 != "/" }.dropFirst().dropFirst())
            if let slash = text.firstIndex(of: "/") { text = String(text[..<slash]) }
        }
        return text
    }
}

public enum ClosureExplanation {
    /// Every basis the collector emits, mapped to a localization key.
    public static let basisKeys: [String: String] = [
        "flow_txbytes": "basis.flowTxbytes",
        "flow_txbytes_udp": "basis.flowTxbytesUdp",
        "flow_attempt": "basis.flowAttempt",
        "live_agent_observed": "basis.liveAgent",
        "observation_impossible": "basis.notVisible",
        "egress_proxy_http_body_match": "basis.proxyBody",
        "egress_proxy_watched_http_no_match": "basis.proxyNoMatch",
        "egress_channel_not_visible": "basis.channelUnseen",
        "exact_bytes": "basis.exactBytes",
        "json_escaped_bytes": "basis.jsonEscaped",
        "base64_whole_value": "basis.base64",
        "fd_observed": "basis.fdObserved",
        "same_identity_descriptor_snapshot": "basis.sameSnapshot",
        "tls_intercept_handshake_failed": "basis.tlsInterceptFailed",
        "tls_intercept_body_unreadable": "basis.tlsInterceptUnreadable",
        "opaque_tunnel_not_inspected": "basis.opaqueTunnel",
        "tcp_4tuple_not_matched": "basis.tupleUnmatched",
        "socket_peer_without_payload": "basis.socketOnly",
        "live_agent_tree_not_attached": "basis.treeNotAttached",
        "access_time_change": "basis.accessTime",
        "inferred": "basis.inferred",
        "no_registered_whole_version_match": "basis.noVersionMatch",
        "gateway_read_registered_file_on_behalf_of_peer;not_native_peer_read": "basis.gatewayRead"
    ]

    public static let outcomeKeys: [(token: String, key: String)] = [
        ("tls_handshake_body_not_visible", "basis.tlsHandshake"),
        ("provider_or_relay_body_not_visible", "basis.providerRelay"),
        ("loopback_not_off_host", "basis.loopback"),
        ("unseen_channel", "basis.unseenChannel"),
        ("live_agent_observed_no_upload", "basis.noUpload"),
        ("aggregate_above_window", "basis.aboveWindow"),
        ("descriptors_or_flows_incomplete", "basis.incomplete"),
        ("process_exited_before_send_measured", "basis.exitedEarly")
    ]

    public static var allKeys: [String] {
        Array(Set(basisKeys.values + outcomeKeys.map(\.key) + ["basis.gzip", "basis.unknown"])).sorted()
    }

    /// Longer tokens first so `flow_txbytes_udp` is not read as `flow_txbytes`.
    public static let matchOrder: [(token: String, key: String)] = outcomeKeys + [
        ("flow_txbytes_udp", "basis.flowTxbytesUdp"),
        ("egress_proxy_http_body_match", "basis.proxyBody"),
        ("egress_proxy_watched_http_no_match", "basis.proxyNoMatch"),
        ("egress_channel_not_visible", "basis.channelUnseen"),
        ("tls_intercept_handshake_failed", "basis.tlsInterceptFailed"),
        ("tls_intercept_body_unreadable", "basis.tlsInterceptUnreadable"),
        ("opaque_tunnel_not_inspected", "basis.opaqueTunnel"),
        ("tcp_4tuple_not_matched", "basis.tupleUnmatched"),
        ("socket_peer_without_payload", "basis.socketOnly"),
        ("live_agent_tree_not_attached", "basis.treeNotAttached"),
        ("same_identity_descriptor_snapshot", "basis.sameSnapshot"),
        ("no_registered_whole_version_match", "basis.noVersionMatch"),
        ("json_escaped_bytes", "basis.jsonEscaped"),
        ("base64_whole_value", "basis.base64"),
        ("exact_bytes", "basis.exactBytes"),
        ("flow_txbytes", "basis.flowTxbytes"),
        ("flow_attempt", "basis.flowAttempt"),
        ("live_agent_observed", "basis.liveAgent"),
        ("observation_impossible", "basis.notVisible"),
        ("fd_observed", "basis.fdObserved"),
        ("access_time_change", "basis.accessTime"),
        ("inferred", "basis.inferred")
    ]

    public static func key(basis: String, outcome: String) -> String {
        if basis.hasPrefix("gzip:") || outcome.hasPrefix("gzip:") { return "basis.gzip" }
        let haystack = outcome + "\n" + basis
        for item in matchOrder where haystack.contains(item.token) { return item.key }
        if let mapped = basisKeys[basis] { return mapped }
        return "basis.unknown"
    }
}

public enum CoverageNotice {
    public static func keys(partialDescriptors: Int, validationFailed: Int, unavailable: Int, enumerationIncomplete: Bool, droppedEvents: Bool) -> [String] {
        var keys: [String] = []
        if partialDescriptors > 0 { keys.append("coverage.descriptors") }
        if validationFailed > 0 { keys.append("coverage.identity") }
        if unavailable > 0 { keys.append("coverage.unreadable") }
        if enumerationIncomplete { keys.append("coverage.enumeration") }
        if droppedEvents { keys.append("coverage.dropped") }
        return keys
    }
}
