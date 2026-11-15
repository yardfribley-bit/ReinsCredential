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

/// Saved NSSplitView frames. A subview taller than the screen is not a real
/// layout; restoring it leaves the visible window blank and keeps laying out.
public enum SplitFrameSanitizer {
    public static func containsImpossibleHeight(_ saved: String, maxHeight: CGFloat) -> Bool {
        guard maxHeight > 1 else { return false }
        return subviewHeights(in: saved).contains { $0 > maxHeight }
    }

    public static func subviewHeights(in saved: String) -> [CGFloat] {
        // Both AppKit forms store x, y, width, height in that order:
        // "{{x, y}, {w, h}}" and "x, y, w, h, NO".
        let parsed = numbers(in: saved)
        var heights: [CGFloat] = []
        var cursor = 3
        while cursor < parsed.count {
            heights.append(parsed[cursor])
            cursor += 4
        }
        return heights
    }

    /// Window frame strings look like `216 54 1224 816 0 0 1440 870`. The fourth
    /// number is the window height. A split column taller than that window is
    /// already off the visible content, even when it is shorter than the screen.
    public static func savedWindowHeights(in defaults: UserDefaults) -> [CGFloat] {
        defaults.dictionaryRepresentation().compactMap { key, value in
            guard key.contains("NSWindow Frame"), let text = value as? String else { return nil }
            let numbers = numbers(in: text)
            guard numbers.count >= 4, numbers[3] > 1 else { return nil }
            return numbers[3]
        }
    }

    /// The tallest height AppKit may restore. This is the hosting window's
    /// height. On the measured Mac the window is 816 points and the screen is
    /// 870, so a column of 850 is already too tall. 5089 and 1469.5 both fail.
    public static func maxRestorableSubviewHeight(defaults: UserDefaults, screenHeight: CGFloat) -> CGFloat {
        let windows = savedWindowHeights(in: defaults)
        if let window = windows.filter({ $0 > 1 }).min() { return window }
        return screenHeight > 1 ? screenHeight : 1_600
    }

    /// Rewrites split-frame text so every subview height is at most `maxHeight`.
    /// Widths and the YES/NO flags stay. This is what a defaults write must store.
    public static func clampFrameText(_ saved: String, maxHeight: CGFloat) -> String {
        var ranges: [Range<String.Index>] = []
        var values: [CGFloat] = []
        var index = saved.startIndex
        while index < saved.endIndex {
            while index < saved.endIndex, !saved[index].isNumber, saved[index] != "-", saved[index] != "." {
                index = saved.index(after: index)
            }
            guard index < saved.endIndex else { break }
            let start = index
            if saved[index] == "-" { index = saved.index(after: index) }
            var saw = false
            while index < saved.endIndex, saved[index].isNumber || saved[index] == "." {
                saw = true
                index = saved.index(after: index)
            }
            guard saw, let value = Double(saved[start..<index]), value.isFinite else { continue }
            ranges.append(start..<index)
            values.append(CGFloat(value))
        }
        var result = saved
        var heightIndex = 3
        var replacements: [(Range<String.Index>, String)] = []
        while heightIndex < values.count {
            if values[heightIndex] > maxHeight {
                replacements.append((ranges[heightIndex], String(format: "%.6f", Double(maxHeight))))
            }
            heightIndex += 4
        }
        for (range, text) in replacements.reversed() {
            result.replaceSubrange(range, with: text)
        }
        return result
    }

    /// Corrects a defaults value in place. Returns the value to store, and whether it changed.
    public static func correcting(_ value: Any?, maxHeight: CGFloat) -> (stored: Any, changed: Bool) {
        let texts = frameTexts(value)
        guard !texts.isEmpty else { return (0, false) }
        let fixed = texts.map { clampFrameText($0, maxHeight: maxHeight) }
        let changed = fixed != texts
        if value is String { return (fixed[0], changed) }
        return (fixed, changed)
    }

    /// Rewrites every saved split frame taller than the window. The key stays;
    /// its height becomes the window height. Widths are unchanged.
    @discardableResult
    public static func correctSavedFrames(defaults: UserDefaults, maxSubviewHeight: CGFloat) -> [String] {
        let keys = defaults.dictionaryRepresentation().keys.filter { $0.contains("NSSplitView Subview Frames") }
        var changed: [String] = []
        for key in keys {
            let original = defaults.object(forKey: key)
            let result = correcting(original, maxHeight: maxSubviewHeight)
            if result.changed {
                defaults.set(result.stored, forKey: key)
                changed.append(key)
            }
        }
        return changed.sorted()
    }

    public static func tallestHeight(of value: Any?) -> CGFloat {
        frameTexts(value).flatMap { subviewHeights(in: $0) }.max() ?? 0
    }

    public static func tallestSubviewHeight(in defaults: UserDefaults) -> CGFloat {
        let keys = defaults.dictionaryRepresentation().keys.filter { $0.contains("NSSplitView Subview Frames") }
        var tallest: CGFloat = 0
        for key in keys {
            for text in frameTexts(defaults.object(forKey: key)) {
                for height in subviewHeights(in: text) { tallest = max(tallest, height) }
            }
        }
        return tallest
    }

    static func numbers(in saved: String) -> [CGFloat] {
        var numbers: [CGFloat] = []
        var index = saved.startIndex
        while index < saved.endIndex {
            while index < saved.endIndex, !saved[index].isNumber, saved[index] != "-", saved[index] != "." {
                index = saved.index(after: index)
            }
            guard index < saved.endIndex else { break }
            let start = index
            if saved[index] == "-" { index = saved.index(after: index) }
            var saw = false
            while index < saved.endIndex, saved[index].isNumber || saved[index] == "." {
                saw = true
                index = saved.index(after: index)
            }
            if saw, let value = Double(saved[start..<index]), value.isFinite {
                numbers.append(CGFloat(value))
            }
        }
        return numbers
    }

    static func frameTexts(_ value: Any?) -> [String] {
        if let text = value as? String { return [text] }
        if let parts = value as? [String] { return parts }
        if let parts = value as? [Any] { return parts.map { "\($0)" } }
        return []
    }

    /// Removes saved split frames whose subviews are taller than the window.
    /// Returns the defaults keys that were deleted. Accepts a single string or
    /// the array-of-strings form AppKit writes for SidebarNavigationSplitView.
    public static func removeImpossibleFrames(defaults: UserDefaults, maxSubviewHeight: CGFloat) -> [String] {
        let keys = defaults.dictionaryRepresentation().keys.filter { $0.contains("NSSplitView Subview Frames") }
        var removed: [String] = []
        for key in keys {
            let texts = frameTexts(defaults.object(forKey: key))
            if texts.contains(where: { containsImpossibleHeight($0, maxHeight: maxSubviewHeight) }) {
                defaults.removeObject(forKey: key)
                removed.append(key)
            }
        }
        return removed.sorted()
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
