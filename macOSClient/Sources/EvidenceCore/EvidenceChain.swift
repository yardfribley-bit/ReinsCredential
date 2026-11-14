import Foundation

/// Closing words already emitted by the collector. Unknown text is not mapped
/// onto 未发现 or 看不到.
public enum UploadVerdictWord: String, Codable, Sendable, Equatable {
    case uploaded
    case attempted
    case notFound = "not_found"
    case notVisible = "not_visible"
    case absent
    case unrecognized

    public var chineseLabel: String {
        switch self {
        case .uploaded: return "已上传"
        case .attempted: return "已尝试未成功"
        case .notFound: return "未发现"
        case .notVisible: return "看不到"
        case .absent: return "没有出口结论"
        case .unrecognized: return "未识别的结论"
        }
    }

    public var englishLabel: String {
        switch self {
        case .uploaded: return "Uploaded"
        case .attempted: return "Attempted"
        case .notFound: return "Not found"
        case .notVisible: return "Not visible"
        case .absent: return "No egress verdict"
        case .unrecognized: return "Unrecognized verdict"
        }
    }

    /// Exact backend codes only. `not_visible` stays 看不到 and never becomes 未发现.
    public static func parse(_ raw: String) -> UploadVerdictWord {
        switch raw {
        case "uploaded": return .uploaded
        case "attempted": return .attempted
        case "not_found": return .notFound
        case "not_visible": return .notVisible
        case "": return .absent
        default: return .unrecognized
        }
    }
}

public enum EvidenceChainKind: String, Codable, Sendable, Equatable {
    case fileAccess = "file_access"
    /// A body or gateway transfer with no observed open. The open is not invented.
    case transferWithoutOpen = "transfer_without_open"
    /// A channel whose bytes were not visible, with no file access joined to it.
    case unseenChannel = "unseen_channel"
}

public enum ChainLinkKind: String, Codable, Sendable, Equatable, CaseIterable {
    case agent, process, file, destination, payload, verdict

    public var title: String {
        switch self {
        case .agent: return "所属 Agent"
        case .process: return "进程"
        case .file: return "文件"
        case .destination: return "目的地"
        case .payload: return "内容匹配"
        case .verdict: return "出口结论"
        }
    }
}

public enum ChainLinkPresence: String, Codable, Sendable, Equatable {
    case present
    case incomplete
    case unrecorded
    case missing
    case unproven

    public var displayName: String {
        switch self {
        case .present: return "已记录"
        case .incomplete: return "不完整"
        case .unrecorded: return "未记录"
        case .missing: return "缺失"
        case .unproven: return "未证明"
        }
    }
}

public struct EvidenceChainLink: Equatable, Sendable {
    public let kind: ChainLinkKind
    public let presence: ChainLinkPresence
    public let title: String
    public let value: String
    public let note: String

    public init(kind: ChainLinkKind, presence: ChainLinkPresence, value: String, note: String) {
        self.kind = kind
        self.presence = presence
        self.title = kind.title
        self.value = EvidenceRedaction.display(value)
        self.note = EvidenceRedaction.display(note)
    }
}

public struct EvidenceChain: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let kind: EvidenceChainKind
    public let timestamp: Date
    public let memberIDs: [UUID]
    public let owningAgentName: String
    public let owningAgentBundle: String
    public let riskLevel: RiskLevel
    public let chainComplete: Bool?
    public let chainStatus: String
    public let filePath: String
    public let openObserved: Bool
    public let evidenceBasis: String
    public let destination: String
    public let payloadSHA256: String
    public let matchKind: String
    public let transferOutcome: String
    public let verdictCode: String
    public let verdict: UploadVerdictWord
    public let links: [EvidenceChainLink]
    public let backendSummary: String
    public let channelReasons: [String]
    public let missingReferenceCount: Int

    public var verdictLabel: String { verdict.chineseLabel }

    public var headline: String {
        let who = owningAgentName.isEmpty ? "未归属" : owningAgentName
        let file = filePath.isEmpty ? "没有对应文件" : filePath
        return "\(who) · \(file) · \(verdictLabel)"
    }

    public var reasonLine: String { channelReasons.joined(separator: " ") }

    public func link(_ kind: ChainLinkKind) -> EvidenceChainLink? {
        links.first { $0.kind == kind }
    }

    public func matchesSearch(_ query: String) -> Bool {
        let blob = [
            owningAgentName, owningAgentBundle, filePath, destination, verdictLabel, verdictCode,
            transferOutcome, evidenceBasis, backendSummary, reasonLine, matchKind, payloadSHA256
        ].joined(separator: "\n")
        return blob.localizedCaseInsensitiveContains(query)
    }
}

public struct EvidenceChainSection: Identifiable, Equatable, Sendable {
    public let id: String
    public let title: String
    public let subtitle: String
    public let chains: [EvidenceChain]

    public init(id: String, title: String, subtitle: String, chains: [EvidenceChain]) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
        self.chains = chains
    }
}

public extension Array where Element == EvidenceChain {
    /// Named agents first, then records with no owning agent. Empty names stay 未归属.
    func groupedByOwningAgent() -> [EvidenceChainSection] {
        let groups = Dictionary(grouping: self) { $0.owningAgentName }
        return groups.keys.sorted { lhs, rhs in
            if lhs.isEmpty { return false }
            if rhs.isEmpty { return true }
            return lhs.localizedStandardCompare(rhs) == .orderedAscending
        }.map { name in
            let items = groups[name] ?? []
            let bundles = Set(items.map(\.owningAgentBundle).filter { !$0.isEmpty })
            return EvidenceChainSection(
                id: name.isEmpty ? "unattributed" : name,
                title: name.isEmpty ? "未归属" : name,
                subtitle: bundles.count == 1 ? (bundles.first ?? "") : "",
                chains: items
            )
        }
    }
}

public enum EvidenceRedaction {
    private static let assignment = try? NSRegularExpression(
        pattern: "(?i)(\\b(?:secret|password|passwd|token|api[_-]?key|credential|private[_-]?key|reins_synthetic_test)\\b\\s*[=:]\\s*)([^\\s,;&]+)"
    )
    private static let literals = [
        "SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef",
        "SYNTHETIC_CREDENTIAL_NOT_A_SECRET"
    ]
    /// Obvious fake-secret markers used by the acceptance harness. Real key material
    /// is not listed here; the harness also refuses to read those files.
    private static let fakeMarkers = try? NSRegularExpression(
        pattern: "(?i)reins-fake-[a-z0-9_-]+|AKIAFAKE[A-Z0-9]*|FAKE-NOT-A-REAL[-A-Z0-9]*"
    )

    /// Hides assignment-style secret values and the repo's published synthetic secrets.
    /// Hashes and paths are kept.
    public static func display(_ text: String) -> String {
        guard !text.isEmpty else { return text }
        guard let assignment else { return "[已省略]" }
        var text = text
        for literal in literals {
            text = text.replacingOccurrences(of: literal, with: "[已省略]")
        }
        var range = NSRange(text.startIndex..., in: text)
        text = assignment.stringByReplacingMatches(in: text, options: [], range: range, withTemplate: "$1[已省略]")
        if let fakeMarkers {
            range = NSRange(text.startIndex..., in: text)
            text = fakeMarkers.stringByReplacingMatches(in: text, options: [], range: range, withTemplate: "[已省略]")
        }
        return text
    }
}

public enum EvidenceChainExport {
    public static let schema = "reinscredential.evidence-chain.v1"
    public static let glossaryText = "结论用词：已上传、已尝试未成功、未发现、看不到。看不到不能写成未发现。未发现只在离机通道都测过、并且合计低于压缩下界时使用。flow_txbytes 和 flow_txbytes_udp 是进程树上的发送字节数，不是解密后的正文。没有出口结论表示记录里没有这四句。打开的描述符、同时出现的连接，都不是上传。原始密钥字节不包含在导出里。"

    public static func markdown(_ chains: [EvidenceChain], window: ClosedRange<Date>? = nil) -> String {
        EvidenceRedaction.display(renderMarkdown(select(chains, window: window), window: normalized(window)))
    }

    public static func json(_ chains: [EvidenceChain], window: ClosedRange<Date>? = nil) -> String {
        let selected = select(chains, window: normalized(window))
        let window = normalized(window)
        let document = EvidenceChainDocument(
            schema: schema,
            rawSecretBytes: "omitted",
            inventedEvents: "none",
            verdictGlossary: [
                "uploaded": UploadVerdictWord.uploaded.chineseLabel,
                "attempted": UploadVerdictWord.attempted.chineseLabel,
                "not_found": UploadVerdictWord.notFound.chineseLabel,
                "not_visible": UploadVerdictWord.notVisible.chineseLabel,
                "absent": UploadVerdictWord.absent.chineseLabel
            ],
            windowStart: window?.lowerBound,
            windowEnd: window?.upperBound,
            chains: selected.map(ExportedEvidenceChain.init)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = (try? encoder.encode(document)) ?? Data("{}".utf8)
        return EvidenceRedaction.display(String(decoding: data, as: UTF8.self))
    }

    private static func select(_ chains: [EvidenceChain], window: ClosedRange<Date>?) -> [EvidenceChain] {
        guard let window = normalized(window) else { return chains }
        return chains.filter { window.contains($0.timestamp) }
    }

    private static func normalized(_ window: ClosedRange<Date>?) -> ClosedRange<Date>? {
        guard let window else { return nil }
        if window.lowerBound <= window.upperBound { return window }
        return window.upperBound...window.lowerBound
    }

    private static func renderMarkdown(_ chains: [EvidenceChain], window: ClosedRange<Date>?) -> String {
        var lines = [
            "# 证据链",
            "",
            "schema: \(schema)",
            "原始密钥字节：已省略",
            "没有补造缺失的事件。",
            "",
            glossaryText,
            ""
        ]
        if let window {
            lines.append("导出范围：\(stamp.string(from: window.lowerBound)) 至 \(stamp.string(from: window.upperBound))")
        } else {
            lines.append("导出范围：全部给出的证据链")
        }
        lines.append("条数：\(chains.count)")
        lines.append("")
        if chains.isEmpty {
            lines.append("这个范围里没有证据链。")
            lines.append("")
            return lines.joined(separator: "\n")
        }
        for (index, chain) in chains.enumerated() {
            lines.append("## \(index + 1). \(chain.headline)")
            lines.append("")
            lines.append("- 时间：\(stamp.string(from: chain.timestamp))")
            lines.append("- 种类：\(chain.kind.rawValue)")
            lines.append("- 打开是否被看到：\(chain.openObserved ? "看到" : "没有看到")")
            for link in chain.links {
                lines.append("- \(link.title)：\(link.value)")
                lines.append("  - 状态：\(link.presence.displayName)")
                if !link.note.isEmpty { lines.append("  - 说明：\(link.note)") }
            }
            if !chain.channelReasons.isEmpty {
                lines.append("- 通道说明：\(chain.channelReasons.joined(separator: " "))")
            }
            if !chain.backendSummary.isEmpty {
                lines.append("- 采集原句：\(chain.backendSummary)")
            }
            lines.append("- 结论代码：\(chain.verdictCode.isEmpty ? "（空）" : chain.verdictCode)")
            lines.append("- 出口结论：\(chain.verdictLabel)")
            lines.append("- 关联事件：\(chain.memberIDs.map(\.uuidString).joined(separator: ", "))")
            lines.append("- 快照中缺少的关联：\(chain.missingReferenceCount)")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }

    private static let stamp: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}

public struct EvidenceChainDocument: Codable, Equatable, Sendable {
    public var schema: String
    public var rawSecretBytes: String
    public var inventedEvents: String
    public var verdictGlossary: [String: String]
    public var windowStart: Date?
    public var windowEnd: Date?
    public var chains: [ExportedEvidenceChain]

    enum CodingKeys: String, CodingKey {
        case schema
        case rawSecretBytes = "raw_secret_bytes"
        case inventedEvents = "invented_events"
        case verdictGlossary = "verdict_glossary"
        case windowStart = "window_start"
        case windowEnd = "window_end"
        case chains
    }
}

public struct ExportedEvidenceChain: Codable, Equatable, Sendable {
    public var id: String
    public var kind: String
    public var timestamp: Date
    public var owningAgent: String
    public var agentBundle: String
    public var processChainComplete: Bool?
    public var processChainStatus: String
    public var file: String
    public var openObserved: Bool
    public var evidenceBasis: String
    public var destination: String
    public var payloadMatch: String
    public var contentSHA256: String
    public var transferOutcome: String
    public var verdict: String
    public var verdictLabel: String
    public var channelReasons: [String]
    public var links: [ExportedChainLink]
    public var memberEventIDs: [String]
    public var missingReferenceCount: Int

    init(_ chain: EvidenceChain) {
        id = chain.id.uuidString
        kind = chain.kind.rawValue
        timestamp = chain.timestamp
        owningAgent = chain.owningAgentName
        agentBundle = chain.owningAgentBundle
        processChainComplete = chain.chainComplete
        processChainStatus = chain.chainStatus
        file = chain.filePath
        openObserved = chain.openObserved
        evidenceBasis = chain.evidenceBasis
        destination = chain.destination
        payloadMatch = chain.matchKind
        contentSHA256 = chain.payloadSHA256
        transferOutcome = chain.transferOutcome
        verdict = chain.verdictCode
        verdictLabel = chain.verdictLabel
        channelReasons = chain.channelReasons
        links = chain.links.map {
            ExportedChainLink(step: $0.kind.rawValue, presence: $0.presence.rawValue, value: $0.value, note: $0.note)
        }
        memberEventIDs = chain.memberIDs.map(\.uuidString)
        missingReferenceCount = chain.missingReferenceCount
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, timestamp
        case owningAgent = "owning_agent"
        case agentBundle = "agent_bundle"
        case processChainComplete = "process_chain_complete"
        case processChainStatus = "process_chain_status"
        case file
        case openObserved = "open_observed"
        case evidenceBasis = "evidence_basis"
        case destination
        case payloadMatch = "payload_match"
        case contentSHA256 = "content_sha256"
        case transferOutcome = "transfer_outcome"
        case verdict
        case verdictLabel = "verdict_label"
        case channelReasons = "channel_reasons"
        case links
        case memberEventIDs = "member_event_ids"
        case missingReferenceCount = "missing_reference_count"
    }
}

public struct ExportedChainLink: Codable, Equatable, Sendable {
    public var step: String
    public var presence: String
    public var value: String
    public var note: String
}

/// One sensitive-file access, or one transfer that never showed an open.
/// Joins explicit `related_event_ids`. A descriptor with the same PID, start
/// time and path is attached to that closing card. Other unclosed descriptors
/// group by the same identity and path. It does not infer an actor from time,
/// and it does not relabel 看不到 as 未发现.
public enum EvidenceChainBuilder {
    public static func chains(from records: [EvidenceRecord]) -> [EvidenceChain] {
        var index: [String: EvidenceRecord] = [:]
        for record in records where index[key(record.id)] == nil {
            index[key(record.id)] = record
        }
        var used = Set<UUID>()
        var plans: [Plan] = []

        // Several closes can describe the same process and file as the watch
        // continues. The card shows the strongest one: 已上传, then 已尝试未成功,
        // then 看不到, then 未发现. Weaker closes stay on that card.
        var closingGroups: [String: [EvidenceRecord]] = [:]
        var closingOrder: [String] = []
        for record in records where record.sourceType == "sensitive_access_closed" {
            let key = (identityKey(record) ?? "id:\(record.id.uuidString)") + "\n" + record.targetResource
            if closingGroups[key] == nil { closingOrder.append(key) }
            closingGroups[key, default: []].append(record)
        }
        for key in closingOrder {
            let group = closingGroups[key] ?? []
            guard let winner = group.max(by: { lhs, rhs in
                let left = closingRank(lhs)
                let right = closingRank(rhs)
                if left != right { return left < right }
                if lhs.timestamp != rhs.timestamp { return lhs.timestamp < rhs.timestamp }
                return lhs.id.uuidString < rhs.id.uuidString
            }) else { continue }
            if used.contains(winner.id) { continue }
            var expanded = expand(winner, index: index)
            for other in group where other.id != winner.id && !expanded.members.contains(where: { $0.id == other.id }) {
                expanded.members.append(other)
            }
            plans.append(Plan(anchor: winner, members: expanded.members, missing: expanded.missing, kind: .fileAccess))
            used.formUnion(expanded.members.map(\.id))
            used.formUnion(group.map(\.id))
        }

        // A collector descriptor for the same PID, start time and path belongs
        // on the closing card. A different process is left alone.
        var descriptors: [EvidenceRecord] = []
        for record in records where isDescriptor(record) && !used.contains(record.id) {
            let matches = plans.indices.filter { index in
                let plan = plans[index]
                let sameActor = sameIdentity(record, plan.anchor) || plan.members.contains(where: { sameIdentity(record, $0) })
                guard plan.kind == .fileAccess, sameActor else { return false }
                return filePath(plan.anchor, plan.members) == record.targetResource && !record.targetResource.isEmpty
            }
            if matches.count == 1 {
                plans[matches[0]].members.append(record)
                used.insert(record.id)
            } else {
                descriptors.append(record)
            }
        }
        let grouped = Dictionary(grouping: descriptors) { descriptorKey($0) }
        for group in grouped.values {
            let ordered = group.sorted(by: earlier)
            guard let anchor = ordered.first else { continue }
            var members = ordered
            if let identity = identityKey(anchor) {
                for candidate in records where candidate.sourceType == "sensitive_network_cooccurrence" && !used.contains(candidate.id) {
                    guard identityKey(candidate) == identity, candidate.targetResource == anchor.targetResource else { continue }
                    members.append(candidate)
                }
            }
            plans.append(Plan(anchor: anchor, members: members, missing: 0, kind: .fileAccess))
            used.formUnion(members.map(\.id))
        }

        for record in records where record.sourceType == "sensitive_access_observed" && !used.contains(record.id) {
            plans.append(Plan(anchor: record, members: [record], missing: 0, kind: .fileAccess))
            used.insert(record.id)
        }
        for record in records where record.sourceType == "filesystem_change" && !used.contains(record.id) {
            plans.append(Plan(anchor: record, members: [record], missing: 0, kind: .fileAccess))
            used.insert(record.id)
        }

        let transferTypes: Set<String> = ["egress_transfer", "transfer_result", "sensitive_payload_observed"]
        for record in records where transferTypes.contains(record.sourceType) && !used.contains(record.id) {
            let expanded = expand(record, index: index)
            let kind: EvidenceChainKind = expanded.members.contains(where: sawOpen) ? .fileAccess : .transferWithoutOpen
            plans.append(Plan(anchor: record, members: expanded.members, missing: expanded.missing, kind: kind))
            used.formUnion(expanded.members.map(\.id))
        }
        for record in records where (record.sourceType == "sensitive_content_delivered" || record.sourceType == "sensitive_content_delivery_attempt") && !used.contains(record.id) {
            let expanded = expand(record, index: index)
            plans.append(Plan(anchor: record, members: expanded.members, missing: expanded.missing, kind: .fileAccess))
            used.formUnion(expanded.members.map(\.id))
        }
        for record in records where record.sourceType == "egress_channel_unseen" && !used.contains(record.id) {
            let expanded = expand(record, index: index)
            let sawFile = expanded.members.contains(where: sawOpen) || !record.targetResource.isEmpty
            let kind: EvidenceChainKind = sawFile ? .fileAccess : .unseenChannel
            plans.append(Plan(anchor: record, members: expanded.members, missing: expanded.missing, kind: kind))
            used.formUnion(expanded.members.map(\.id))
        }

        for event in records where event.sourceType == "sensitive_network_cooccurrence" && !used.contains(event.id) {
            let identity = identityKey(event)
            let matches = plans.enumerated().filter { _, plan in
                guard plan.kind == .fileAccess, identity != nil else { return false }
                let path = filePath(plan.anchor, plan.members)
                guard path == event.targetResource else { return false }
                if identityKey(plan.anchor) == identity { return true }
                return plan.members.contains { identityKey($0) == identity }
            }
            if matches.count == 1, let found = matches.first {
                plans[found.offset].members.append(event)
            } else {
                plans.append(Plan(anchor: event, members: [event], missing: 0, kind: .fileAccess))
            }
            used.insert(event.id)
        }

        return plans.map(assemble).sorted { lhs, rhs in
            if lhs.timestamp != rhs.timestamp { return lhs.timestamp > rhs.timestamp }
            return lhs.id.uuidString < rhs.id.uuidString
        }
    }

    private struct Plan {
        var anchor: EvidenceRecord
        var members: [EvidenceRecord]
        var missing: Int
        var kind: EvidenceChainKind
    }

    private enum ProcessOpinion { case complete, incomplete, unrecorded }

    private static func assemble(_ plan: Plan) -> EvidenceChain {
        let anchor = plan.anchor
        var members = plan.members
        if !members.contains(where: { $0.id == anchor.id }) { members.insert(anchor, at: 0) }
        var seen = Set<UUID>()
        members = members.filter { seen.insert($0.id).inserted }
        let verdict = UploadVerdictWord.parse(anchor.uploadVerdict)
        let reasons = channelReasons(members)
        let path = filePath(anchor, members)
        let open = members.contains(where: sawOpen)
        let basis = fileBasis(anchor, members)
        let destination = chooseDestination(anchor, members)
        let hash = chooseHash(anchor, members, path: path, verdict: verdict)
        let match = chooseMatch(anchor, members, path: path, verdict: verdict)
        let process = mergedProcess(anchor: anchor, members: members)
        let agentName = firstAgentName(anchor, members)
        let agentBundle = firstAgentBundle(anchor, members, name: agentName)
        let links = [
            agentLink(name: agentName, bundle: agentBundle),
            processLink(process),
            fileLink(path: path, basis: basis, open: open, anchor: anchor, members: members, kind: plan.kind),
            destinationLink(destination, members: members, reasons: reasons),
            payloadLink(verdict: verdict, hash: hash, match: match, members: members),
            verdictLink(verdict: verdict, code: anchor.uploadVerdict, outcome: anchor.transferOutcome, kind: plan.kind)
        ]
        return EvidenceChain(
            id: anchor.id,
            kind: plan.kind,
            timestamp: anchor.timestamp,
            memberIDs: members.map(\.id),
            owningAgentName: agentName,
            owningAgentBundle: agentBundle,
            riskLevel: anchor.riskLevel,
            chainComplete: process.complete,
            chainStatus: process.status,
            filePath: path,
            openObserved: open,
            evidenceBasis: basis,
            destination: EvidenceRedaction.display(destination.value),
            payloadSHA256: verdict == .notVisible ? "" : hash,
            matchKind: verdict == .notVisible ? "" : match,
            transferOutcome: EvidenceRedaction.display(anchor.transferOutcome.isEmpty ? destination.outcome : anchor.transferOutcome),
            verdictCode: anchor.uploadVerdict,
            verdict: verdict,
            links: links,
            backendSummary: EvidenceRedaction.display(anchor.summary),
            channelReasons: reasons.map(EvidenceRedaction.display),
            missingReferenceCount: plan.missing
        )
    }

    private static func expand(_ anchor: EvidenceRecord, index: [String: EvidenceRecord]) -> (members: [EvidenceRecord], missing: Int) {
        var ordered: [EvidenceRecord] = []
        var seen = Set<String>()
        var missing = 0
        var queue: [(String, Int)] = [(key(anchor.id), 0)]
        var head = 0
        while head < queue.count {
            let (item, depth) = queue[head]
            head += 1
            guard seen.insert(item).inserted else { continue }
            guard let record = index[item] else {
                missing += 1
                continue
            }
            ordered.append(record)
            guard depth < 8 else { continue }
            for related in record.relatedEventIDs where !related.isEmpty {
                queue.append((related.lowercased(), depth + 1))
            }
        }
        return (ordered, missing)
    }

    private static func isDescriptor(_ record: EvidenceRecord) -> Bool {
        switch record.sourceType {
        case "sensitive_fd_observed":
            return !record.targetResource.isEmpty
        case "activity_observed":
            return !record.targetResource.isEmpty && (record.evidenceBasis == "fd_observed" || record.evidenceBasis.isEmpty || record.detail.hasPrefix("sensitive_file_open:"))
        default:
            return false
        }
    }

    /// A descriptor snapshot or a same-sample co-occurrence. Neither one is an upload.
    private static func sawOpen(_ record: EvidenceRecord) -> Bool {
        if isDescriptor(record) { return true }
        return record.sourceType == "sensitive_network_cooccurrence" && !record.targetResource.isEmpty
    }

    private static func descriptorKey(_ record: EvidenceRecord) -> String {
        let identity = identityKey(record) ?? "solo:\(record.id.uuidString.lowercased())"
        return identity + "\n" + record.targetResource
    }

    private static func sameIdentity(_ lhs: EvidenceRecord, _ rhs: EvidenceRecord) -> Bool {
        guard let left = identityKey(lhs), let right = identityKey(rhs) else { return false }
        return left == right
    }

    private static func identityKey(_ record: EvidenceRecord) -> String? {
        guard let actor = record.processTree.first,
              let seconds = actor.startSeconds,
              let micros = actor.startMicroseconds else { return nil }
        return "\(actor.pid):\(seconds):\(micros)"
    }

    private static func earlier(_ lhs: EvidenceRecord, _ rhs: EvidenceRecord) -> Bool {
        if lhs.timestamp != rhs.timestamp { return lhs.timestamp < rhs.timestamp }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    private static func key(_ id: UUID) -> String { id.uuidString.lowercased() }

    private static func filePath(_ anchor: EvidenceRecord, _ members: [EvidenceRecord]) -> String {
        if !anchor.targetResource.isEmpty { return anchor.targetResource }
        return members.first { !$0.targetResource.isEmpty }?.targetResource ?? ""
    }

    private static func fileBasis(_ anchor: EvidenceRecord, _ members: [EvidenceRecord]) -> String {
        let preferred = ["sensitive_fd_observed", "activity_observed", "sensitive_network_cooccurrence", "sensitive_access_observed", "filesystem_change", "sensitive_content_delivered"]
        for type in preferred {
            if let record = members.first(where: { $0.sourceType == type && !$0.evidenceBasis.isEmpty }) {
                return record.evidenceBasis
            }
        }
        if !isChannelOrPayloadBasis(anchor.evidenceBasis) { return anchor.evidenceBasis }
        return ""
    }

    private static func isChannelOrPayloadBasis(_ basis: String) -> Bool {
        switch basis {
        case "egress_proxy_http_body_match", "egress_proxy_watched_http_no_match", "egress_channel_not_visible",
             "exact_bytes", "json_escaped_bytes", "base64_whole_value", "no_registered_whole_version_match",
             "socket_peer_without_payload", "tls_intercept_handshake_failed", "tls_intercept_body_unreadable",
             "opaque_tunnel_not_inspected", "live_agent_tree_not_attached", "tcp_4tuple_not_matched",
             "flow_txbytes", "flow_txbytes_udp", "flow_attempt", "live_agent_observed", "observation_impossible":
            return true
        default:
            return basis.hasPrefix("gzip:")
        }
    }

    private struct DestinationChoice {
        var value: String
        var fromCooccurrence: Bool
        var outcome: String
    }

    private static func chooseDestination(_ anchor: EvidenceRecord, _ members: [EvidenceRecord]) -> DestinationChoice {
        if !anchor.destination.isEmpty {
            return DestinationChoice(value: anchor.destination, fromCooccurrence: false, outcome: anchor.transferOutcome)
        }
        if let peer = members.first(where: { !$0.destination.isEmpty && $0.sourceType != "sensitive_network_cooccurrence" }) {
            return DestinationChoice(value: peer.destination, fromCooccurrence: false, outcome: peer.transferOutcome)
        }
        if let peer = members.first(where: { $0.sourceType == "sensitive_network_cooccurrence" && !$0.destination.isEmpty }) {
            return DestinationChoice(value: peer.destination, fromCooccurrence: true, outcome: peer.transferOutcome)
        }
        return DestinationChoice(value: "", fromCooccurrence: false, outcome: "")
    }

    private static func chooseHash(_ anchor: EvidenceRecord, _ members: [EvidenceRecord], path: String, verdict: UploadVerdictWord) -> String {
        guard verdict != .notVisible else { return "" }
        if !anchor.contentSHA256.isEmpty { return anchor.contentSHA256 }
        return members.first {
            !$0.contentSHA256.isEmpty && ($0.targetResource.isEmpty || $0.targetResource == path || path.isEmpty)
        }?.contentSHA256 ?? ""
    }

    private static func chooseMatch(_ anchor: EvidenceRecord, _ members: [EvidenceRecord], path: String, verdict: UploadVerdictWord) -> String {
        guard verdict != .notVisible, verdict != .notFound else { return "" }
        let pool = [anchor] + members.filter { $0.targetResource.isEmpty || $0.targetResource == path || path.isEmpty }
        for record in pool {
            if let kind = matchKind(in: record), !kind.isEmpty { return kind }
        }
        return ""
    }

    private static func matchKind(in record: EvidenceRecord) -> String? {
        if let range = record.detail.range(of: #"match=[A-Za-z0-9:_-]+"#, options: .regularExpression) {
            return String(record.detail[range]).replacingOccurrences(of: "match=", with: "")
        }
        let basis = record.evidenceBasis
        if basis == "exact_bytes" || basis == "json_escaped_bytes" || basis == "base64_whole_value" || basis.hasPrefix("gzip:") {
            return basis
        }
        return nil
    }

    private static func channelReasons(_ records: [EvidenceRecord]) -> [String] {
        var reasons: [String] = []
        func add(_ text: String) {
            if !reasons.contains(text) { reasons.append(text) }
        }
        for record in records {
            let basis = record.evidenceBasis
            let outcome = record.transferOutcome
            let detail = record.detail
            if basis == "live_agent_tree_not_attached" || detail.contains("already_running_not_redirected")
                || outcome.contains("already_running") || outcome.contains("live_agent_tree_not_proxied") {
                add("这个 Agent 在采集开始前已经在运行。没有修改它的 MCP 或应用设置，用户态不能把已有连接改道到本地代理。")
            }
            if outcome.contains("udp_or_quic") || record.destination.contains("protocol=17") {
                add("这是 UDP 或 QUIC。正文看不到。")
            }
            if basis == "tls_intercept_handshake_failed" || outcome.contains("tls_intercept_handshake_failed") {
                add("HTTPS 没有完成代理侧握手。证书固定，或客户端不信任临时 CA。这个 CA 不会装进登录钥匙串。")
            }
            if basis == "tls_intercept_body_unreadable" {
                add("TLS 握手之后没有读到完整请求。不能把它写成未发现。")
            }
            if basis == "opaque_tunnel_not_inspected" || outcome.contains("opaque_tunnel") {
                add("CONNECT 隧道里的字节没有被检查。")
            }
            if basis == "tcp_4tuple_not_matched" || outcome == "client_not_attributed" {
                add("连到本地代理的套接字没有对上进程，请求体没有记成上传。")
            }
            if basis == "socket_peer_without_payload" && !outcome.contains("udp_or_quic") {
                add("只看到了套接字对端，没有看到发送的字节。")
            }
            if basis == "flow_txbytes_udp" || outcome.contains("flow_txbytes_udp") {
                add("打开已登记文件之后，发往非回环地址的 UDP/QUIC 发送字节数落在压缩下界和文件窗口之间。没有解密，没有安装 CA，也没有系统代理。")
            } else if basis == "flow_txbytes" || outcome.contains("flow_txbytes") {
                add("打开已登记文件之后，进程树上发往非回环地址的发送字节数合计落在压缩下界和文件窗口之间。没有解密 TLS，没有安装 CA，也没有系统代理。")
            }
            if basis == "flow_attempt" || outcome.contains("flow_attempt") {
                add("看到了文件打开，以及一次没有把不少于文件大小的字节送出本机的外连。")
            }
            if basis == "live_agent_observed" || outcome.contains("live_agent_observed") {
                add("这个 Agent 的进程和 TCP 发送字节数都已查看。没有看到离开本机的上传。")
            }
            if basis == "observation_impossible" || outcome.contains("descriptors_or_flows_incomplete") || outcome == "agent_not_visible" {
                add("这个进程的描述符或流量没有看全，不能写成未发现。")
            }
            if outcome.contains("unseen_channel") || outcome.contains("tls_handshake_body_not_visible") {
                add("没有看到可核对的正文。不能把这次关闭写成未发现，也不能写成已上传。")
            }
            if outcome == "egress_not_watched" {
                add("这棵进程树的明文出口当时不在本地代理的查看范围内。")
            }
            let inspectedTLS = detail.contains("tls_intercept")
                && basis != "tls_intercept_handshake_failed"
                && basis != "tls_intercept_body_unreadable"
                && !outcome.contains("tls_intercept_handshake_failed")
                && record.uploadVerdict != "not_visible"
            if inspectedTLS {
                add("这次 HTTPS 用调用方提供的临时 CA 检查了正文。CA 没有装进登录钥匙串。")
            }
        }
        return reasons
    }

    private struct ProcessView {
        var tree: [ProcessNode]
        var complete: Bool?
        var status: String
    }

    private static func opinion(_ record: EvidenceRecord) -> ProcessOpinion {
        let status = record.chainStatus
        if record.chainComplete == false || status == "missing_parent" || status == "parent_not_observed" {
            return .incomplete
        }
        if record.chainComplete == true || status == "observed_chain_to_root" || status == "observed_chain_to_launchd" {
            return .complete
        }
        return .unrecorded
    }

    private static func mergedProcess(anchor: EvidenceRecord, members: [EvidenceRecord]) -> ProcessView {
        let voters = members.filter { !$0.processTree.isEmpty || $0.chainComplete != nil || !$0.chainStatus.isEmpty }
        let treeSource = !anchor.processTree.isEmpty ? anchor : (voters.first { !$0.processTree.isEmpty } ?? anchor)
        let opinions = voters.map(opinion)
        if opinions.contains(.incomplete) {
            let status = voters.first { opinion($0) == .incomplete }?.chainStatus ?? "missing_parent"
            return ProcessView(tree: treeSource.processTree, complete: false, status: status)
        }
        if opinions.contains(.complete) {
            let status = voters.first { opinion($0) == .complete }?.chainStatus ?? ""
            return ProcessView(tree: treeSource.processTree, complete: true, status: status)
        }
        return ProcessView(tree: treeSource.processTree, complete: nil, status: "")
    }

    private static func firstAgentName(_ anchor: EvidenceRecord, _ members: [EvidenceRecord]) -> String {
        if !anchor.owningAgentName.isEmpty { return anchor.owningAgentName }
        return members.first { !$0.owningAgentName.isEmpty }?.owningAgentName ?? ""
    }

    private static func firstAgentBundle(_ anchor: EvidenceRecord, _ members: [EvidenceRecord], name: String) -> String {
        if anchor.owningAgentName == name && !anchor.owningAgentBundle.isEmpty { return anchor.owningAgentBundle }
        return members.first { $0.owningAgentName == name && !$0.owningAgentBundle.isEmpty }?.owningAgentBundle ?? ""
    }

    private static func agentLink(name: String, bundle: String) -> EvidenceChainLink {
        guard !name.isEmpty else {
            return EvidenceChainLink(kind: .agent, presence: .missing, value: "缺失", note: "没有识别到所属 Agent。不会用进程名补一个。")
        }
        let value = bundle.isEmpty ? name : "\(name)（\(bundle)）"
        return EvidenceChainLink(kind: .agent, presence: .present, value: value, note: "名称或 bundle 匹配是候选分类，不是身份认证。")
    }

    private static func processLink(_ process: ProcessView) -> EvidenceChainLink {
        guard let actor = process.tree.first else {
            return EvidenceChainLink(kind: .process, presence: .missing, value: "缺失", note: "没有可归因的进程。")
        }
        let value = process.tree.map { node in
            let name = node.name.isEmpty ? "未知进程" : node.name
            return "\(name)（pid \(node.pid)）"
        }.joined(separator: " → ")
        var note: String
        let presence: ChainLinkPresence
        if process.complete == false {
            presence = .incomplete
            switch process.status {
            case "missing_parent", "parent_not_observed":
                note = "进程链不完整：没有观察到父进程。"
            case let status where !status.isEmpty:
                note = "进程链不完整：记录的状态是 \(status)。"
            default:
                note = "进程链不完整：记录标明链条不完整。"
            }
        } else if process.complete == true {
            presence = .present
            switch process.status {
            case "observed_chain_to_root":
                note = "进程链完整：到达根进程。"
            case "observed_chain_to_launchd":
                note = "进程链完整：到达 launchd（pid 1）。没有读到 launchd 自己的启动时间。"
            case let status where !status.isEmpty:
                note = "进程链完整：\(status)。"
            default:
                note = "进程链完整：记录标明链条完整，但没有写明原因。"
            }
        } else {
            presence = .unrecorded
            note = "没有记录进程链是否完整，不能显示为完整。"
        }
        note += " 行为进程在前。"
        if let seconds = actor.startSeconds, let micros = actor.startMicroseconds {
            note += " 启动世代 \(seconds).\(padded(micros))。"
        } else {
            note += " 没有记录启动时间。不能只靠 PID 区分进程。"
        }
        return EvidenceChainLink(kind: .process, presence: presence, value: value, note: note)
    }

    private static func fileLink(path: String, basis: String, open: Bool, anchor: EvidenceRecord, members: [EvidenceRecord], kind: EvidenceChainKind) -> EvidenceChainLink {
        if path.isEmpty {
            return EvidenceChainLink(kind: .file, presence: .missing, value: "缺失", note: "没有对应的文件。不会补一个路径。")
        }
        let gateway = members.contains {
            $0.sourceType == "sensitive_content_delivered" || $0.sourceType == "sensitive_content_delivery_attempt"
                || $0.evidenceBasis.contains("gateway_read")
        }
        if open {
            let note = basis == "same_identity_descriptor_snapshot"
                ? "同一次采样看到了文件描述符。没有证明读入了字节，也不是上传。依据：\(basisLabel(basis))。"
                : "看到了打开的文件描述符。没有证明读入了字节，也不是上传。依据：\(basisLabel(basis))。"
            return EvidenceChainLink(kind: .file, presence: .present, value: path, note: note)
        }
        if gateway {
            return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "网关按请求读过已登记文件。这不是那个进程打开的描述符，这里不把它写成打开。")
        }
        if anchor.sourceType == "filesystem_change" {
            return EvidenceChainLink(kind: .file, presence: .present, value: path, note: "文件系统报告了变化。没有行为进程，也不是打开或上传。")
        }
        if basis == "inferred" || anchor.evidenceBasis == "inferred" {
            return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "只有访问时间与一个进程的存在时间重合。没有看到打开。")
        }
        if basis == "access_time_change" || anchor.evidenceBasis == "access_time_change" {
            return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "访问时间变了。没有识别到进程，也没有看到打开。")
        }
        if kind == .transferWithoutOpen {
            return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "正文匹配指向这个已登记路径，但没有看到打开。这里不补造打开记录。")
        }
        if anchor.sourceType == "sensitive_access_closed" {
            return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "关闭记录写了这个路径。本快照里没有打开事件，不能补造描述符观测。")
        }
        return EvidenceChainLink(kind: .file, presence: .unproven, value: path, note: "记录了路径，但没有看到打开。依据：\(basisLabel(basis))。")
    }

    private static func basisLabel(_ basis: String) -> String {
        switch basis {
        case "fd_observed": return "fd_observed，看到描述符"
        case "inferred": return "inferred，时间重合"
        case "access_time_change": return "access_time_change，访问时间变化"
        case "same_identity_descriptor_snapshot": return "same_identity_descriptor_snapshot，同一次采样"
        case "": return "没有写下依据"
        default: return basis
        }
    }

    private static func destinationLink(_ destination: DestinationChoice, members: [EvidenceRecord], reasons: [String]) -> EvidenceChainLink {
        var notes = reasons
        if destination.fromCooccurrence {
            notes.insert("同一次采样看到的套接字对端。对端不是正文，也不是上传。", at: 0)
        } else if members.contains(where: { $0.sourceType == "sensitive_network_cooccurrence" }) {
            notes.append("同一次采样里还有一个套接字对端。对端不是正文，也不是上传。")
        }
        let note = notes.joined(separator: " ")
        guard !destination.value.isEmpty else {
            return EvidenceChainLink(kind: .destination, presence: .missing, value: "缺失", note: note.isEmpty ? "没有观察到目的地。" : note)
        }
        return EvidenceChainLink(kind: .destination, presence: .present, value: destination.value, note: note)
    }

    private static func payloadLink(verdict: UploadVerdictWord, hash: String, match: String, members: [EvidenceRecord]) -> EvidenceChainLink {
        let bytes = members.map(\.count).filter { $0 > 0 }.max()
        switch verdict {
        case .notFound:
            let flowNote = members.contains { $0.transferOutcome.contains("live_agent_observed") || $0.evidenceBasis == "live_agent_observed" }
            if flowNote {
                return EvidenceChainLink(kind: .payload, presence: .present, value: "没有看到离开本机的上传", note: "进程和 TCP 发送字节数已查看。这不是看不到。打开的描述符本身不是上传。")
            }
            return EvidenceChainLink(kind: .payload, presence: .present, value: "没有匹配到已登记内容", note: "这是看过的出口里没有内容，不是看不到。")
        case .notVisible:
            return EvidenceChainLink(kind: .payload, presence: .missing, value: "缺失", note: "这个通道的字节看不到，不能写成没有匹配，也不能写成未发现。")
        case .uploaded, .attempted:
            if hash.isEmpty && match.isEmpty {
                return EvidenceChainLink(kind: .payload, presence: .unproven, value: "记录写了正文匹配，但没有摘要", note: "没有补造哈希。原始字节不在记录里。")
            }
            let value = [match, hash.isEmpty ? "" : "SHA-256 \(hash)"].filter { !$0.isEmpty }.joined(separator: " · ")
            var note = "原始字节不在记录里。"
            if let bytes, bytes > 0 { note += " 请求体长度 \(bytes) 字节。" }
            return EvidenceChainLink(kind: .payload, presence: .present, value: value, note: note)
        case .absent, .unrecognized:
            if !hash.isEmpty || !match.isEmpty {
                let value = [match, hash.isEmpty ? "" : "SHA-256 \(hash)"].filter { !$0.isEmpty }.joined(separator: " · ")
                return EvidenceChainLink(kind: .payload, presence: .unproven, value: value, note: "只有摘要。没有出口结论，不能写成已上传或未发现。原始字节不在记录里。")
            }
            return EvidenceChainLink(kind: .payload, presence: .missing, value: "缺失", note: "没有内容匹配。打开的描述符或同时出现的连接不是上传。")
        }
    }

    private static func verdictLink(verdict: UploadVerdictWord, code: String, outcome: String, kind: EvidenceChainKind) -> EvidenceChainLink {
        let outcomeNote = outcome.isEmpty ? "" : "传输结果：\(outcome)。"
        switch verdict {
        case .uploaded:
            if outcome.contains("flow_txbytes_udp") {
                return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                         note: "打开已登记文件之后，UDP/QUIC 发送字节数落在压缩下界和文件窗口之间。这是流量关联，不是解密后的正文，也不是对端回执。\(outcomeNote)")
            }
            if outcome.contains("flow_txbytes") {
                return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                         note: "打开已登记文件之后，进程树上的离机发送字节数合计落在压缩下界和文件窗口之间。这是流量关联，不是解密后的正文，也不是对端回执。\(outcomeNote)")
            }
            return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                     note: "请求体与已登记内容匹配，并且代理看到了成功的 HTTP 结果。这不是对端的独立回执。\(outcomeNote)")
        case .attempted:
            if outcome.contains("flow_attempt") {
                return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                         note: "看到了文件打开，以及一次没有完成的外连。没有把不少于文件大小的字节送出本机。\(outcomeNote)")
            }
            return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                     note: "请求体与已登记内容匹配，但这次传输没有成功。\(outcomeNote)")
        case .notFound:
            if outcome.contains("live_agent_observed") {
                return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                         note: "这个 Agent 已被观察到。没有看到离开本机的上传。这不是看不到。\(outcomeNote)")
            }
            return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                     note: "已查看的出口里没有已登记内容。这句话不覆盖没有被检查的通道。\(outcomeNote)")
        case .notVisible:
            return EvidenceChainLink(kind: .verdict, presence: .present, value: verdict.chineseLabel,
                                     note: "看不到。不能把它写成未发现。\(outcomeNote)")
        case .absent:
            let prefix = kind == .transferWithoutOpen ? "没有看到打开。" : ""
            return EvidenceChainLink(kind: .verdict, presence: .missing, value: verdict.chineseLabel,
                                     note: "\(prefix)没有出口结论。打开的描述符或同时出现的连接不是上传。这不是未发现，也不是看不到。")
        case .unrecognized:
            return EvidenceChainLink(kind: .verdict, presence: .unproven, value: verdict.chineseLabel,
                                     note: "记录里的结论代码是 \(code)。不会把它写成未发现或看不到。")
        }
    }

    private static func closingRank(_ record: EvidenceRecord) -> Int {
        // A descriptor listing that came up short is provisional. A later close
        // that names the channel (including 未发现 for a measured loopback send)
        // is the card to show.
        if record.uploadVerdict == "not_visible" && record.transferOutcome == "descriptors_or_flows_incomplete" {
            return 0
        }
        switch record.uploadVerdict {
        case "uploaded": return 4
        case "attempted": return 3
        case "not_visible": return 2
        case "not_found": return 1
        default: return 0
        }
    }

    private static func padded(_ micros: UInt64) -> String {
        let digits = String(micros)
        if digits.count >= 6 { return digits }
        return String(repeating: "0", count: 6 - digits.count) + digits
    }

}
