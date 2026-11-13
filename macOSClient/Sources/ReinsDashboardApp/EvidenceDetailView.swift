import EvidenceCore
import SwiftUI

struct EvidenceDetailView: View {
    let record: EvidenceRecord

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack {
                    Label(L10n.tr("detail.title"), systemImage: "doc.text.magnifyingglass")
                        .font(.headline)
                    Spacer()
                    if !record.uploadVerdict.isEmpty {
                        VerdictBadge(verdict: UploadVerdictWord.parse(record.uploadVerdict))
                    }
                    RiskBadge(level: record.riskLevel)
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text(EvidenceRedaction.display(record.summary.isEmpty ? record.findingTitle : record.summary))
                        .font(.title3.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    if let action = record.recommendedAction {
                        Text(action).font(.subheadline).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                detailSection(L10n.tr("detail.event")) {
                    DetailValue(title: L10n.tr("detail.eventId"), value: record.id.uuidString, monospaced: true)
                    DetailValue(title: L10n.tr("detail.localTime"), value: Self.timestampFormatter.string(from: record.timestamp), monospaced: true)
                    DetailValue(title: L10n.tr("detail.action"), value: record.actionType, monospaced: true)
                    if !record.sourceType.isEmpty {
                        DetailValue(title: L10n.tr("detail.backendType"), value: record.sourceType, monospaced: true)
                    }
                    DetailValue(title: L10n.tr("detail.target"), value: record.targetResource.isEmpty ? L10n.tr("detail.unrecorded") : record.targetResource, monospaced: true)
                    if !record.destination.isEmpty {
                        DetailValue(title: L10n.tr("detail.destination"), value: EvidenceRedaction.display(record.destination), monospaced: true)
                    }
                    if !record.contentSHA256.isEmpty {
                        DetailValue(title: L10n.tr("detail.sha"), value: record.contentSHA256, monospaced: true)
                    }
                }

                detailSection(L10n.tr("detail.basisSection")) {
                    DetailValue(title: L10n.tr("detail.attribution"), value: record.attribution.isEmpty ? L10n.tr("detail.unrecorded") : record.attribution)
                    if !record.owningAgentName.isEmpty {
                        DetailValue(title: L10n.tr("link.agent"), value: record.owningAgentBundle.isEmpty
                            ? record.owningAgentName
                            : "\(record.owningAgentName) (\(record.owningAgentBundle))")
                    }
                    if !record.classification.isEmpty {
                        DetailValue(title: L10n.tr("detail.classification"), value: record.classification)
                    }
                    if !record.evidenceBasis.isEmpty {
                        DetailValue(title: L10n.tr("detail.evidence"), value: record.evidenceBasis)
                    }
                    if !record.transferOutcome.isEmpty {
                        DetailValue(title: L10n.tr("detail.transfer"), value: record.transferOutcome)
                    }
                    if !record.detail.isEmpty {
                        DetailValue(title: L10n.tr("detail.note"), value: EvidenceRedaction.display(record.detail))
                    }
                    Text(L10n.tr("detail.limit"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                detailSection(L10n.tr("detail.processChain")) {
                    Text(L10n.tr("detail.tree"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if record.processTree.isEmpty {
                        Label(L10n.tr("detail.noProcess"), systemImage: "person.crop.circle.badge.questionmark")
                            .font(.subheadline)
                    } else {
                        ForEach(Array(record.processTree.enumerated()), id: \.offset) { index, process in
                            ProcessNodeView(process: process, isActor: index == 0)
                            if index < record.processTree.count - 1 {
                                Image(systemName: "arrow.down")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                                    .padding(.leading, 12)
                                    .accessibilityHidden(true)
                            }
                        }
                    }
                    Text(chainStatus)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
        }
        .background(.ultraThinMaterial)
        .textSelection(.enabled)
    }

    private var chainStatus: String {
        switch record.chainStatus {
        case "observed_chain_to_root":
            return "Process chain reaches the root process."
        case "observed_chain_to_launchd":
            return "Process chain reaches launchd (pid 1). launchd's own start time was not readable."
        case "missing_parent":
            return "Process chain is incomplete: a parent was not observed."
        case let status where !status.isEmpty:
            return "Process chain: \(status)."
        default:
            switch record.chainComplete {
            case .some(true): return "Process chain is marked complete."
            case .some(false): return "Process chain is incomplete."
            case .none: return "No process-chain status was recorded."
            }
        }
    }

    private func detailSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.subheadline.weight(.semibold))
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS ZZZZZ"
        return formatter
    }()
}

private struct DetailValue: View {
    let title: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(.caption, design: .monospaced) : .subheadline)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct ProcessNodeView: View {
    let process: ProcessNode
    let isActor: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .firstTextBaseline) {
                Text(process.name.isEmpty ? L10n.tr("detail.unknownProcess") : process.name)
                    .font(.subheadline.weight(.medium))
                Spacer()
                if isActor {
                    Text(L10n.tr("detail.actor")).font(.caption2).foregroundStyle(.secondary)
                }
            }
            Text(L10n.format("detail.pid", String(process.pid), String(process.ppid)))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            if let seconds = process.startSeconds, let microseconds = process.startMicroseconds {
                Text(L10n.format("detail.start", seconds, String(format: "%06llu", microseconds)))
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(process.path.isEmpty ? L10n.tr("detail.noPath") : process.path)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.07)))
    }
}
