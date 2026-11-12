import EvidenceCore
import SwiftUI
import UniformTypeIdentifiers

extension UploadVerdictWord {
    var tint: Color {
        switch self {
        case .uploaded: return .red
        case .attempted: return .orange
        case .notFound: return .blue
        case .notVisible: return .purple
        case .absent, .unrecognized: return .secondary
        }
    }

    var symbol: String {
        switch self {
        case .uploaded: return "arrow.up.doc"
        case .attempted: return "exclamationmark.arrow.triangle.2.circlepath"
        case .notFound: return "magnifyingglass"
        case .notVisible: return "eye.slash"
        case .absent, .unrecognized: return "questionmark.circle"
        }
    }
}

struct VerdictBadge: View {
    let verdict: UploadVerdictWord

    var body: some View {
        Label(verdict.chineseLabel, systemImage: verdict.symbol)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .foregroundStyle(verdict.tint)
            .background(verdict.tint.opacity(0.12), in: Capsule())
            .accessibilityLabel("出口结论：\(verdict.chineseLabel)")
    }
}

struct ChainExportFile: FileDocument {
    static var readableContentTypes: [UTType] { [.json, .plainText] }
    var text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        text = String(decoding: configuration.file.regularFileContents ?? Data(), as: UTF8.self)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

struct EvidenceChainList: View {
    let sections: [EvidenceChainSection]
    @Binding var selection: UUID?

    var body: some View {
        List(selection: $selection) {
            ForEach(sections) { section in
                Section {
                    ForEach(section.chains) { chain in
                        ChainRow(chain: chain)
                            .tag(chain.id)
                    }
                } header: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(section.title)
                        if !section.subtitle.isEmpty {
                            Text(section.subtitle).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .listStyle(.inset)
        .accessibilityLabel("证据链")
    }
}

struct ChainRow: View {
    let chain: EvidenceChain

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                VerdictBadge(verdict: chain.verdict)
                if chain.link(.process)?.presence == .incomplete {
                    Text("进程链不完整")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.orange)
                }
                if chain.kind == .transferWithoutOpen {
                    Text("没有看到打开")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.orange)
                }
                Spacer(minLength: 4)
                Text(chain.timestamp, format: .dateTime.hour().minute().second())
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Text(chain.filePath.isEmpty ? "没有对应文件" : chain.filePath)
                .font(.body.weight(.medium))
                .lineLimit(1)
                .truncationMode(.middle)
            HStack(spacing: 8) {
                Label(chain.link(.agent)?.presence == .missing ? "Agent 缺失" : (chain.owningAgentName.isEmpty ? "未归属" : chain.owningAgentName),
                      systemImage: "person.crop.rectangle")
                if chain.destination.isEmpty {
                    Label("目的地缺失", systemImage: "circle.dashed")
                } else {
                    Text(chain.destination).lineLimit(1).truncationMode(.middle)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            if !chain.reasonLine.isEmpty {
                Text(chain.reasonLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(chain.headline)
    }
}

struct EvidenceChainDetailView: View {
    let chain: EvidenceChain
    let records: [EvidenceRecord]
    var exportMarkdown: () -> Void
    var exportJSON: () -> Void

    var body: some View {
        ScrollView {
            EvidenceChainDetailBody(chain: chain, records: records, exportMarkdown: exportMarkdown, exportJSON: exportJSON)
        }
        .background(.ultraThinMaterial)
        .textSelection(.enabled)
    }
}

/// The card body without a scroll view, so ImageRenderer can lay out the whole chain.
struct EvidenceChainDetailBody: View {
    let chain: EvidenceChain
    let records: [EvidenceRecord]
    var exportMarkdown: () -> Void
    var exportJSON: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("证据链")
                        .font(.headline)
                    Text(chain.headline)
                        .font(.title3.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                VerdictBadge(verdict: chain.verdict)
            }
            Text(EvidenceChainExport.glossaryText)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("导出 Markdown", action: exportMarkdown)
                Button("导出 JSON", action: exportJSON)
            }
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(chain.links.enumerated()), id: \.element.kind) { index, link in
                    ChainStep(link: link, showsConnector: index < chain.links.count - 1, emphasize: link.kind == .verdict)
                }
            }
            if chain.missingReferenceCount > 0 {
                Label("有 \(chain.missingReferenceCount) 个关联事件不在当前快照里，没有补造。", systemImage: "link.badge.plus")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if !chain.backendSummary.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("采集原句").font(.caption).foregroundStyle(.secondary)
                    Text(chain.backendSummary)
                        .font(.subheadline)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            memberList
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var members: [EvidenceRecord] {
        records.filter { chain.memberIDs.contains($0.id) }
            .sorted { $0.timestamp == $1.timestamp ? $0.id.uuidString < $1.id.uuidString : $0.timestamp < $1.timestamp }
    }

    private var memberList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("相关事件").font(.subheadline.weight(.semibold))
            if members.isEmpty {
                Text("当前快照里没有展开这些事件。").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(members) { record in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(record.findingTitle).font(.caption.weight(.medium))
                        Spacer()
                        if !record.uploadVerdict.isEmpty {
                            Text(UploadVerdictWord.parse(record.uploadVerdict).chineseLabel)
                                .font(.caption2)
                                .foregroundStyle(UploadVerdictWord.parse(record.uploadVerdict).tint)
                        }
                    }
                    Text(record.timestamp.formatted(date: .abbreviated, time: .standard))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text(record.id.uuidString)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}

private struct ChainStep: View {
    let link: EvidenceChainLink
    let showsConnector: Bool
    var emphasize = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Image(systemName: symbol)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(tint)
                    .frame(width: 28, height: 28)
                    .background(tint.opacity(0.12), in: Circle())
                    .overlay(Circle().strokeBorder(tint.opacity(link.presence == .present ? 0.01 : 0.7),
                                                   style: StrokeStyle(lineWidth: 1, dash: link.presence == .present ? [] : [3, 2])))
                if showsConnector {
                    Rectangle()
                        .fill(Color.secondary.opacity(0.25))
                        .frame(width: 1, height: 16)
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(link.title).font(.subheadline.weight(.semibold))
                    Text(link.presence.displayName)
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .foregroundStyle(tint)
                        .background(tint.opacity(0.12), in: Capsule())
                }
                Text(link.value)
                    .font(emphasize ? .title3.weight(.semibold) : .subheadline)
                    .foregroundStyle(emphasize ? tint : .primary)
                    .fixedSize(horizontal: false, vertical: true)
                if !link.note.isEmpty {
                    Text(link.note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.bottom, showsConnector ? 8 : 0)
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    private var tint: Color {
        if link.kind == .verdict, let verdict = UploadVerdictWord(rawValue: verdictCode(from: link.value)) {
            return verdict.tint
        }
        switch link.presence {
        case .present: return .accentColor
        case .incomplete, .unproven: return .orange
        case .missing, .unrecorded: return .secondary
        }
    }

    private var symbol: String {
        switch link.presence {
        case .present: return "checkmark"
        case .incomplete: return "exclamationmark"
        case .unrecorded: return "questionmark"
        case .missing: return "circle.dashed"
        case .unproven: return "questionmark"
        }
    }

    private func verdictCode(from label: String) -> String {
        switch label {
        case UploadVerdictWord.uploaded.chineseLabel: return UploadVerdictWord.uploaded.rawValue
        case UploadVerdictWord.attempted.chineseLabel: return UploadVerdictWord.attempted.rawValue
        case UploadVerdictWord.notFound.chineseLabel: return UploadVerdictWord.notFound.rawValue
        case UploadVerdictWord.notVisible.chineseLabel: return UploadVerdictWord.notVisible.rawValue
        default: return ""
        }
    }
}
