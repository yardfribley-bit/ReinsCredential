import AppKit
import EvidenceCore
import SwiftUI

enum EvidenceChainSnapshotError: Error, CustomStringConvertible {
    case missingVerdict(String)
    case noImage
    case emptyImage

    var description: String {
        switch self {
        case .missingVerdict(let label): return "Synthetic demo has no \(label) chain."
        case .noImage: return "ImageRenderer did not produce a bitmap."
        case .emptyImage: return "ImageRenderer produced an empty bitmap."
        }
    }
}

/// Renders the synthetic demo with ImageRenderer. List and scroll views stay in the
/// live app; these stacks use the same row and card body so the bitmap contains
/// every agent group and the whole selected chain.
enum EvidenceChainSnapshot {
    static let fileNames = [
        "evidence-chains-by-agent.png",
        "evidence-chain-uploaded.png",
        "evidence-chain-attempted.png",
        "evidence-chain-not-found.png",
        "evidence-chain-not-visible.png",
        "evidence-chains.md"
    ]

    @MainActor
    static func renderDemo() throws -> [String: Data] {
        let records = EvidenceRecord.sampleRecords
        let chains = EvidenceChainBuilder.chains(from: records)
        let sections = chains.groupedByOwningAgent()
        var files: [String: Data] = [:]
        files["evidence-chains-by-agent.png"] = try png(
            EvidenceChainAgentGallery(sections: sections), width: 960, height: 2800)
        let pages: [(UploadVerdictWord, String)] = [
            (.uploaded, "evidence-chain-uploaded.png"),
            (.attempted, "evidence-chain-attempted.png"),
            (.notFound, "evidence-chain-not-found.png"),
            (.notVisible, "evidence-chain-not-visible.png")
        ]
        for (verdict, name) in pages {
            guard let chain = chains.first(where: { $0.verdict == verdict }) else {
                throw EvidenceChainSnapshotError.missingVerdict(verdict.chineseLabel)
            }
            files[name] = try png(
                EvidenceChainDetailBody(chain: chain, records: records, exportMarkdown: {}, exportJSON: {})
                    .padding(20)
                    .background(Color(nsColor: .windowBackgroundColor)),
                width: 760, height: 2200)
        }
        let markdown = EvidenceChainExport.markdown(chains)
        files["evidence-chains.md"] = Data(markdown.utf8)
        return files
    }

    @MainActor
    private static func png<V: View>(_ view: V, width: CGFloat, height: CGFloat) throws -> Data {
        let content = view
            .frame(width: width, height: height, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor))
            .environment(\.colorScheme, .light)
        let renderer = ImageRenderer(content: content)
        renderer.scale = 2
        renderer.proposedSize = ProposedViewSize(width: width, height: height)
        guard let image = renderer.cgImage else { throw EvidenceChainSnapshotError.noImage }
        let rep = NSBitmapImageRep(cgImage: image)
        guard rep.pixelsWide >= 700, rep.pixelsHigh >= 600,
              let data = rep.representation(using: .png, properties: [:]),
              data.count > 10_000 else {
            throw EvidenceChainSnapshotError.emptyImage
        }
        return data
    }
}

struct EvidenceChainAgentGallery: View {
    let sections: [EvidenceChainSection]

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(L10n.tr("board.chains")).font(.title2.bold())
            Text(L10n.tr("mode.demo")).font(.caption).foregroundStyle(.secondary)
            ForEach(sections) { section in
                VStack(alignment: .leading, spacing: 8) {
                    Text(section.title).font(.headline)
                    if !section.subtitle.isEmpty {
                        Text(section.subtitle).font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(section.chains) { chain in
                        ChainRow(chain: chain)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
                    }
                }
            }
            Text(L10n.tr("glossary"))
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(20)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}
