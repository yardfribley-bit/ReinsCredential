import EvidenceCore
import Foundation
import SwiftUI

enum AgentFilter: Hashable, Identifiable {
    case all
    case named(String)
    case unattributed

    var id: String {
        switch self {
        case .all: return "all"
        case .named(let name): return "named:\(name)"
        case .unattributed: return "unattributed"
        }
    }

    func includes(_ chain: EvidenceChain) -> Bool {
        switch self {
        case .all: return true
        case .named(let name): return chain.owningAgentName == name
        case .unattributed: return chain.owningAgentName.isEmpty
        }
    }

    func includes(_ record: EvidenceRecord) -> Bool {
        switch self {
        case .all: return true
        case .named(let name): return record.owningAgentName == name
        case .unattributed: return record.owningAgentName.isEmpty
        }
    }
}

struct AgentChoice: Identifiable, Equatable {
    var id: String { filter.id }
    var filter: AgentFilter
    var title: String
    var count: Int
}

enum RiskFilter: String, CaseIterable, Identifiable {
    case all, high, medium, low

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return L10n.tr("risk.all")
        case .high: return L10n.tr("risk.high")
        case .medium: return L10n.tr("risk.medium")
        case .low: return L10n.tr("risk.low")
        }
    }

    var symbol: String {
        switch self {
        case .all: return "square.stack.3d.up"
        case .high: return "exclamationmark.shield"
        case .medium: return "exclamationmark.triangle"
        case .low: return "info.circle"
        }
    }

    var color: Color {
        switch self {
        case .all: return .accentColor
        case .high: return .red
        case .medium: return .orange
        case .low: return .blue
        }
    }

    func includes(_ record: EvidenceRecord) -> Bool {
        self == .all || rawValue.uppercased() == record.riskLevel.rawValue
    }
}

@MainActor
final class DashboardStore: ObservableObject {
    enum DatasetMode: String {
        case live, imported, demo
        var title: String {
            switch self {
            case .live: return L10n.tr("mode.live")
            case .imported: return L10n.tr("mode.imported")
            case .demo: return L10n.tr("mode.demo")
            }
        }
    }

    @Published private(set) var records: [EvidenceRecord] = []
    /// Closures and the records chains are built from. Separate from `records`.
    @Published private(set) var chainRecords: [EvidenceRecord] = []
    private var cachedChains: [EvidenceChain] = []
    @Published var riskFilter: RiskFilter = .all
    @Published var agentFilter: AgentFilter = .all
    @Published var searchText = ""
    @Published var selectedRecordID: UUID?
    @Published var selectedChainID: UUID?
    @Published var isImporterPresented = false
    @Published private(set) var isLoading = false
    @Published private(set) var mode: DatasetMode = .live
    @Published private(set) var importedURL: URL?
    @Published private(set) var rejectedLines: [Int] = []
    @Published private(set) var incompleteTail = false
    @Published var errorMessage: String?

    var isDemo: Bool { mode == .demo }

    /// Live updates cannot overwrite an imported snapshot or synthetic demo.
    /// Keep selection and filters stable as new records arrive.
    func applyLive(records: [EvidenceRecord], chainRecords: [EvidenceRecord]? = nil) {
        guard mode == .live, !isLoading else { return }
        storeDataset(records: records, chainRecords: chainRecords)
        reconcileSelection()
    }

    func returnToLive(records: [EvidenceRecord]) {
        guard !isLoading else { return }
        mode = .live
        importedURL = nil
        rejectedLines = []
        incompleteTail = false
        errorMessage = nil
        riskFilter = .all
        agentFilter = .all
        searchText = ""
        applyLive(records: records)
    }

    var chains: [EvidenceChain] { cachedChains }

    /// Chain detail looks up members here, including closures the events window has dropped.
    var recordsForChains: [EvidenceRecord] { chainRecords.isEmpty ? records : chainRecords }

    var chainsMatchingRiskAndSearch: [EvidenceChain] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return chains.filter { chain in
            guard riskFilter == .all || riskFilter.rawValue.uppercased() == chain.riskLevel.rawValue else { return false }
            return query.isEmpty || chain.matchesSearch(query)
        }
    }

    var visibleChains: [EvidenceChain] {
        chainsMatchingRiskAndSearch.filter { agentFilter.includes($0) }
    }

    var chainSections: [EvidenceChainSection] { visibleChains.groupedByOwningAgent() }

    var selectedChain: EvidenceChain? { visibleChains.first { $0.id == selectedChainID } }

    var agentChoices: [AgentChoice] {
        chainsMatchingRiskAndSearch.groupedByOwningAgent().map { section in
            let filter: AgentFilter = section.id == "unattributed" ? .unattributed : .named(section.title)
            return AgentChoice(filter: filter, title: section.title, count: section.chains.count)
        }
    }

    var hasSensorGap: Bool { records.contains { $0.sourceType == "sensor_gap" } }

    /// Selects the chain for a synthetic self-test file once that file is in the live set.
    @discardableResult
    func focusChain(matchingResource path: String) -> Bool {
        guard mode == .live, !path.isEmpty else { return false }
        let matches = chains.filter { $0.filePath == path }
        guard let match = matches.first(where: \.openObserved) ?? matches.first else { return false }
        if !visibleChains.contains(where: { $0.id == match.id }) {
            agentFilter = .all
            riskFilter = .all
            searchText = ""
        }
        selectedChainID = match.id
        return true
    }

    var visibleRecords: [EvidenceRecord] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return records.filter { record in
            guard riskFilter.includes(record) else { return false }
            guard agentFilter.includes(record) else { return false }
            guard !query.isEmpty else { return true }
            let fields = [record.targetResource, record.actionType, record.sourceType,
                          record.destination, record.id.uuidString, record.owningAgentName,
                          record.uploadVerdict, record.summary,
                          UploadVerdictWord.parse(record.uploadVerdict).chineseLabel] +
                record.processTree.flatMap { [$0.name, $0.path, String($0.pid)] }
            return fields.contains { $0.localizedCaseInsensitiveContains(query) }
        }
    }

    var selectedRecord: EvidenceRecord? {
        visibleRecords.first { $0.id == selectedRecordID }
    }

    func count(for filter: RiskFilter) -> Int {
        records.filter(filter.includes).count
    }

    func reconcileSelection() {
        if !visibleRecords.contains(where: { $0.id == selectedRecordID }) {
            selectedRecordID = visibleRecords.first?.id
        }
        if !visibleChains.contains(where: { $0.id == selectedChainID }) {
            selectedChainID = visibleChains.first?.id
        }
    }

    func showSamples() {
        guard !isLoading else { return }
        storeDataset(records: EvidenceRecord.sampleRecords)
        importedURL = nil
        rejectedLines = []
        incompleteTail = false
        mode = .demo
        riskFilter = .all
        agentFilter = .all
        searchText = ""
        selectedRecordID = records.first?.id
        reconcileSelection()
        errorMessage = nil
    }

    func importLog(from url: URL) {
        guard !isLoading else { return }
        isLoading = true
        errorMessage = nil
        Task {
            let hasScope = url.startAccessingSecurityScopedResource()
            defer {
                if hasScope { url.stopAccessingSecurityScopedResource() }
                isLoading = false
            }
            do {
                let result = try await EvidenceLogReader.read(url: url)
                guard !result.records.isEmpty || (result.rejectedLines.isEmpty && !result.incompleteTail) else {
                    throw ImportFailure.noUsableRecords(rejected: result.rejectedLines.count,
                                                        incomplete: result.incompleteTail)
                }
                storeDataset(records: result.records) // Reader supplies timestamp + UUID ordering.
                rejectedLines = result.rejectedLines
                incompleteTail = result.incompleteTail
                importedURL = url
                mode = .imported
                riskFilter = .all
                agentFilter = .all
                searchText = ""
                selectedRecordID = records.first?.id
                reconcileSelection()
            } catch {
                // A failed import never replaces the last usable dataset.
                errorMessage = error.localizedDescription
            }
        }
    }

    private func storeDataset(records: [EvidenceRecord], chainRecords explicitChain: [EvidenceRecord]? = nil) {
        let chain = explicitChain ?? records
        let chainChanged = chain.count != chainRecords.count
            || zip(chain, chainRecords).contains { $0.id != $1.id }
        self.records = records
        if chainChanged || (cachedChains.isEmpty && !chain.isEmpty) {
            chainRecords = chain
            cachedChains = EvidenceChainBuilder.chains(from: chain)
        }
    }

    private enum ImportFailure: LocalizedError {
        case noUsableRecords(rejected: Int, incomplete: Bool)

        var errorDescription: String? {
            switch self {
            case .noUsableRecords(let rejected, let incomplete):
                return L10n.format("store.importEmpty", rejected, incomplete ? L10n.tr("store.tailYes") : L10n.tr("store.tailNo"))
            }
        }
    }
}
