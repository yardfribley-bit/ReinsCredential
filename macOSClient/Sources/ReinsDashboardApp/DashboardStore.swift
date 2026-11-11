import EvidenceCore
import Foundation
import SwiftUI

enum RiskFilter: String, CaseIterable, Identifiable {
    case all, high, medium, low

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: return "全部证据"
        case .high: return "高风险"
        case .medium: return "中风险"
        case .low: return "低风险"
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
    @Published private(set) var records = EvidenceRecord.sampleRecords
    @Published var riskFilter: RiskFilter = .all
    @Published var searchText = ""
    @Published var selectedRecordID: UUID?
    @Published var isImporterPresented = false
    @Published private(set) var isLoading = false
    @Published private(set) var isDemo = true
    @Published private(set) var importedURL: URL?
    @Published private(set) var rejectedLines: [Int] = []
    @Published private(set) var incompleteTail = false
    @Published var errorMessage: String?

    init() {
        selectedRecordID = records.first?.id
    }

    var visibleRecords: [EvidenceRecord] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return records.filter { record in
            guard riskFilter.includes(record) else { return false }
            guard !query.isEmpty else { return true }
            let fields = [record.targetResource, record.actionType, record.sourceType,
                          record.destination, record.id.uuidString] +
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
    }

    func showSamples() {
        guard !isLoading else { return }
        records = EvidenceRecord.sampleRecords
        importedURL = nil
        rejectedLines = []
        incompleteTail = false
        isDemo = true
        riskFilter = .all
        searchText = ""
        selectedRecordID = records.first?.id
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
                records = result.records // Reader supplies timestamp + UUID ordering.
                rejectedLines = result.rejectedLines
                incompleteTail = result.incompleteTail
                importedURL = url
                isDemo = false
                riskFilter = .all
                searchText = ""
                selectedRecordID = records.first?.id
            } catch {
                // A failed import never replaces the last usable dataset.
                errorMessage = error.localizedDescription
            }
        }
    }

    private enum ImportFailure: LocalizedError {
        case noUsableRecords(rejected: Int, incomplete: Bool)

        var errorDescription: String? {
            switch self {
            case .noUsableRecords(let rejected, let incomplete):
                return "日志中没有完整且有效的证据记录（无效或重复行：\(rejected)，未完成尾行：\(incomplete ? "有" : "无")）。已保留当前数据。"
            }
        }
    }
}
