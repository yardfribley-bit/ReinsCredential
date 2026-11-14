import EvidenceCore
import SwiftUI
import UniformTypeIdentifiers

private enum BoardMode: String, Hashable {
    case chains, events
}

struct DashboardView: View {
    @ObservedObject var store: DashboardStore
    @ObservedObject var runtime: RuntimeController
    @State private var isConfigurationPresented = false
    @State private var boardMode: BoardMode = .chains
    @State private var focusedSelfTest = ""
    @State private var exportPresented = false
    @State private var exportDocument = ChainExportFile(text: "")
    @State private var exportType: UTType = .json
    @State private var exportName = "evidence-chain.json"
    @State private var windowSheet = false
    @State private var windowStart = Date()
    @State private var windowEnd = Date()

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 260)
        } content: {
            evidenceContent
                .navigationSplitViewColumnWidth(min: 450, ideal: 680)
        } detail: {
            detailColumn
                .navigationSplitViewColumnWidth(min: 300, ideal: 380)
        }
        .navigationTitle("ReinsCredential")
        .background(Color(nsColor: .windowBackgroundColor))
        .toolbar {
            ToolbarItemGroup {
                if store.mode != .live {
                    Button { store.returnToLive(records: runtime.records) } label: {
                        Label(L10n.tr("nav.backLive"), systemImage: "waveform.path.ecg")
                    }
                    .disabled(store.isLoading)
                }
                Button { isConfigurationPresented = true } label: {
                    Label(L10n.tr("nav.scope"), systemImage: "folder.badge.gearshape")
                }
                .help(L10n.tr("help.scope"))
                Button(action: runtime.runSelfTest) {
                    Label(L10n.tr("nav.selfTest"), systemImage: "checkmark.shield")
                }
                .disabled(runtime.isBusy || !runtime.state.canSelfTest)
                .help(L10n.tr("help.selfTest"))
                if store.isLoading {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel(L10n.tr("nav.importing"))
                }
                Menu {
                    Button(L10n.tr("nav.exportMarkdown")) { exportSelected(markdown: true) }
                    Button(L10n.tr("nav.exportJSON")) { exportSelected(markdown: false) }
                    Divider()
                    Button(L10n.tr("nav.exportWindow")) { presentWindow() }
                    Divider()
                    Button(L10n.tr("nav.import")) { store.isImporterPresented = true }
                    Button(L10n.tr("nav.demo")) { store.showSamples() }
                } label: {
                    Label(L10n.tr("nav.more"), systemImage: "ellipsis.circle")
                }
                .disabled(store.isLoading)
            }
        }
        .sheet(isPresented: $isConfigurationPresented) {
            RuntimeConfigurationView(runtime: runtime)
        }
        .fileImporter(isPresented: $store.isImporterPresented,
                      allowedContentTypes: [.json, .plainText, .data]) { result in
            switch result {
            case .success(let url): store.importLog(from: url)
            case .failure(let error):
                let nsError = error as NSError
                if !(nsError.domain == NSCocoaErrorDomain && nsError.code == NSUserCancelledError) {
                    store.errorMessage = error.localizedDescription
                }
            }
        }
        .alert(L10n.tr("alert.importFailed"), isPresented: Binding(
            get: { store.errorMessage != nil },
            set: { if !$0 { store.errorMessage = nil } }
        )) {
            Button(L10n.tr("alert.ok"), role: .cancel) { store.errorMessage = nil }
        } message: {
            Text(store.errorMessage ?? "")
        }
        .alert(L10n.tr("alert.monitorService"), isPresented: Binding(
            get: { runtime.errorMessage != nil },
            set: { if !$0 { runtime.errorMessage = nil } }
        )) {
            Button(L10n.tr("alert.ok"), role: .cancel) { runtime.errorMessage = nil }
        } message: { Text(runtime.errorMessage ?? "") }
        .onChange(of: store.searchText) { _ in store.reconcileSelection() }
        .onChange(of: store.riskFilter) { _ in store.reconcileSelection() }
        .onChange(of: store.agentFilter) { _ in store.reconcileSelection() }
        .onChange(of: runtime.selfTestResource) { _ in focusSelfTestIfNeeded() }
        .onReceive(runtime.$records) { records in
            store.applyLive(records: records, chainRecords: runtime.chainRecords)
            focusSelfTestIfNeeded()
        }
        .onReceive(runtime.$chainRecords) { chainRecords in
            store.applyLive(records: runtime.records, chainRecords: chainRecords)
            focusSelfTestIfNeeded()
        }
        .fileExporter(isPresented: $exportPresented, document: exportDocument, contentType: exportType, defaultFilename: exportName) { _ in }
        .sheet(isPresented: $windowSheet) { windowExportSheet }
    }

    @ViewBuilder
    private var detailColumn: some View {
        switch boardMode {
        case .chains:
            if let chain = store.selectedChain {
                EvidenceChainDetailView(chain: chain, records: store.recordsForChains,
                                        exportMarkdown: { exportSelected(markdown: true) },
                                        exportJSON: { exportSelected(markdown: false) })
            } else {
                EmptyEvidenceView(symbol: "link", title: L10n.tr("empty.selectChain"),
                                  message: L10n.tr("empty.selectChainBody"))
            }
        case .events:
            if let record = store.selectedRecord {
                EvidenceDetailView(record: record)
            } else {
                EmptyEvidenceView(symbol: "doc.text.magnifyingglass", title: L10n.tr("empty.selectRecord"),
                                  message: L10n.tr("empty.selectRecordBody"))
            }
        }
    }

    private var windowExportSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.tr("window.exportTitle")).font(.title3.weight(.semibold))
            Text(L10n.tr("window.exportBody"))
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            DatePicker(L10n.tr("window.start"), selection: $windowStart)
            DatePicker(L10n.tr("window.end"), selection: $windowEnd)
            HStack {
                Button(L10n.tr("window.exportMarkdown")) { exportWindow(markdown: true) }
                Button(L10n.tr("window.exportJSON")) { exportWindow(markdown: false) }
                Spacer()
                Button(L10n.tr("window.cancel"), role: .cancel) { windowSheet = false }
            }
        }
        .padding(20)
        .frame(width: 440)
    }

    private func exportSelected(markdown: Bool) {
        guard let chain = store.selectedChain else { return }
        presentExport(markdown: markdown, text: markdown ? EvidenceChainExport.markdown([chain]) : EvidenceChainExport.json([chain]),
                      name: markdown ? "evidence-chain.md" : "evidence-chain.json")
    }

    private func presentWindow() {
        let stamps = store.visibleChains.map(\.timestamp)
        windowStart = stamps.min() ?? Date()
        windowEnd = stamps.max() ?? Date()
        windowSheet = true
    }

    private func exportWindow(markdown: Bool) {
        let window = min(windowStart, windowEnd)...max(windowStart, windowEnd)
        let text = markdown ? EvidenceChainExport.markdown(store.visibleChains, window: window)
            : EvidenceChainExport.json(store.visibleChains, window: window)
        windowSheet = false
        presentExport(markdown: markdown, text: text, name: markdown ? "evidence-chains.md" : "evidence-chains.json")
    }

    private func presentExport(markdown: Bool, text: String, name: String) {
        exportDocument = ChainExportFile(text: text)
        exportType = markdown ? .plainText : .json
        exportName = name
        exportPresented = true
    }

    private func focusSelfTestIfNeeded() {
        let path = runtime.selfTestResource
        guard store.mode == .live, !path.isEmpty, focusedSelfTest != path else { return }
        guard store.focusChain(matchingResource: path) else { return }
        boardMode = .chains
        focusedSelfTest = path
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title2)
                    .foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 3) {
                    Text(L10n.tr("sidebar.runtimeSecurity")).font(.headline)
                    Text(L10n.tr("sidebar.localMonitor")).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(18)
            .fixedSize(horizontal: false, vertical: true)

            List(selection: $store.agentFilter) {
                Section(L10n.tr("sidebar.agents")) {
                        agentRow(title: L10n.tr("sidebar.allChains"), count: store.chainsMatchingRiskAndSearch.count, symbol: "square.stack.3d.up")
                            .tag(AgentFilter.all)
                    ForEach(store.agentChoices) { choice in
                        agentRow(title: choice.title, count: choice.count,
                                 symbol: choice.filter == .unattributed ? "person.crop.circle.badge.questionmark" : "person.2")
                            .tag(choice.filter)
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .frame(maxHeight: .infinity)
            VStack(alignment: .leading, spacing: 7) {
                Label(store.mode.title, systemImage: store.mode == .live ? "waveform.path.ecg" : "doc.text")
                    .font(.caption.weight(.semibold))
                Text(store.mode == .live ? L10n.format("mode.liveDetail", runtime.watchedPaths.count) : L10n.tr("mode.otherDetail"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if store.mode == .live, let date = runtime.lastUpdate {
                    Text(L10n.format("mode.updated", date.formatted(date: .omitted, time: .standard)))
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .fixedSize(horizontal: false, vertical: true)
        }
        .background(.ultraThinMaterial)
    }

    private var evidenceContent: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                RuntimeStatusPanel(runtime: runtime)
                HStack(alignment: .firstTextBaseline) {
                    Text(boardMode == .chains ? L10n.tr("board.chains") : store.riskFilter.title).font(.title2.bold())
                    Spacer()
                    Text(boardMode == .chains ? L10n.format("board.chainCount", store.visibleChains.count) : L10n.format("board.recordCount", store.visibleRecords.count))
                        .font(.subheadline.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Picker(L10n.tr("board.view"), selection: $boardMode) {
                    Text(L10n.tr("board.chains")).tag(BoardMode.chains)
                    Text(L10n.tr("board.events")).tag(BoardMode.events)
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 240)
                HStack {
                    Menu {
                        ForEach(RiskFilter.allCases) { filter in
                            Button(filter.title) { store.riskFilter = filter }
                        }
                    } label: {
                        Label(store.riskFilter.title, systemImage: store.riskFilter.symbol)
                    }
                    Spacer()
                }
                datasetNotice
                if store.hasSensorGap {
                    Label(L10n.tr("gap.banner"), systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if !store.rejectedLines.isEmpty || store.incompleteTail {
                    importWarning
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.ultraThinMaterial)
            .fixedSize(horizontal: false, vertical: true)
            .layoutPriority(1)

            Divider()
            switch boardMode {
            case .chains:
                if store.visibleChains.isEmpty {
                    emptyDataset
                } else {
                    VStack(spacing: 0) {
                        EvidenceChainList(sections: store.chainSections, selection: $store.selectedChainID)
                        Text(L10n.tr("glossary"))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            case .events:
                if store.visibleRecords.isEmpty {
                    emptyDataset
                } else {
                    EvidenceTable(records: store.visibleRecords, selection: $store.selectedRecordID)
                }
            }
        }
        .searchable(text: $store.searchText, placement: .toolbar,
                    prompt: L10n.tr("search.prompt"))
    }

    private func agentRow(title: String, count: Int, symbol: String) -> some View {
        HStack {
            Label(title, systemImage: symbol)
            Spacer(minLength: 4)
            Text(count, format: .number)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
    }

    private var datasetNotice: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: store.isDemo ? "sparkles" : (store.mode == .live ? "dot.radiowaves.left.and.right" : "doc.text"))
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(datasetTitle)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                    .help(store.importedURL?.path ?? store.mode.title)
                Text(datasetDescription)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var datasetTitle: String {
        switch store.mode {
        case .live: return L10n.tr("dataset.liveTitle")
        case .imported: return store.importedURL?.lastPathComponent ?? L10n.tr("dataset.importedFallback")
        case .demo: return L10n.tr("dataset.demoTitle")
        }
    }

    private var datasetDescription: String {
        switch store.mode {
        case .live: return L10n.tr("dataset.liveBody")
        case .imported: return L10n.tr("dataset.importedBody")
        case .demo: return L10n.tr("dataset.demoBody")
        }
    }

    @ViewBuilder
    private var emptyDataset: some View {
        if boardMode == .chains && store.visibleChains.isEmpty && !store.records.isEmpty
            && store.searchText.isEmpty && store.riskFilter == .all && store.agentFilter == .all {
            EmptyEvidenceView(symbol: "link", title: L10n.tr("empty.noChains"),
                              message: L10n.tr("empty.noChainsBody"))
        } else if !store.records.isEmpty || (boardMode == .chains && !store.chains.isEmpty) {
            EmptyEvidenceView(symbol: "line.3.horizontal.decrease.circle", title: L10n.tr("empty.noMatch"),
                              message: L10n.tr("empty.noMatchBody"))
        } else if store.mode == .live {
            VStack(spacing: 14) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 38)).foregroundStyle(Color.accentColor)
                Text(runtime.state.canStop ? L10n.tr("empty.waitingTitle") : L10n.tr("empty.startTitle"))
                    .font(.title3.bold())
                Text(runtime.state.canStop ? L10n.tr("empty.waitingBody") : L10n.tr("empty.startBody"))
                    .font(.subheadline).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                HStack {
                    Button(L10n.tr("empty.chooseFolder")) { isConfigurationPresented = true }
                    if runtime.state.canSelfTest {
                        Button(L10n.tr("empty.runSelfTest"), action: runtime.runSelfTest).buttonStyle(.borderedProminent)
                            .disabled(runtime.isBusy)
                    }
                }
            }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            EmptyEvidenceView(symbol: "doc.text", title: L10n.tr("empty.snapshotTitle"),
                              message: L10n.tr("empty.snapshotBody"))
        }
    }

    private var importWarning: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                if !store.rejectedLines.isEmpty {
                    Text(L10n.format("rejected.skip", store.rejectedLines.count))
                    Text(L10n.format("rejected.lines", store.rejectedLines.prefix(20).map(String.init).joined(separator: ", ")) +
                         (store.rejectedLines.count > 20 ? "…" : ""))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if store.incompleteTail {
                    Text(L10n.tr("rejected.tail"))
                }
            }
            .font(.caption)
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct EvidenceTable: View {
    let records: [EvidenceRecord]
    @Binding var selection: UUID?

    var body: some View {
        Table(records, selection: $selection) {
            TableColumn(L10n.tr("column.risk")) { record in
                RiskBadge(level: record.riskLevel, isSelected: selection == record.id)
            }.width(62)
            TableColumn(L10n.tr("column.time")) { record in
                Text(record.timestamp, format: .dateTime.hour().minute().second())
                    .monospacedDigit()
                    .help(record.timestamp.formatted(date: .complete, time: .complete))
            }.width(82)
            TableColumn(L10n.tr("column.finding")) { record in
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.findingTitle).font(.caption).lineLimit(2)
                    if !record.uploadVerdict.isEmpty {
                        VerdictBadge(verdict: UploadVerdictWord.parse(record.uploadVerdict))
                    }
                }
                .help(record.sourceType.isEmpty ? record.actionType : record.sourceType)
            }.width(min: 120, ideal: 170)
            TableColumn(L10n.tr("column.process")) { record in
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.summary.isEmpty ? (record.processTree.first?.name ?? L10n.tr("row.unattributed")) : record.summary)
                        .font(.body.weight(.medium))
                        .lineLimit(record.summary.isEmpty ? 1 : 3)
                    Text(record.targetResource.isEmpty ? L10n.tr("row.noFile") : record.targetResource)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .padding(.vertical, 6)
                .help(record.targetResource)
            }.width(min: 160, ideal: 300)
        }
        .tableStyle(.inset(alternatesRowBackgrounds: true))
        .accessibilityLabel(L10n.tr("row.a11y"))
    }
}

struct RiskBadge: View {
    let level: RiskLevel
    var isSelected = false

    private var filter: RiskFilter { RiskFilter(rawValue: level.rawValue.lowercased()) ?? .low }

    var body: some View {
        Text(filter.title)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .foregroundStyle(isSelected ? Color.primary : filter.color)
            .background((isSelected ? Color.primary : filter.color).opacity(0.12), in: Capsule())
            .accessibilityLabel(L10n.format("risk.a11y", filter.title))
    }
}

struct EmptyEvidenceView: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: symbol).font(.system(size: 34)).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(message).font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
