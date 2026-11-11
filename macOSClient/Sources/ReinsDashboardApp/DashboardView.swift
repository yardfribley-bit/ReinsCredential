import EvidenceCore
import SwiftUI
import UniformTypeIdentifiers

struct DashboardView: View {
    @ObservedObject var store: DashboardStore
    @ObservedObject var runtime: RuntimeController
    @State private var isConfigurationPresented = false

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 260)
        } content: {
            evidenceContent
                .navigationSplitViewColumnWidth(min: 450, ideal: 680)
        } detail: {
            if let record = store.selectedRecord {
                EvidenceDetailView(record: record)
                    .navigationSplitViewColumnWidth(min: 300, ideal: 350)
            } else {
                EmptyEvidenceView(symbol: "doc.text.magnifyingglass", title: "选择一条证据",
                                  message: "查看资源、进程链与后端记录的关联依据。")
            }
        }
        .navigationTitle("ReinsCredential")
        .background(Color(nsColor: .windowBackgroundColor))
        .toolbar {
            ToolbarItemGroup {
                if store.mode != .live {
                    Button { store.returnToLive(records: runtime.records) } label: {
                        Label("返回实时监控", systemImage: "waveform.path.ecg")
                    }
                    .disabled(store.isLoading)
                }
                Button { isConfigurationPresented = true } label: {
                    Label("监控范围", systemImage: "folder.badge.gearshape")
                }
                .help("选择敏感文件所在的目录")
                Button(action: runtime.runSelfTest) {
                    Label("检测自检", systemImage: "checkmark.shield")
                }
                .disabled(runtime.isBusy || !runtime.state.canSelfTest)
                .help("创建合成测试文件，验证采集与显示；不会读取真实凭据或上传内容")
                if store.isLoading {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel("正在导入证据日志")
                }
                Menu {
                    Button("导入日志快照…") { store.isImporterPresented = true }
                    Button("查看合成演示") { store.showSamples() }
                } label: {
                    Label("更多", systemImage: "ellipsis.circle")
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
        .alert("无法导入日志", isPresented: Binding(
            get: { store.errorMessage != nil },
            set: { if !$0 { store.errorMessage = nil } }
        )) {
            Button("好", role: .cancel) { store.errorMessage = nil }
        } message: {
            Text(store.errorMessage ?? "")
        }
        .alert("监控服务", isPresented: Binding(
            get: { runtime.errorMessage != nil },
            set: { if !$0 { runtime.errorMessage = nil } }
        )) {
            Button("好", role: .cancel) { runtime.errorMessage = nil }
        } message: { Text(runtime.errorMessage ?? "") }
        .onChange(of: store.searchText) { _ in store.reconcileSelection() }
        .onChange(of: store.riskFilter) { _ in store.reconcileSelection() }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title2)
                    .foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 3) {
                    Text("运行时安全").font(.headline)
                    Text("本机 Agent 监控").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(18)
            .fixedSize(horizontal: false, vertical: true)

            List(selection: $store.riskFilter) {
                Section("风险分级") {
                    ForEach(RiskFilter.allCases) { filter in
                        HStack {
                            Label(filter.title, systemImage: filter.symbol)
                            Spacer(minLength: 4)
                            Text(store.count(for: filter), format: .number)
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                        .tag(filter)
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .frame(maxHeight: .infinity)
            VStack(alignment: .leading, spacing: 7) {
                Label(store.mode.title, systemImage: store.mode == .live ? "waveform.path.ecg" : "doc.text")
                    .font(.caption.weight(.semibold))
                Text(store.mode == .live ? "\(runtime.watchedPaths.count) 个监控目录" : "当前显示独立数据集。后台监控状态见主面板。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if store.mode == .live, let date = runtime.lastUpdate {
                    Text("最近更新 \(date.formatted(date: .omitted, time: .standard))")
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
                    Text(store.riskFilter.title).font(.title2.bold())
                    Spacer()
                    Text("\(store.visibleRecords.count) 条记录")
                        .font(.subheadline.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                datasetNotice
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
            if store.visibleRecords.isEmpty {
                emptyDataset
            } else {
                EvidenceTable(records: store.visibleRecords, selection: $store.selectedRecordID)
            }
        }
        .searchable(text: $store.searchText, placement: .toolbar,
                    prompt: "搜索文件、进程、PID 或目的地")
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
        case .live: return "本机采集结果"
        case .imported: return store.importedURL?.lastPathComponent ?? "已导入日志"
        case .demo: return "演示数据 · 合成示例"
        }
    }

    private var datasetDescription: String {
        switch store.mode {
        case .live: return "持续显示采集服务的实际记录。高风险表示需要核查的证据，不等同于已确认泄露。"
        case .imported: return "导入时的本地快照；实时监控仍独立运行。点击“返回实时监控”查看新增记录。"
        case .demo: return "这些记录不是本机检测结果。点击“返回实时监控”查看真实采集。"
        }
    }

    @ViewBuilder
    private var emptyDataset: some View {
        if !store.records.isEmpty {
            EmptyEvidenceView(symbol: "line.3.horizontal.decrease.circle", title: "没有匹配的证据",
                              message: "调整风险分类或搜索条件。")
        } else if store.mode == .live {
            VStack(spacing: 14) {
                Image(systemName: "shield.lefthalf.filled").font(.system(size: 38)).foregroundStyle(Color.accentColor)
                Text(runtime.state.canStop ? "等待本机检测记录" : "开始监控本机 Agent")
                    .font(.title3.bold())
                Text(runtime.state.canStop ? "可执行检测自检，验证敏感文件活动能否出现在这里。没有记录不代表不存在风险。" : "启动服务、选择敏感目录，进程与文件活动将自动显示。关闭窗口后，后台服务可继续运行。")
                    .font(.subheadline).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 420)
                HStack {
                    Button("选择监控目录…") { isConfigurationPresented = true }
                    if runtime.state.canSelfTest {
                        Button("运行检测自检", action: runtime.runSelfTest).buttonStyle(.borderedProminent)
                            .disabled(runtime.isBusy)
                    }
                }
            }.padding(28).frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            EmptyEvidenceView(symbol: "doc.text", title: "此快照没有证据记录",
                              message: "可导入其他日志，或返回实时监控查看本机采集结果。")
        }
    }

    private var importWarning: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                if !store.rejectedLines.isEmpty {
                    Text("跳过 \(store.rejectedLines.count) 行无效或重复记录")
                    Text("行号：" + store.rejectedLines.prefix(20).map(String.init).joined(separator: ", ") +
                         (store.rejectedLines.count > 20 ? "…" : ""))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if store.incompleteTail {
                    Text("文件末尾有未完成记录，已忽略；可在写入完成后重新导入。")
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
            TableColumn("风险") { record in
                RiskBadge(level: record.riskLevel, isSelected: selection == record.id)
            }.width(62)
            TableColumn("时间") { record in
                Text(record.timestamp, format: .dateTime.hour().minute().second())
                    .monospacedDigit()
                    .help(record.timestamp.formatted(date: .complete, time: .complete))
            }.width(82)
            TableColumn("检测项") { record in
                Text(record.findingTitle).font(.caption).lineLimit(2)
                    .help(record.sourceType.isEmpty ? record.actionType : record.sourceType)
            }.width(min: 105, ideal: 150)
            TableColumn("进程 / 资源") { record in
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.summary.isEmpty ? (record.processTree.first?.name ?? "未归因") : record.summary)
                        .font(.body.weight(.medium))
                        .lineLimit(record.summary.isEmpty ? 1 : 3)
                    Text(record.targetResource.isEmpty ? "无文件资源" : record.targetResource)
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
        .accessibilityLabel("证据记录")
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
            .accessibilityLabel("风险等级：\(filter.title)")
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
