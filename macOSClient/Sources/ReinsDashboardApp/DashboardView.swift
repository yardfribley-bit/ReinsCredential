import EvidenceCore
import SwiftUI
import UniformTypeIdentifiers

struct DashboardView: View {
    @ObservedObject var store: DashboardStore

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
                if store.isLoading {
                    ProgressView().controlSize(.small)
                        .accessibilityLabel("正在导入证据日志")
                }
                Button { store.isImporterPresented = true } label: {
                    Label("导入日志", systemImage: "square.and.arrow.down")
                }
                .disabled(store.isLoading)
                .help("打开 C++ 后端生成的 JSONL 证据日志（⌘O）")
                Button { store.showSamples() } label: {
                    Label("演示数据", systemImage: "play.rectangle")
                }
                .disabled(store.isLoading)
                .help("查看合成示例；不代表本机检测结果")
            }
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
                    Text("证据浏览器").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(18)

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
            Spacer(minLength: 0)
            VStack(alignment: .leading, spacing: 7) {
                Label(store.isDemo ? "演示模式" : "日志快照", systemImage: "doc.text")
                    .font(.caption.weight(.semibold))
                Text("本客户端按需读取日志；当前未连接实时采集服务。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
        }
        .background(.ultraThinMaterial)
    }

    private var evidenceContent: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
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

            Divider()
            if store.visibleRecords.isEmpty {
                EmptyEvidenceView(symbol: "line.3.horizontal.decrease.circle", title: "没有匹配的证据",
                                  message: store.records.isEmpty ? "导入 JSONL 日志后，记录会显示在这里。" : "调整风险分类或搜索条件。")
            } else {
                EvidenceTable(records: store.visibleRecords, selection: $store.selectedRecordID)
            }
        }
        .searchable(text: $store.searchText, placement: .toolbar,
                    prompt: "搜索文件、进程、PID 或目的地")
    }

    private var datasetNotice: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: store.isDemo ? "sparkles" : "doc.text")
                .foregroundStyle(Color.accentColor)
            VStack(alignment: .leading, spacing: 4) {
                Text(store.isDemo ? "演示数据 · 合成示例" : (store.importedURL?.lastPathComponent ?? "已导入日志"))
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                    .help(store.importedURL?.path ?? "用于展示界面的合成数据")
                Text(store.isDemo ? "这些记录不是本机采集结果。导入日志以查看实际证据。" : "导入时的本地快照；重新导入以查看新增记录。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
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
            TableColumn("动作") { record in
                Text(record.actionType).font(.caption.monospaced()).lineLimit(1)
                    .help(record.sourceType)
            }.width(min: 65, ideal: 78)
            TableColumn("进程 / 资源") { record in
                VStack(alignment: .leading, spacing: 4) {
                    Text(record.processTree.first?.name ?? "未归因")
                        .font(.body.weight(.medium))
                        .lineLimit(1)
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
