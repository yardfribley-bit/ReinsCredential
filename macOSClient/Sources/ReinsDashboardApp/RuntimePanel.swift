import EvidenceCore
import SwiftUI
import UniformTypeIdentifiers

extension RuntimeUIState {
    var statusColor: Color {
        switch self {
        case .running: return .green
        case .starting: return .accentColor
        case .degraded, .approvalRequired: return .orange
        case .failed: return .red
        case .stopped: return .secondary
        }
    }

    var statusSymbol: String {
        switch self {
        case .running: return "waveform.path.ecg"
        case .starting: return "hourglass"
        case .degraded: return "exclamationmark.triangle.fill"
        case .approvalRequired: return "hand.raised.fill"
        case .failed: return "xmark.octagon.fill"
        case .stopped: return "pause.circle"
        }
    }

    var canStop: Bool { self == .running || self == .degraded || self == .starting || self == .failed || self == .approvalRequired }
    var canSelfTest: Bool { self == .running || self == .degraded }
}

struct RuntimeStatusPanel: View {
    @ObservedObject var runtime: RuntimeController

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: runtime.state.statusSymbol)
                    .font(.title3)
                    .foregroundStyle(runtime.state.statusColor)
                VStack(alignment: .leading, spacing: 4) {
                    Text(runtime.state.title).font(.headline)
                    Text(runtime.statusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if runtime.isBusy {
                    ProgressView().controlSize(.small)
                }
                Button(runtime.state.canStop ? "停止监控" : "启动监控") {
                    if runtime.state.canStop { runtime.stop() } else { runtime.start() }
                }
                .disabled(runtime.isBusy)
            }
            if runtime.state == .approvalRequired {
                Button("前往系统设置允许后台运行", action: runtime.openBackgroundSettings)
                    .buttonStyle(.link)
            }
            if !runtime.selfTestStatus.isEmpty {
                Label(runtime.selfTestStatus, systemImage: "testtube.2")
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if runtime.rejectedCount > 0 {
                Label("有 \(runtime.rejectedCount) 条日志无法解析，请检查服务状态。", systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(14)
        .background(runtime.state.statusColor.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(runtime.state.statusColor.opacity(0.18)))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("本机监控状态")
    }
}

struct RuntimeConfigurationView: View {
    @ObservedObject var runtime: RuntimeController
    @Environment(\.dismiss) private var dismiss
    @State private var isDirectoryImporterPresented = false
    @State private var selectionError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Label("监控范围", systemImage: "folder.badge.gearshape")
                    .font(.title2.bold())
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Text("选择存放敏感文件的目录，例如 SSH 配置、云凭据或项目目录。监控只使用本机用户权限；无法访问的目录不会自动获得授权。")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List {
                if runtime.watchedPaths.isEmpty {
                    Text("尚未选择目录").foregroundStyle(.secondary)
                }
                ForEach(runtime.watchedPaths, id: \.self) { path in
                    HStack(spacing: 10) {
                        Image(systemName: "folder").foregroundStyle(Color.accentColor)
                        Text(path).font(.system(.body, design: .monospaced))
                            .lineLimit(2).truncationMode(.middle).help(path)
                        Spacer()
                        Button { runtime.removeWatchedPath(path) } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                        .help("移除此监控目录")
                        .accessibilityLabel("移除目录 \(path)")
                        .disabled(runtime.isBusy)
                    }.padding(.vertical, 5)
                }
            }
            .listStyle(.inset)
            .frame(minHeight: 180)
            HStack {
                Button { isDirectoryImporterPresented = true } label: {
                    Label("添加目录…", systemImage: "plus")
                }
                .disabled(runtime.isBusy)
                Spacer()
                Button("重新加载配置", action: runtime.reloadConfiguration)
                    .disabled(runtime.isBusy)
            }
            Divider()
            Text("检测范围：文件变化、可见进程及敏感文件描述符。短暂读取可能漏报；网络连接本身不证明文件已上传。")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(width: 610, height: 440)
        .background(.ultraThinMaterial)
        .fileImporter(isPresented: $isDirectoryImporterPresented,
                      allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let url): runtime.addWatchedPath(url)
            case .failure(let error):
                let nsError = error as NSError
                if nsError.domain != NSCocoaErrorDomain || nsError.code != NSUserCancelledError {
                    selectionError = error.localizedDescription
                }
            }
        }
        .alert("无法选择目录", isPresented: Binding(
            get: { selectionError != nil }, set: { if !$0 { selectionError = nil } }
        )) {
            Button("好", role: .cancel) { selectionError = nil }
        } message: { Text(selectionError ?? "") }
    }
}
