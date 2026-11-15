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
                Button(runtime.state.canStop ? L10n.tr("menu.stop") : L10n.tr("menu.start")) {
                    if runtime.state.canStop { runtime.stop() } else { runtime.start() }
                }
                .disabled(runtime.isBusy)
            }
            if !runtime.coverageKeys.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(runtime.coverageKeys, id: \.self) { key in
                        Text(L10n.tr(key))
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if runtime.state == .approvalRequired {
                Button(L10n.tr("runtime.openSettings"), action: runtime.openBackgroundSettings)
                    .buttonStyle(.link)
            }
            if !runtime.selfTestStatus.isEmpty {
                Label(runtime.selfTestStatus, systemImage: "testtube.2")
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if runtime.rejectedCount > 0 {
                Label(L10n.format("runtime.rejected", runtime.rejectedCount), systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(14)
        .background(runtime.state.statusColor.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(runtime.state.statusColor.opacity(0.18)))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(L10n.tr("runtime.a11y"))
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
                Label(L10n.tr("scope.title"), systemImage: "folder.badge.gearshape")
                    .font(.title2.bold())
                Spacer()
                Button(L10n.tr("scope.done")) { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Text(L10n.tr("scope.help"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List {
                if runtime.watchedPaths.isEmpty {
                    Text(L10n.tr("scope.empty")).foregroundStyle(.secondary)
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
                        .help(L10n.tr("scope.removeHelp"))
                        .accessibilityLabel(L10n.format("scope.remove", path))
                        .disabled(runtime.isBusy)
                    }.padding(.vertical, 5)
                }
            }
            .listStyle(.inset)
            .frame(minHeight: 180)
            HStack {
                Button { isDirectoryImporterPresented = true } label: {
                    Label(L10n.tr("scope.add"), systemImage: "plus")
                }
                .disabled(runtime.isBusy)
                Spacer()
                Button(L10n.tr("scope.reload"), action: runtime.reloadConfiguration)
                    .disabled(runtime.isBusy)
            }
            Divider()
            Text(L10n.tr("scope.limit"))
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
        .alert(L10n.tr("scope.chooseFailed"), isPresented: Binding(
            get: { selectionError != nil }, set: { if !$0 { selectionError = nil } }
        )) {
            Button(L10n.tr("alert.ok"), role: .cancel) { selectionError = nil }
        } message: { Text(selectionError ?? "") }
    }
}
