import AppKit
import SwiftUI

@main
struct ReinsDashboardApp: App {
    @StateObject private var store = DashboardStore()
    @StateObject private var runtime = RuntimeController()
    @StateObject private var language = LanguageStore.shared
    @State private var didStartSession = false
    @State private var aboutPresented = false

    var body: some Scene {
        WindowGroup("ReinsCredential") {
            GeometryReader { geometry in
                DashboardView(store: store, runtime: runtime)
                    .environmentObject(language)
                    .id(language.resolved)
                    .frame(width: geometry.size.width, height: geometry.size.height, alignment: .topLeading)
                    .onChange(of: language.choice) { _ in runtime.refresh() }
                    .sheet(isPresented: $aboutPresented) { AboutReinsView().environmentObject(language) }
            }
                .frame(minWidth: 1_050, minHeight: 640)
                .onOpenURL { store.importLog(from: $0) }
                .onAppear {
                    guard !didStartSession else { return }
                    didStartSession = true
                    #if DEBUG
                    DashboardSmoke.runIfRequested(store: store)
                    #endif
                    // Development previews and synthetic render probes must not
                    // register a login item or start a real process collector.
                    guard !CommandLine.arguments.contains("--smoke-test") else { return }
                    if ProductVerification.stopIfRequested(runtime: runtime) { return }
                    runtime.beginPolling()
                    runtime.refresh()
                    let bundle = Bundle.main.bundleURL
                    let helper = bundle.appendingPathComponent("Contents/MacOS/ReinsRuntime")
                    let collector = bundle.appendingPathComponent("Contents/Helpers/agent-monitor")
                    if bundle.pathExtension == "app",
                       FileManager.default.isExecutableFile(atPath: helper.path),
                       FileManager.default.isExecutableFile(atPath: collector.path) {
                        if CommandLine.arguments.contains("--verify-installation") { runtime.start() }
                        else { runtime.startIfNeeded() }
                    }
                    ProductVerification.runIfRequested(runtime: runtime)
                }
        }
        .defaultSize(width: 1_360, height: 840)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(language.tr("menu.openLog")) { store.isImporterPresented = true }
                    .keyboardShortcut("o", modifiers: .command)
                    .disabled(store.isLoading)
                Divider()
                Button(language.tr("menu.demo")) { store.showSamples() }
                    .disabled(store.isLoading)
                Button(language.tr("menu.backLive")) { store.returnToLive(records: runtime.records) }
                    .disabled(store.isLoading || store.mode == .live)
            }
            CommandMenu(language.tr("menu.monitor")) {
                Button(runtime.state.canStop ? language.tr("menu.stop") : language.tr("menu.start")) {
                    if runtime.state.canStop { runtime.stop() } else { runtime.start() }
                }
                .disabled(runtime.isBusy)
                Button(language.tr("menu.selfTest"), action: runtime.runSelfTest)
                    .disabled(runtime.isBusy || !runtime.state.canSelfTest)
                Button(language.tr("menu.background"), action: runtime.openBackgroundSettings)
                Button(language.tr("menu.notifications"), action: runtime.requestNotifications)
                Divider()
                Button(language.tr("menu.followSystem")) { language.choice = .system }
                Button(language.tr("menu.chinese")) { language.choice = .zhHans }
                Button(language.tr("menu.english")) { language.choice = .en }
            }
            CommandGroup(replacing: .appInfo) {
                Button(language.tr("menu.about")) { aboutPresented = true }
            }
        }
    }
}

struct AboutReinsView: View {
    @EnvironmentObject private var language: LanguageStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 16) {
                if let url = Bundle.module.url(forResource: "ReinsCredential-Logo-rounded-512", withExtension: "png"),
                   let image = NSImage(contentsOf: url) {
                    Image(nsImage: image)
                        .resizable()
                        .frame(width: 72, height: 72)
                        .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(language.tr("product.name")).font(.title2.bold())
                    Text(language.tr("tagline")).foregroundStyle(.secondary)
                    Text(language.tr("about.version")).font(.caption).foregroundStyle(.secondary)
                }
            }
            Text(language.tr("about.body"))
            Text(language.tr("limit.tls")).font(.callout)
            Text(language.tr("limit.flow")).font(.callout)
            Text(language.tr("limit.udp")).font(.callout)
            HStack {
                Spacer()
                Button(language.tr("alert.ok")) { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}
