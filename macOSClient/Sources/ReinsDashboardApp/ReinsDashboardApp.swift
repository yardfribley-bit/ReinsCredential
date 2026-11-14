import AppKit
import EvidenceCore
import SwiftUI

@main
struct ReinsDashboardApp: App {
    @NSApplicationDelegateAdaptor(DashboardAppDelegate.self) private var appDelegate
    @StateObject private var store = DashboardStore()
    @StateObject private var runtime = RuntimeController()
    @StateObject private var language = LanguageStore.shared
    @State private var didStartSession = false
    @State private var aboutPresented = false

    var body: some Scene {
        WindowGroup(id: "main") {
            DashboardRoot(store: store, runtime: runtime, language: language,
                          aboutPresented: $aboutPresented, didStartSession: $didStartSession)
        }
        .defaultSize(width: WindowPlacement.preferred.width, height: WindowPlacement.preferred.height)
        .windowResizability(.contentMinSize)
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

private struct DashboardRoot: View {
    @ObservedObject var store: DashboardStore
    @ObservedObject var runtime: RuntimeController
    @ObservedObject var language: LanguageStore
    @Binding var aboutPresented: Bool
    @Binding var didStartSession: Bool
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        DashboardView(store: store, runtime: runtime)
            .environmentObject(language)
            .id(language.resolved)
            .frame(minWidth: WindowPlacement.minimum.width, minHeight: WindowPlacement.minimum.height)
            .onChange(of: language.choice) { _ in runtime.refresh() }
            .sheet(isPresented: $aboutPresented) { AboutReinsView().environmentObject(language) }
            .onOpenURL { store.importLog(from: $0) }
            .onAppear {
                MainWindowOpener.shared.open = { openWindow(id: "main") }
                DashboardAppDelegate.restoreWindows()
                guard !didStartSession else { return }
                didStartSession = true
                #if DEBUG
                DashboardSmoke.runIfRequested(store: store)
                #endif
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
}

final class MainWindowOpener {
    static let shared = MainWindowOpener()
    var open: (() -> Void)?
}

final class DashboardAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async { Self.restoreWindows() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Self.restoreWindows(createIfMissing: !flag)
        return true
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        Self.clampAndFront(activate: false)
    }

    static func restoreWindows(createIfMissing: Bool = false) {
        NSApp.unhide(nil)
        let mains = NSApp.windows.filter { $0.canBecomeMain && $0.frame.width > 1 }
        if mains.isEmpty && createIfMissing {
            MainWindowOpener.shared.open?()
            DispatchQueue.main.async { clampAndFront(activate: true) }
            return
        }
        clampAndFront(activate: true)
    }

    static func clampAndFront(activate: Bool = true) {
        if activate {
            NSApp.activate(ignoringOtherApps: true)
        }
        for window in NSApp.windows where window.canBecomeMain {
            let visible = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
                ?? CGRect(x: 0, y: 0, width: WindowPlacement.preferred.width, height: WindowPlacement.preferred.height)
            window.setFrame(WindowPlacement.clamped(saved: window.frame, visible: visible), display: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
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
