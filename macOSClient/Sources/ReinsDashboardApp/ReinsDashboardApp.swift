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
                DashboardAppDelegate.stopRuntime = { await runtime.stopForQuit() }
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
    static var isQuitting = false
    static var stopRuntime: (@MainActor () async -> Void)?

    func applicationWillFinishLaunching(_ notification: Notification) {
        let tallest = NSScreen.screens.map(\.frame.height).max() ?? 1_600
        _ = SplitFrameSanitizer.removeImpossibleFrames(defaults: .standard, maxSubviewHeight: tallest)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.async { Self.restoreWindows() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Self.restoreWindows(createIfMissing: !flag)
        return true
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        _ = (application, urls)
        Self.restoreWindows(createIfMissing: true)
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        // Already active. Resizing or activating again starts another display
        // cycle, which lays the split view out forever.
        DispatchQueue.main.async { Self.orderFront(allowResize: false) }
    }

    func applicationWillTerminate(_ notification: Notification) {
        Self.repairSplitViews()
        Self.isQuitting = true
        let waiter = DispatchSemaphore(value: 0)
        Task { @MainActor in
            await Self.stopRuntime?()
            waiter.signal()
        }
        let deadline = Date().addingTimeInterval(4)
        while waiter.wait(timeout: .now()) == .timedOut && Date() < deadline {
            RunLoop.current.run(mode: .common, before: Date().addingTimeInterval(0.05))
        }
    }

    static func restoreWindows(createIfMissing: Bool = false) {
        NSApp.unhide(nil)
        NSRunningApplication.current.activate(options: [.activateAllWindows])
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        let mains = NSApp.windows.filter { $0.canBecomeMain && $0.frame.width > 1 }
        if mains.isEmpty && createIfMissing {
            MainWindowOpener.shared.open?()
        }
        DispatchQueue.main.async {
            orderFront(allowResize: true)
            repairSplitViews()
        }
    }

    /// Brings a main window forward. `allowResize` is only for the explicit
    /// open/reopen path, and only when the saved frame is actually off screen.
    private static var orderingFront = false

    static func orderFront(allowResize: Bool) {
        guard !orderingFront else { return }
        orderingFront = true
        defer { orderingFront = false }
        for window in NSApp.windows where window.canBecomeMain {
            if allowResize, let visible = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame {
                let clamped = WindowPlacement.clamped(saved: window.frame, visible: visible)
                if !framesMatch(window.frame, clamped) {
                    window.setFrame(clamped, display: false)
                }
            }
            if !window.isKeyWindow || window.isMiniaturized {
                window.makeKeyAndOrderFront(nil)
                window.orderFrontRegardless()
            }
        }
        repairSplitViews()
    }

    static func contentHeightLimit(_ window: NSWindow) -> CGFloat {
        let layout = window.contentLayoutRect.height
        let cap = layout > 2 ? layout : window.frame.height
        let screen = window.screen?.frame.height ?? cap
        return min(cap, screen)
    }

    static func repairSplitViews() {
        for window in NSApp.windows where window.canBecomeMain {
            guard let content = window.contentView else { continue }
            constrainSplits(content, limit: contentHeightLimit(window))
        }
        let screen = NSScreen.screens.map(\.frame.height).max() ?? 1_600
        _ = SplitFrameSanitizer.removeImpossibleFrames(defaults: .standard, maxSubviewHeight: screen)
    }

    static func splitViewsFit(_ window: NSWindow) -> Bool {
        guard let content = window.contentView else { return false }
        let limit = contentHeightLimit(window) + 8
        var found = false
        var fits = true
        func walk(_ view: NSView) {
            if let split = view as? NSSplitView, split.subviews.count >= 2 {
                found = true
                for subview in split.subviews {
                    if subview.frame.height > limit || subview.frame.height < 1 || subview.frame.width < 1 {
                        fits = false
                    }
                }
                if split.subviews.count >= 3 {
                    if split.subviews[0].frame.width < 140 || split.subviews[split.subviews.count - 1].frame.width < 200 {
                        fits = false
                    }
                }
            }
            for child in view.subviews { walk(child) }
        }
        walk(content)
        return found && fits
    }

    /// Sidebar and inspector each contain readable text. A column that is only a
    /// blank hosting view does not pass.
    static func panesHaveContent(_ window: NSWindow) -> Bool {
        guard let content = window.contentView else { return false }
        func text(_ view: NSView) -> Bool {
            if view.bounds.width > 8, view.bounds.height > 8 {
                if let label = view.accessibilityLabel(), !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
                if let field = view as? NSTextField, !field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
            }
            return view.subviews.contains(where: text)
        }
        func find(_ identifier: String, in view: NSView) -> NSView? {
            if view.accessibilityIdentifier() == identifier { return view }
            for child in view.subviews {
                if let found = find(identifier, in: child) { return found }
            }
            return nil
        }
        if let sidebar = find("reins.sidebar", in: content), let inspector = find("reins.inspector", in: content),
           sidebar.bounds.width >= 140, sidebar.bounds.height >= 80, text(sidebar),
           inspector.bounds.width >= 200, inspector.bounds.height >= 80, text(inspector) {
            return true
        }
        var splits: [NSSplitView] = []
        func collect(_ view: NSView) {
            if let split = view as? NSSplitView, split.subviews.count >= 3 { splits.append(split) }
            for child in view.subviews { collect(child) }
        }
        collect(content)
        guard let split = splits.max(by: { $0.bounds.width < $1.bounds.width }) else { return false }
        let sidebar = split.subviews[0]
        let inspector = split.subviews[split.subviews.count - 1]
        return sidebar.frame.width >= 140 && sidebar.frame.height >= 80 && text(sidebar)
            && inspector.frame.width >= 200 && inspector.frame.height >= 80 && text(inspector)
    }

    private static func constrainSplits(_ view: NSView, limit: CGFloat) {
        if let split = view as? NSSplitView, limit > 2 {
            if split.frame.height > limit + 1 {
                var frame = split.frame
                frame.size.height = limit
                split.frame = frame
            }
            let height = min(split.bounds.height > 2 ? split.bounds.height : limit, limit)
            let tooTall = split.subviews.contains { $0.frame.height > height + 1 || $0.frame.height < 1 }
            let narrowSides = split.subviews.count >= 3 &&
                (split.subviews[0].frame.width < 140 || split.subviews[split.subviews.count - 1].frame.width < 200)
            if tooTall || narrowSides {
                if split.subviews.count >= 3, split.bounds.width > 400 {
                    let sidebar: CGFloat = 210
                    let detail: CGFloat = 340
                    let content = max(400, split.bounds.width - sidebar - detail)
                    var x: CGFloat = 0
                    for (index, width) in [sidebar, content, detail].enumerated() where index < split.subviews.count {
                        split.subviews[index].frame = CGRect(x: x, y: 0, width: width, height: height)
                        x += width
                    }
                } else {
                    for subview in split.subviews {
                        var frame = subview.frame
                        frame.size.height = height
                        frame.origin.y = 0
                        subview.frame = frame
                    }
                }
                split.adjustSubviews()
                if split.subviews.count >= 3, split.bounds.width > 400 {
                    let sidebar: CGFloat = 210
                    let detail: CGFloat = 340
                    let contentWidth = max(400, split.bounds.width - sidebar - detail)
                    var x: CGFloat = 0
                    for (index, width) in [sidebar, contentWidth, detail].enumerated() where index < split.subviews.count {
                        split.subviews[index].frame = CGRect(x: x, y: 0, width: width, height: height)
                        x += width
                    }
                }
                // Only forget autosave after correcting a frame that cannot be shown.
                if tooTall { split.autosaveName = nil }
            }
        }
        let childLimit = view.bounds.height > 2 ? min(view.bounds.height, limit) : limit
        for child in view.subviews { constrainSplits(child, limit: childLimit) }
    }

    private static func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.origin.x - rhs.origin.x) < 1 && abs(lhs.origin.y - rhs.origin.y) < 1
            && abs(lhs.size.width - rhs.size.width) < 1 && abs(lhs.size.height - rhs.size.height) < 1
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
