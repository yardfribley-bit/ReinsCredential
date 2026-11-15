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

    override init() {
        super.init()
        if CommandLine.arguments.contains("--smoke-seed-split") {
            // Written before the guard exists, so launch correction has to
            // rewrite these three measured fixtures before the window reads them.
            UserDefaults.standard.set("216 54 1224 816 0 0 1440 870", forKey: "NSWindow Frame main-AppWindow-1")
            UserDefaults.standard.set(Self.oversizedSplitFrames, forKey: Self.splitFrameKey)
            UserDefaults.standard.set(["0.000000, 0.000000, 898.000000, 1469.500000, NO, NO"],
                                      forKey: "NSSplitView Subview Frames main-AppWindow-1, ListRewrite")
            UserDefaults.standard.set(
                "0.000000, 0.000000, 211.000000, 6161.000000, NO, 211.000000, 0.000000, 680.000000, 6161.000000, NO",
                forKey: "NSSplitView Subview Frames SidebarNavigationSplitView")
            UserDefaults.standard.set(
                ["0.000000, 2000.000000, 218.000000, 11488.000000, NO, NO"],
                forKey: "NSSplitView Subview Frames main-AppWindow-1, DocumentHeight")
        }
        SplitWriteGuard.install()
        SplitFrameCap.install()
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        Self.repairSplitViews()
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

    static let splitFrameKey = "NSSplitView Subview Frames main-AppWindow-1, SidebarNavigationSplitView"
    static let oversizedSplitFrames = [
        "0.000000, 0.000000, 218.000000, 5089.000000, NO, NO",
        "0.000000, 0.000000, 898.000000, 5089.000000, NO, NO",
        "899.000000, 0.000000, 325.000000, 5089.000000, NO, NO"
    ]

    static func repairSplitViews() {
        clampLiveSplits()
    }

    /// Fits each split column into its split view. Height follows that bounds,
    /// or the window content rect when the split is still the document height.
    /// Divider widths stay. The saved key keeps those widths and that height.
    private static var clamping = false
    static func clampLiveSplits() {
        guard !clamping else { return }
        clamping = true
        defer { clamping = false }
        var hosting = CGRect.null
        for window in NSApp.windows where window.canBecomeMain {
            guard let content = window.contentView else { continue }
            if content.subviews.contains(where: { $0 is SplitClampView }) == false {
                let hook = SplitClampView(frame: .zero)
                content.addSubview(hook)
            }
            clamp(content, window: window)
            content.layoutSubtreeIfNeeded()
            let bounds = SplitFrameCap.hostingBounds(in: window)
            if bounds.height > 2 { hosting = bounds }
        }
        if hosting.height > 2 {
            _ = SplitFrameSanitizer.correctSavedFrames(defaults: .standard, bounds: hosting)
        }
    }

    private static func clamp(_ view: NSView, window: NSWindow) {
        if view !== window.contentView, let parent = view.superview, hostsSplit(view) {
            let target = SplitFrameCap.fitTarget(parent, window: window)
            if target.height > 2 {
                let fitted = SplitFrameSanitizer.fitted(view.frame, into: target)
                if !framesMatch(view.frame, fitted) { view.frame = fitted }
            }
        }
        if let split = view as? NSSplitView {
            let bounds = SplitFrameCap.columnBounds(split, window: window)
            if bounds.height > 2 {
                for subview in split.subviews {
                    let fitted = SplitFrameSanitizer.fitted(subview.frame, into: bounds)
                    if !framesMatch(subview.frame, fitted) { subview.frame = fitted }
                    placeInside(subview)
                }
            }
        }
        for child in view.subviews { clamp(child, window: window) }
    }

    /// Pulls a column's descendants back inside their parent. A document-sized
    /// origin here is what left the headings thousands of points above the window.
    private static func placeInside(_ view: NSView) {
        if abs(view.bounds.origin.y) > view.bounds.height + 1 || abs(view.bounds.origin.x) > view.bounds.width + 1 {
            var bounds = view.bounds
            bounds.origin = .zero
            view.bounds = bounds
        }
        let bounds = CGRect(origin: .zero, size: view.bounds.size)
        guard bounds.height > 2, bounds.width > 2 else { return }
        for child in view.subviews {
            let placed = SplitFrameSanitizer.placed(child.frame, into: bounds)
            if !framesMatch(child.frame, placed) { child.frame = placed }
            placeInside(child)
        }
    }

    private static func hostsSplit(_ view: NSView) -> Bool {
        if view is NSSplitView { return true }
        return view.subviews.contains(where: hostsSplit)
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

    private static func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.origin.x - rhs.origin.x) < 1 && abs(lhs.origin.y - rhs.origin.y) < 1
            && abs(lhs.size.width - rhs.size.width) < 1 && abs(lhs.size.height - rhs.size.height) < 1
    }
}

/// Lays out with the window and pulls split columns back to the content height.
final class SplitClampView: NSView {
    override var isFlipped: Bool { true }
    override func layout() {
        super.layout()
        DashboardAppDelegate.clampLiveSplits()
    }
}

/// Rewrites a split-frame defaults write before it is stored. The stored
/// height is the hosting window's height. The key is not deleted.
enum SplitWriteGuard {
    private static var installed = false

    static func install() {
        guard !installed else { return }
        let selector = NSSelectorFromString("setObject:forKey:")
        guard let original = class_getInstanceMethod(UserDefaults.self, selector),
              let replacement = class_getInstanceMethod(UserDefaults.self, #selector(UserDefaults.reins_setObject(_:forKey:))) else { return }
        method_exchangeImplementations(original, replacement)
        installed = true
    }

}

extension UserDefaults {
    @objc(reins_setObject:forKey:)
    func reins_setObject(_ value: Any?, forKey key: String) {
        var stored = value
        if key.contains("NSSplitView Subview Frames"), let bounds = SplitFrameCap.hostingBounds() {
            let result = SplitFrameSanitizer.correcting(value, bounds: bounds)
            if result.changed { stored = result.stored }
        }
        reins_setObject(stored, forKey: key)
    }
}

/// Rejects a split-column frame taller than the hosting window at the moment
/// AppKit or SwiftUI assigns it. The stored defaults key is a separate path.
enum SplitFrameCap {
    private static var installed = false

    static func install() {
        guard !installed else { return }
        guard swizzle("setFrame:", "reins_setFrame:"),
              swizzle("setFrameSize:", "reins_setFrameSize:"),
              swizzle("setFrameOrigin:", "reins_setFrameOrigin:"),
              swizzle("setBoundsOrigin:", "reins_setBoundsOrigin:") else { return }
        installed = true
    }

    private static func swizzle(_ originalName: String, _ replacementName: String) -> Bool {
        let cls: AnyClass = NSView.self
        guard let original = class_getInstanceMethod(cls, NSSelectorFromString(originalName)),
              let replacement = class_getInstanceMethod(cls, NSSelectorFromString(replacementName)) else { return false }
        method_exchangeImplementations(original, replacement)
        return true
    }

    /// The rect a column must fill. A split that is taller than the content
    /// area is still the document height, so the content rect is used instead.
    static func fitTarget(_ parent: NSView, window: NSWindow) -> CGRect {
        let content = window.contentLayoutRect
        if parent === window.contentView, content.height > 2, content.width > 2 {
            return CGRect(origin: .zero, size: content.size)
        }
        if parent.bounds.height > 2, parent.bounds.width > 2,
           content.height <= 2 || parent.bounds.height <= content.height + 1 {
            return CGRect(origin: .zero, size: parent.bounds.size)
        }
        guard content.width > 2, content.height > 2 else { return .zero }
        return CGRect(origin: .zero, size: content.size)
    }

    static func columnBounds(_ split: NSSplitView, window: NSWindow) -> CGRect {
        let content = window.contentLayoutRect
        if split.bounds.height > 2, split.bounds.width > 2,
           content.height <= 2 || split.bounds.height <= content.height + 1 {
            return CGRect(origin: .zero, size: split.bounds.size)
        }
        guard content.width > 2, content.height > 2 else { return .zero }
        return CGRect(origin: .zero, size: content.size)
    }

    static func hostingBounds(in window: NSWindow) -> CGRect {
        guard let content = window.contentView else { return .zero }
        var found = CGRect.null
        func walk(_ view: NSView) {
            if let split = view as? NSSplitView {
                let bounds = columnBounds(split, window: window)
                if bounds.height > 2 { found = bounds }
            }
            for child in view.subviews { walk(child) }
        }
        walk(content)
        if found.height > 2 { return found }
        let layout = window.contentLayoutRect
        guard layout.width > 2, layout.height > 2 else { return .zero }
        return CGRect(origin: .zero, size: layout.size)
    }

    static func hostingBounds() -> CGRect? {
        let bounds = NSApp.windows.filter(\.canBecomeMain).map { hostingBounds(in: $0) }.filter { $0.height > 2 }
        guard let height = bounds.map(\.height).min(), let match = bounds.first(where: { abs($0.height - height) < 0.5 }) else { return nil }
        return match
    }

    static func capped(_ frame: NSRect, view: NSView) -> NSRect {
        if let split = view.superview as? NSSplitView {
            let window = view.window ?? split.window
            guard let window, window.canBecomeMain else { return frame }
            let bounds = columnBounds(split, window: window)
            guard bounds.height > 2 else { return frame }
            return SplitFrameSanitizer.fitted(frame, into: bounds)
        }
        if view is NSSplitView, let parent = view.superview {
            let window = view.window ?? parent.window
            guard let window, window.canBecomeMain else { return frame }
            let target = fitTarget(parent, window: window)
            guard target.height > 2 else { return frame }
            return SplitFrameSanitizer.fitted(frame, into: target)
        }
        if ancestorIsSplit(view), let parent = view.superview, parent.bounds.height > 2, parent.bounds.width > 2 {
            return SplitFrameSanitizer.placed(frame, into: CGRect(origin: .zero, size: parent.bounds.size))
        }
        return frame
    }

    private static func ancestorIsSplit(_ view: NSView) -> Bool {
        var parent = view.superview
        while let current = parent {
            if current is NSSplitView { return true }
            parent = current.superview
        }
        return false
    }
}

extension NSView {
    @objc(reins_setFrame:)
    func reins_setFrame(_ frame: NSRect) {
        reins_setFrame(SplitFrameCap.capped(frame, view: self))
    }

    @objc(reins_setFrameSize:)
    func reins_setFrameSize(_ size: NSSize) {
        var next = frame
        next.size = size
        reins_setFrameSize(SplitFrameCap.capped(next, view: self).size)
    }

    @objc(reins_setFrameOrigin:)
    func reins_setFrameOrigin(_ origin: NSPoint) {
        var next = frame
        next.origin = origin
        reins_setFrameOrigin(SplitFrameCap.capped(next, view: self).origin)
    }

    @objc(reins_setBoundsOrigin:)
    func reins_setBoundsOrigin(_ origin: NSPoint) {
        var origin = origin
        if SplitFrameCap.ancestorIsSplit(self) {
            if abs(origin.y) > bounds.height + 1 { origin.y = 0 }
            if abs(origin.x) > bounds.width + 1 { origin.x = 0 }
        }
        reins_setBoundsOrigin(origin)
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
