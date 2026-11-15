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
        if layout > 2 { return layout }
        let content = window.contentView?.bounds.height ?? 0
        return content > 2 ? content : 0
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

    /// Shrinks each split and every ancestor under the content view into the
    /// content rect, then fits the panes and clears a leftover document offset.
    /// Divider widths stay. Saved frames keep those widths and the content height.
    private static var clamping = false
    static var isClamping: Bool { clamping }
    /// Frame changes are not applied from inside `layout`. AppKit lays the
    /// split out itself; doing it again here re-enters layout and crashes.
    static func clampLiveSplits() {
        guard !clamping else { return }
        clamping = true
        defer { clamping = false }
        var hosting = CGRect.null
        for window in NSApp.windows where window.canBecomeMain && window.isVisible {
            guard let content = window.contentView else { continue }
            if content.subviews.contains(where: { $0 is SplitClampView }) == false {
                let hook = SplitClampView(frame: .zero)
                content.addSubview(hook)
            }
            clamp(content, window: window)
            revealContent(in: content, window: window)
            let bounds = SplitFrameCap.hostingBounds(in: window)
            if bounds.height > 2 { hosting = bounds }
        }
        if hosting.height > 2 {
            _ = SplitFrameSanitizer.correctSavedFrames(defaults: .standard, bounds: hosting)
        }
    }

    private static func clamp(_ view: NSView, window: NSWindow) {
        if let split = view as? NSSplitView {
            clampAncestors(of: split, window: window)
            clampContainer(split, window: window)
            fitSubviews(split)
            resetOffsets(in: split)
        }
        for child in view.subviews { clamp(child, window: window) }
    }

    /// Outermost ancestor first, stopping at the window content view. The
    /// content view is the content area, so it is not resized.
    private static func clampAncestors(of split: NSSplitView, window: NSWindow) {
        var chain: [NSView] = []
        var view = split.superview
        while let current = view, current !== window.contentView {
            chain.append(current)
            view = current.superview
        }
        for ancestor in chain.reversed() {
            clampContainer(ancestor, window: window)
        }
    }

    private static func clampContainer(_ view: NSView, window: NSWindow) {
        guard view !== window.contentView, let parent = view.superview else { return }
        let limit = SplitFrameCap.visibleLimit(in: parent, window: window)
        let next = SplitFrameSanitizer.clamped(view.frame, into: limit)
        if !framesMatch(view.frame, next) { view.frame = next }
        resetStaleBoundsOrigin(view)
    }

    /// Real panes only. Divider views live in `subviews` as well, and writing
    /// their frames corrupts the split.
    private static func panes(of split: NSSplitView) -> [NSView] {
        let arranged = split.arrangedSubviews
        if !arranged.isEmpty { return arranged }
        return split.subviews.filter { !String(describing: type(of: $0)).contains("Divider") }
    }

    private static func fitSubviews(_ split: NSSplitView) {
        let bounds = split.bounds
        let panes = panes(of: split)
        guard bounds.width > 2, bounds.height > 2, !panes.isEmpty else { return }
        for subview in panes {
            let fitted = split.isVertical
                ? SplitFrameSanitizer.fitted(subview.frame, into: bounds)
                : SplitFrameSanitizer.fittedHorizontal(subview.frame, into: bounds)
            if !framesMatch(subview.frame, fitted) { subview.frame = fitted }
            resetStaleBoundsOrigin(subview)
        }
        placeDividers(split, panes: panes, bounds: bounds)
    }

    /// Puts each divider between the panes that were just fitted. Leaving a
    /// divider at the old document height makes the next layout crash.
    private static func placeDividers(_ split: NSSplitView, panes: [NSView], bounds: CGRect) {
        guard panes.count >= 2 else { return }
        let dividers = split.subviews.filter { candidate in panes.contains { $0 === candidate } == false }
        guard dividers.count == panes.count - 1 else { return }
        let thickness = max(split.dividerThickness, 1)
        for index in dividers.indices {
            let edge = split.isVertical ? panes[index].frame.maxX : panes[index].frame.maxY
            let frame: CGRect
            if split.isVertical {
                frame = CGRect(x: edge, y: bounds.minY, width: thickness, height: bounds.height)
            } else {
                frame = CGRect(x: bounds.minX, y: edge, width: bounds.width, height: thickness)
            }
            if !framesMatch(dividers[index].frame, frame) { dividers[index].frame = frame }
        }
    }

    /// Drops a document offset on a split, an ancestor, or a column. Clip views
    /// and scroll documents keep their own scroll position.
    private static func resetStaleBoundsOrigin(_ view: NSView) {
        if view is NSClipView || view is NSScrollView { return }
        if view.enclosingScrollView?.documentView === view { return }
        guard view.bounds.origin != .zero else { return }
        var bounds = view.bounds
        bounds.origin = .zero
        view.bounds = bounds
    }

    private static func resetOffsets(in view: NSView) {
        if let scroll = view as? NSScrollView { resetStaleScroll(scroll) }
        for child in view.subviews { resetOffsets(in: child) }
    }

    private static func resetStaleScroll(_ scroll: NSScrollView) {
        guard let document = scroll.documentView else { return }
        if !scroll.contentView.bounds.intersects(document.bounds) {
            scrollToTop(scroll)
        }
    }

    private static func revealContent(in content: NSView, window: NSWindow) {
        func walk(_ view: NSView) {
            if let split = view as? NSSplitView {
                for column in panes(of: split) {
                    guard let top = topmostText(in: column), !textInsideContent(top, window: window) else { continue }
                    scrollToTop(in: column)
                    if let top = topmostText(in: column), !textInsideContent(top, window: window) {
                        revealTop(column)
                    }
                }
            }
            for child in view.subviews { walk(child) }
        }
        walk(content)
    }

    private static func scrollToTop(in view: NSView) {
        if let scroll = view as? NSScrollView { scrollToTop(scroll) }
        for child in view.subviews { scrollToTop(in: child) }
    }

    private static func scrollToTop(_ scroll: NSScrollView) {
        guard let document = scroll.documentView else { return }
        let clip = scroll.contentView
        let y = document.isFlipped
            ? document.bounds.minY
            : max(document.bounds.minY, document.bounds.maxY - clip.bounds.height)
        let origin = NSPoint(x: document.bounds.minX, y: y)
        guard abs(clip.bounds.origin.x - origin.x) > 1 || abs(clip.bounds.origin.y - origin.y) > 1 else { return }
        clip.scroll(to: origin)
        scroll.reflectScrolledClipView(clip)
    }

    /// The first content in a column: the topmost text in that column's coordinates.
    private static func topmostText(in column: NSView) -> NSView? {
        var best: NSView?
        var bestEdge: CGFloat?
        func walk(_ candidate: NSView) {
            let raw = ((candidate as? NSTextField)?.stringValue ?? "") + " " + (candidate.accessibilityLabel() ?? "")
            let rect = column.convert(candidate.bounds, from: candidate)
            if raw.trimmingCharacters(in: .whitespacesAndNewlines).count >= 2, rect.width > 1, rect.height > 1 {
                let edge = column.isFlipped ? rect.minY : rect.maxY
                let nearer = bestEdge.map { column.isFlipped ? edge < $0 : edge > $0 } ?? true
                if nearer {
                    best = candidate
                    bestEdge = edge
                }
            }
            for child in candidate.subviews { walk(child) }
        }
        walk(column)
        return best
    }

    private static func textInsideContent(_ view: NSView, window: NSWindow) -> Bool {
        let content = window.convertToScreen(window.contentLayoutRect)
        let screen = view.window?.convertToScreen(view.convert(view.bounds, to: nil)) ?? .null
        guard screen.width > 1, screen.height > 1, screen.height <= content.height + 2 else { return false }
        return screen.minY >= content.minY - 1 && screen.maxY <= content.maxY + 1
            && screen.minX >= content.minX - 1 && screen.maxX <= content.maxX + 1
    }

    /// Moves the column's bounds so its topmost text sits on the visible top edge.
    private static func revealTop(_ column: NSView) {
        guard let top = topmostText(in: column) else { return }
        let rect = column.convert(top.bounds, from: top)
        let edge = column.isFlipped ? rect.minY : rect.maxY
        var bounds = column.bounds
        let originY = column.isFlipped ? edge : edge - bounds.height
        guard abs(originY - bounds.origin.y) > 1 else { return }
        bounds.origin.y = originY
        column.bounds = bounds
    }

    static func splitViewsFit(_ window: NSWindow) -> Bool {
        guard let content = window.contentView else { return false }
        let limit = contentHeightLimit(window)
        guard limit > 2 else { return false }
        var found = false
        var fits = true
        func walk(_ view: NSView) {
            if let split = view as? NSSplitView, panes(of: split).count >= 2, let parent = split.superview {
                found = true
                let container = SplitFrameCap.visibleLimit(in: parent, window: window)
                if split.frame.height > limit + 8 || split.frame.height < 1 || split.frame.width < 1
                    || split.frame.minY < container.minY - 1 || split.frame.maxY > container.maxY + 1
                    || split.frame.minX < container.minX - 1 || split.frame.maxX > container.maxX + 1 {
                    fits = false
                }
                let panes = panes(of: split)
                for subview in panes {
                    if subview.frame.height > limit + 8 || subview.frame.height < 1 || subview.frame.width < 1 {
                        fits = false
                    }
                    if split.isVertical,
                       abs(subview.frame.height - split.bounds.height) > 1
                       || abs(subview.frame.minY - split.bounds.minY) > 1 {
                        fits = false
                    }
                }
                if split.isVertical, panes.count >= 3 {
                    if panes[0].frame.width < 140 || panes[panes.count - 1].frame.width < 200 {
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
/// The correction is scheduled, not run inside `layout`, because setting frames
/// from a layout pass crashes AppKit.
final class SplitClampView: NSView {
    private static var scheduled = false
    override var isFlipped: Bool { true }
    override func layout() {
        super.layout()
        guard !DashboardAppDelegate.isClamping, !Self.scheduled else { return }
        Self.scheduled = true
        DispatchQueue.main.async {
            Self.scheduled = false
            DashboardAppDelegate.clampLiveSplits()
        }
    }
}

/// Rewrites a split-frame defaults write before it is stored. The stored
/// height is the visible content height. The key is not deleted.
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

/// Rejects a split frame, an ancestor frame, or a pane frame that does not fit
/// the visible content. The stored defaults key is a separate path and keeps
/// only frames that already fit that content rect.
enum SplitFrameCap {
    private static var installed = false

    static func install() {
        guard !installed else { return }
        guard swizzle("setFrame:", "reins_setFrame:"), swizzle("setFrameSize:", "reins_setFrameSize:") else { return }
        installed = true
    }

    private static func swizzle(_ originalName: String, _ replacementName: String) -> Bool {
        let cls: AnyClass = NSView.self
        guard let original = class_getInstanceMethod(cls, NSSelectorFromString(originalName)),
              let replacement = class_getInstanceMethod(cls, NSSelectorFromString(replacementName)) else { return false }
        method_exchangeImplementations(original, replacement)
        return true
    }

    /// Where a child of `parent` is allowed to sit. This is the parent's bounds
    /// clipped to `contentLayoutRect` (window coordinates, `nil` view).
    static func visibleLimit(in parent: NSView, window: NSWindow) -> CGRect {
        let layout = window.contentLayoutRect
        guard layout.width > 2, layout.height > 2 else {
            return parent.bounds.width > 1 && parent.bounds.height > 1 ? parent.bounds : .zero
        }
        let layoutInParent = parent.convert(layout, from: nil)
        let intersection = parent.bounds.intersection(layoutInParent)
        if !intersection.isNull, intersection.width > 2, intersection.height > 2 {
            return intersection
        }
        var limit = parent.bounds
        limit.size.width = min(max(limit.width, 0), layout.width)
        limit.size.height = min(max(limit.height, 0), layout.height)
        return limit
    }

    /// The rect a saved column must fit. A split that is still the document
    /// height contributes the content size, so the list's document height is
    /// not what gets stored. The origin is zero: saved `y` is not a scroll offset.
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
        var best = CGRect.null
        var bestScore = -1
        func walk(_ view: NSView) {
            if let split = view as? NSSplitView {
                let bounds = columnBounds(split, window: window)
                let score = (split.isVertical ? 1_000 : 0) + split.subviews.count
                if bounds.height > 2, score > bestScore || (score == bestScore && bounds.height > best.height) {
                    best = bounds
                    bestScore = score
                }
            }
            for child in view.subviews { walk(child) }
        }
        walk(content)
        if best.height > 2, best.width > 2 { return CGRect(origin: .zero, size: best.size) }
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
            let panes = split.arrangedSubviews
            if !panes.isEmpty, panes.contains(where: { $0 === view }) == false { return frame }
            return cappedSubview(frame, split: split)
        }
        guard let window = view.window, window.canBecomeMain else { return frame }
        if view === window.contentView || isScrollDocument(view) { return frame }
        guard let parent = view.superview else { return frame }
        let limit = visibleLimit(in: parent, window: window)
        let overflows = frame.height > limit.height + 1 || frame.width > limit.width + 1
            || frame.minX < limit.minX - 1 || frame.maxX > limit.maxX + 1
            || frame.minY < limit.minY - 1 || frame.maxY > limit.maxY + 1
        guard overflows, view is NSSplitView || containsSplit(view) else { return frame }
        return SplitFrameSanitizer.clamped(frame, into: limit)
    }

    /// Side-by-side panes fill the split's height. Stacked panes fill the width
    /// and keep their own height. A split that is still document-sized contributes
    /// its content height; the split frame itself is clamped in the same pass.
    private static func cappedSubview(_ frame: NSRect, split: NSSplitView) -> NSRect {
        let bounds = subviewBounds(split)
        guard bounds.width > 2, bounds.height > 2 else { return frame }
        if split.isVertical {
            return SplitFrameSanitizer.fitted(frame, into: bounds)
        }
        return SplitFrameSanitizer.fittedHorizontal(frame, into: bounds)
    }

    private static func subviewBounds(_ split: NSSplitView) -> CGRect {
        let bounds = split.bounds
        guard let window = split.window, window.canBecomeMain else { return bounds }
        let content = window.contentLayoutRect
        guard content.height > 2, bounds.height > content.height + 1 else { return bounds }
        let width = content.width > 2 ? min(bounds.width, content.width) : bounds.width
        let height = content.height
        return CGRect(x: bounds.minX, y: bounds.minY, width: max(width, 0), height: height)
    }

    private static func isScrollDocument(_ view: NSView) -> Bool {
        guard let clip = view.superview as? NSClipView,
              let scroll = clip.superview as? NSScrollView else { return false }
        return scroll.documentView === view
    }

    private static func containsSplit(_ view: NSView) -> Bool {
        if view is NSSplitView { return true }
        for child in view.subviews where containsSplit(child) { return true }
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
        let capped = SplitFrameCap.capped(next, view: self)
        if abs(capped.origin.x - frame.origin.x) > 0.5 || abs(capped.origin.y - frame.origin.y) > 0.5 {
            reins_setFrame(capped)
        } else {
            reins_setFrameSize(capped.size)
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
