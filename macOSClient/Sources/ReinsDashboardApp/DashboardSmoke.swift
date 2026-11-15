#if DEBUG
import AppKit
import EvidenceCore
import Foundation

/// Opt-in rendering probe. It loads a fixture log into this process and checks
/// that the sidebar, the chain list, and the inspector actually drew. A window
/// whose columns have width but no rows fails. It never starts the collector.
@MainActor
enum DashboardSmoke {
    private static var started = false

    static func runIfRequested(store: DashboardStore) {
        let arguments = CommandLine.arguments
        guard !started, let flag = arguments.firstIndex(of: "--smoke-test"),
              arguments.indices.contains(flag + 1) else { return }
        started = true
        let directory = URL(fileURLWithPath: arguments[flag + 1], isDirectory: true)
        let evidence = arguments.firstIndex(of: "--smoke-evidence").flatMap { index in
            arguments.indices.contains(index + 1) ? URL(fileURLWithPath: arguments[index + 1]) : nil
        }
        Task {
            var failed = false
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                if let evidence {
                    try writeFixture(evidence)
                    store.importLog(from: evidence)
                    let deadline = Date().addingTimeInterval(8)
                    while store.isLoading || store.records.isEmpty {
                        if Date() > deadline { throw SmokeFailure.emptyFixture }
                        try await Task.sleep(nanoseconds: 50_000_000)
                    }
                } else if arguments.contains("--smoke-empty") {
                    store.returnToLive(records: [])
                } else {
                    store.showSamples()
                }
                try await Task.sleep(nanoseconds: 400_000_000)
                guard let window = NSApp.windows.first(where: { $0.contentView != nil && $0.isVisible }),
                      let view = window.contentView else { throw SmokeFailure.noWindow }
                NSApp.setActivationPolicy(.regular)
                NSApp.activate(ignoringOtherApps: true)
                window.makeKeyAndOrderFront(nil)
                view.layoutSubtreeIfNeeded()
                view.displayIfNeeded()
                try await Task.sleep(nanoseconds: 600_000_000)
                view.layoutSubtreeIfNeeded()
                let width = view.bounds.width
                guard width > 400, view.bounds.height > 200 else { throw SmokeFailure.noWindow }
                let sidebarRows = rowCount(in: view, minX: 0, maxX: width * 0.35)
                let listRows = rowCount(in: view, minX: width * 0.28, maxX: width * 0.78)
                guard sidebarRows >= 1 else { throw SmokeFailure.noRows(column: "sidebar", count: sidebarRows) }
                guard listRows >= 1 else { throw SmokeFailure.noRows(column: "list", count: listRows) }
                DashboardAppDelegate.clampLiveSplits()
                view.layoutSubtreeIfNeeded()
                let before = headingHits(in: view, window: window)
                try await Task.sleep(nanoseconds: 60_000_000_000)
                view.layoutSubtreeIfNeeded()
                let after = headingHits(in: view, window: window)
                guard !after.isEmpty else {
                    throw SmokeFailure.hiddenHeading(before: before.count, sample: visibleTextSample(in: view, window: window))
                }
                guard rowIsVisible(in: view, window: window) else { throw SmokeFailure.hiddenRows }
                guard inspectorHasSelection(in: view, window: window) else { throw SmokeFailure.emptyInspector }
                let windowHeight = window.frame.height
                let savedHeight = SplitFrameSanitizer.tallestSubviewHeight(in: .standard)
                if savedHeight > windowHeight {
                    throw SmokeFailure.savedHeight(saved: savedHeight, window: windowHeight)
                }
                let seeded = [
                    "NSSplitView Subview Frames main-AppWindow-1, SidebarNavigationSplitView",
                    "NSSplitView Subview Frames main-AppWindow-1, ListRewrite",
                    "NSSplitView Subview Frames SidebarNavigationSplitView"
                ]
                for key in seeded {
                    guard let stored = UserDefaults.standard.object(forKey: key) else { throw SmokeFailure.missingSplitKey(key) }
                    let height = SplitFrameSanitizer.tallestHeight(of: stored)
                    if height > windowHeight { throw SmokeFailure.savedHeight(saved: height, window: windowHeight) }
                }
                for subview in splitSubviews(in: view) where subview.frame.height > windowHeight {
                    throw SmokeFailure.savedHeight(saved: subview.frame.height, window: windowHeight)
                }
                let panes = panesInsideWindow(in: view, window: window)
                guard panes.sidebar else { throw SmokeFailure.paneOutside(column: "sidebar") }
                guard panes.list else { throw SmokeFailure.paneOutside(column: "list") }
                guard panes.inspector else { throw SmokeFailure.paneOutside(column: "inspector") }
                let contentHeight = window.contentLayoutRect.height
                let sidebarView = columnHost(in: view, minX: 0, maxX: width * 0.4) ?? view
                let listView = columnHost(in: view, minX: width * 0.3, maxX: width * 0.75) ?? view
                let inspectorView = columnHost(in: view, minX: width * 0.62, maxX: width) ?? view
                let sidebarPixels = try contentPixels(sidebarView)
                let listPixels = try contentPixels(listView)
                let inspectorPixels = try contentPixels(inspectorView)
                func blank(_ pixels: Pixels) -> Bool {
                    pixels.dark < 15 && pixels.light > 30
                }
                guard !blank(sidebarPixels) else { throw SmokeFailure.blankColumn(column: "sidebar", pixels: sidebarPixels.dark) }
                guard !blank(listPixels) else { throw SmokeFailure.blankColumn(column: "list", pixels: listPixels.dark) }
                guard !blank(inspectorPixels) else { throw SmokeFailure.blankColumn(column: "inspector", pixels: inspectorPixels.dark) }
                guard inspectorHasSelection(in: view, minX: width * 0.65) else { throw SmokeFailure.emptyInspector }
                let report: [String: Any] = [
                    "status": "rendered",
                    "fixture_records": store.records.count,
                    "sidebar_rows": sidebarRows,
                    "list_rows": listRows,
                    "sidebar_pixels": sidebarPixels.dark,
                    "list_pixels": listPixels.dark,
                    "inspector_pixels": inspectorPixels.dark,
                    "saved_split_height": savedHeight,
                    "window_height": windowHeight,
                    "content_height": contentHeight,
                    "panes_inside_window": panes.sidebar && panes.list && panes.inspector,
                ]
                try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
                    .write(to: directory.appendingPathComponent("ui-smoke.json"), options: .atomic)
            } catch {
                failed = true
            let message = "dashboard smoke failed: \(error.localizedDescription)\n"
            try? FileHandle.standardError.write(Data(message.utf8))
                let report: [String: Any] = ["status": "failed", "error": error.localizedDescription]
                if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: directory.appendingPathComponent("ui-smoke.json"), options: .atomic)
                }
            }
            exit(failed ? 1 : 0)
        }
    }

    private static func writeFixture(_ url: URL) throws {
        let encoder = JSONEncoder()
        var data = Data()
        for copy in 0..<24 {
            for record in EvidenceRecord.sampleRecords {
                let object = try JSONSerialization.jsonObject(with: encoder.encode(record))
                guard var fields = object as? [String: Any] else { continue }
                fields["id"] = UUID().uuidString
                if copy > 0, var tree = fields["processTree"] as? [[String: Any]] {
                    for index in tree.indices { tree[index]["id"] = UUID().uuidString }
                    fields["processTree"] = tree
                }
                data.append(try JSONSerialization.data(withJSONObject: fields))
                data.append(0x0a)
            }
        }
        try data.write(to: url, options: .atomic)
    }

    private static func rowCount(in view: NSView, minX: CGFloat, maxX: CGFloat) -> Int {
        let frame = view.convert(view.bounds, to: nil)
        var best = 0
        if frame.midX >= minX, frame.midX <= maxX, frame.width > 20, frame.height > 8 {
            if let table = view as? NSTableView { best = max(best, table.numberOfRows) }
            let role = view.accessibilityRole()
            if role == .row || role == .cell { best = max(best, 1) }
        }
        for child in view.subviews {
            best = max(best, rowCount(in: child, minX: minX, maxX: maxX))
        }
        if frame.width <= (maxX - minX) + 80, frame.midX >= minX, frame.midX <= maxX,
           let children = view.accessibilityChildren() {
            for child in children {
                let childRole = (child as AnyObject).accessibilityRole?()
                if childRole == .row || childRole == .cell { best = max(best, 1) }
            }
        }
        return best
    }

    private static func accessibilityValueText(_ object: AnyObject) -> String {
        guard let item = object as? NSObject else { return "" }
        let selector = NSSelectorFromString("accessibilityValue")
        guard item.responds(to: selector) else { return "" }
        typealias Getter = @convention(c) (AnyObject, Selector) -> AnyObject?
        let implementation = unsafeBitCast(item.method(for: selector), to: Getter.self)
        return implementation(item, selector) as? String ?? ""
    }

    private static func screenFrame(of object: AnyObject, window: NSWindow) -> NSRect {
        let reported = object.accessibilityFrame?() ?? .null
        if !reported.isNull, reported.width > 1, reported.height > 1, reported.height <= window.frame.height + 2,
           window.frame.contains(CGPoint(x: reported.midX, y: reported.midY)) {
            return reported
        }
        guard let view = object as? NSView, let host = view.window else { return .null }
        let local = host.convertToScreen(view.convert(view.bounds, to: nil))
        guard local.width > 1, local.height > 1, local.height <= window.frame.height + 2,
              window.frame.contains(CGPoint(x: local.midX, y: local.midY)) else { return .null }
        return local
    }

    private static func headingHits(in view: NSView, window: NSWindow) -> [String] {
        let bounds = window.frame
        var hits: [String] = []
        func isHeading(_ text: String) -> Bool {
            text.localizedCaseInsensitiveContains("Runtime security") || text.contains("运行时安全")
                || text.localizedCaseInsensitiveContains("Local agent") || text.contains("本机 Agent")
                || text.contains("sidebar.runtimeSecurity")
        }
        func walk(_ candidate: NSView) {
            let label = candidate.accessibilityLabel() ?? ""
            let value = (candidate as? NSTextField)?.stringValue ?? ""
            let title = candidate.accessibilityTitle() ?? ""
            let text = "\(label) \(value) \(title)"
            let screen = candidate.window?.convertToScreen(candidate.convert(candidate.bounds, to: nil)) ?? .null
            let inside = screen.width > 1 && screen.height > 1 && screen.height <= bounds.height + 2
                && bounds.contains(CGPoint(x: screen.midX, y: screen.midY))
            if isHeading(text) && inside { hits.append(text) }
            for child in candidate.subviews { walk(child) }
        }
        walk(view)
        return hits
    }

    private static func rowIsVisible(in view: NSView, window: NSWindow) -> Bool {
        guard let content = window.contentView else { return false }
        let visible = content.visibleRect
        func walk(_ candidate: NSView) -> Bool {
            if let table = candidate as? NSTableView, table.numberOfRows > 0 {
                let row = content.convert(table.rect(ofRow: 0), from: table)
                if row.intersects(visible), row.height > 1, row.width > 1 { return true }
            }
            return candidate.subviews.contains(where: walk)
        }
        return walk(view)
    }

    private static func inspectorHasSelection(in view: NSView, window: NSWindow) -> Bool {
        onScreenText(in: view, window: window) { text in text.count >= 2 }
    }

    private static func onScreenText(in view: NSView, window: NSWindow, matches: (String) -> Bool) -> Bool {
        guard let content = window.contentView else { return false }
        let visible = content.visibleRect
        func walk(_ candidate: NSView) -> Bool {
            let rect = content.convert(candidate.bounds, from: candidate)
            if rect.intersects(visible), rect.height > 2, rect.width > 2 {
                let label = candidate.accessibilityLabel() ?? ""
                let value = (candidate as? NSTextField)?.stringValue ?? ""
                if matches(label) || matches(value) { return true }
            }
            return candidate.subviews.contains(where: walk)
        }
        return walk(view)
    }

    private static func visibleTextSample(in view: NSView, window: NSWindow) -> String {
        let bounds = window.frame
        var lines: [String] = []
        func walk(_ candidate: NSView) {
            guard lines.count < 8 else { return }
            let label = candidate.accessibilityLabel() ?? ""
            let value = (candidate as? NSTextField)?.stringValue ?? ""
            let text = "\(label) \(value)".trimmingCharacters(in: .whitespacesAndNewlines)
            guard text.count >= 2 else {
                for child in candidate.subviews { walk(child) }
                return
            }
            let screen = candidate.window?.convertToScreen(candidate.convert(candidate.bounds, to: nil)) ?? .null
            let inside = bounds.contains(CGPoint(x: screen.midX, y: screen.midY))
            lines.append("\(text.prefix(28)) y=\(Int(screen.midY)) h=\(Int(screen.height)) \(inside ? "inside" : "outside")")
            for child in candidate.subviews { walk(child) }
        }
        walk(view)
        let heights = splitSubviews(in: view).map { Int($0.frame.height) }
        return "windowY=\(Int(bounds.midY)) h=\(Int(bounds.height)) text=[\(lines.joined(separator: "; "))] splits=\(heights)"
    }

    private static func panesInsideWindow(in view: NSView, window: NSWindow) -> (sidebar: Bool, list: Bool, inspector: Bool) {
        let bounds = window.frame
        var sidebar = false
        var list = false
        var inspector = false
        func consider(_ frame: NSRect, text: String) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.count >= 2, frame.width > 1, frame.height > 1, frame.height <= bounds.height + 2 else { return }
            guard bounds.contains(CGPoint(x: frame.midX, y: frame.midY)) else { return }
            let x = (frame.midX - bounds.minX) / max(bounds.width, 1)
            if x < 0.38 { sidebar = true }
            if x > 0.22 && x < 0.78 { list = true }
            if x > 0.62 { inspector = true }
        }
        func walk(_ object: AnyObject, depth: Int) {
            if depth > 16 { return }
            let label = object.accessibilityLabel?() ?? ""
            let value = accessibilityValueText(object)
            let title = object.accessibilityTitle?() ?? ""
            consider(screenFrame(of: object, window: window), text: "\(label) \(value) \(title)")
            if let children = object.accessibilityChildren?() {
                for child in children { walk(child as AnyObject, depth: depth + 1) }
            }
        }
        walk(view, depth: 0)
        return (sidebar, list, inspector)
    }

    private static func splitSubviews(in view: NSView) -> [NSView] {
        var found: [NSView] = []
        if let split = view as? NSSplitView { found.append(contentsOf: split.subviews) }
        for child in view.subviews { found.append(contentsOf: splitSubviews(in: child)) }
        return found
    }

    private static func inspectorHasSelection(in view: NSView, minX: CGFloat) -> Bool {
        let frame = view.convert(view.bounds, to: nil)
        if frame.midX >= minX, frame.width > 20, frame.height > 8 {
            let label = view.accessibilityLabel()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let value = (view as? NSTextField)?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if label.count >= 2 || value.count >= 2 { return true }
        }
        return view.subviews.contains { inspectorHasSelection(in: $0, minX: minX) }
    }

    private struct Pixels { var dark = 0, light = 0 }

    private static func columnHost(in view: NSView, minX: CGFloat, maxX: CGFloat) -> NSView? {
        let frame = view.convert(view.bounds, to: nil)
        var best: NSView?
        var bestArea: CGFloat = 0
        if let table = view as? NSTableView, frame.midX >= minX, frame.midX <= maxX, frame.width > 40, frame.height > 40 {
            return table
        }
        if frame.midX >= minX, frame.midX <= maxX, frame.width > 40, frame.width < (maxX - minX) + 120, frame.height > 40 {
            let area = frame.width * frame.height
            if area > bestArea { best = view; bestArea = area }
        }
        for child in view.subviews {
            if let found = columnHost(in: child, minX: minX, maxX: maxX) {
                if found is NSTableView { return found }
                let foundFrame = found.convert(found.bounds, to: nil)
                let area = foundFrame.width * foundFrame.height
                if area > bestArea { best = found; bestArea = area }
            }
        }
        return best
    }

    /// Off-screen render of this window's content. A blank column is one color.
    private static func contentPixels(_ view: NSView) throws -> Pixels {
        let visible = view.visibleRect
        let width = Int(visible.width.rounded(.down))
        let height = Int(visible.height.rounded(.down))
        guard width > 40, height > 40,
              let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
                                          bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                          colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: rep) else { throw SmokeFailure.noBitmap }
        view.wantsLayer = true
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
        func draw(into rep: NSBitmapImageRep) {
            guard let context = NSGraphicsContext(bitmapImageRep: rep) else { return }
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = context
            context.cgContext.translateBy(x: -visible.origin.x, y: -visible.origin.y)
            view.cacheDisplay(in: visible, to: rep)
            NSGraphicsContext.restoreGraphicsState()
        }
        draw(into: rep)
        guard let data = rep.bitmapData else { throw SmokeFailure.noBitmap }
        let rowBytes = rep.bytesPerRow
        func ink(_ x0: Int, _ x1: Int) -> (dark: Int, light: Int) {
            var dark = 0
            var light = 0
            var y = 16
            while y < height - 16 {
                var x = x0
                while x < x1 {
                    let index = y * rowBytes + x * 4
                    let red = Int(data[index])
                    let green = Int(data[index + 1])
                    let blue = Int(data[index + 2])
                    if red < 170 && green < 170 && blue < 170 { dark += 1 }
                    else if red > 185 && green > 185 && blue > 185 { light += 1 }
                    x += 4
                }
                y += 4
            }
            return (dark, light)
        }
        let ink = ink(0, width)
        return Pixels(dark: ink.dark, light: ink.light)
    }

    private enum SmokeFailure: LocalizedError {
        case noWindow, noBitmap, emptyFixture, emptyInspector, hiddenRows
        case hiddenHeading(before: Int, sample: String)
        case noRows(column: String, count: Int)
        case blankColumn(column: String, pixels: Int)
        case savedHeight(saved: CGFloat, window: CGFloat)
        case missingSplitKey(String)
        case paneOutside(column: String)
        var errorDescription: String? {
            switch self {
            case .noWindow: return "No visible dashboard window was created."
            case .noBitmap: return "The window content could not be rendered off screen."
            case .emptyFixture: return "The fixture evidence file produced no records."
            case .emptyInspector: return "Selecting a chain left the inspector without text."
            case .hiddenHeading(let before, let sample):
                return "The sidebar heading is not inside the visible window after 60 seconds (hits before the wait: \(before); \(sample))."
            case .hiddenRows: return "No list row intersects the visible window."
            case .noRows(let column, let count): return "The \(column) has \(count) rows; a blank window must fail."
            case .blankColumn(let column, let pixels): return "The \(column) rendered \(pixels) non-background pixels."
            case .savedHeight(let saved, let window): return "Split height \(saved) is taller than the hosting window \(window)."
            case .missingSplitKey(let key): return "The split defaults key was deleted instead of clamped: \(key)."
            case .paneOutside(let column): return "The \(column) has no accessibility text inside the window."
            }
        }
    }
}
#endif
