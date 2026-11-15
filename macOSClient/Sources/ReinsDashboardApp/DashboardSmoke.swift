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
                let pixels = try contentPixels(view)
                guard pixels.sidebar >= 40 else { throw SmokeFailure.blankColumn(column: "sidebar", pixels: pixels.sidebar) }
                guard pixels.list >= 40 else { throw SmokeFailure.blankColumn(column: "list", pixels: pixels.list) }
                guard pixels.inspector >= 40 else { throw SmokeFailure.blankColumn(column: "inspector", pixels: pixels.inspector) }
                guard inspectorHasSelection(in: view, minX: width * 0.65) else { throw SmokeFailure.emptyInspector }
                let report: [String: Any] = [
                    "status": "rendered",
                    "fixture_records": store.records.count,
                    "sidebar_rows": sidebarRows,
                    "list_rows": listRows,
                    "sidebar_pixels": pixels.sidebar,
                    "list_pixels": pixels.list,
                    "inspector_pixels": pixels.inspector,
                    "selected_chain": store.selectedChain?.owningAgentName ?? ""
                ]
                try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
                    .write(to: directory.appendingPathComponent("ui-smoke.json"), options: .atomic)
            } catch {
                failed = true
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
        for record in EvidenceRecord.sampleRecords {
            data.append(try encoder.encode(record))
            data.append(0x0a)
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

    private static func inspectorHasSelection(in view: NSView, minX: CGFloat) -> Bool {
        let frame = view.convert(view.bounds, to: nil)
        if frame.midX >= minX, frame.width > 20, frame.height > 8 {
            let label = view.accessibilityLabel()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let value = (view as? NSTextField)?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if label.count >= 2 || value.count >= 2 { return true }
        }
        return view.subviews.contains { inspectorHasSelection(in: $0, minX: minX) }
    }

    private struct Pixels { var sidebar = 0, list = 0, inspector = 0 }

    /// Off-screen render of this window's content. A blank column is one color.
    private static func contentPixels(_ view: NSView) throws -> Pixels {
        let width = Int(view.bounds.width.rounded(.down))
        let height = Int(view.bounds.height.rounded(.down))
        guard width > 300, height > 200,
              let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
                                          bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                          colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: rep) else { throw SmokeFailure.noBitmap }
        view.wantsLayer = true
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        if let layer = view.layer {
            layer.render(in: context.cgContext)
        } else {
            view.cacheDisplay(in: view.bounds, to: rep)
        }
        NSGraphicsContext.restoreGraphicsState()
        guard let data = rep.bitmapData else { throw SmokeFailure.noBitmap }
        let rowBytes = rep.bytesPerRow
        func ink(_ x0: Int, _ x1: Int) -> Int {
            var count = 0
            var y = 16
            while y < height - 16 {
                var x = x0
                while x < x1 {
                    let index = y * rowBytes + x * 4
                    let red = Int(data[index])
                    let green = Int(data[index + 1])
                    let blue = Int(data[index + 2])
                    let nearWhite = red > 248 && green > 248 && blue > 248
                    let flatGrey = abs(red - green) < 4 && abs(green - blue) < 4 && red > 220
                    if !nearWhite && !flatGrey { count += 1 }
                    x += 4
                }
                y += 4
            }
            return count
        }
        let side = max(40, width / 5)
        let inspect = max(40, width / 4)
        return Pixels(sidebar: ink(4, side), list: ink(side + 8, width - inspect), inspector: ink(width - inspect + 8, width - 4))
    }

    private enum SmokeFailure: LocalizedError {
        case noWindow, noBitmap, emptyFixture, emptyInspector
        case noRows(column: String, count: Int)
        case blankColumn(column: String, pixels: Int)
        var errorDescription: String? {
            switch self {
            case .noWindow: return "No visible dashboard window was created."
            case .noBitmap: return "The window content could not be rendered off screen."
            case .emptyFixture: return "The fixture evidence file produced no records."
            case .emptyInspector: return "Selecting a chain left the inspector without text."
            case .noRows(let column, let count): return "The \(column) has \(count) rows; a blank window must fail."
            case .blankColumn(let column, let pixels): return "The \(column) rendered \(pixels) non-background pixels."
            }
        }
    }
}
#endif
