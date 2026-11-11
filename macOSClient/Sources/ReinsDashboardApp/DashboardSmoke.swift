#if DEBUG
import AppKit
import Foundation

/// Local, opt-in rendering probe; omitted from release builds. It captures only
/// this app's own sample-data window, never the desktop or another app's window.
/// Window capture may require the host's Screen Recording permission.
@MainActor
enum DashboardSmoke {
    private static var started = false

    static func runIfRequested(store: DashboardStore) {
        let arguments = CommandLine.arguments
        guard !started, let flag = arguments.firstIndex(of: "--smoke-test"),
              arguments.indices.contains(flag + 1) else { return }
        started = true
        let directory = URL(fileURLWithPath: arguments[flag + 1], isDirectory: true)
        store.showSamples()
        Task {
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                try await Task.sleep(nanoseconds: 600_000_000)
                guard let window = NSApp.windows.first(where: { $0.contentView != nil && $0.isVisible }),
                      let view = window.contentView else {
                    throw SmokeFailure.noWindow
                }
                NSApp.setActivationPolicy(.regular)
                NSApp.activate(ignoringOtherApps: true)
                window.makeKeyAndOrderFront(nil)
                let windowNumber = window.windowNumber
                guard windowNumber > 0 else { throw SmokeFailure.noWindow }
                var renders: [[String: Any]] = []
                for (name, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
                    NSApp.appearance = NSAppearance(named: appearance)
                    window.appearance = NSAppearance(named: appearance)
                    try await Task.sleep(nanoseconds: 500_000_000)
                    view.layoutSubtreeIfNeeded()
                    let output = directory.appendingPathComponent("dashboard-\(name).png")
                    // AppKit cacheDisplay misses compositor-rendered glass and
                    // sidebar content on recent macOS. Capture the actual window
                    // instead; there is deliberately no whole-screen fallback.
                    try await Task.detached(priority: .userInitiated) {
                        try captureOwnWindow(number: windowNumber, output: output)
                    }.value
                    guard let bitmap = NSBitmapImageRep(data: try Data(contentsOf: output)),
                          bitmap.pixelsWide > 0, bitmap.pixelsHigh > 0 else {
                        throw SmokeFailure.noBitmap
                    }
                    renders.append(["appearance": name, "width": bitmap.pixelsWide, "height": bitmap.pixelsHigh])
                }
                let report: [String: Any] = ["status": "rendered", "sample_records": store.records.count,
                                             "demo_mode": store.isDemo, "captures": renders,
                                             "capture_method": "screencapture-window-id",
                                             "window_number": windowNumber,
                                             "scope": "Own synthetic-data window only; visual review required; not interaction automation"]
                try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
                    .write(to: directory.appendingPathComponent("ui-smoke.json"), options: .atomic)
            } catch {
                let report: [String: Any] = ["status": "failed", "error": error.localizedDescription]
                if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: directory.appendingPathComponent("ui-smoke.json"), options: .atomic)
                }
            }
            NSApp.terminate(nil)
        }
    }

    nonisolated private static func captureOwnWindow(number: Int, output: URL) throws {
        let process = Process()
        let errors = Pipe()
        let completion = DispatchSemaphore(value: 0)
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        process.arguments = ["-x", "-o", "-a", "-l", String(number), output.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        process.terminationHandler = { _ in completion.signal() }
        try process.run()
        guard completion.wait(timeout: .now() + 10) == .success else {
            process.terminate()
            throw SmokeFailure.captureTimeout
        }
        let errorText = String(data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw SmokeFailure.captureFailed(status: process.terminationStatus,
                                              reason: String(errorText.prefix(1_000)))
        }
    }

    private enum SmokeFailure: LocalizedError {
        case noWindow, noBitmap, captureTimeout
        case captureFailed(status: Int32, reason: String)
        var errorDescription: String? {
            switch self {
            case .noWindow: return "No visible dashboard window was created."
            case .noBitmap: return "Window capture did not produce a valid PNG."
            case .captureTimeout: return "Own-window screencapture timed out after 10 seconds. No desktop fallback was attempted."
            case .captureFailed(let status, let reason):
                return "Own-window screencapture failed (status \(status)); Screen Recording permission may be required. No desktop fallback was attempted. \(reason)"
            }
        }
    }
}
#endif
