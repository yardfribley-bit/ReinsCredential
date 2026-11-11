import AppKit
import Foundation

/// Opt-in installed-product diagnostics. Uses the same service registration,
/// health checks and synthetic self-test as the UI. Never inserts evidence.
@MainActor
enum ProductVerification {
    static func stopIfRequested(runtime: RuntimeController) -> Bool {
        let args = CommandLine.arguments
        guard let index = args.firstIndex(of: "--stop-monitoring"), args.indices.contains(index + 1) else { return false }
        let output = URL(fileURLWithPath: args[index + 1])
        runtime.stop()
        Task {
            for _ in 0..<150 {
                if !runtime.isBusy { break }
                try? await Task.sleep(nanoseconds: 100_000_000)
            }
            let result: [String: Any] = ["result": runtime.state == .stopped && !runtime.isBusy ? "PASS" : "FAIL",
                                         "state": runtime.state.rawValue, "message": runtime.statusMessage]
            if let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: output, options: .atomic)
            }
            NSApp.terminate(nil)
        }
        return true
    }

    static func runIfRequested(runtime: RuntimeController) {
        let args = CommandLine.arguments
        guard let index = args.firstIndex(of: "--verify-installation"), args.indices.contains(index + 1) else { return }
        let output = URL(fileURLWithPath: args[index + 1])
        Task {
            var ready = false
            for _ in 0..<60 {
                await runtime.refreshNow()
                if runtime.state.canSelfTest { ready = true; break }
                if runtime.state == .approvalRequired { break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            if ready {
                runtime.runSelfTest()
                for _ in 0..<25 {
                    if runtime.selfTestPassed != nil { break }
                    try? await Task.sleep(nanoseconds: 500_000_000)
                }
            }
            let report: [String: Any] = [
                "result": ready && runtime.selfTestPassed == true ? "PASS" : "FAIL",
                "state": runtime.state.rawValue, "status_message": runtime.statusMessage,
                "self_test_passed": runtime.selfTestPassed == true,
                "self_test_message": runtime.selfTestStatus,
                "rejected_lines": runtime.rejectedCount,
                "generated_at": ISO8601DateFormatter().string(from: Date()),
                "service_mode": Bundle.main.object(forInfoDictionaryKey: "ReinsLocalLaunchAgent") as? Bool == true ? "local_launchagent" : "smappservice",
                "scope": "Installed app and real background monitor; synthetic file/loopback peer; no external transfer; background service left registered."
            ]
            do {
                let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
                try data.write(to: output, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: output.path)
            } catch { fputs("Product verification: \(error.localizedDescription)\n", stderr) }
            NSApp.terminate(nil)
        }
    }
}
