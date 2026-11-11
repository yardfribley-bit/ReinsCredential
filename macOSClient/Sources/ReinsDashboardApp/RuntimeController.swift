import AppKit
import EvidenceCore
import Foundation
import RuntimeCore
import ServiceManagement
import SwiftUI
import UserNotifications

enum RuntimeUIState: String {
    case stopped, starting, running, degraded, approvalRequired, failed
    var title: String {
        switch self {
        case .stopped: return "监控已停止"
        case .starting: return "正在启动采集"
        case .running: return "监控中"
        case .degraded: return "监控运行中 · 覆盖受限"
        case .approvalRequired: return "需要允许后台运行"
        case .failed: return "采集服务异常"
        }
    }
}

enum BackgroundRegistration { case enabled, requiresApproval, absent, missing }

@MainActor
protocol BackgroundServiceManaging {
    var registration: BackgroundRegistration { get }
    func register() async throws
    func unregister() async throws
    func openSettings()
}

@MainActor
private final class NativeBackgroundService: BackgroundServiceManaging {
    let service = SMAppService.agent(plistName: "io.github.yardfribley-bit.ReinsCredential.runtime.plist")
    var registration: BackgroundRegistration {
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered: return .absent
        case .notFound: return .missing
        @unknown default: return .missing
        }
    }
    func register() async throws { if registration != .enabled { try service.register() } }
    func unregister() async throws { try await service.unregister() }
    func openSettings() { SMAppService.openSystemSettingsLoginItems() }
}

@MainActor
private final class LocalBackgroundService: BackgroundServiceManaging {
    let agent: LocalLaunchAgent
    init(bundleURL: URL) { agent = LocalLaunchAgent(helper: bundleURL.appendingPathComponent("Contents/MacOS/ReinsRuntime")) }
    var registration: BackgroundRegistration { agent.isInstalled ? .enabled : .absent }
    func register() async throws {
        let agent = agent
        try await Task.detached { try agent.installAndStart() }.value
    }
    func unregister() async throws {
        let agent = agent
        try await Task.detached { try agent.stopAndRemove() }.value
    }
    func openSettings() { SMAppService.openSystemSettingsLoginItems() }
}

@MainActor
final class RuntimeController: ObservableObject {
    @Published private(set) var state: RuntimeUIState = .stopped
    @Published private(set) var statusMessage = "首次启动会注册本用户的后台采集服务。"
    @Published private(set) var records: [EvidenceRecord] = []
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?
    @Published private(set) var watchedPaths: [String] = []
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var rejectedCount = 0
    @Published private(set) var selfTestStatus = ""
    @Published private(set) var selfTestPassed: Bool?
    private let paths: RuntimePaths
    private let service: BackgroundServiceManaging
    private let reader = LiveEvidenceReader()
    private let bundleURL: URL
    private let defaults: UserDefaults
    private var polling: Task<Void, Never>?
    private var refreshing = false
    private var selfTesting = false
    private var notificationsEnabled = false
    private var lastNotification: Date = .distantPast
    private let requiresBundle: Bool
    private var awaitingStatusSince: Date?

    init(paths: RuntimePaths = RuntimePaths(), service: BackgroundServiceManaging? = nil,
         bundleURL: URL = Bundle.main.bundleURL, defaults: UserDefaults = .standard,
         requiresBundle: Bool = true) {
        self.paths = paths
        if let service { self.service = service }
        else if Bundle.main.object(forInfoDictionaryKey: "ReinsLocalLaunchAgent") as? Bool == true {
            self.service = LocalBackgroundService(bundleURL: bundleURL)
        } else { self.service = NativeBackgroundService() }
        self.bundleURL = bundleURL
        self.defaults = defaults
        self.requiresBundle = requiresBundle
    }

    func beginPolling() {
        guard polling == nil else { return }
        polling = Task { [weak self] in
            if let paths = self?.paths,
               let configuration = try? await Task.detached(operation: { try RuntimeConfiguration.load(from: paths.configurationURL) }).value {
                self?.watchedPaths = configuration.sensitivePaths
            }
            while !Task.isCancelled {
                await self?.refreshNow()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }
    func endPolling() { polling?.cancel(); polling = nil }
    func refresh() { Task { await refreshNow() } }
    func startIfNeeded() {
        if !defaults.bool(forKey: "monitoringDisabledByUser") { start() }
    }

    func start() {
        guard !isBusy else { return }
        isBusy = true
        errorMessage = nil
        Task {
            defer { isBusy = false }
            do {
                let helper = bundleURL.appendingPathComponent("Contents/MacOS/ReinsRuntime")
                guard !requiresBundle || (bundleURL.pathExtension == "app" && FileManager.default.isExecutableFile(atPath: helper.path)) else {
                    throw RuntimeFileError.invalidConfiguration("请运行完整安装的 ReinsCredential.app；开发命令行界面未包含后台服务。")
                }
                let paths = paths
                watchedPaths = try await Task.detached { try Self.prepareConfiguration(paths).sensitivePaths }.value
                defaults.set(false, forKey: "monitoringDisabledByUser")
                state = .starting
                awaitingStatusSince = Date()
                statusMessage = "正在启动后台采集，等待独立健康记录。"
                try await service.register()
                await refreshNow()
            } catch {
                if service.registration == .requiresApproval {
                    state = .approvalRequired
                    statusMessage = "请在系统设置的登录项与扩展中允许 ReinsCredential 后台运行。"
                } else { fail(error) }
            }
        }
    }

    func stop() {
        guard !isBusy else { return }
        isBusy = true
        Task {
            defer { isBusy = false }
            do {
                try await service.unregister()
                defaults.set(true, forKey: "monitoringDisabledByUser")
                state = .stopped
                statusMessage = "后台服务已停用；已有证据保留在本机。"
            } catch { fail(error) }
        }
    }

    func openBackgroundSettings() { service.openSettings() }

    nonisolated private static func prepareConfiguration(_ paths: RuntimePaths) throws -> RuntimeConfiguration {
        try paths.prepare()
        if !FileManager.default.fileExists(atPath: paths.configurationURL.path) {
            try RuntimeConfiguration.defaults().save(to: paths.configurationURL)
        }
        return try RuntimeConfiguration.loadEffective(from: paths.configurationURL)
    }

    func reloadConfiguration() {
        guard !isBusy else { return }
        isBusy = true
        let paths = paths
        Task {
            defer { isBusy = false }
            do { watchedPaths = try await Task.detached { try Self.prepareConfiguration(paths).sensitivePaths }.value }
            catch { fail(error) }
        }
    }

    func addWatchedPath(_ url: URL) {
        guard url.isFileURL else { return }
        changeConfiguration { config in config.sensitivePaths.append(url.standardizedFileURL.path) }
    }

    func removeWatchedPath(_ path: String) {
        changeConfiguration { config in config.sensitivePaths.removeAll { $0 == path } }
    }

    private func changeConfiguration(_ change: @escaping @Sendable (inout RuntimeConfiguration) -> Void) {
        guard !isBusy else { return }
        isBusy = true
        let paths = paths
        Task {
            defer { isBusy = false }
            do {
                watchedPaths = try await Task.detached {
                    var config = try Self.prepareConfiguration(paths)
                    change(&config)
                    try config.save(to: paths.configurationURL)
                    return try config.validated().sensitivePaths
                }.value
                statusMessage = "目录配置已保存；后台采集将在数秒内应用更新，重启期间存在采样间隙。"
            } catch { errorMessage = error.localizedDescription }
        }
    }

    func refreshNow(now: Date = Date()) async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do {
            let batch = try await reader.poll(url: paths.evidenceURL)
            if !batch.records.isEmpty {
                records = Array((batch.records.reversed() + records).prefix(2_000))
                notifyIfNeeded(batch.records, now: now)
            }
            rejectedCount = batch.rejectedCount
            lastUpdate = batch.latestCoverage?.timestamp
            switch service.registration {
            case .requiresApproval:
                state = .approvalRequired
                statusMessage = "系统尚未允许后台运行，当前没有完整采集覆盖。"
                return
            case .absent, .missing:
                state = .stopped
                statusMessage = "后台采集未启用。点击启动监控后会自动显示本机风险。"
                return
            case .enabled: break
            }
            let statusURL = paths.statusURL
            let status = try await Task.detached { try RuntimeStatus.load(from: statusURL) }.value
            awaitingStatusSince = nil
            guard status.isFresh(at: now) else {
                state = .failed
                statusMessage = "后台服务状态已过期，不能确认采集器仍在工作。"
                return
            }
            if status.state == .failed || status.state == .stopped {
                state = .failed
                statusMessage = status.message ?? "采集器已停止。"
                return
            }
            guard status.state == .running,
                  let health = batch.latestCoverage, health.sourceType == "coverage",
                  health.timestamp >= (status.monitorStartedAt ?? .distantFuture).addingTimeInterval(-1),
                  now.timeIntervalSince(health.timestamp) >= -2,
                  now.timeIntervalSince(health.timestamp) < 15 else {
                let expired = now.timeIntervalSince(status.monitorStartedAt ?? .distantPast) > 15
                state = status.state == .backoff ? .degraded : (expired ? .failed : .starting)
                statusMessage = status.message ?? (expired ? "采集器未产生及时的健康记录，检测可能已中断。" : "等待采集器健康记录；尚不能确认检测已就绪。")
                return
            }
            let partial = health.metrics["fd_scans_partial", default: 0]
            let validation = health.metrics["activity_validation_failed", default: 0]
            let unavailable = health.metrics["unavailable", default: 0]
            let loss = health.count > 0 || rejectedCount > 0 || health.metrics["enumeration_complete"] == 0
            state = loss || partial > 0 || validation > 0 || unavailable > 0 ? .degraded : .running
            let visible = health.metrics["visible", default: 0]
            let candidates = health.metrics["known_candidates", default: 0]
            statusMessage = "可见进程 \(visible)，Agent 候选 \(candidates)。" +
                (loss ? "存在采集丢失或解析异常。" : "") +
                ((partial > 0 || validation > 0 || unavailable > 0) ? "部分进程或描述符不可见。" : "") +
                (batch.hasBacklog ? "正在追赶日志。" : "") + "用户态采样可能漏过短暂活动。"
        } catch {
            if service.registration == .enabled {
                // A missing or invalid status must not look like endless startup.
                if awaitingStatusSince == nil { awaitingStatusSince = now }
                state = now.timeIntervalSince(awaitingStatusSince!) > 15 ? .failed : .starting
                statusMessage = "无法确认后台状态：\(error.localizedDescription)"
            } else { state = .stopped }
        }
    }

    func runSelfTest() {
        guard !selfTesting, state == .running || state == .degraded else { return }
        selfTesting = true
        selfTestPassed = nil
        selfTestStatus = "正在创建合成测试文件与本机连接…"
        Task {
            defer { selfTesting = false }
            var file: URL?
            do {
                try paths.prepare()
                let target = paths.selfTestDirectory.appendingPathComponent("synthetic-\(UUID().uuidString).env")
                file = target
                try Data("REINS_SYNTHETIC_TEST=not-a-credential\n".utf8).write(to: target, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
                defer { try? FileManager.default.removeItem(at: target) }
                let probe = Process()
                probe.executableURL = bundleURL.appendingPathComponent("Contents/MacOS/ReinsRuntime")
                probe.arguments = ["--probe", target.path, "--hold-seconds", "6"]
                probe.standardOutput = FileHandle.nullDevice
                probe.standardError = FileHandle.nullDevice
                try probe.run()
                let pid = probe.processIdentifier
                let started = Date()
                var found = false
                for _ in 0..<20 {
                    await refreshNow()
                    found = records.contains { record in
                        record.sourceType == "sensitive_network_cooccurrence" &&
                        record.targetResource == target.path && record.processTree.first?.pid == pid &&
                        record.destination.contains("127.0.0.1:") && record.timestamp >= started.addingTimeInterval(-1)
                    }
                    if !probe.isRunning && found { break }
                    try await Task.sleep(nanoseconds: 500_000_000)
                }
                if probe.isRunning { probe.terminate() }
                selfTestPassed = found
                selfTestStatus = found ? "自检通过：独立采集器关联了测试进程、文件和本机连接。未向外网发送。" :
                    "自检未通过：采集器未在时限内发现完整关联，请检查后台权限与覆盖状态。"
            } catch { selfTestPassed = false; selfTestStatus = "自检失败：\(error.localizedDescription)" }
            if let file { try? FileManager.default.removeItem(at: file) }
        }
    }

    func requestNotifications() {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        Task {
            do { notificationsEnabled = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) }
            catch { errorMessage = error.localizedDescription }
        }
    }

    private func notifyIfNeeded(_ incoming: [EvidenceRecord], now: Date) {
        guard notificationsEnabled, now.timeIntervalSince(lastNotification) > 30,
              let event = incoming.last(where: { $0.sourceType == "sensitive_network_cooccurrence" && now.timeIntervalSince($0.timestamp) < 10 }) else { return }
        lastNotification = now
        let content = UNMutableNotificationContent()
        content.title = "发现敏感文件与网络连接共现"
        content.body = "打开 ReinsCredential 查看进程链与目的地。这是一条风险线索，尚未证明内容上传。"
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: event.id.uuidString, content: content, trigger: nil))
    }

    private func fail(_ error: Error) {
        state = .failed
        statusMessage = error.localizedDescription
        errorMessage = error.localizedDescription
    }
}
