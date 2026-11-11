import Foundation
import XCTest
import EvidenceCore
import RuntimeCore
@testable import ReinsDashboardApp

@MainActor private final class MockBackgroundService: BackgroundServiceManaging {
    var registration: BackgroundRegistration = .enabled
    var registrations = 0
    var unregistrations = 0
    func register() throws { registrations += 1; registration = .enabled }
    func unregister() async throws { unregistrations += 1; registration = .absent }
    func openSettings() {}
}

final class RuntimeControllerTests: XCTestCase {
    @MainActor private func setup() throws -> (RuntimePaths, MockBackgroundService, RuntimeController) {
        let paths = RuntimePaths(baseURL: URL(fileURLWithPath: "/private/tmp/reins-controller-\(UUID().uuidString)"))
        try paths.prepare()
        let suite = "reins-tests-\(UUID().uuidString)"; let defaults = UserDefaults(suiteName: suite)!
        addTeardownBlock { try FileManager.default.removeItem(at: paths.baseURL); UserDefaults.standard.removePersistentDomain(forName: suite) }
        let service = MockBackgroundService()
        let controller = RuntimeController(paths: paths, service: service, defaults: defaults, requiresBundle: false)
        return (paths, service, controller)
    }
    private func status(_ paths: RuntimePaths, now: Date, started: Date? = nil) throws {
        try RuntimeStatus(state: .running, supervisorPID: 123, monitorPID: 124,
            monitorStartedAt: started ?? now.addingTimeInterval(-1), updatedAt: now,
            sessionID: "synthetic").save(to: paths.statusURL)
    }
    private func health(_ paths: RuntimePaths, at date: Date, count: UInt64 = 0) throws {
        let event = EvidenceRecord(timestamp: date, riskLevel: .low, targetResource: "", actionType: "OBSERVE",
            processTree: [], sourceType: "coverage", metrics: ["enumeration_complete": 1, "visible": 2], count: count)
        try (JSONEncoder().encode(event) + Data([10])).write(to: paths.evidenceURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: paths.evidenceURL.path)
    }
    @MainActor func testFreshSupervisorWithoutFreshBackendNeverClaimsRunning() async throws {
        let (paths, _, controller) = try setup(); let now = Date()
        try status(paths, now: now, started: now.addingTimeInterval(-30))
        try health(paths, at: now.addingTimeInterval(-60))
        await controller.refreshNow(now: now)
        XCTAssertEqual(controller.state, .failed)
    }
    @MainActor func testFreshHealthyBackendAndLossAreDistinguished() async throws {
        let (paths, _, controller) = try setup(); let now = Date()
        try status(paths, now: now); try health(paths, at: now)
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .running)
        try FileManager.default.removeItem(at: paths.evidenceURL)
        try health(paths, at: now.addingTimeInterval(1), count: 2)
        await controller.refreshNow(now: now.addingTimeInterval(1)); XCTAssertEqual(controller.state, .degraded)
    }
    @MainActor func testPreviousMonitorHealthCannotQualifyNewMonitor() async throws {
        let (paths, _, controller) = try setup(); let now = Date()
        try status(paths, now: now); try health(paths, at: now.addingTimeInterval(-5))
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .starting)
    }
    @MainActor func testStaleSupervisorAndApprovalAreVisible() async throws {
        let (paths, service, controller) = try setup(); let now = Date()
        try status(paths, now: now.addingTimeInterval(-30)); try health(paths, at: now)
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .failed)
        service.registration = .requiresApproval
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .approvalRequired)
        service.registration = .absent
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .stopped)
    }
    @MainActor func testMissingStatusTimesOutInsteadOfEndlessStarting() async throws {
        let (_, _, controller) = try setup(); let now = Date()
        await controller.refreshNow(now: now); XCTAssertEqual(controller.state, .starting)
        await controller.refreshNow(now: now.addingTimeInterval(16)); XCTAssertEqual(controller.state, .failed)
    }
    @MainActor func testStopPersistsUserIntentAndPreventsAutomaticRestart() async throws {
        let (_, service, controller) = try setup()
        controller.stop()
        for _ in 0..<20 { if !controller.isBusy { break }; try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(service.unregistrations, 1); XCTAssertEqual(controller.state, .stopped)
        controller.startIfNeeded(); XCTAssertEqual(service.registrations, 0)
    }
}
