import Darwin
import Foundation
import XCTest
@testable import RuntimeCore

final class RuntimeCoreTests: XCTestCase {
    private var root: URL!
    private var paths: RuntimePaths!

    override func setUpWithError() throws {
        root = URL(fileURLWithPath: "/private/tmp/reins-runtime-tests-\(UUID().uuidString)", isDirectory: true)
        paths = RuntimePaths(baseURL: root)
        try paths.prepare()
    }

    override func tearDownWithError() throws {
        if let root { try FileManager.default.removeItem(at: root) }
    }

    func testPrivateRuntimeLayoutAndRepeatedPreparation() throws {
        // Reconstructing paths for an existing directory must retain /private/tmp,
        // not Foundation's standardizedFileURL rewrite through the /tmp symlink.
        let reopened = RuntimePaths(baseURL: root)
        XCTAssertEqual(reopened.baseURL.path, root.path)
        try reopened.prepare()
        try paths.prepare()
        for directory in [root!, paths.runtimeDirectory, paths.archiveDirectory, paths.selfTestDirectory] {
            var info = stat()
            XCTAssertEqual(lstat(directory.path, &info), 0)
            XCTAssertEqual(info.st_mode & 0o777, 0o700)
            XCTAssertEqual(info.st_uid, geteuid())
        }
    }

    func testConfigurationRoundTripsAndNormalizes() throws {
        let source = RuntimeConfiguration(sensitivePaths: ["/private/tmp/a/../test.env", "/private/tmp/test.env"], intervalMilliseconds: 200)
        try source.save(to: paths.configurationURL)
        XCTAssertEqual(try RuntimeConfiguration.load(from: paths.configurationURL),
                       RuntimeConfiguration(sensitivePaths: ["/private/tmp/test.env"], intervalMilliseconds: 200))
        var info = stat()
        XCTAssertEqual(lstat(paths.configurationURL.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
        XCTAssertEqual(info.st_nlink, 1)
    }

    func testConfigurationRejectsUnboundedOrAmbiguousInput() {
        for config in [RuntimeConfiguration(sensitivePaths: []),
                       RuntimeConfiguration(sensitivePaths: ["relative.env"]),
                       RuntimeConfiguration(sensitivePaths: ["/"]),
                       RuntimeConfiguration(sensitivePaths: ["/foo\0bar"]),
                       RuntimeConfiguration(sensitivePaths: ["/" + String(repeating: "a", count: 4096)]),
                       RuntimeConfiguration(sensitivePaths: ["/test"], intervalMilliseconds: 1),
                       RuntimeConfiguration(sensitivePaths: ["/test"], intervalMilliseconds: 60_001),
                       RuntimeConfiguration(sensitivePaths: Array(repeating: "/test", count: 129))] {
            XCTAssertThrowsError(try config.validated())
        }
    }

    func testAbsentAndMalformedConfigurationAreErrors() throws {
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
        try Data("not a property list".utf8).write(to: paths.configurationURL)
        XCTAssertEqual(chmod(paths.configurationURL.path, 0o600), 0)
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
    }

    func testStatusRoundTripsMonitorEpoch() throws {
        let start = Date(timeIntervalSince1970: 1_700_000_000.123)
        let value = RuntimeStatus(state: .running, supervisorPID: 100, monitorPID: 101,
                                  monitorStartedAt: start, updatedAt: start.addingTimeInterval(2),
                                  message: nil, sessionID: "synthetic-session")
        try value.save(to: paths.statusURL)
        XCTAssertEqual(try RuntimeStatus.load(from: paths.statusURL), value)
        XCTAssertTrue(value.isFresh(at: start.addingTimeInterval(8)))
        XCTAssertFalse(value.isFresh(at: start.addingTimeInterval(30)))
        XCTAssertFalse(value.isFresh(at: start.addingTimeInterval(-10)))
    }

    func testAtomicReplacementRetainsPrivatePermissionsAndNoTemporaryFiles() throws {
        for number in 0..<20 {
            let status = RuntimeStatus(state: .backoff, supervisorPID: 100, message: "attempt \(number)", sessionID: "test")
            try status.save(to: paths.statusURL)
            XCTAssertEqual(try RuntimeStatus.load(from: paths.statusURL).message, "attempt \(number)")
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: paths.runtimeDirectory.path)
        XCTAssertFalse(names.contains { $0.hasPrefix(".reins-write-") })
    }

    func testRejectsSymlinkedPropertyListWithoutModifyingDestination() throws {
        let target = root.appendingPathComponent("untouched")
        try Data("untouched".utf8).write(to: target)
        XCTAssertEqual(symlink(target.path, paths.configurationURL.path), 0)
        XCTAssertThrowsError(try RuntimeConfiguration.defaults().save(to: paths.configurationURL))
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
        XCTAssertEqual(try String(contentsOf: target), "untouched")
    }

    func testRejectsHardLinkedPropertyList() throws {
        try RuntimeConfiguration.defaults().save(to: paths.configurationURL)
        XCTAssertEqual(link(paths.configurationURL.path, root.appendingPathComponent("alias.plist").path), 0)
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
        XCTAssertThrowsError(try RuntimeConfiguration.defaults().save(to: paths.configurationURL))
    }

    func testRejectsNonPrivateFilesAndDirectories() throws {
        try RuntimeConfiguration.defaults().save(to: paths.configurationURL)
        XCTAssertEqual(chmod(paths.configurationURL.path, 0o644), 0)
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
        XCTAssertEqual(chmod(paths.runtimeDirectory.path, 0o755), 0)
        XCTAssertThrowsError(try paths.prepare())
    }

    func testRejectsSymlinkedRuntimeDirectory() throws {
        try FileManager.default.removeItem(at: paths.runtimeDirectory)
        let elsewhere = root.appendingPathComponent("elsewhere", isDirectory: true)
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertEqual(symlink(elsewhere.path, paths.runtimeDirectory.path), 0)
        XCTAssertThrowsError(try paths.prepare())
    }

    func testLockRejectsSecondInstanceAndReleasesOnLifetimeEnd() throws {
        var first: RuntimeInstanceLock? = try RuntimeInstanceLock(url: paths.lockURL)
        XCTAssertNotNil(first)
        XCTAssertThrowsError(try RuntimeInstanceLock(url: paths.lockURL))
        first = nil
        let next = try RuntimeInstanceLock(url: paths.lockURL)
        withExtendedLifetime(next) {}
    }

    func testLockRejectsSymlinkAndFifo() throws {
        let target = root.appendingPathComponent("lock-target")
        try Data().write(to: target)
        XCTAssertEqual(symlink(target.path, paths.lockURL.path), 0)
        XCTAssertThrowsError(try RuntimeInstanceLock(url: paths.lockURL))
        XCTAssertEqual(unlink(paths.lockURL.path), 0)
        XCTAssertEqual(mkfifo(paths.lockURL.path, 0o600), 0)
        XCTAssertThrowsError(try RuntimeInstanceLock(url: paths.lockURL))
    }

    func testPropertyListReaderRejectsFifoWithoutBlocking() throws {
        XCTAssertEqual(mkfifo(paths.configurationURL.path, 0o600), 0)
        XCTAssertThrowsError(try RuntimeConfiguration.load(from: paths.configurationURL))
    }

    func testArchiveRetentionAndActiveLogRemoval() throws {
        for index in 0..<8 {
            try Data("synthetic \(index)\n".utf8).write(to: paths.evidenceURL)
            XCTAssertEqual(chmod(paths.evidenceURL.path, 0o600), 0)
            try paths.rotateEvidence(retaining: 5)
            XCTAssertFalse(FileManager.default.fileExists(atPath: paths.evidenceURL.path))
        }
        let archives = try FileManager.default.contentsOfDirectory(at: paths.archiveDirectory, includingPropertiesForKeys: nil)
        XCTAssertEqual(archives.count, 5)
        let contents = try archives.map { try String(contentsOf: $0) }
        XCTAssertTrue(contents.contains("synthetic 7\n"))
        XCTAssertFalse(contents.contains("synthetic 0\n"))
    }

    func testRotationRefusesSymlinkWithoutDeletingTarget() throws {
        let target = root.appendingPathComponent("evidence-target")
        try Data("synthetic".utf8).write(to: target)
        XCTAssertEqual(symlink(target.path, paths.evidenceURL.path), 0)
        XCTAssertThrowsError(try paths.rotateEvidence())
        XCTAssertEqual(try String(contentsOf: target), "synthetic")
    }

    func testEmptyEvidenceIsRemovedAndRetentionValidated() throws {
        try Data().write(to: paths.evidenceURL)
        XCTAssertEqual(chmod(paths.evidenceURL.path, 0o600), 0)
        try paths.rotateEvidence()
        XCTAssertFalse(FileManager.default.fileExists(atPath: paths.evidenceURL.path))
        XCTAssertThrowsError(try paths.rotateEvidence(retaining: -1))
    }

    func testLocalAgentWritesOwnedConfigurationWithoutLaunching() throws {
        let agent = LocalLaunchAgent(helper: URL(fileURLWithPath: "/usr/bin/true"), directory: root.appendingPathComponent("LaunchAgents"))
        try agent.writeConfiguration(); try agent.writeConfiguration()
        let data = try Data(contentsOf: agent.plistURL)
        let value = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        XCTAssertEqual(value["Label"] as? String, LocalLaunchAgent.label)
        XCTAssertEqual(value["ProgramArguments"] as? [String], ["/usr/bin/true"])
        var info = stat(); XCTAssertEqual(lstat(agent.plistURL.path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }

    func testLocalAgentRefusesForeignConfiguration() throws {
        let agent = LocalLaunchAgent(helper: URL(fileURLWithPath: "/usr/bin/true"), directory: root)
        let original = Data("unrelated configuration".utf8)
        try original.write(to: agent.plistURL); XCTAssertEqual(chmod(agent.plistURL.path, 0o600), 0)
        XCTAssertThrowsError(try agent.writeConfiguration())
        XCTAssertEqual(try Data(contentsOf: agent.plistURL), original)
    }

    func testLocalAgentRefusesSymlinkWithoutTouchingTarget() throws {
        let agent = LocalLaunchAgent(helper: URL(fileURLWithPath: "/usr/bin/true"), directory: root)
        let target = root.appendingPathComponent("untouched")
        try Data("unchanged".utf8).write(to: target)
        XCTAssertEqual(symlink(target.path, agent.plistURL.path), 0)
        XCTAssertThrowsError(try agent.writeConfiguration())
        XCTAssertEqual(try String(contentsOf: target), "unchanged")
    }

    func testLocalAgentRejectsGroupWritableParentAndMissingHelper() throws {
        let agent = LocalLaunchAgent(helper: URL(fileURLWithPath: "/usr/bin/true"), directory: root)
        XCTAssertEqual(chmod(root.path, 0o770), 0)
        XCTAssertThrowsError(try agent.writeConfiguration())
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        let missing = LocalLaunchAgent(helper: root.appendingPathComponent("absent"), directory: root)
        XCTAssertThrowsError(try missing.writeConfiguration())
    }
}
