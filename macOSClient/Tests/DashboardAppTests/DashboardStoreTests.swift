import Darwin
import EvidenceCore
import Foundation
import XCTest
@testable import ReinsDashboardApp

@MainActor
final class DashboardStoreTests: XCTestCase {
    func testRiskFiltersSearchAndSelectionUseImportedEvidence() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let high = record(risk: .high, pid: 101, name: "Cursor", path: "/Fixtures/.env",
                          destination: "https://collector.example.invalid/upload")
        let medium = record(risk: .medium, pid: 202, name: "Codex", path: "/Fixtures/.ssh/config")
        let low = record(risk: .low, pid: 303, name: "worker", path: "/Fixtures/project")
        let store = DashboardStore()
        try await importRecords([high, medium, low], into: store, directory: directory)

        XCTAssertEqual(store.count(for: .all), 3)
        for (filter, expected) in [(RiskFilter.high, high), (.medium, medium), (.low, low)] {
            XCTAssertEqual(store.count(for: filter), 1)
            store.riskFilter = filter
            store.reconcileSelection()
            XCTAssertEqual(store.visibleRecords.map(\.id), [expected.id])
            XCTAssertEqual(store.selectedRecord?.id, expected.id)
        }

        store.riskFilter = .all
        for query in ["101", "/fixtures/.ENV", "COLLECTOR.example.invalid", "cursor"] {
            store.searchText = query
            store.reconcileSelection()
            XCTAssertEqual(store.visibleRecords.map(\.id), [high.id], "Search: \(query)")
            XCTAssertEqual(store.selectedRecord?.id, high.id)
        }
        store.searchText = "cannot-match-any-evidence"
        store.reconcileSelection()
        XCTAssertTrue(store.visibleRecords.isEmpty)
        XCTAssertNil(store.selectedRecordID)
        XCTAssertNil(store.selectedRecord)
    }

    func testSuccessfulImportReplacesDemoAndResetsFilters() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        XCTAssertTrue(store.isDemo)
        store.riskFilter = .high
        store.searchText = "stale search"
        let imported = record(risk: .medium, pid: 404, name: "fixture", path: "/Fixtures/secret")
        let url = try await importRecords([imported], into: store, directory: directory)

        XCTAssertFalse(store.isDemo)
        XCTAssertEqual(store.records, [imported])
        XCTAssertEqual(store.importedURL, url)
        XCTAssertEqual(store.riskFilter, .all)
        XCTAssertTrue(store.searchText.isEmpty)
        XCTAssertEqual(store.selectedRecordID, imported.id)
        XCTAssertTrue(store.rejectedLines.isEmpty)
        XCTAssertFalse(store.incompleteTail)
        XCTAssertNil(store.errorMessage)
    }

    func testPartialImportRetainsWarningsAndShowSamplesClearsThem() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        let imported = record(risk: .low, pid: 505, name: "fixture", path: "/Fixtures/source")
        let url = directory.appendingPathComponent("partial.jsonl")
        var data = try JSONEncoder().encode(imported)
        data.append(Data("\nnot json\n{\"incomplete\":".utf8))
        try data.write(to: url)
        store.importLog(from: url)
        try await waitForImport(store)

        XCTAssertFalse(store.isDemo)
        XCTAssertEqual(store.records, [imported])
        XCTAssertEqual(store.rejectedLines, [2])
        XCTAssertTrue(store.incompleteTail)
        XCTAssertNil(store.errorMessage)

        store.searchText = "hidden"
        store.riskFilter = .high
        store.showSamples()
        XCTAssertTrue(store.isDemo)
        XCTAssertNil(store.importedURL)
        XCTAssertFalse(store.records.isEmpty)
        XCTAssertTrue(store.rejectedLines.isEmpty)
        XCTAssertFalse(store.incompleteTail)
        XCTAssertTrue(store.searchText.isEmpty)
        XCTAssertEqual(store.riskFilter, .all)
        XCTAssertEqual(store.selectedRecordID, store.records.first?.id)
    }

    func testMalformedOnlyImportPreservesPreviousDataset() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        let previous = record(risk: .low, pid: 606, name: "known", path: "/Fixtures/known")
        let previousURL = try await importRecords([previous], into: store, directory: directory)
        let malformed = directory.appendingPathComponent("malformed.jsonl")
        try Data("{broken}\n".utf8).write(to: malformed)
        store.importLog(from: malformed)
        try await waitForImport(store)

        assertPreserved(store, record: previous, url: previousURL)
        XCTAssertNotNil(store.errorMessage)
    }

    func testMissingFileImportPreservesPreviousDataset() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        let previous = record(risk: .low, pid: 707, name: "known", path: "/Fixtures/known")
        let previousURL = try await importRecords([previous], into: store, directory: directory)
        store.importLog(from: directory.appendingPathComponent("does-not-exist.jsonl"))
        try await waitForImport(store)

        assertPreserved(store, record: previous, url: previousURL)
        XCTAssertNotNil(store.errorMessage)
    }

    func testPermissionFailurePreservesPreviousDataset() async throws {
        guard geteuid() != 0 else { throw XCTSkip("Permission denial requires a non-root test user") }
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        let previous = record(risk: .low, pid: 808, name: "known", path: "/Fixtures/known")
        let previousURL = try await importRecords([previous], into: store, directory: directory)
        let denied = directory.appendingPathComponent("denied.jsonl")
        try Data("{}\n".utf8).write(to: denied)
        XCTAssertEqual(chmod(denied.path, 0), 0)
        defer { _ = chmod(denied.path, 0o600) }
        store.importLog(from: denied)
        try await waitForImport(store)

        assertPreserved(store, record: previous, url: previousURL)
        XCTAssertNotNil(store.errorMessage)
    }

    func testEmptyValidLogIsImportedAsEmptySnapshot() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = DashboardStore()
        let url = directory.appendingPathComponent("empty.jsonl")
        try Data().write(to: url)
        store.importLog(from: url)
        try await waitForImport(store)

        XCTAssertFalse(store.isDemo)
        XCTAssertTrue(store.records.isEmpty)
        XCTAssertNil(store.selectedRecord)
        XCTAssertNil(store.errorMessage)
    }

    @discardableResult
    private func importRecords(_ records: [EvidenceRecord], into store: DashboardStore,
                               directory: URL) async throws -> URL {
        let url = directory.appendingPathComponent("valid.jsonl")
        var data = Data()
        for record in records {
            data.append(try JSONEncoder().encode(record))
            data.append(0x0a)
        }
        try data.write(to: url)
        store.importLog(from: url)
        try await waitForImport(store)
        XCTAssertNil(store.errorMessage)
        return url
    }

    private func waitForImport(_ store: DashboardStore) async throws {
        for _ in 0..<400 {
            if !store.isLoading { return }
            try await Task.sleep(nanoseconds: 25_000_000)
        }
        XCTFail("Import did not finish within 10 seconds")
        throw TestFailure.importTimeout
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("reins-dashboard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func record(risk: RiskLevel, pid: Int32, name: String, path: String,
                        destination: String = "") -> EvidenceRecord {
        EvidenceRecord(timestamp: Date(timeIntervalSince1970: 1_800_000_000 + Double(pid)),
                       riskLevel: risk, targetResource: path, actionType: "OBSERVE",
                       processTree: [ProcessNode(pid: pid, ppid: 1, name: name, path: "/Applications/\(name)")],
                       destination: destination)
    }

    private func assertPreserved(_ store: DashboardStore, record: EvidenceRecord, url: URL,
                                 file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(store.records, [record], file: file, line: line)
        XCTAssertEqual(store.importedURL, url, file: file, line: line)
        XCTAssertFalse(store.isDemo, file: file, line: line)
        XCTAssertEqual(store.selectedRecordID, record.id, file: file, line: line)
    }

    private enum TestFailure: Error { case importTimeout }
}
