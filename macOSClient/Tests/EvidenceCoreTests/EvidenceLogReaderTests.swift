import Darwin
import Foundation
import XCTest
@testable import EvidenceCore

final class EvidenceLogReaderTests: XCTestCase {
    func testJSONLRejectsInvalidDuplicateAndOversizedRowsWithoutLosingGoodRows() throws {
        let record = sample(id: 1, seconds: 100)
        let encoded = try JSONEncoder().encode(record)
        var bytes = Data(" \t\r\n".utf8) // Blank line retains source line numbering.
        bytes.append(encoded)
        bytes.append(Data("\nnot-json\n".utf8))
        bytes.append(encoded)
        bytes.append(0x0a)
        bytes.append(Data(repeating: 0x78, count: EvidenceLogReader.maxLineBytes + 1))
        bytes.append(0x0a)
        bytes.append(try JSONEncoder().encode(sample(id: 2, seconds: 200)))
        bytes.append(0x0a)
        let imported = try EvidenceLogReader.parse(bytes)
        XCTAssertEqual(imported.rejectedLines, [3, 4, 5])
        XCTAssertEqual(imported.records.map(\.id), [sample(id: 2, seconds: 200).id, record.id])
        XCTAssertFalse(imported.incompleteTail)
    }

    func testUnterminatedTailIsNotAcceptedEvenWhenItContainsValidJSON() throws {
        let first = sample(id: 1, seconds: 100)
        let tail = sample(id: 2, seconds: 200)
        var bytes = try JSONEncoder().encode(first)
        bytes.append(0x0a)
        bytes.append(try JSONEncoder().encode(tail))
        let imported = try EvidenceLogReader.parse(bytes)
        XCTAssertEqual(imported.records, [first])
        XCTAssertTrue(imported.incompleteTail)
        XCTAssertTrue(imported.rejectedLines.isEmpty, "Uncommitted tails must not be reported as malformed complete rows")
        bytes.append(0x0a)
        XCTAssertEqual(try EvidenceLogReader.parse(bytes).records, [tail, first])
    }

    func testEmptyInputAndIncompleteOnlyInput() throws {
        let empty = try EvidenceLogReader.parse(Data())
        XCTAssertTrue(empty.records.isEmpty)
        XCTAssertTrue(empty.rejectedLines.isEmpty)
        XCTAssertFalse(empty.incompleteTail)
        let unfinished = try EvidenceLogReader.parse(Data(#"{"event_id":"#.utf8))
        XCTAssertTrue(unfinished.records.isEmpty)
        XCTAssertTrue(unfinished.rejectedLines.isEmpty)
        XCTAssertTrue(unfinished.incompleteTail)
    }

    func testEqualTimestampSortingIsDeterministicByEventUUID() throws {
        let bytes = try encodeLines([sample(id: 3, seconds: 500), sample(id: 2, seconds: 600),
                                     sample(id: 1, seconds: 500)])
        XCTAssertEqual(try EvidenceLogReader.parse(bytes).records.map(\.id),
                       [sample(id: 2, seconds: 600).id, sample(id: 1, seconds: 500).id,
                        sample(id: 3, seconds: 500).id])
    }

    func testImportLimitsRejectExcessiveSizeAndLineCount() throws {
        XCTAssertThrowsError(try EvidenceLogReader.parse(Data(repeating: 0x20, count: EvidenceLogReader.maxFileBytes + 1))) {
            guard case EvidenceImportError.tooLarge = $0 else { return XCTFail("Wrong error: \($0)") }
        }
        XCTAssertThrowsError(try EvidenceLogReader.parse(Data(repeating: 0x0a, count: EvidenceLogReader.maxLines + 1))) {
            guard case EvidenceImportError.tooManyRecords = $0 else { return XCTFail("Wrong error: \($0)") }
        }
    }

    func testAsyncReadImportsRegularFileWithoutModifyingIt() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("evidence.jsonl")
        let bytes = try encodeLines([sample(id: 1, seconds: 100), sample(id: 2, seconds: 200)])
        try bytes.write(to: url)
        let imported = try await EvidenceLogReader.read(url: url)
        XCTAssertEqual(imported.records.map(\.id), [sample(id: 2, seconds: 200).id, sample(id: 1, seconds: 100).id])
        XCTAssertTrue(imported.rejectedLines.isEmpty)
        XCTAssertEqual(try Data(contentsOf: url), bytes)
    }

    func testFIFOIsRejectedWithoutWaitingForWriter() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("named-pipe.jsonl")
        XCTAssertEqual(mkfifo(url.path, mode_t(0o600)), 0)
        do {
            _ = try await EvidenceLogReader.read(url: url)
            XCTFail("FIFO must be rejected")
        } catch EvidenceImportError.notRegularFile {
            // No writer exists; returning also demonstrates nonblocking open.
        }
    }

    func testDirectoryAndRemoteURLAreRejected() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        for url in [directory, URL(string: "https://example.invalid/evidence.jsonl")!] {
            do {
                _ = try await EvidenceLogReader.read(url: url)
                XCTFail("Nonregular input must be rejected")
            } catch EvidenceImportError.notRegularFile {
                // A remote URL is rejected locally before any network work.
            }
        }
    }

    func testCancelledReadDoesNotReturnPartialImport() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("cancel.jsonl")
        try encodeLines([sample(id: 1, seconds: 100)]).write(to: url)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await EvidenceLogReader.read(url: url)
        }
        do {
            _ = try await task.value
            XCTFail("Cancelled read must throw rather than publish partial data")
        } catch is CancellationError {
            // Cancellation is propagated to the detached I/O task.
        }
    }

    func testCancelledEmptyReadStillThrowsCancellation() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("empty.jsonl")
        try Data().write(to: url)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await EvidenceLogReader.read(url: url)
        }
        do {
            _ = try await task.value
            XCTFail("An empty input must not suppress cancellation")
        } catch is CancellationError {
            // Cancellation has the same result for empty and nonempty files.
        }
    }

    private func sample(id: Int, seconds: TimeInterval) -> EvidenceRecord {
        let uuid = UUID(uuidString: String(format: "00000000-0000-4000-8000-%012d", id))!
        return EvidenceRecord(id: uuid, timestamp: Date(timeIntervalSince1970: seconds), riskLevel: .low,
                              targetResource: "/synthetic/.env", actionType: "CHANGE", processTree: [])
    }

    private func encodeLines(_ records: [EvidenceRecord]) throws -> Data {
        var bytes = Data()
        for record in records {
            bytes.append(try JSONEncoder().encode(record))
            bytes.append(0x0a)
        }
        return bytes
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("reins-swift-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
