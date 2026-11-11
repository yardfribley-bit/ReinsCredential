import Darwin
import Foundation
import XCTest
@testable import EvidenceCore

final class LiveEvidenceReaderTests: XCTestCase {
    private func directory() throws -> URL {
        let url = URL(fileURLWithPath: "/private/tmp/reins-live-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: url) }
        return url
    }
    private func record(_ type: String = "coverage") -> EvidenceRecord {
        EvidenceRecord(timestamp: Date(), riskLevel: .low, targetResource: "", actionType: "OBSERVE",
                       processTree: [], sourceType: type, metrics: ["visible": 42], count: 3, sessionID: "test-session")
    }
    private func line(_ record: EvidenceRecord) throws -> Data { try JSONEncoder().encode(record) + Data([10]) }
    private func write(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    private func append(_ data: Data, to url: URL) throws {
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.seekToEnd(); try handle.write(contentsOf: data)
    }
    func testIncompleteAppendIsHeldUntilNewlineAndThenConsumedOnce() async throws {
        let url = try directory().appendingPathComponent("live.jsonl")
        let event = record(); let bytes = try line(event)
        try write(bytes.dropLast(), to: url)
        let reader = LiveEvidenceReader()
        let first = try await reader.poll(url: url)
        XCTAssertTrue(first.records.isEmpty); XCTAssertEqual(first.rejectedCount, 0)
        try append(Data([10]), to: url)
        let second = try await reader.poll(url: url)
        XCTAssertEqual(second.records, [event]); XCTAssertEqual(second.latestCoverage?.metrics["visible"], 42)
        XCTAssertEqual(second.latestCoverage?.count, 3); XCTAssertEqual(second.latestCoverage?.sessionID, "test-session")
        let third = try await reader.poll(url: url)
        XCTAssertTrue(third.records.isEmpty)
    }
    func testRotationInvalidatesOldHealthAndReadsNewInode() async throws {
        let dir = try directory(); let url = dir.appendingPathComponent("live.jsonl")
        try write(try line(record()), to: url)
        let reader = LiveEvidenceReader(); _ = try await reader.poll(url: url)
        try FileManager.default.moveItem(at: url, to: dir.appendingPathComponent("archive.jsonl"))
        try write(Data(), to: url)
        let empty = try await reader.poll(url: url)
        XCTAssertNil(empty.latestCoverage)
        let next = record(); try append(try line(next), to: url)
        let batch = try await reader.poll(url: url)
        XCTAssertEqual(batch.records, [next])
    }
    func testBoundedChunksCatchUpWithoutLosingRecords() async throws {
        let url = try directory().appendingPathComponent("live.jsonl")
        let values = (0..<3).map { _ in record() }
        try write(try values.reduce(into: Data()) { $0.append(try line($1)) }, to: url)
        let reader = LiveEvidenceReader(maxBytesPerPoll: 73)
        var found: [EvidenceRecord] = []; var backlog = true; var iterations = 0
        while backlog && iterations < 100 {
            let batch = try await reader.poll(url: url)
            found += batch.records; backlog = batch.hasBacklog; iterations += 1
        }
        XCTAssertEqual(found, values); XCTAssertGreaterThan(iterations, 1); XCTAssertFalse(backlog)
    }
    func testMalformedAndDuplicateRowsDoNotHideGoodRows() async throws {
        let url = try directory().appendingPathComponent("live.jsonl"); let value = record()
        try write(try Data("bad\n".utf8) + line(value) + line(value), to: url)
        let batch = try await LiveEvidenceReader().poll(url: url)
        XCTAssertEqual(batch.records, [value]); XCTAssertEqual(batch.rejectedCount, 2)
    }
    func testOversizedLineRecoversAtNextNewline() async throws {
        let url = try directory().appendingPathComponent("live.jsonl"); let value = record()
        try write(try Data(repeating: 65, count: EvidenceLogReader.maxLineBytes + 1) + Data([10]) + line(value), to: url)
        let reader = LiveEvidenceReader(maxBytesPerPoll: 524_288)
        var found: [EvidenceRecord] = []; var rejected = 0
        for _ in 0..<3 { let batch = try await reader.poll(url: url); found += batch.records; rejected = batch.rejectedCount }
        XCTAssertEqual(found, [value]); XCTAssertEqual(rejected, 1)
    }
    func testUnsafeFilesRefusedWithoutBlocking() async throws {
        let dir = try directory(); let file = dir.appendingPathComponent("file")
        try write(Data(), to: file)
        let link = dir.appendingPathComponent("symlink"); try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        let fifo = dir.appendingPathComponent("fifo"); XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        let hardlink = dir.appendingPathComponent("hardlink"); try FileManager.default.linkItem(at: file, to: hardlink)
        for url in [link, fifo, file, hardlink] {
            do { _ = try await LiveEvidenceReader().poll(url: url); XCTFail("Unsafe file accepted") } catch { }
        }
    }
    func testMissingFileDoesNotReportOldHealth() async throws {
        let url = try directory().appendingPathComponent("live.jsonl")
        try write(try line(record()), to: url); let reader = LiveEvidenceReader()
        _ = try await reader.poll(url: url); try FileManager.default.removeItem(at: url)
        let absent = try await reader.poll(url: url)
        XCTAssertFalse(absent.fileAvailable); XCTAssertNil(absent.latestCoverage)
    }
}
