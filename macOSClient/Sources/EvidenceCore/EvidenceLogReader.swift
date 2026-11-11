import Darwin
import Foundation

public struct EvidenceImport: Sendable {
    public let records: [EvidenceRecord]
    /// Invalid, oversized, or duplicate-ID complete lines, numbered from one.
    public let rejectedLines: [Int]
    public let incompleteTail: Bool
}

public enum EvidenceImportError: LocalizedError {
    case notRegularFile, tooLarge, tooManyRecords
    public var errorDescription: String? {
        switch self {
        case .notRegularFile: return "请选择普通 JSONL 日志文件。"
        case .tooLarge: return "日志超过 32 MiB；请先轮转或选择较小的日志。"
        case .tooManyRecords: return "日志超过 100,000 行；请先轮转日志。"
        }
    }
}

/// Read-only, bounded snapshot import. No daemon launch or network transmission.
public enum EvidenceLogReader {
    public static let maxFileBytes = 32 * 1024 * 1024
    public static let maxLineBytes = 1024 * 1024
    public static let maxLines = 100_000

    public static func read(url: URL) async throws -> EvidenceImport {
        let worker = Task.detached(priority: .userInitiated) { try load(url: url) }
        return try await withTaskCancellationHandler(operation: {
            try await worker.value
        }, onCancel: { worker.cancel() })
    }

    private static func load(url: URL) throws -> EvidenceImport {
        try Task.checkCancellation()
        guard url.isFileURL else { throw EvidenceImportError.notRegularFile }
        // Nonblocking open + fstat rejects a FIFO without hanging the importer.
        let fd = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_CLOEXEC | O_NONBLOCK) } ?? -1
        }
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var status = stat()
        guard fstat(fd, &status) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        guard (status.st_mode & S_IFMT) == S_IFREG else { throw EvidenceImportError.notRegularFile }
        guard status.st_size <= maxFileBytes else { throw EvidenceImportError.tooLarge }
        // Take one snapshot length. An active appender cannot keep this read alive.
        var remaining = Int(status.st_size)
        var data = Data()
        while remaining > 0 {
            try Task.checkCancellation()
            let chunk = try handle.read(upToCount: min(remaining, 64 * 1024)) ?? Data()
            if chunk.isEmpty { break }
            data.append(chunk)
            remaining -= chunk.count
        }
        return try parse(data)
    }

    public static func parse(_ data: Data) throws -> EvidenceImport {
        try Task.checkCancellation()
        guard data.count <= maxFileBytes else { throw EvidenceImportError.tooLarge }
        let lines = data.split(separator: 0x0a, omittingEmptySubsequences: false)
        guard lines.count <= maxLines + 1 else { throw EvidenceImportError.tooManyRecords }
        let incomplete = !data.isEmpty && data.last != 0x0a
        var records: [EvidenceRecord] = []
        var rejected: [Int] = []
        var ids = Set<UUID>()
        let decoder = JSONDecoder()
        for (index, line) in lines.enumerated() {
            try Task.checkCancellation()
            if index == lines.count - 1 { break } // Only committed newline-terminated records.
            guard line.count <= maxLineBytes else { rejected.append(index + 1); continue }
            if line.allSatisfy({ $0 == 0x0d || $0 == 0x20 || $0 == 0x09 }) { continue }
            guard let record = try? decoder.decode(EvidenceRecord.self, from: Data(line)),
                  ids.insert(record.id).inserted else {
                rejected.append(index + 1)
                continue
            }
            records.append(record)
        }
        records.sort { $0.timestamp == $1.timestamp ? $0.id.uuidString < $1.id.uuidString : $0.timestamp > $1.timestamp }
        return EvidenceImport(records: records, rejectedLines: rejected, incompleteTail: incomplete)
    }
}
