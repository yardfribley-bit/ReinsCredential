import Darwin
import Foundation

public struct LiveEvidenceBatch: Sendable {
    public let records: [EvidenceRecord]
    public let latestCoverage: EvidenceRecord?
    public let rejectedCount: Int
    public let fileAvailable: Bool
    public let hasBacklog: Bool
}

/// One bounded incremental reader per live session. Rotation is identified by
/// device/inode, not filename; a partial final line is held until a newline arrives.
public actor LiveEvidenceReader {
    private var identity: String?
    private var offset: UInt64 = 0
    private var partial = Data()
    private var discardingLongLine = false
    private var rejected = 0
    private var ids = Set<UUID>()
    private var idOrder: [UUID] = []
    private var coverage: EvidenceRecord?
    private let maxBytesPerPoll: Int

    public init(maxBytesPerPoll: Int = 1_048_576) {
        self.maxBytesPerPoll = max(1, min(maxBytesPerPoll, 4_194_304))
    }

    public func poll(url: URL) throws -> LiveEvidenceBatch {
        try Task.checkCancellation()
        guard url.isFileURL else { throw EvidenceImportError.notRegularFile }
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 && errno == ENOENT {
            return LiveEvidenceBatch(records: [], latestCoverage: nil, rejectedCount: rejected,
                                     fileAvailable: false, hasBacklog: false)
        }
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
              info.st_mode & 0o077 == 0, info.st_size >= 0 else { throw EvidenceImportError.notRegularFile }
        let newIdentity = "\(info.st_dev):\(info.st_ino)"
        if identity != newIdentity || UInt64(info.st_size) < offset {
            if !partial.isEmpty || discardingLongLine { rejected += 1 }
            identity = newIdentity
            offset = 0
            partial.removeAll(keepingCapacity: false)
            discardingLongLine = false
            coverage = nil
        }
        try file.seek(toOffset: offset)
        let length = min(maxBytesPerPoll, Int(UInt64(info.st_size) - offset))
        let chunk = try file.read(upToCount: length) ?? Data()
        offset += UInt64(chunk.count)
        var bytes = partial
        bytes.append(chunk)
        partial.removeAll(keepingCapacity: false)
        var records: [EvidenceRecord] = []
        var cursor = bytes.startIndex
        let decoder = JSONDecoder()
        while let newline = bytes[cursor...].firstIndex(of: 0x0a) {
            try Task.checkCancellation()
            let line = bytes[cursor..<newline]
            cursor = bytes.index(after: newline)
            if discardingLongLine { discardingLongLine = false; continue }
            guard line.count <= EvidenceLogReader.maxLineBytes else { rejected += 1; continue }
            if line.allSatisfy({ $0 == 0x0d || $0 == 0x20 || $0 == 0x09 }) { continue }
            guard let record = try? decoder.decode(EvidenceRecord.self, from: Data(line)),
                  ids.insert(record.id).inserted else { rejected += 1; continue }
            idOrder.append(record.id)
            if record.sourceType == "coverage" || record.sourceType == "shutdown_summary" { coverage = record }
            records.append(record)
        }
        if !discardingLongLine {
            let tail = bytes[cursor...]
            if tail.count > EvidenceLogReader.maxLineBytes {
                rejected += 1
                discardingLongLine = true
            } else { partial = Data(tail) }
        }
        if idOrder.count > 6_000 {
            idOrder = Array(idOrder.suffix(4_000))
            ids = Set(idOrder)
        }
        return LiveEvidenceBatch(records: records, latestCoverage: coverage, rejectedCount: rejected,
                                 fileAvailable: true, hasBacklog: offset < UInt64(info.st_size))
    }
}
