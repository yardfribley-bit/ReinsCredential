import Darwin
import EvidenceCore
import Foundation
import RuntimeCore

public struct WebDashboardSources: Sendable, Equatable {
    public var evidenceFiles: [URL]
    /// Read-only. Nil skips the runtime plist. `loadEffective` is never called;
    /// that helper can write an upgraded configuration.
    public var configurationURL: URL?
    public var statusURL: URL?
    /// True when the files are the installed runtime logs, not an explicit `--log`.
    public var presentsLiveRuntime: Bool

    public init(evidenceFiles: [URL], configurationURL: URL? = nil, statusURL: URL? = nil,
                presentsLiveRuntime: Bool = false) {
        self.evidenceFiles = evidenceFiles
        self.configurationURL = configurationURL
        self.statusURL = statusURL
        self.presentsLiveRuntime = presentsLiveRuntime
    }

    public static func runtimeDefaults() -> WebDashboardSources {
        let paths = RuntimePaths()
        return WebDashboardSources(
            evidenceFiles: [paths.evidenceURL, paths.egressEvidenceURL],
            configurationURL: paths.configurationURL,
            statusURL: paths.statusURL,
            presentsLiveRuntime: true)
    }
}

struct WebDashboardSnapshot {
    var records: [EvidenceRecord]
    var rejectedCount: Int
    var incompleteTail: Bool
    var errors: [String]
    var truncated: Bool
    var watchedDirectories: Int?
    var statusLine: String?
    var live: Bool
    var sourceNames: [String]

    static let recordCap = 2_000
}

enum WebDashboardStore {
    static func load(_ sources: WebDashboardSources) -> WebDashboardSnapshot {
        var records: [EvidenceRecord] = []
        var seen = Set<UUID>()
        var rejected = 0
        var tail = false
        var errors: [String] = []
        for url in sources.evidenceFiles {
            let name = url.lastPathComponent
            do {
                guard let data = try readPrivateLog(url) else { continue }
                let parsed = try EvidenceLogReader.parse(data)
                rejected += parsed.rejectedLines.count
                tail = tail || parsed.incompleteTail
                for record in parsed.records {
                    if seen.insert(record.id).inserted { records.append(record) }
                    else { rejected += 1 }
                }
            } catch WebLogReadError.notPrivate {
                errors.append("已拒绝读取 \(name)：文件必须是当前用户拥有的、单一链接、mode 0600 的普通文件。")
            } catch WebLogReadError.tooLarge {
                errors.append("已拒绝读取 \(name)：日志超过 32 MiB。")
            } catch let WebLogReadError.io(code) {
                errors.append("无法读取 \(name)（\(code)）。")
            } catch {
                errors.append("无法读取 \(name)。")
            }
        }
        records.sort { lhs, rhs in
            if lhs.timestamp != rhs.timestamp { return lhs.timestamp > rhs.timestamp }
            return lhs.id.uuidString < rhs.id.uuidString
        }
        let truncated = records.count > WebDashboardSnapshot.recordCap
        if truncated { records = Array(records.prefix(WebDashboardSnapshot.recordCap)) }
        return WebDashboardSnapshot(
            records: records,
            rejectedCount: rejected,
            incompleteTail: tail,
            errors: errors,
            truncated: truncated,
            watchedDirectories: watchedCount(sources.configurationURL),
            statusLine: statusLine(sources.statusURL),
            live: sources.presentsLiveRuntime,
            sourceNames: sources.evidenceFiles.map(\.lastPathComponent))
    }

    /// Mode 0600, owned, single-link regular file. The bytes are not read when
    /// that check fails, so a loose file cannot reach the page.
    private static func readPrivateLog(_ url: URL) throws -> Data? {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw WebLogReadError.io(errno)
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw WebLogReadError.io(errno) }
        let mode = info.st_mode
        guard (mode & S_IFMT) == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
              (mode & 0o777) == 0o600 else {
            throw WebLogReadError.notPrivate
        }
        guard info.st_size >= 0, info.st_size <= EvidenceLogReader.maxFileBytes else {
            throw WebLogReadError.tooLarge
        }
        var data = Data()
        data.reserveCapacity(Int(info.st_size))
        var remaining = Int(info.st_size)
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while remaining > 0 {
            let count = Darwin.read(fd, &buffer, min(buffer.count, remaining))
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { throw WebLogReadError.io(count == 0 ? EIO : errno) }
            data.append(buffer, count: count)
            remaining -= count
        }
        return data
    }

    private static func watchedCount(_ url: URL?) -> Int? {
        guard let url else { return nil }
        return (try? RuntimeConfiguration.load(from: url))?.sensitivePaths.count
    }

    private static func statusLine(_ url: URL?) -> String? {
        guard let url, let status = try? RuntimeStatus.load(from: url) else { return nil }
        if !status.isFresh() { return "后台服务状态已过期，不能确认采集器仍在工作。" }
        switch status.state {
        case .starting: return "正在启动采集"
        case .running: return "监控中"
        case .backoff, .failed: return "采集服务异常"
        case .stopped: return "监控已停止"
        }
    }
}

private enum WebLogReadError: Error {
    case notPrivate
    case tooLarge
    case io(Int32)
}
