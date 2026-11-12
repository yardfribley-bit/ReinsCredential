import Darwin
import Foundation

public enum RuntimeFileError: Error, LocalizedError {
    case system(String, Int32)
    case unsafePath(String)
    case invalidConfiguration(String)
    case alreadyRunning

    public var errorDescription: String? {
        switch self {
        case let .system(operation, code): return "\(operation): \(String(cString: strerror(code)))"
        case let .unsafePath(path): return "Unsafe runtime path (expected a private, owned directory or file): \(path)"
        case let .invalidConfiguration(message): return message
        case .alreadyRunning: return "The ReinsCredential runtime is already running."
        }
    }
}

public struct RuntimePaths: Sendable {
    public let baseURL: URL
    public var runtimeDirectory: URL { baseURL.appendingPathComponent("runtime", isDirectory: true) }
    public var configurationURL: URL { baseURL.appendingPathComponent("config.plist") }
    public var evidenceURL: URL { runtimeDirectory.appendingPathComponent("evidence.jsonl") }
    /// agent-egress holds its own exclusive log lock, so it writes a separate file.
    public var egressEvidenceURL: URL { runtimeDirectory.appendingPathComponent("egress.jsonl") }
    public var statusURL: URL { runtimeDirectory.appendingPathComponent("status.plist") }
    public var lockURL: URL { runtimeDirectory.appendingPathComponent("supervisor.lock") }
    public var archiveDirectory: URL { runtimeDirectory.appendingPathComponent("archives", isDirectory: true) }
    public var selfTestDirectory: URL { runtimeDirectory.appendingPathComponent("self-test", isDirectory: true) }

    public init(baseURL: URL? = nil) {
        self.baseURL = (baseURL ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/ReinsCredential", isDirectory: true))
    }

    public func prepare() throws {
        guard baseURL.isFileURL, baseURL.path.hasPrefix("/") else {
            throw RuntimeFileError.unsafePath(baseURL.path)
        }
        try Self.makePrivateDirectory(baseURL)
        try Self.makePrivateDirectory(runtimeDirectory)
        try Self.makePrivateDirectory(archiveDirectory)
        try Self.makePrivateDirectory(selfTestDirectory)
    }

    static func makePrivateDirectory(_ url: URL) throws {
        // Inspect every existing component before Foundation creates intermediates;
        // an owned final directory must never conceal a symlinked managed path.
        var component = URL(fileURLWithPath: "/", isDirectory: true)
        for part in url.pathComponents.dropFirst() {
            component.appendPathComponent(part, isDirectory: true)
            var value = stat()
            if lstat(component.path, &value) == 0 {
                guard value.st_mode & S_IFMT == S_IFDIR else { throw RuntimeFileError.unsafePath(component.path) }
            } else if errno != ENOENT { throw RuntimeFileError.system("Inspect directory", errno) }
        }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try validatePrivateDirectory(url)
    }

    public static func validatePrivateDirectory(_ url: URL) throws {
        var value = stat()
        guard lstat(url.path, &value) == 0 else { throw RuntimeFileError.system("Inspect directory", errno) }
        guard value.st_mode & S_IFMT == S_IFDIR, value.st_uid == geteuid(), value.st_mode & 0o077 == 0 else {
            throw RuntimeFileError.unsafePath(url.path)
        }
    }

    /// Rotate only validated application-owned logs; filenames cannot originate in
    /// incoming evidence. The active file must be closed by the child beforehand.
    public func rotateEvidence(retaining count: Int = 5) throws {
        guard (0...100).contains(count) else { throw RuntimeFileError.invalidConfiguration("Invalid archive retention.") }
        try prepare()
        var value = stat()
        if lstat(evidenceURL.path, &value) == 0 {
            try PrivatePropertyList.validateRegular(value, path: evidenceURL.path)
            if value.st_size > 0 {
                let destination = archiveDirectory.appendingPathComponent("evidence-\(Int64(Date().timeIntervalSince1970 * 1_000_000))-\(UUID().uuidString).jsonl")
                guard rename(evidenceURL.path, destination.path) == 0 else { throw RuntimeFileError.system("Archive evidence", errno) }
            } else if unlink(evidenceURL.path) != 0 { throw RuntimeFileError.system("Remove empty evidence", errno) }
        } else if errno != ENOENT { throw RuntimeFileError.system("Inspect evidence", errno) }
        let archives = try FileManager.default.contentsOfDirectory(at: archiveDirectory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("evidence-") && $0.pathExtension == "jsonl" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
        for archive in archives.dropFirst(count) {
            var info = stat()
            guard lstat(archive.path, &info) == 0 else { throw RuntimeFileError.system("Inspect archive", errno) }
            try PrivatePropertyList.validateRegular(info, path: archive.path)
            guard unlink(archive.path) == 0 else { throw RuntimeFileError.system("Prune archive", errno) }
        }
    }
}

/// This lock is held for its owner's lifetime. PID files are not used as locks and
/// are never used to signal another process.
public final class RuntimeInstanceLock {
    private let descriptor: Int32

    public init(url: URL) throws {
        try RuntimePaths.validatePrivateDirectory(url.deletingLastPathComponent())
        let fd = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw RuntimeFileError.system("Open runtime lock", errno) }
        do {
            var value = stat()
            guard fstat(fd, &value) == 0 else { throw RuntimeFileError.system("Inspect runtime lock", errno) }
            try PrivatePropertyList.validateRegular(value, path: url.path)
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                if errno == EWOULDBLOCK { throw RuntimeFileError.alreadyRunning }
                throw RuntimeFileError.system("Lock runtime", errno)
            }
        } catch { close(fd); throw error }
        descriptor = fd
    }

    deinit { close(descriptor) }
}

enum PrivatePropertyList {
    static func validateRegular(_ value: stat, path: String) throws {
        guard value.st_mode & S_IFMT == S_IFREG, value.st_uid == geteuid(),
              value.st_mode & 0o077 == 0, value.st_nlink == 1 else { throw RuntimeFileError.unsafePath(path) }
    }

    static func read<T: Decodable>(_ type: T.Type, from url: URL, limit: Int) throws -> T {
        try RuntimePaths.validatePrivateDirectory(url.deletingLastPathComponent())
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw RuntimeFileError.system("Open \(url.lastPathComponent)", errno) }
        defer { close(fd) }
        var value = stat()
        guard fstat(fd, &value) == 0 else { throw RuntimeFileError.system("Inspect property list", errno) }
        try validateRegular(value, path: url.path)
        guard value.st_size >= 0, value.st_size <= limit else { throw RuntimeFileError.unsafePath(url.path) }
        var data = Data(count: Int(value.st_size))
        try data.withUnsafeMutableBytes { storage in
            var offset = 0
            while offset < storage.count {
                let result = Darwin.read(fd, storage.baseAddress!.advanced(by: offset), storage.count - offset)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { throw RuntimeFileError.system("Read property list", result == 0 ? EIO : errno) }
                offset += result
            }
        }
        return try PropertyListDecoder().decode(type, from: data)
    }

    static func write<T: Encodable>(_ value: T, to url: URL) throws {
        let directory = url.deletingLastPathComponent()
        try RuntimePaths.validatePrivateDirectory(directory)
        var existing = stat()
        if lstat(url.path, &existing) == 0 { try validateRegular(existing, path: url.path) }
        else if errno != ENOENT { throw RuntimeFileError.system("Inspect destination", errno) }
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(value)
        var template = Array(directory.appendingPathComponent(".reins-write-XXXXXX").path.utf8CString)
        let fd = mkstemp(&template)
        guard fd >= 0 else { throw RuntimeFileError.system("Create property list", errno) }
        let temporary = String(cString: template)
        defer { close(fd); unlink(temporary) }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fchmod(fd, 0o600) == 0 else {
            throw RuntimeFileError.system("Protect property list", errno)
        }
        try data.withUnsafeBytes { storage in
            var offset = 0
            while offset < storage.count {
                let result = Darwin.write(fd, storage.baseAddress!.advanced(by: offset), storage.count - offset)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { throw RuntimeFileError.system("Write property list", result == 0 ? EIO : errno) }
                offset += result
            }
        }
        guard fsync(fd) == 0, rename(temporary, url.path) == 0 else { throw RuntimeFileError.system("Persist property list", errno) }
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryFD >= 0 else { throw RuntimeFileError.system("Open property list directory", errno) }
        defer { close(directoryFD) }
        guard fsync(directoryFD) == 0 else { throw RuntimeFileError.system("Persist property list directory", errno) }
    }
}
