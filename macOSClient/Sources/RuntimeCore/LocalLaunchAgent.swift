import Darwin
import Foundation

/// Explicit local-build service installation. Developer ID builds use
/// SMAppService instead. No root privileges, shell, or global security changes.
public struct LocalLaunchAgent: Sendable {
    public static let label = "io.github.yardfribley-bit.ReinsCredential.runtime.local"
    public let directory: URL
    public let helper: URL
    public var plistURL: URL { directory.appendingPathComponent(Self.label + ".plist") }
    public var isInstalled: Bool { FileManager.default.fileExists(atPath: plistURL.path) }

    public init(helper: URL, directory: URL? = nil) {
        self.helper = helper
        self.directory = directory ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    }

    public func installAndStart() throws {
        try writeConfiguration()
        let domain = "gui/\(geteuid())"
        if try command(["print", "\(domain)/\(Self.label)"]) == 0 { return }
        let result = try command(["bootstrap", domain, plistURL.path])
        guard result == 0 else {
            throw RuntimeFileError.invalidConfiguration("本机后台服务启动失败（launchctl \(result)）。请检查系统登录项设置和 App 安装位置。")
        }
    }

    public func stopAndRemove() throws {
        guard isInstalled else { return }
        try validateExistingConfiguration()
        let domain = "gui/\(geteuid())/\(Self.label)"
        if try command(["print", domain]) == 0 {
            let result = try command(["bootout", domain])
            guard result == 0 else { throw RuntimeFileError.invalidConfiguration("停止本机后台服务失败（launchctl \(result)）。") }
        }
        try FileManager.default.removeItem(at: plistURL)
    }

    /// Also used in tests; this writes a plist but does not launch anything.
    public func writeConfiguration() throws {
        var executable = stat()
        guard helper.isFileURL, lstat(helper.path, &executable) == 0,
              executable.st_mode & S_IFMT == S_IFREG, access(helper.path, X_OK) == 0 else {
            throw RuntimeFileError.unsafePath(helper.path)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        var parent = stat()
        guard lstat(directory.path, &parent) == 0, parent.st_mode & S_IFMT == S_IFDIR,
              parent.st_uid == geteuid(), parent.st_mode & 0o022 == 0 else { throw RuntimeFileError.unsafePath(directory.path) }
        if isInstalled { try validateExistingConfiguration() }
        else {
            var existing = stat()
            guard lstat(plistURL.path, &existing) != 0, errno == ENOENT else { throw RuntimeFileError.unsafePath(plistURL.path) }
        }
        let values: [String: Any] = ["Label": Self.label, "ProgramArguments": [helper.path],
            "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 30, "ExitTimeOut": 15,
            "ProcessType": "Background", "ReinsCredentialManaged": true]
        let data = try PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
        // The temp file is private before it has content; publish by rename.
        var template = Array(directory.appendingPathComponent(".reins-agent-XXXXXX").path.utf8CString)
        let fd = mkstemp(&template)
        guard fd >= 0 else { throw RuntimeFileError.system("Create local LaunchAgent", errno) }
        let temporary = String(cString: template)
        defer { close(fd); unlink(temporary) }
        guard fchmod(fd, 0o600) == 0 else { throw RuntimeFileError.system("Protect local LaunchAgent", errno) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let result = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if result < 0 && errno == EINTR { continue }
                guard result > 0 else { throw RuntimeFileError.system("Write local LaunchAgent", result == 0 ? EIO : errno) }
                offset += result
            }
        }
        guard fsync(fd) == 0, rename(temporary, plistURL.path) == 0 else { throw RuntimeFileError.system("Persist local LaunchAgent", errno) }
    }

    private func validateExistingConfiguration() throws {
        let fd = open(plistURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RuntimeFileError.system("Inspect local LaunchAgent", errno) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var file = stat()
        guard fstat(fd, &file) == 0 else { throw RuntimeFileError.system("Inspect local LaunchAgent", errno) }
        try PrivatePropertyList.validateRegular(file, path: plistURL.path)
        guard file.st_size >= 0, file.st_size < 16_384,
              let data = try handle.read(upToCount: 16_384),
              let value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              value["Label"] as? String == Self.label,
              value["ReinsCredentialManaged"] as? Bool == true,
              value["ProgramArguments"] as? [String] == [helper.path] else {
            throw RuntimeFileError.unsafePath(plistURL.path)
        }
    }

    private func command(_ arguments: [String]) throws -> Int32 {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        child.arguments = arguments
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        try child.run(); child.waitUntilExit()
        return child.terminationStatus
    }
}
