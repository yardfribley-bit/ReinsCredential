import Darwin
import Foundation
import MachO
import RuntimeCore

private final class StopRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var requested = false
    func request() { lock.lock(); requested = true; lock.unlock() }
    var isRequested: Bool { lock.lock(); defer { lock.unlock() }; return requested }
}

private struct Options {
    var dataRoot: URL?
    var monitor: URL?
    var probe: URL?
    var canaryAgent: URL?
    var holdSeconds: Int = 6

    init(_ arguments: [String]) throws {
        var index = 0
        while index < arguments.count {
            let flag = arguments[index]
            guard index + 1 < arguments.count else { throw RuntimeFileError.invalidConfiguration("Missing value for \(flag)") }
            let value = arguments[index + 1]
            switch flag {
            case "--data-root", "--monitor", "--probe", "--canary-agent":
                guard value.hasPrefix("/"), !value.utf8.contains(0) else { throw RuntimeFileError.invalidConfiguration("\(flag) requires an absolute path.") }
                // standardizedFileURL rewrites an existing /private/tmp to the
                // /tmp symlink on macOS, defeating the managed-path check.
                let url = URL(fileURLWithPath: value)
                if flag == "--data-root" { dataRoot = url }
                else if flag == "--monitor" { monitor = url }
                else if flag == "--canary-agent" { canaryAgent = url }
                else { probe = url }
            case "--hold-seconds":
                guard let seconds = Int(value), (1...30).contains(seconds) else { throw RuntimeFileError.invalidConfiguration("Probe duration must be 1–30 seconds.") }
                holdSeconds = seconds
            default: throw RuntimeFileError.invalidConfiguration("Unknown option: \(flag)")
            }
            index += 2
        }
        guard (dataRoot == nil) == (monitor == nil) else {
            throw RuntimeFileError.invalidConfiguration("Development overrides require both --data-root and --monitor.")
        }
        guard probe == nil || (dataRoot == nil && monitor == nil && canaryAgent == nil) else {
            throw RuntimeFileError.invalidConfiguration("Probe mode cannot run the supervisor.")
        }
        guard canaryAgent == nil || (dataRoot == nil && monitor == nil && probe == nil) else {
            throw RuntimeFileError.invalidConfiguration("Canary agent mode cannot run the supervisor.")
        }
    }
}

private func bundledMonitor() throws -> URL {
    return try bundledHelper("agent-monitor")
}

private func bundledHelper(_ name: String) throws -> URL {
    // Works both when launchd starts Contents/MacOS/ReinsRuntime and when the app
    // launches its bundled executable directly. No shell or PATH lookup is used.
    // launchd may supply a relative argv[0] for BundleProgram. Resolve the loaded
    // Mach-O image, never the caller-controlled argument string or working dir.
    var length: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &length)
    guard length > 0, length < 1_048_576 else { throw RuntimeFileError.invalidConfiguration("Cannot resolve runtime executable.") }
    var buffer = [CChar](repeating: 0, count: Int(length))
    guard _NSGetExecutablePath(&buffer, &length) == 0 else { throw RuntimeFileError.invalidConfiguration("Cannot resolve runtime executable.") }
    let executable = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
    let contents = executable.deletingLastPathComponent().deletingLastPathComponent()
    guard contents.lastPathComponent == "Contents" else {
        throw RuntimeFileError.invalidConfiguration("Run the installed app, or supply explicit --data-root and --monitor development paths.")
    }
    return contents.appendingPathComponent("Helpers/\(name)")
}

private func helperNextToMonitor(_ monitor: URL, name: String) throws -> URL {
    let url = monitor.deletingLastPathComponent().appendingPathComponent(name)
    try validateExecutable(url)
    return url
}

/// agent-egress fingerprints regular files of 16 bytes–1 MiB, at most 32 paths.
private func fingerprintableFiles(from roots: [URL], limit: Int = 32, minimumBytes: off_t = 16, maximumBytes: off_t = 1_048_576) -> [URL] {
    var files: [URL] = []
    var queue = roots
    var visited = 0
    while !queue.isEmpty, files.count < limit, visited < 1024 {
        let url = queue.removeFirst()
        visited += 1
        var info = stat()
        guard lstat(url.path, &info) == 0 else { continue }
        let type = info.st_mode & S_IFMT
        if type == S_IFREG {
            if info.st_size >= minimumBytes, info.st_size <= maximumBytes {
                let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
                if fd >= 0 {
                    var opened = stat()
                    if fstat(fd, &opened) == 0, opened.st_mode & S_IFMT == S_IFREG,
                       opened.st_size >= minimumBytes, opened.st_size <= maximumBytes {
                        files.append(url)
                    }
                    close(fd)
                }
            }
            continue
        }
        guard type == S_IFDIR else { continue }
        guard let children = try? FileManager.default.contentsOfDirectory(
            at: url,
            includingPropertiesForKeys: nil,
            options: [.skipsPackageDescendants]
        ) else { continue }
        queue.append(contentsOf: children)
    }
    return files
}

private func validateExecutable(_ url: URL) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw RuntimeFileError.system("Inspect monitor executable", errno) }
    guard info.st_mode & S_IFMT == S_IFREG, access(url.path, X_OK) == 0 else {
        throw RuntimeFileError.unsafePath(url.path)
    }
}

private func holdSyntheticProbe(_ url: URL, seconds: Int) throws {
    let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw RuntimeFileError.system("Open synthetic probe file", errno) }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == geteuid(), info.st_size <= 4096 else { throw RuntimeFileError.unsafePath(url.path) }
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    guard listener >= 0 else { throw RuntimeFileError.system("Create loopback listener", errno) }
    defer { close(listener) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = 0
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bound = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0, listen(listener, 1) == 0 else { throw RuntimeFileError.system("Bind loopback listener", errno) }
    var size = socklen_t(MemoryLayout<sockaddr_in>.size)
    guard withUnsafeMutablePointer(to: &address, { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) }
    }) == 0 else { throw RuntimeFileError.system("Inspect loopback listener", errno) }
    let client = socket(AF_INET, SOCK_STREAM, 0)
    guard client >= 0 else { throw RuntimeFileError.system("Create loopback client", errno) }
    defer { close(client) }
    let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, size) }
    }
    guard connected == 0 else { throw RuntimeFileError.system("Connect loopback probe", errno) }
    let accepted = accept(listener, nil, nil)
    guard accepted >= 0 else { throw RuntimeFileError.system("Accept loopback probe", errno) }
    defer { close(accepted) }
    print("PROBE_READY \(getpid())")
    fflush(stdout)
    // Deliberately no content read or send: this checks descriptor and peer
    // observations, and must never be described as an exfiltration self-test.
    Thread.sleep(forTimeInterval: Double(seconds))
}


private func runtimeExecutable() throws -> URL {
    var length: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &length)
    guard length > 0, length < 1_048_576 else { throw RuntimeFileError.invalidConfiguration("Cannot resolve runtime executable.") }
    var buffer = [CChar](repeating: 0, count: Int(length))
    guard _NSGetExecutablePath(&buffer, &length) == 0 else { throw RuntimeFileError.invalidConfiguration("Cannot resolve runtime executable.") }
    return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath()
}

private func ensureCanaryFile(_ paths: RuntimePaths) throws -> URL {
    let url = paths.selfTestDirectory.appendingPathComponent("canary.txt")
    var info = stat()
    if lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size >= 16, info.st_size <= 1_048_576 {
        return url
    }
    let payload = "REINS_EGRESS_CANARY_0123456789abcdef\n"
    try payload.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    return url
}

private func runCanaryAgent(_ url: URL) throws {
    let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw RuntimeFileError.system("Open canary file", errno) }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == geteuid(), info.st_size >= 16, info.st_size <= 1_048_576 else {
        throw RuntimeFileError.unsafePath(url.path)
    }
    var body = Data(count: Int(info.st_size))
    let readCount = body.withUnsafeMutableBytes { raw in
        Darwin.read(fd, raw.baseAddress, raw.count)
    }
    guard readCount == info.st_size else { throw RuntimeFileError.system("Read canary file", errno) }
    defer {
        body.resetBytes(in: 0..<body.count)
    }
    let listener = socket(AF_INET, SOCK_STREAM, 0)
    guard listener >= 0 else { throw RuntimeFileError.system("Create canary sink", errno) }
    defer { close(listener) }
    var yes: Int32 = 1
    _ = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = 0
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bound = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0, listen(listener, 1) == 0 else { throw RuntimeFileError.system("Bind canary sink", errno) }
    var size = socklen_t(MemoryLayout<sockaddr_in>.size)
    guard withUnsafeMutablePointer(to: &address, { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) }
    }) == 0 else { throw RuntimeFileError.system("Inspect canary sink", errno) }
    let sinkPort = Int(UInt16(bigEndian: address.sin_port))
    let acceptedReady = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        let accepted = accept(listener, nil, nil)
        acceptedReady.signal()
        guard accepted >= 0 else { return }
        defer { close(accepted) }
        var buffer = [UInt8](repeating: 0, count: 4096)
        _ = Darwin.read(accepted, &buffer, buffer.count)
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        _ = ok.withCString { Darwin.write(accepted, $0, strlen($0)) }
    }
    let proxyValue = ProcessInfo.processInfo.environment["HTTP_PROXY"]
        ?? ProcessInfo.processInfo.environment["http_proxy"]
        ?? ""
    guard let proxyURL = URL(string: proxyValue), let host = proxyURL.host, let proxyPort = proxyURL.port else {
        throw RuntimeFileError.invalidConfiguration("Canary agent requires HTTP_PROXY from agent-egress.")
    }
    let client = socket(AF_INET, SOCK_STREAM, 0)
    guard client >= 0 else { throw RuntimeFileError.system("Create canary proxy client", errno) }
    defer { close(client) }
    var proxyAddress = sockaddr_in()
    proxyAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    proxyAddress.sin_family = sa_family_t(AF_INET)
    proxyAddress.sin_port = in_port_t(UInt16(proxyPort).bigEndian)
    proxyAddress.sin_addr = in_addr(s_addr: inet_addr(host))
    let connected = withUnsafePointer(to: &proxyAddress) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { throw RuntimeFileError.system("Connect canary through proxy", errno) }
    var header = "POST http://127.0.0.1:\(sinkPort)/upload HTTP/1.1\r\nHost: 127.0.0.1:\(sinkPort)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
    try header.withUTF8 { raw in
        var sent = 0
        while sent < raw.count {
            let n = Darwin.write(client, raw.baseAddress! + sent, raw.count - sent)
            if n <= 0 { throw RuntimeFileError.system("Write canary request", errno) }
            sent += n
        }
    }
    header = ""
    try body.withUnsafeBytes { raw in
        var sent = 0
        let total = raw.count
        while sent < total {
            let n = Darwin.write(client, raw.baseAddress! + sent, total - sent)
            if n <= 0 { throw RuntimeFileError.system("Write canary body", errno) }
            sent += n
        }
    }
    var reply = [UInt8](repeating: 0, count: 256)
    _ = Darwin.read(client, &reply, reply.count)
    fputs("canary_agent_upload_done\n", stderr)
    // Stay alive so agent-egress keeps the launched process tree.
    while true { Thread.sleep(forTimeInterval: 3600) }
}

private func runSupervisor(_ options: Options) throws {
    let paths = RuntimePaths(baseURL: options.dataRoot)
    try paths.prepare()
    let instance = try RuntimeInstanceLock(url: paths.lockURL)
    try withExtendedLifetime(instance) {
        let monitor = try options.monitor ?? bundledMonitor()
        try validateExecutable(monitor)
        if !FileManager.default.fileExists(atPath: paths.configurationURL.path) {
            try RuntimeConfiguration.defaults().save(to: paths.configurationURL)
        }
        let stop = StopRequest()
        var blocked = sigset_t()
        sigemptyset(&blocked)
        sigaddset(&blocked, SIGTERM)
        sigaddset(&blocked, SIGINT)
        pthread_sigmask(SIG_BLOCK, &blocked, nil)
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        term.setEventHandler { stop.request() }; interrupt.setEventHandler { stop.request() }
        term.resume(); interrupt.resume()
        defer { term.cancel(); interrupt.cancel() }
        var session = UUID().uuidString
        var failures: [Date] = []
        var configuration: RuntimeConfiguration?
        var monitorChild: OwnedChild?
        var egressChild: OwnedChild?
        var monitorStarted: Date?
        func stopChildren() {
            monitorChild?.stop()
            egressChild?.stop()
            monitorChild = nil
            egressChild = nil
        }
        func publish(_ state: RuntimeStatus.State, _ message: String? = nil) throws {
            try RuntimeStatus(state: state, supervisorPID: getpid(), monitorPID: monitorChild?.isRunning == true ? monitorChild?.processIdentifier : nil,
                              monitorStartedAt: monitorStarted, message: message, sessionID: session).save(to: paths.statusURL)
        }
        defer { stopChildren() }
        try publish(.starting)
        while !stop.isRequested {
            do {
                configuration = try RuntimeConfiguration.loadEffective(from: paths.configurationURL)
            } catch {
                try publish(.failed, "Configuration error: \(error.localizedDescription)")
                let until = Date().addingTimeInterval(2)
                while !stop.isRequested && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
                continue
            }
            failures.removeAll { Date().timeIntervalSince($0) > 300 }
            if failures.count >= 5 {
                // Remain alive to expose an actionable failure instead of causing
                // launchd KeepAlive to repeatedly respawn a crashing monitor.
                try publish(.failed, "Monitor stopped repeatedly. Retrying after the five-minute failure window; inspect permissions and configuration.")
                Thread.sleep(forTimeInterval: 1)
                continue
            }
            guard let active = configuration else { continue }
            session = UUID().uuidString
            monitorStarted = Date()
            do {
                let canary = try ensureCanaryFile(paths)
                let files = fingerprintableFiles(from: (active.sensitivePaths + [paths.selfTestDirectory.path]).map { URL(fileURLWithPath: $0) })
                guard !files.isEmpty else {
                    throw RuntimeFileError.invalidConfiguration("No fingerprintable sensitive files (16 bytes–1 MiB) were found.")
                }
                let egress = try helperNextToMonitor(monitor, name: "agent-egress")
                let runtime = try runtimeExecutable()
                monitorChild = try OwnedChild(executable: monitor,
                    arguments: ["--no-default-sensitive", "--log", paths.evidenceURL.path, "--interval-ms", String(active.intervalMilliseconds),
                                "--max-log-bytes", "16777216"] + (active.sensitivePaths + [paths.selfTestDirectory.path]).flatMap { ["--sensitive", $0] },
                    workingDirectory: paths.runtimeDirectory,
                    standardError: paths.runtimeDirectory.appendingPathComponent("monitor.err"))
                egressChild = try OwnedChild(executable: egress,
                    arguments: ["--log", paths.egressEvidenceURL.path, "--watch-live", "--port-file", paths.runtimeDirectory.appendingPathComponent("egress.port").path] +
                        files.flatMap { ["--sensitive-file", $0.path] } +
                        ["--launch", "--", runtime.path, "--canary-agent", canary.path],
                    workingDirectory: paths.runtimeDirectory,
                    standardError: paths.runtimeDirectory.appendingPathComponent("egress.err"))
            } catch {
                stopChildren()
                failures.append(Date())
                try publish(.backoff, "Cannot start monitor or egress proxy: \(error.localizedDescription)")
                let until = Date().addingTimeInterval(min(30, pow(2, Double(failures.count))))
                while !stop.isRequested && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
                continue
            }
            try publish(.running)
            var reload = false
            var lastUpdate = Date()
            while monitorChild?.isRunning == true && egressChild?.isRunning == true && !stop.isRequested {
                if Date().timeIntervalSince(lastUpdate) >= 2 {
                    do {
                        let updated = try RuntimeConfiguration.load(from: paths.configurationURL)
                        if updated != active { reload = true; break }
                        try publish(.running)
                    } catch {
                        stopChildren()
                        try publish(.failed, "Configuration error: \(error.localizedDescription)")
                        reload = true
                        break
                    }
                    lastUpdate = Date()
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if stop.isRequested { stopChildren(); break }
            if reload { stopChildren(); continue }
            let monitorCode = monitorChild?.terminationStatus ?? -1
            let monitorNormal = monitorChild?.exitedNormally ?? false
            let egressExited = egressChild?.isRunning != true
            let egressCode = egressChild?.terminationStatus ?? -1
            stopChildren()
            if monitorCode == 3 && monitorNormal {
                try paths.rotateEvidence()
                try publish(.starting, "Rotating the bounded evidence log.")
                continue
            }
            failures.append(Date())
            if egressExited && monitorCode == -1 {
                try publish(.backoff, "Egress proxy exited with status \(egressCode). A new session will be attempted.")
            } else {
                try publish(.backoff, "Monitor exited with status \(monitorCode). A new session will be attempted.")
            }
            let until = Date().addingTimeInterval(min(30, pow(2, Double(failures.count))))
            while !stop.isRequested && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
        }
        try publish(.stopped)
    }
}

do {
    let options = try Options(Array(CommandLine.arguments.dropFirst()))
    if let file = options.canaryAgent { try runCanaryAgent(file) }
    else if let file = options.probe { try holdSyntheticProbe(file, seconds: options.holdSeconds) }
    else { try runSupervisor(options) }
} catch {
    fputs("ReinsRuntime: \(error.localizedDescription)\n", stderr)
    exit(1)
}
