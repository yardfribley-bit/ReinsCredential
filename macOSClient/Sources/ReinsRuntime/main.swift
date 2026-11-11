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
    var holdSeconds: Int = 6

    init(_ arguments: [String]) throws {
        var index = 0
        while index < arguments.count {
            let flag = arguments[index]
            guard index + 1 < arguments.count else { throw RuntimeFileError.invalidConfiguration("Missing value for \(flag)") }
            let value = arguments[index + 1]
            switch flag {
            case "--data-root", "--monitor", "--probe":
                guard value.hasPrefix("/"), !value.utf8.contains(0) else { throw RuntimeFileError.invalidConfiguration("\(flag) requires an absolute path.") }
                // standardizedFileURL rewrites an existing /private/tmp to the
                // /tmp symlink on macOS, defeating the managed-path check.
                let url = URL(fileURLWithPath: value)
                if flag == "--data-root" { dataRoot = url }
                else if flag == "--monitor" { monitor = url }
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
        guard probe == nil || (dataRoot == nil && monitor == nil) else {
            throw RuntimeFileError.invalidConfiguration("Probe mode cannot run the supervisor.")
        }
    }
}

private func bundledMonitor() throws -> URL {
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
    return contents.appendingPathComponent("Helpers/agent-monitor")
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
        signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        term.setEventHandler { stop.request() }; interrupt.setEventHandler { stop.request() }
        term.resume(); interrupt.resume()
        defer { term.cancel(); interrupt.cancel() }
        var session = UUID().uuidString
        var failures: [Date] = []
        var configuration: RuntimeConfiguration?
        var child: OwnedChild?
        var monitorStarted: Date?
        func publish(_ state: RuntimeStatus.State, _ message: String? = nil) throws {
            try RuntimeStatus(state: state, supervisorPID: getpid(), monitorPID: child?.isRunning == true ? child?.processIdentifier : nil,
                              monitorStartedAt: monitorStarted, message: message, sessionID: session).save(to: paths.statusURL)
        }
        defer { if let running = child { running.stop() } }
        try publish(.starting)
        while !stop.isRequested {
            do {
                configuration = try RuntimeConfiguration.load(from: paths.configurationURL)
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
            try paths.rotateEvidence()
            session = UUID().uuidString
            let next: OwnedChild
            monitorStarted = Date()
            do {
                next = try OwnedChild(executable: monitor,
                    arguments: ["--no-default-sensitive", "--log", paths.evidenceURL.path, "--interval-ms", String(active.intervalMilliseconds),
                                "--max-log-bytes", "16777216"] + (active.sensitivePaths + [paths.selfTestDirectory.path]).flatMap { ["--sensitive", $0] },
                    workingDirectory: paths.runtimeDirectory)
                child = next
            }
            catch {
                child = nil
                failures.append(Date())
                try publish(.backoff, "Cannot start monitor: \(error.localizedDescription)")
                let until = Date().addingTimeInterval(min(30, pow(2, Double(failures.count))))
                while !stop.isRequested && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
                continue
            }
            try publish(.running)
            var reload = false
            var lastUpdate = Date()
            while next.isRunning && !stop.isRequested {
                if Date().timeIntervalSince(lastUpdate) >= 2 {
                    do {
                        let updated = try RuntimeConfiguration.load(from: paths.configurationURL)
                        if updated != active { reload = true; break }
                        try publish(.running)
                    } catch {
                        next.stop()
                        try publish(.failed, "Configuration error: \(error.localizedDescription)")
                        reload = true
                        break
                    }
                    lastUpdate = Date()
                }
                Thread.sleep(forTimeInterval: 0.1)
            }
            if stop.isRequested { next.stop(); break }
            if reload { next.stop(); child = nil; continue }
            let exitCode = next.terminationStatus ?? -1
            child = nil
            if exitCode == 3 && next.exitedNormally {
                try publish(.starting, "Rotating the bounded evidence log.")
                continue
            }
            failures.append(Date())
            try publish(.backoff, "Monitor exited with status \(exitCode). A new session will be attempted.")
            let until = Date().addingTimeInterval(min(30, pow(2, Double(failures.count))))
            while !stop.isRequested && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
        }
        child = nil
        try publish(.stopped)
    }
}

do {
    let options = try Options(Array(CommandLine.arguments.dropFirst()))
    if let file = options.probe { try holdSyntheticProbe(file, seconds: options.holdSeconds) }
    else { try runSupervisor(options) }
} catch {
    fputs("ReinsRuntime: \(error.localizedDescription)\n", stderr)
    exit(1)
}
