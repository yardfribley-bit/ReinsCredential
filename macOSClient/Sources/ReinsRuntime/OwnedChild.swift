import Darwin
import Foundation
import RuntimeCore

/// A supervisor-owned child, accessed only on the supervisor's control thread.
/// Unlike Foundation Process, no independent callback reaps this PID between a
/// liveness check and signal delivery. A child that exits stays a zombie (and its
/// PID stays reserved) until this object calls waitpid.
final class OwnedChild {
    let processIdentifier: pid_t
    private(set) var terminationStatus: Int32?
    private(set) var exitedNormally = false

    init(executable: URL, arguments: [String], workingDirectory: URL) throws {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        var result = posix_spawn_file_actions_init(&actions)
        guard result == 0 else { throw RuntimeFileError.system("Initialize child file actions", result) }
        defer { posix_spawn_file_actions_destroy(&actions) }
        result = posix_spawnattr_init(&attributes)
        guard result == 0 else { throw RuntimeFileError.system("Initialize child attributes", result) }
        defer { posix_spawnattr_destroy(&attributes) }
        func check(_ code: Int32, _ operation: String) throws {
            guard code == 0 else { throw RuntimeFileError.system(operation, code) }
        }
        try check(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0), "Redirect child input")
        try check(posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0), "Redirect child output")
        try check(posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0), "Redirect child errors")
        if #available(macOS 26, *) {
            try check(posix_spawn_file_actions_addchdir(&actions, workingDirectory.path), "Set child directory")
        } else {
            try check(posix_spawn_file_actions_addchdir_np(&actions, workingDirectory.path), "Set child directory")
        }
        var defaults = sigset_t()
        var mask = sigset_t()
        sigemptyset(&defaults); sigaddset(&defaults, SIGTERM); sigaddset(&defaults, SIGINT)
        sigemptyset(&mask)
        try check(posix_spawnattr_setsigdefault(&attributes, &defaults), "Reset child signal handlers")
        try check(posix_spawnattr_setsigmask(&attributes, &mask), "Reset child signal mask")
        try check(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT)), "Set child spawn flags")
        let values = [executable.path] + arguments
        let strings = values.map { strdup($0) }
        defer { for pointer in strings { free(pointer) } }
        guard strings.allSatisfy({ $0 != nil }) else { throw RuntimeFileError.system("Allocate child arguments", ENOMEM) }
        var argv = strings + [nil]
        // The collector needs no API credentials or dynamic-loader overrides
        // inherited from an interactive shell or login session.
        let allowedEnvironment = ["HOME", "TMPDIR", "LANG", "LC_ALL"]
        var childEnvironment = ProcessInfo.processInfo.environment.filter { allowedEnvironment.contains($0.key) }
        childEnvironment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        let environment = childEnvironment.map { strdup("\($0.key)=\($0.value)") }
        defer { for pointer in environment { free(pointer) } }
        guard environment.allSatisfy({ $0 != nil }) else { throw RuntimeFileError.system("Allocate child environment", ENOMEM) }
        var envp = environment + [nil]
        var childPID: pid_t = 0
        result = argv.withUnsafeMutableBufferPointer { argumentBuffer in
            envp.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(&childPID, executable.path, &actions, &attributes, argumentBuffer.baseAddress!, environmentBuffer.baseAddress!)
            }
        }
        guard result == 0 else { throw RuntimeFileError.system("Start monitor", result) }
        processIdentifier = childPID
    }

    var isRunning: Bool {
        if terminationStatus != nil { return false }
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(processIdentifier, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result == 0 { return true }
        if result == processIdentifier {
            exitedNormally = status & 0x7f == 0
            terminationStatus = exitedNormally ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        } else {
            // Nobody else should reap our child. If an embedding runtime does,
            // disown it and never send another signal to this PID.
            terminationStatus = -1
        }
        return false
    }

    func stop(gracePeriod: TimeInterval = 8) {
        guard isRunning else { return }
        kill(processIdentifier, SIGTERM)
        let deadline = Date().addingTimeInterval(gracePeriod)
        while isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        guard isRunning else { return }
        kill(processIdentifier, SIGKILL)
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(processIdentifier, &status, 0) } while result < 0 && errno == EINTR
        exitedNormally = result == processIdentifier && status & 0x7f == 0
        terminationStatus = result == processIdentifier ? (exitedNormally ? (status >> 8) & 0xff : 128 + (status & 0x7f)) : -1
    }

    deinit { stop() }
}
