import Darwin
import EvidenceCore
import Foundation
import XCTest
@testable import WebDashboard

final class WebDashboardTests: XCTestCase {
    private let secret = "super-secret-value"
    private let cookie = "raw-cookie-value"
    private let assignmentToken = "assignment-token-value"
    private let bearer = "raw-token-value"
    private let synthetic = "SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef"

    func testLoopbackBareURLShowsEmptyLiveDashboard() throws {
        let missing = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("reins-web-missing-\(UUID().uuidString)/evidence.jsonl")
        let server = try start(WebDashboardSources(evidenceFiles: [missing], presentsLiveRuntime: true))
        let response = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                    hostHeader: "127.0.0.1:\(server.boundPort)")
        XCTAssertEqual(response.status, 200)
        for heading in ["ReinsCredential", "运行时安全", "本机 Agent 监控", "所属 Agent", "证据链", "事件", "等待本机检测记录"] {
            XCTAssertTrue(response.body.contains(heading), heading)
        }
        XCTAssertTrue(response.body.contains("http-equiv=\"refresh\""))
        XCTAssertTrue(response.body.contains("127.0.0.1"))
        XCTAssertFalse(response.body.contains("0.0.0.0"))
    }

    func testEmptyPrivateLogShowsSnapshotEmptyState() throws {
        let url = try writeLog(name: "evidence.jsonl", bytes: Data(), mode: 0o600)
        let server = try start(WebDashboardSources(evidenceFiles: [url], presentsLiveRuntime: false))
        let response = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                    hostHeader: "127.0.0.1")
        XCTAssertEqual(response.status, 200)
        XCTAssertTrue(response.body.contains("此快照没有证据记录"))
        XCTAssertTrue(response.body.contains("证据链"))
        XCTAssertTrue(response.body.contains("选择一条证据链"))
    }

    func testSeededEvidenceIsShownAndSecretsAreRedacted() throws {
        let url = try writeLog(name: "evidence.jsonl", bytes: try seededLine(), mode: 0o600)
        let parsed = try EvidenceLogReader.parse(try seededLine())
        XCTAssertEqual(parsed.records.count, 1)
        XCTAssertEqual(parsed.records[0].owningAgentName, "Codex")
        XCTAssertEqual(parsed.records[0].uploadVerdict, "not_visible")

        let server = try start(WebDashboardSources(evidenceFiles: [url], presentsLiveRuntime: false))
        let page = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                hostHeader: "localhost")
        XCTAssertEqual(page.status, 200)
        assertDashboard(page.body)
        XCTAssertTrue(page.body.contains("Codex"))
        XCTAssertTrue(page.body.contains("/synthetic/demo.env"))
        XCTAssertTrue(page.body.contains("看不到"))
        XCTAssertTrue(page.body.contains("所属 Agent"))
        XCTAssertTrue(page.body.contains("出口结论"))
        XCTAssertTrue(page.body.contains("[已省略]"))
        assertSecretsAbsent(page.body)

        let events = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/?view=events",
                                                  hostHeader: "127.0.0.1")
        XCTAssertEqual(events.status, 200)
        XCTAssertTrue(events.body.contains("证据详情"))
        XCTAssertTrue(events.body.contains("敏感文件访问的出口结论"))
        assertSecretsAbsent(events.body)

        let snapshot = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/api/snapshot",
                                                    hostHeader: "127.0.0.1")
        XCTAssertEqual(snapshot.status, 200)
        XCTAssertTrue(snapshot.body.contains("raw_secret_bytes"))
        XCTAssertTrue(snapshot.body.contains("omitted"))
        assertSecretsAbsent(snapshot.body)
    }

    func testWorldReadableLogIsNotRendered() throws {
        let url = try writeLog(name: "evidence.jsonl", bytes: try seededLine(), mode: 0o644)
        let server = try start(WebDashboardSources(evidenceFiles: [url], presentsLiveRuntime: false))
        let response = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                    hostHeader: "127.0.0.1")
        XCTAssertEqual(response.status, 200)
        XCTAssertTrue(response.body.contains("已拒绝读取"))
        assertSecretsAbsent(response.body)
        XCTAssertFalse(response.body.contains("Codex"))
    }

    func testNonLoopbackHostAndMissingHostAreDenied() throws {
        let server = try start(WebDashboardSources(evidenceFiles: [], presentsLiveRuntime: true))
        let forwarded = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                     hostHeader: "192.0.2.10")
        XCTAssertEqual(forwarded.status, 403)
        XCTAssertTrue(forwarded.body.contains("仅允许本机回环访问"))
        XCTAssertFalse(forwarded.body.contains("192.0.2.10"))
        XCTAssertFalse(forwarded.body.contains("证据链"))

        let missing = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                   hostHeader: nil)
        XCTAssertEqual(missing.status, 403)

        let page = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                hostHeader: "127.0.0.1")
        XCTAssertEqual(page.status, 200)
    }

    func testAccessPolicyRejectsNonLoopbackPeers() {
        XCTAssertTrue(WebDashboardAccess.allows(peerAddress: "127.0.0.1", hostHeader: "127.0.0.1:8790"))
        XCTAssertTrue(WebDashboardAccess.allows(peerAddress: "127.0.0.1", hostHeader: "localhost"))
        XCTAssertTrue(WebDashboardAccess.allows(peerAddress: "::1", hostHeader: "[::1]:8790"))
        XCTAssertFalse(WebDashboardAccess.allows(peerAddress: "10.0.0.8", hostHeader: "127.0.0.1"))
        XCTAssertFalse(WebDashboardAccess.allows(peerAddress: "0.0.0.0", hostHeader: "127.0.0.1"))
        XCTAssertFalse(WebDashboardAccess.allows(peerAddress: "127.0.0.1", hostHeader: "10.0.0.8"))
        XCTAssertFalse(WebDashboardAccess.allows(peerAddress: "127.0.0.1", hostHeader: "127.0.0.1.example"))
        XCTAssertFalse(WebDashboardAccess.allows(peerAddress: "127.0.0.1", hostHeader: nil))
        XCTAssertThrowsError(try WebDashboardAccess.validateRequestedHost("0.0.0.0"))
        XCTAssertThrowsError(try WebDashboardAccess.validateRequestedHost("::"))
        XCTAssertNoThrow(try WebDashboardAccess.validateRequestedHost("127.0.0.1"))
    }

    func testServerBindsOnlyLoopback() throws {
        let server = try start(WebDashboardSources(evidenceFiles: [], presentsLiveRuntime: true))
        XCTAssertEqual(server.boundHost, "127.0.0.1")
        XCTAssertNotEqual(server.boundPort, 0)
        let output = try netstat()
        let port = String(server.boundPort)
        let loopback = output.contains("127.0.0.1.\(port)") || output.contains("127.0.0.1:\(port)")
        XCTAssertTrue(loopback, output)
        XCTAssertFalse(output.contains("0.0.0.0.\(port)") || output.contains("0.0.0.0:\(port)"), output)
        XCTAssertFalse(output.contains("*.\(port)") || output.contains("*:\(port)"), output)
        for address in nonLoopbackIPv4() {
            XCTAssertFalse(tcpConnects(host: address, port: server.boundPort), "listener answered on \(address)")
        }
    }

    func testStopDoesNotAcceptOtherMethodsAndThenCloses() throws {
        let server = try start(WebDashboardSources(evidenceFiles: [], presentsLiveRuntime: true))
        let wrong = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/stop",
                                                 hostHeader: "127.0.0.1")
        XCTAssertEqual(wrong.status, 405)
        let stillUp = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                   hostHeader: "127.0.0.1")
        XCTAssertEqual(stillUp.status, 200)
        let deniedStop = try WebDashboardHTTP.exchange(port: server.boundPort, method: "POST", path: "/stop",
                                                      hostHeader: "10.1.2.3")
        XCTAssertEqual(deniedStop.status, 403)
        let stopped = try WebDashboardHTTP.exchange(port: server.boundPort, method: "POST", path: "/stop",
                                                   hostHeader: "127.0.0.1:\(server.boundPort)")
        XCTAssertEqual(stopped.status, 200)
        var refused = false
        for _ in 0..<30 {
            do {
                _ = try WebDashboardHTTP.exchange(port: server.boundPort, method: "GET", path: "/",
                                                 hostHeader: "127.0.0.1", timeoutMilliseconds: 300)
                Thread.sleep(forTimeInterval: 0.05)
            } catch {
                refused = true
                break
            }
        }
        XCTAssertTrue(refused)
    }

    func testCommandLineRejectsTheOtherConsolePort() throws {
        let serve = try WebDashboardCommand.parse([])
        XCTAssertEqual(serve.mode, .serve)
        XCTAssertEqual(serve.port, 8790)
        XCTAssertTrue(serve.logs.isEmpty)
        let custom = try WebDashboardCommand.parse(["--port", "8791", "--log", "a.jsonl", "--log", "b.jsonl"])
        XCTAssertEqual(custom.port, 8791)
        XCTAssertEqual(custom.logs, ["a.jsonl", "b.jsonl"])
        XCTAssertEqual(try WebDashboardCommand.parse(["stop", "--port", "8792"]).mode, .stop)
        XCTAssertThrowsError(try WebDashboardCommand.parse(["--port", "8787"]))
        XCTAssertThrowsError(try WebDashboardCommand.parse(["--bind", "0.0.0.0"]))
        XCTAssertEqual(WebDashboardAccess.defaultURL, "http://127.0.0.1:8790/")
    }

    func testDisplayRedactsSecretsTheDashboardMustNotRender() {
        let raw = "password=\(secret) cookie=\(cookie) token=\(assignmentToken) Authorization: Bearer \(bearer) \(synthetic)"
        let cleaned = WebDashboardDisplay.redact(raw)
        XCTAssertTrue(cleaned.contains("[已省略]"))
        XCTAssertFalse(cleaned.contains(secret))
        XCTAssertFalse(cleaned.contains(cookie))
        XCTAssertFalse(cleaned.contains(assignmentToken))
        XCTAssertFalse(cleaned.contains(bearer))
        XCTAssertFalse(cleaned.contains(synthetic))
    }

    private func assertDashboard(_ body: String) {
        for heading in ["ReinsCredential", "运行时安全", "证据链", "事件"] {
            XCTAssertTrue(body.contains(heading), heading)
        }
    }

    private func assertSecretsAbsent(_ body: String, file: StaticString = #filePath, line: UInt = #line) {
        for secret in [secret, cookie, assignmentToken, bearer, synthetic] {
            XCTAssertFalse(body.contains(secret), secret, file: file, line: line)
        }
    }

    private func start(_ sources: WebDashboardSources) throws -> WebDashboardServer {
        let server = WebDashboardServer(port: 0, sources: sources)
        try server.start()
        addTeardownBlock { server.stop() }
        return server
    }

    private func writeLog(name: String, bytes: Data, mode: Int) throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("reins-web-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent(name)
        try bytes.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    private func seededLine() throws -> Data {
        let fixture: [String: Any] = [
            "schema_version": 2,
            "event_id": "11111111-1111-4111-8111-111111111111",
            "timestamp": 1_735_689_600_123_456,
            "timestamp_unit": "unix_microseconds",
            "risk_level": "High",
            "target_resource": "/synthetic/demo.env",
            "type": "sensitive_access_closed",
            "attribution": "synthetic",
            "summary": "password=\(secret) cookie=\(cookie) \(synthetic)",
            "detail": "token=\(assignmentToken) Authorization: Bearer \(bearer)",
            "destination": "203.0.113.10:443",
            "upload_verdict": "not_visible",
            "transfer_outcome": "socket_body_not_visible",
            "evidence_basis": "fd_observed",
            "actor_process": [
                "process": [
                    "identity": ["pid": 42, "start_seconds": 1_700_000_000, "start_microseconds": 1] as [String: Any],
                    "ppid": 1,
                    "name": "codex",
                    "executable": "/synthetic/Codex.app/Contents/MacOS/codex"
                ] as [String: Any],
                "ppid_tree": [] as [Any],
                "chain_complete": true,
                "chain_status": "observed_chain_to_launchd",
                "classification": "agent_candidate",
                "owning_agent": ["name": "Codex", "bundle": "Codex.app"]
            ] as [String: Any]
        ]
        var data = try JSONSerialization.data(withJSONObject: fixture, options: [.sortedKeys])
        data.append(0x0A)
        return data
    }

    private func netstat() throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        process.arguments = ["-an", "-p", "tcp"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    private func nonLoopbackIPv4() -> [String] {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [] }
        defer { freeifaddrs(pointer) }
        var found: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            cursor = item.pointee.ifa_next
            let flags = item.pointee.ifa_flags
            guard (flags & UInt32(IFF_UP)) != 0, (flags & UInt32(IFF_LOOPBACK)) == 0 else { continue }
            guard let address = item.pointee.ifa_addr, address.pointee.sa_family == sa_family_t(AF_INET) else { continue }
            let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer -> String? in
                var addr = pointer.pointee.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return nil }
                return String(cString: buffer)
            }
            guard let ip, ip != "0.0.0.0", !ip.hasPrefix("169.254.") else { continue }
            found.append(ip)
        }
        return found
    }

    private func tcpConnects(host: String, port: UInt16) -> Bool {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else { return false }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { return false }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connected == 0 { return true }
        if errno != EINPROGRESS { return false }
        var pollSet = pollfd()
        pollSet.fd = fd
        pollSet.events = Int16(POLLOUT)
        pollSet.revents = 0
        let waited = poll(&pollSet, nfds_t(1), 300)
        if waited <= 0 { return false }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
        return error == 0
    }
}
