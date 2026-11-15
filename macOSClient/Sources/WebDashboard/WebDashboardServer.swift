import Darwin
import Dispatch
import Foundation

public final class WebDashboardServer: @unchecked Sendable {
    public let boundHost = WebDashboardAccess.loopbackHost
    public private(set) var boundPort: UInt16 = 0
    /// Runs after the listening socket is closed. The CLI uses this to exit.
    public var onStop: (() -> Void)?

    private let requestedPort: UInt16
    private let sources: WebDashboardSources
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "reins.web-dashboard")
    private var source: DispatchSourceRead?
    private var stopped = false

    public init(port: UInt16, sources: WebDashboardSources) {
        self.requestedPort = port
        self.sources = sources
    }

    public func start() throws {
        signal(SIGPIPE, SIG_IGN)
        lock.lock()
        let already = source != nil || stopped
        lock.unlock()
        if already { throw WebDashboardError.usage("网页控制台已经启动或已经停止") }
        let listened = try Self.listenLoopback(port: requestedPort)
        boundPort = listened.port
        let source = DispatchSource.makeReadSource(fileDescriptor: listened.fd, queue: queue)
        source.setEventHandler { [weak self] in
            self?.acceptPending(on: listened.fd)
        }
        source.setCancelHandler { Darwin.close(listened.fd) }
        lock.lock()
        self.source = source
        lock.unlock()
        source.resume()
    }

    public func stop() {
        lock.lock()
        if stopped {
            lock.unlock()
            return
        }
        stopped = true
        let source = self.source
        self.source = nil
        let callback = onStop
        lock.unlock()
        source?.cancel()
        callback?()
    }

    private func shouldStop() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    private func acceptPending(on fd: Int32) {
        while !shouldStop() {
            var peer = sockaddr_in()
            var peerLength = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &peerLength) { lengthPtr in
                withUnsafeMutablePointer(to: &peer) { peerPtr in
                    peerPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                        Darwin.accept(fd, address, lengthPtr)
                    }
                }
            }
            if client < 0 {
                if errno == EINTR { continue }
                return
            }
            handle(client: client, peer: peer)
        }
    }

    private func handle(client: Int32, peer: sockaddr_in) {
        defer { Darwin.close(client) }
        _ = fcntl(client, F_SETFD, FD_CLOEXEC)
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        let timeoutLength = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeoutLength)
        _ = setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeoutLength)
        let peerHost = Self.ipv4(peer.sin_addr)
        let bytes = Self.readHeaders(client)
        guard let request = WebRequestParser.parse(bytes) else {
            Self.writeAll(client, Self.http(status: 400, reason: "Bad Request", type: "text/plain; charset=utf-8", body: "无法解析请求\n"))
            return
        }
        guard WebDashboardAccess.allows(peerAddress: peerHost, hostHeader: request.host) else {
            Self.writeAll(client, Self.http(status: 403, reason: "Forbidden", type: "text/plain; charset=utf-8", body: "仅允许本机回环访问\n"))
            return
        }
        let decision = route(request)
        Self.writeAll(client, Self.http(status: decision.status, reason: decision.reason, type: decision.type, body: decision.body))
        if decision.stopAfter {
            queue.async { [weak self] in self?.stop() }
        }
    }

    private func route(_ request: WebRequest) -> WebDecision {
        switch (request.method, request.path) {
        case ("GET", "/"):
            let snapshot = WebDashboardStore.load(sources)
            let body = WebDashboardPage.html(snapshot: snapshot, query: WebBoardQuery.parse(request.query), port: boundPort)
            return WebDecision(status: 200, reason: "OK", type: "text/html; charset=utf-8", body: body, stopAfter: false)
        case ("GET", "/api/snapshot"):
            let body = WebDashboardPage.snapshotJSON(WebDashboardStore.load(sources))
            return WebDecision(status: 200, reason: "OK", type: "application/json; charset=utf-8", body: body, stopAfter: false)
        case ("POST", "/stop"):
            return WebDecision(status: 200, reason: "OK", type: "text/plain; charset=utf-8", body: "已停止\n", stopAfter: true)
        case ("GET", _):
            return WebDecision(status: 404, reason: "Not Found", type: "text/plain; charset=utf-8", body: "未找到\n", stopAfter: false)
        default:
            return WebDecision(status: 405, reason: "Method Not Allowed", type: "text/plain; charset=utf-8", body: "方法不被允许\n", stopAfter: false)
        }
    }

    private static func listenLoopback(port: UInt16) throws -> (fd: Int32, port: UInt16) {
        try WebDashboardAccess.validateRequestedHost(WebDashboardAccess.loopbackHost)
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw WebDashboardError.socket("socket", errno) }
        var handedOff = false
        defer { if !handedOff { Darwin.close(fd) } }
        if fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 { throw WebDashboardError.socket("fcntl", errno) }
        var reuse: Int32 = 1
        if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) < 0 {
            throw WebDashboardError.socket("setsockopt", errno)
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, WebDashboardAccess.loopbackHost, &address.sin_addr) == 1 else {
            throw WebDashboardError.refusedBindHost
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound != 0 { throw WebDashboardError.socket("bind", errno) }
        if Darwin.listen(fd, 16) != 0 { throw WebDashboardError.socket("listen", errno) }
        let observed = try endpoint(of: fd)
        guard observed.host == WebDashboardAccess.loopbackHost else { throw WebDashboardError.refusedBindHost }
        let flags = fcntl(fd, F_GETFL)
        if flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            throw WebDashboardError.socket("fcntl", errno)
        }
        handedOff = true
        return (fd, observed.port)
    }

    private static func endpoint(of fd: Int32) throws -> (host: String, port: UInt16) {
        var storage = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &length) { lengthPtr in
            withUnsafeMutablePointer(to: &storage) { storagePtr in
                storagePtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { address in
                    getsockname(fd, address, lengthPtr)
                }
            }
        }
        guard result == 0 else { throw WebDashboardError.socket("getsockname", errno) }
        return (ipv4(storage.sin_addr), UInt16(bigEndian: storage.sin_port))
    }

    private static func ipv4(_ address: in_addr) -> String {
        var copy = address
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &copy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else { return "" }
        return String(cString: buffer)
    }

    private static func readHeaders(_ fd: Int32) -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 2048)
        let marker = Data([13, 10, 13, 10])
        while data.count < 8192 {
            let count = Darwin.read(fd, &buffer, min(buffer.count, 8192 - data.count))
            if count < 0 && errno == EINTR { continue }
            if count <= 0 { break }
            data.append(buffer, count: count)
            if data.range(of: marker) != nil { break }
        }
        return data
    }

    private static func writeAll(_ fd: Int32, _ data: Data) {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let count = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return }
                sent += count
            }
        }
    }

    private static func http(status: Int, reason: String, type: String, body: String) -> Data {
        let payload = Data(body.utf8)
        let header = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: \(type)\r\nContent-Length: \(payload.count)\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'self'\r\n\r\n"
        var data = Data(header.utf8)
        data.append(payload)
        return data
    }
}

private struct WebDecision {
    var status: Int
    var reason: String
    var type: String
    var body: String
    var stopAfter: Bool
}

private struct WebRequest {
    var method: String
    var path: String
    var query: String
    var host: String?
}

private enum WebRequestParser {
    static func parse(_ data: Data) -> WebRequest? {
        guard let text = String(data: data, encoding: .utf8), let marker = text.range(of: "\r\n\r\n") else { return nil }
        let lines = text[..<marker.lowerBound].components(separatedBy: "\r\n")
        guard let first = lines.first, !first.isEmpty, lines.count <= 64 else { return nil }
        let parts = first.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0])
        let target = String(parts[1])
        guard target.hasPrefix("/"), !target.contains(".."), target.utf8.count < 2048 else { return nil }
        let path: String
        let query: String
        if let mark = target.firstIndex(of: "?") {
            path = String(target[..<mark])
            query = String(target[target.index(after: mark)...])
        } else {
            path = target
            query = ""
        }
        var host: String?
        var hosts = 0
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name == "host" {
                hosts += 1
                host = String(value)
            }
        }
        if hosts != 1 { host = nil }
        return WebRequest(method: method, path: path, query: query, host: host)
    }
}

public enum WebDashboardHTTP {
    public struct Response: Equatable {
        public var status: Int
        public var body: String
    }

    /// Connects to 127.0.0.1 only. `hostHeader` is what the request claims; tests
    /// use that to prove a non-loopback Host is refused.
    public static func exchange(port: UInt16, method: String, path: String, hostHeader: String?,
                                timeoutMilliseconds: Int = 3000) throws -> Response {
        if let hostHeader, hostHeader.contains("\r") || hostHeader.contains("\n") {
            throw WebDashboardError.usage("invalid host")
        }
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw WebDashboardError.socket("socket", errno) }
        defer { Darwin.close(fd) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw WebDashboardError.socket("fcntl", errno)
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, WebDashboardAccess.loopbackHost, &address.sin_addr) == 1 else {
            throw WebDashboardError.refusedBindHost
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connected != 0 {
            if errno != EINPROGRESS { throw WebDashboardError.socket("connect", errno) }
            var pollSet = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let waited = poll(&pollSet, nfds_t(1), Int32(timeoutMilliseconds))
            if waited <= 0 { throw WebDashboardError.socket("connect", waited == 0 ? ETIMEDOUT : errno) }
            var error: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)
            if error != 0 { throw WebDashboardError.socket("connect", error) }
        }
        guard fcntl(fd, F_SETFL, flags) >= 0 else { throw WebDashboardError.socket("fcntl", errno) }
        var timeout = timeval(tv_sec: timeoutMilliseconds / 1000, tv_usec: suseconds_t((timeoutMilliseconds % 1000) * 1000))
        let timeoutLength = socklen_t(MemoryLayout<timeval>.size)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, timeoutLength)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, timeoutLength)
        var header = "\(method) \(path) HTTP/1.1\r\nConnection: close\r\nContent-Length: 0\r\n"
        if let hostHeader { header += "Host: \(hostHeader)\r\n" }
        header += "\r\n"
        try writeAll(fd, Data(header.utf8))
        let data = try readAll(fd, limit: 8_000_000)
        guard let text = String(data: data, encoding: .utf8), let marker = text.range(of: "\r\n\r\n") else {
            throw WebDashboardError.malformedResponse
        }
        let statusLine = text[..<marker.lowerBound].split(separator: "\r\n", maxSplits: 1, omittingEmptySubsequences: false).first ?? ""
        let fields = statusLine.split(separator: " ")
        guard fields.count >= 2, let status = Int(fields[1]) else { throw WebDashboardError.malformedResponse }
        return Response(status: status, body: String(text[marker.upperBound...]))
    }

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let count = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { throw WebDashboardError.socket("write", errno) }
                sent += count
            }
        }
    }

    private static func readAll(_ fd: Int32, limit: Int) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while data.count < limit {
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 { throw WebDashboardError.socket("read", errno) }
            if count == 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}
