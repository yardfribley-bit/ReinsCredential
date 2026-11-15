import Foundation

/// Loopback gate for the local evidence page. The socket is bound to
/// 127.0.0.1, and each request is still refused unless the TCP peer and the
/// Host header are both loopback. There is no URL token.
public enum WebDashboardAccess {
    public static let loopbackHost = "127.0.0.1"
    public static let defaultPort: UInt16 = 8790
    /// ReinsAARM's console. This process does not bind it.
    public static let reservedForeignPort: UInt16 = 8787
    public static var defaultURL: String { "http://\(loopbackHost):\(defaultPort)/" }

    public static func validateRequestedHost(_ host: String) throws {
        guard host == loopbackHost else { throw WebDashboardError.refusedBindHost }
    }

    public static func isLoopbackPeer(_ address: String) -> Bool {
        address == "127.0.0.1" || address == "::1"
    }

    /// Hostname from a Host header, without the port. `[::1]:8790` stays `::1`.
    public static func hostName(fromHostHeader header: String) -> String {
        let value = header.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("[") {
            guard let end = value.firstIndex(of: "]") else { return "" }
            return String(value[value.index(after: value.startIndex)..<end]).lowercased()
        }
        if let colon = value.lastIndex(of: ":"),
           !value[value.index(after: colon)...].isEmpty,
           value[value.index(after: colon)...].allSatisfy(\.isNumber) {
            return String(value[..<colon]).lowercased()
        }
        return value.lowercased()
    }

    public static func allows(peerAddress: String, hostHeader: String?) -> Bool {
        guard isLoopbackPeer(peerAddress) else { return false }
        guard let hostHeader else { return false }
        switch hostName(fromHostHeader: hostHeader) {
        case "127.0.0.1", "localhost", "::1": return true
        default: return false
        }
    }
}

public enum WebDashboardError: Error, CustomStringConvertible, Equatable {
    case refusedBindHost
    case socket(String, Int32)
    case malformedResponse
    case notRunning(UInt16)
    case usage(String)

    public var description: String {
        switch self {
        case .refusedBindHost:
            return "网页控制台只绑定 127.0.0.1"
        case let .socket(operation, code):
            return "\(operation) 失败（\(code)）"
        case .malformedResponse:
            return "网页控制台没有返回完整响应"
        case let .notRunning(port):
            return "没有正在运行的网页控制台：http://127.0.0.1:\(port)/"
        case let .usage(message):
            return message
        }
    }
}
