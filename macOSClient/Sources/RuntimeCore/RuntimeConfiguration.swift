import Foundation

public struct RuntimeConfiguration: Codable, Equatable, Sendable {
    public var sensitivePaths: [String]
    public var intervalMilliseconds: Int

    public init(sensitivePaths: [String], intervalMilliseconds: Int = 500) {
        self.sensitivePaths = sensitivePaths
        self.intervalMilliseconds = intervalMilliseconds
    }

    public static func defaults(homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) -> Self {
        Self(sensitivePaths: [".ssh", ".aws"].map { homeDirectory.appendingPathComponent($0).path })
    }

    public func validated() throws -> Self {
        guard (100...60_000).contains(intervalMilliseconds) else {
            throw RuntimeFileError.invalidConfiguration("Sampling interval must be 100–60000 milliseconds.")
        }
        guard !sensitivePaths.isEmpty, sensitivePaths.count <= 128 else {
            throw RuntimeFileError.invalidConfiguration("Choose between 1 and 128 sensitive paths.")
        }
        var result: [String] = []
        for path in sensitivePaths {
            guard path.hasPrefix("/"), !path.utf8.contains(0), path.utf8.count <= 4096 else {
                throw RuntimeFileError.invalidConfiguration("Sensitive paths must be absolute, without NUL bytes, and at most 4096 bytes.")
            }
            let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
            guard normalized != "/" else {
                throw RuntimeFileError.invalidConfiguration("Select specific sensitive locations instead of the entire filesystem.")
            }
            if !result.contains(normalized) { result.append(normalized) }
        }
        return Self(sensitivePaths: result, intervalMilliseconds: intervalMilliseconds)
    }

    public static func load(from url: URL) throws -> Self {
        try PrivatePropertyList.read(Self.self, from: url, limit: 1_048_576).validated()
    }

    public func save(to url: URL) throws {
        try PrivatePropertyList.write(try validated(), to: url)
    }
}

public struct RuntimeStatus: Codable, Equatable, Sendable {
    public enum State: String, Codable, Sendable {
        case starting, running, backoff, stopped, failed
    }
    public var state: State
    public var supervisorPID: Int32
    public var monitorPID: Int32?
    public var monitorStartedAt: Date?
    public var updatedAt: Date
    public var message: String?
    public var sessionID: String

    public init(state: State, supervisorPID: Int32, monitorPID: Int32? = nil, monitorStartedAt: Date? = nil,
                updatedAt: Date = Date(), message: String? = nil, sessionID: String) {
        self.state = state
        self.supervisorPID = supervisorPID
        self.monitorPID = monitorPID
        self.monitorStartedAt = monitorStartedAt
        self.updatedAt = updatedAt
        self.message = message
        self.sessionID = sessionID
    }

    public static func load(from url: URL) throws -> Self {
        try PrivatePropertyList.read(Self.self, from: url, limit: 16_384)
    }

    public func save(to url: URL) throws { try PrivatePropertyList.write(self, to: url) }

    /// This only measures supervisor status freshness. The UI must independently
    /// inspect current backend coverage records before claiming monitoring health.
    public func isFresh(at now: Date = Date(), maximumAge: TimeInterval = 10) -> Bool {
        let age = now.timeIntervalSince(updatedAt)
        return age >= -2 && age <= maximumAge
    }
}
