import Darwin
import Dispatch
import Foundation

public struct WebDashboardInvocation: Equatable {
    public enum Mode: Equatable { case serve, stop }
    public var mode: Mode
    public var port: UInt16
    public var logs: [String]
}

public enum WebDashboardCommand {
    public static let usageText = """
    usage: web-dashboard [--port 8790] [--log PATH]...
           web-dashboard stop [--port 8790]

    Serves \(WebDashboardAccess.defaultURL) on 127.0.0.1 only.
    Reads evidence JSONL and does not start collection.
    Stop with Ctrl-C, or: web-dashboard stop
    Port 8787 is reserved for ReinsAARM.
    """

    public static func parse(_ args: [String]) throws -> WebDashboardInvocation {
        var mode = WebDashboardInvocation.Mode.serve
        var port = WebDashboardAccess.defaultPort
        var logs: [String] = []
        var index = 0
        while index < args.count {
            let arg = args[index]
            index += 1
            switch arg {
            case "stop":
                mode = .stop
            case "--port":
                guard index < args.count else { throw WebDashboardError.usage("missing --port") }
                let raw = args[index]
                index += 1
                if raw == String(WebDashboardAccess.reservedForeignPort) {
                    throw WebDashboardError.usage("port 8787 is reserved for ReinsAARM; use \(WebDashboardAccess.defaultURL)")
                }
                guard let value = UInt16(raw), value != 0 else {
                    throw WebDashboardError.usage("invalid --port")
                }
                port = value
            case "--log":
                guard index < args.count else { throw WebDashboardError.usage("missing --log path") }
                logs.append(args[index])
                index += 1
            default:
                throw WebDashboardError.usage("unrecognized argument")
            }
        }
        return WebDashboardInvocation(mode: mode, port: port, logs: logs)
    }

    public static func main() -> Never {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.contains("-h") || args.contains("--help") {
            FileHandle.standardOutput.write(Data(usageText + "\n").utf8)
            exit(0)
        }
        do {
            let invocation = try parse(args)
            switch invocation.mode {
            case .stop:
                try stop(port: invocation.port)
                exit(0)
            case .serve:
                try serve(invocation)
            }
        } catch let error as WebDashboardError {
            var message = "web-dashboard: \(error)\n"
            if case .usage = error { message += usageText + "\n" }
            FileHandle.standardError.write(Data(message.utf8))
            switch error {
            case .usage: exit(2)
            default: exit(1)
            }
        } catch {
            FileHandle.standardError.write(Data("web-dashboard: \(error)\n".utf8))
            exit(1)
        }
    }

    private static func serve(_ invocation: WebDashboardInvocation) throws -> Never {
        let sources = invocation.logs.isEmpty
            ? WebDashboardSources.runtimeDefaults()
            : WebDashboardSources(evidenceFiles: invocation.logs.map { URL(fileURLWithPath: $0) },
                                  presentsLiveRuntime: false)
        let server = WebDashboardServer(port: invocation.port, sources: sources)
        server.onStop = { exit(0) }
        try server.start()
        let banner = """
        ReinsCredential 网页控制台
        http://127.0.0.1:\(server.boundPort)/
        只读证据日志，不启动采集。Ctrl-C 结束，或另开终端运行 web-dashboard stop --port \(server.boundPort)。

        """
        FileHandle.standardOutput.write(Data(banner.utf8))
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        let signals = [SIGINT, SIGTERM].map { sig -> DispatchSourceSignal in
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler { server.stop() }
            source.resume()
            return source
        }
        withExtendedLifetime(signals) { dispatchMain() }
    }

    private static func stop(port: UInt16) throws {
        do {
            let response = try WebDashboardHTTP.exchange(port: port, method: "POST", path: "/stop",
                                                        hostHeader: "127.0.0.1:\(port)")
            guard response.status == 200 else { throw WebDashboardError.usage("停止失败，HTTP \(response.status)") }
        } catch let error as WebDashboardError {
            if case .socket = error { throw WebDashboardError.notRunning(port) }
            throw error
        }
        FileHandle.standardOutput.write(Data("已停止 http://127.0.0.1:\(port)/\n".utf8))
    }
}
