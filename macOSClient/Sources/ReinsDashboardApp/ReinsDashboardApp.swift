import SwiftUI

@main
struct ReinsDashboardApp: App {
    @StateObject private var store = DashboardStore()
    @StateObject private var runtime = RuntimeController()
    @State private var didStartSession = false

    var body: some Scene {
        WindowGroup("ReinsCredential") {
            GeometryReader { geometry in
                DashboardView(store: store, runtime: runtime)
                    .frame(width: geometry.size.width, height: geometry.size.height, alignment: .topLeading)
            }
                .frame(minWidth: 1_050, minHeight: 640)
                .onOpenURL { store.importLog(from: $0) }
                .onReceive(runtime.$records) { store.applyLive(records: $0) }
                .onAppear {
                    guard !didStartSession else { return }
                    didStartSession = true
                    #if DEBUG
                    DashboardSmoke.runIfRequested(store: store)
                    #endif
                    // Development previews and synthetic render probes must not
                    // register a login item or start a real process collector.
                    guard !CommandLine.arguments.contains("--smoke-test") else { return }
                    if ProductVerification.stopIfRequested(runtime: runtime) { return }
                    runtime.beginPolling()
                    runtime.refresh()
                    let bundle = Bundle.main.bundleURL
                    let helper = bundle.appendingPathComponent("Contents/MacOS/ReinsRuntime")
                    let collector = bundle.appendingPathComponent("Contents/Helpers/agent-monitor")
                    if bundle.pathExtension == "app",
                       FileManager.default.isExecutableFile(atPath: helper.path),
                       FileManager.default.isExecutableFile(atPath: collector.path) {
                        if CommandLine.arguments.contains("--verify-installation") { runtime.start() }
                        else { runtime.startIfNeeded() }
                    }
                    ProductVerification.runIfRequested(runtime: runtime)
                }
        }
        .defaultSize(width: 1_360, height: 840)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("打开证据日志…") { store.isImporterPresented = true }
                    .keyboardShortcut("o", modifiers: .command)
                    .disabled(store.isLoading)
                Divider()
                Button("查看演示数据") { store.showSamples() }
                    .disabled(store.isLoading)
                Button("返回实时监控") { store.returnToLive(records: runtime.records) }
                    .disabled(store.isLoading || store.mode == .live)
            }
            CommandMenu("监控") {
                Button(runtime.state.canStop ? "停止监控" : "启动监控") {
                    if runtime.state.canStop { runtime.stop() } else { runtime.start() }
                }
                .disabled(runtime.isBusy)
                Button("运行检测自检", action: runtime.runSelfTest)
                    .disabled(runtime.isBusy || !runtime.state.canSelfTest)
                Button("后台运行设置…", action: runtime.openBackgroundSettings)
                Button("允许风险通知…", action: runtime.requestNotifications)
            }
        }
    }
}
