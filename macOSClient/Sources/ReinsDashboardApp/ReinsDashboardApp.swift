import SwiftUI

@main
struct ReinsDashboardApp: App {
    @StateObject private var store = DashboardStore()

    var body: some Scene {
        WindowGroup("ReinsCredential") {
            DashboardView(store: store)
                .frame(minWidth: 1_050, minHeight: 640)
                .onOpenURL { store.importLog(from: $0) }
                .onAppear {
                    #if DEBUG
                    DashboardSmoke.runIfRequested(store: store)
                    #endif
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
            }
        }
    }
}
