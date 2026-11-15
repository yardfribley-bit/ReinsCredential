// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ReinsCredentialDashboard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "EvidenceCore", targets: ["EvidenceCore"]),
        .library(name: "RuntimeCore", targets: ["RuntimeCore"]),
        .executable(name: "ReinsDashboard", targets: ["ReinsDashboardApp"]),
        .executable(name: "ReinsRuntime", targets: ["ReinsRuntime"]),
        .executable(name: "chain-export", targets: ["ChainExport"]),
        .executable(name: "web-dashboard", targets: ["WebDashboardCLI"])
    ],
    targets: [
        .target(name: "EvidenceCore"),
        .target(name: "RuntimeCore"),
        .target(name: "WebDashboard", dependencies: ["EvidenceCore", "RuntimeCore"]),
        .executableTarget(name: "WebDashboardCLI", dependencies: ["WebDashboard"]),
        .executableTarget(name: "ReinsRuntime", dependencies: ["RuntimeCore"]),
        .executableTarget(name: "ChainExport", dependencies: ["EvidenceCore"]),
        .executableTarget(name: "ReinsDashboardApp", dependencies: ["EvidenceCore", "RuntimeCore"], resources: [
            .copy("Resources/en.lproj"),
            .copy("Resources/zh-Hans.lproj"),
            .process("Resources/ReinsCredential-Logo-rounded-512.png")
        ]),
        .testTarget(name: "EvidenceCoreTests", dependencies: ["EvidenceCore"]),
        .testTarget(name: "RuntimeCoreTests", dependencies: ["RuntimeCore"]),
        .testTarget(name: "DashboardAppTests", dependencies: ["EvidenceCore", "RuntimeCore", "ReinsDashboardApp"]),
        .testTarget(name: "WebDashboardTests", dependencies: ["WebDashboard"])
    ]
)
