// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ReinsCredentialDashboard",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "EvidenceCore", targets: ["EvidenceCore"]),
        .executable(name: "ReinsDashboard", targets: ["ReinsDashboardApp"])
    ],
    targets: [
        .target(name: "EvidenceCore"),
        .executableTarget(name: "ReinsDashboardApp", dependencies: ["EvidenceCore"]),
        .testTarget(name: "EvidenceCoreTests", dependencies: ["EvidenceCore"]),
        .testTarget(name: "DashboardAppTests", dependencies: ["EvidenceCore", "ReinsDashboardApp"])
    ]
)
