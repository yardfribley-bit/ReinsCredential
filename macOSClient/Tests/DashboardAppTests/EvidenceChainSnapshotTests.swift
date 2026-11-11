import Foundation
import XCTest
@testable import EvidenceCore
@testable import ReinsDashboardApp

@MainActor
final class EvidenceChainSnapshotTests: XCTestCase {
    func testSyntheticDemoRendersGroupedChainsAndOneCardPerVerdict() throws {
        let files = try EvidenceChainSnapshot.renderDemo()
        for name in EvidenceChainSnapshot.fileNames {
            XCTAssertNotNil(files[name], name)
        }
        for (name, data) in files where name.hasSuffix(".png") {
            XCTAssertEqual(Array(data.prefix(8)), [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], name)
        }
        let markdown = String(decoding: try XCTUnwrap(files["evidence-chains.md"]), as: UTF8.self)
        for label in ["出口结论：已上传", "出口结论：已尝试未成功", "出口结论：未发现", "出口结论：看不到"] {
            XCTAssertTrue(markdown.contains(label), label)
        }
        let secrets = [
            "SYNTHETIC_EGRESS_SECRET_v2_0123456789abcdef",
            "SYNTHETIC_CREDENTIAL_NOT_A_SECRET",
            "REINS_SYNTHETIC_TEST="
        ]
        for secret in secrets {
            XCTAssertFalse(markdown.contains(secret))
            let needle = Data(secret.utf8)
            for (name, data) in files where name.hasSuffix(".png") {
                XCTAssertFalse(data.range(of: needle) != nil, "\(name) contains \(secret)")
            }
        }
        if let directory = ProcessInfo.processInfo.environment["REINS_CHAIN_SNAPSHOT_DIR"], !directory.isEmpty {
            let url = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            for (name, data) in files {
                try data.write(to: url.appendingPathComponent(name), options: .atomic)
            }
        }
    }
}
