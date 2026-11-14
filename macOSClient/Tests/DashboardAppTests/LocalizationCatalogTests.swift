import XCTest
import EvidenceCore
@testable import ReinsDashboardApp

final class LocalizationCatalogTests: XCTestCase {
    private let keys = [
        "verdict.uploaded", "verdict.attempted", "verdict.notFound", "verdict.notVisible",
        "verdict.absent", "limit.tls", "limit.flow", "limit.udp", "glossary", "tagline",
        "menu.language", "menu.followSystem", "menu.start", "menu.stop", "menu.selfTest",
        "nav.scope", "empty.startTitle", "scope.help", "chain.title", "detail.title",
        "about.body", "notification.title"
    ]

    func testMainStringsExistInEnglishAndChinese() {
        for key in keys {
            let english = LanguageStore.lookup(key, language: "en")
            let chinese = LanguageStore.lookup(key, language: "zh-Hans")
            XCTAssertNotEqual(english, key, "missing English \(key)")
            XCTAssertNotEqual(chinese, key, "missing Chinese \(key)")
            XCTAssertFalse(english.isEmpty)
            XCTAssertFalse(chinese.isEmpty)
            XCTAssertNotEqual(english, chinese, "\(key) is identical in both locales")
        }
        XCTAssertEqual(LanguageStore.lookup("verdict.uploaded", language: "en"), "Uploaded")
        XCTAssertEqual(LanguageStore.lookup("verdict.attempted", language: "en"), "Attempted")
        XCTAssertEqual(LanguageStore.lookup("verdict.notFound", language: "en"), "Not found")
        XCTAssertEqual(LanguageStore.lookup("verdict.notVisible", language: "en"), "Not visible")
        XCTAssertEqual(LanguageStore.lookup("verdict.uploaded", language: "zh-Hans"), "已上传")
        XCTAssertEqual(LanguageStore.lookup("verdict.attempted", language: "zh-Hans"), "已尝试未成功")
        XCTAssertEqual(LanguageStore.lookup("verdict.notFound", language: "zh-Hans"), "未发现")
        XCTAssertEqual(LanguageStore.lookup("verdict.notVisible", language: "zh-Hans"), "看不到")
        XCTAssertEqual(LanguageStore.lookup("product.name", language: "en"), "ReinsCredential")
        XCTAssertEqual(LanguageStore.lookup("product.name", language: "zh-Hans"), "ReinsCredential")
        for key in ClosureExplanation.allKeys + ["coverage.descriptors", "coverage.identity", "coverage.unreadable", "coverage.enumeration", "coverage.dropped", "closure.selfCheck", "closure.history", "state.degraded"] {
            let english = LanguageStore.lookup(key, language: "en")
            let chinese = LanguageStore.lookup(key, language: "zh-Hans")
            XCTAssertNotEqual(english, key, "missing English \(key)")
            XCTAssertNotEqual(chinese, key, "missing Chinese \(key)")
            XCTAssertNotEqual(english, chinese, "\(key) is identical in both locales")
            XCTAssertFalse(english.contains("flow_txbytes"), key)
            XCTAssertFalse(chinese.contains("flow_txbytes"), key)
        }
        XCTAssertFalse(LanguageStore.lookup("state.degraded", language: "zh-Hans").contains("覆盖受限"))
        XCTAssertFalse(LanguageStore.lookup("coverage.descriptors", language: "en").count < 40)
    }
}
