import EvidenceCore
import Foundation

enum AppLanguage: String, CaseIterable, Identifiable {
    case system
    case en
    case zhHans = "zh-Hans"

    var id: String { rawValue }

    var menuKey: String {
        switch self {
        case .system: return "menu.followSystem"
        case .en: return "menu.english"
        case .zhHans: return "menu.chinese"
        }
    }
}

/// In-app language. Follow System uses the macOS preferred language.
/// English and 简体中文 apply immediately; views read `resolved`.
final class LanguageStore: ObservableObject {
    static let shared = LanguageStore()
    private static let defaultsKey = "reins.uiLanguage"

    @Published var choice: AppLanguage {
        didSet { UserDefaults.standard.set(choice.rawValue, forKey: Self.defaultsKey) }
    }

    var resolved: String {
        switch choice {
        case .en: return "en"
        case .zhHans: return "zh-Hans"
        case .system:
            let preferred = Locale.preferredLanguages.first ?? "en"
            return preferred.hasPrefix("zh") ? "zh-Hans" : "en"
        }
    }

    private init() {
        let raw = UserDefaults.standard.string(forKey: Self.defaultsKey) ?? AppLanguage.system.rawValue
        choice = AppLanguage(rawValue: raw) ?? .system
    }

    func tr(_ key: String) -> String {
        let primary = Self.lookup(key, language: resolved)
        if primary != key { return primary }
        return Self.lookup(key, language: "en")
    }

    func format(_ key: String, _ args: CVarArg...) -> String {
        String(format: tr(key), locale: Locale(identifier: resolved == "en" ? "en_US" : "zh_CN"), arguments: args)
    }

    func verdict(_ word: UploadVerdictWord) -> String {
        switch word {
        case .uploaded: return tr("verdict.uploaded")
        case .attempted: return tr("verdict.attempted")
        case .notFound: return tr("verdict.notFound")
        case .notVisible: return tr("verdict.notVisible")
        case .absent: return tr("verdict.absent")
        case .unrecognized: return tr("verdict.unrecognized")
        }
    }

    static func lookup(_ key: String, language: String) -> String {
        bundle(for: language).localizedString(forKey: key, value: key, table: nil)
    }

    static func bundle(for language: String) -> Bundle {
        if let url = Bundle.module.url(forResource: language, withExtension: "lproj"),
           let bundle = Bundle(url: url) {
            return bundle
        }
        return .module
    }
}

enum L10n {
    static func tr(_ key: String) -> String { LanguageStore.shared.tr(key) }
    static func format(_ key: String, _ args: CVarArg...) -> String {
        String(format: LanguageStore.shared.tr(key), locale: Locale(identifier: LanguageStore.shared.resolved == "en" ? "en_US" : "zh_CN"), arguments: args)
    }
}
