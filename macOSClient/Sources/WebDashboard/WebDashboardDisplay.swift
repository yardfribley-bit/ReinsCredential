import Foundation

/// Display redaction for the web page. EvidenceRedaction already hides
/// assignment-style secrets and the published synthetic markers. Cookie,
/// Authorization, and Bearer values are removed here as well so the page
/// never renders them. Hashes and ordinary paths stay visible.
public enum WebDashboardDisplay {
    public static func redact(_ text: String) -> String {
        guard !text.isEmpty else { return text }
        var text = EvidenceRedaction.display(text)
        text = replace(authorization, in: text, template: "$1[已省略]")
        text = replace(bearer, in: text, template: "bearer [已省略]")
        text = replace(cookie, in: text, template: "$1[已省略]")
        return text
    }

    private static let authorization: NSRegularExpression = pattern(
        #"(?i)(\bauthorization\b\s*[:=]\s*)(?:bearer\s+)?[^\s,;&"'<>]+"#
    )
    private static let bearer: NSRegularExpression = pattern(
        #"(?i)\bbearer\s+[^\s,;&"'<>]+"#
    )
    private static let cookie: NSRegularExpression = pattern(
        #"(?i)(\b(?:set-cookie|cookie)\b\s*[:=]\s*)[^\s,;&"'<>]+"#
    )

    private static func pattern(_ value: String) -> NSRegularExpression {
        do { return try NSRegularExpression(pattern: value) }
        catch { fatalError("web redaction pattern failed to compile") }
    }

    private static func replace(_ expression: NSRegularExpression, in text: String, template: String) -> String {
        let range = NSRange(text.startIndex..., in: text)
        return expression.stringByReplacingMatches(in: text, options: [], range: range, withTemplate: template)
    }
}

enum WebHTML {
    static func text(_ raw: String) -> String {
        escape(WebDashboardDisplay.redact(raw).filter { $0 != "\u{0}" })
    }

    static func attr(_ raw: String) -> String {
        text(raw).replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ")
    }

    static func escape(_ raw: String) -> String {
        var out = ""
        out.reserveCapacity(raw.count)
        for scalar in raw.unicodeScalars {
            switch scalar {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            case "\u{0000}": continue
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out
    }
}
