import CryptoKit
import Foundation

/// The attestation subject: a digest binding the exact argv that will run AND
/// the origin identity, computed by the helper itself and mirrored by cc-sudo's
/// root verifier. Both encodings are FROZEN cross-repo:
///
///   canonical(argv)  = for each argument, an 8-byte big-endian count of its
///                      UTF-8 bytes followed by those bytes (length prefixes
///                      make it injective — ["ab","c"] ≠ ["a","bc"])
///   subject_bytes    = sha256( canonical(argv) ‖ 0x00 ‖ utf8(origin_host) )
///
/// `origin_host` is the requested_from value, empty for a local request, so a
/// spoofed provenance label fails verification at the origin.
public enum Subject {
    public static func canonicalEncoding(argv: [String]) -> Data {
        var encoded = Data()
        for argument in argv {
            let bytes = Data(argument.utf8)
            var length = UInt64(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { encoded.append(contentsOf: $0) }
            encoded.append(bytes)
        }
        return encoded
    }

    public static func digest(argv: [String], originHost: String) -> Data {
        var message = canonicalEncoding(argv: argv)
        message.append(0x00)
        message.append(Data(originHost.utf8))
        return Data(SHA256.hash(data: message))
    }

    /// The display digest: SHA-256 over the canonical argv alone, printed on
    /// its own line of every sheet so the rendering can never silently diverge
    /// from what gets signed.
    public static func argvDigestHex(argv: [String]) -> String {
        SHA256.hash(data: canonicalEncoding(argv: argv)).map { String(format: "%02x", $0) }.joined()
    }

    static let argumentDisplayLimit = 32
    static let elementDisplayLimit = 256
    static let hostDisplayLimit = 64

    /// Renders argv for the consent sheet under the frozen display-binding
    /// render rule: NO silent truncation. Every argument is shown (an
    /// individual pathologically long element is middle-elided with a visible
    /// "[N chars]" marker), arguments beyond the display cap are replaced by a
    /// quantified "(+K more arguments)" marker, "— requested from <host>" is
    /// appended for routed requests, and the full 64-hex sha256(canonical argv)
    /// is printed on its own line.
    public static func display(argv: [String], requestedFrom: String? = nil) -> String {
        let shown = argv.prefix(Self.argumentDisplayLimit).map(quoted)
        var rendered = shown.joined(separator: " ")
        let dropped = argv.count - shown.count
        if dropped > 0 {
            rendered += " (+\(dropped) more arguments)"
        }
        var reason = "Run: \(rendered)"
        if let host = requestedFrom {
            reason += " — requested from \(elided(sanitized(host), limit: Self.hostDisplayLimit))"
        }
        reason += "\nsha256: \(argvDigestHex(argv: argv))"
        return reason
    }

    private static func quoted(_ argument: String) -> String {
        let safe = elided(sanitized(argument), limit: Self.elementDisplayLimit)
        let needsQuotes = safe.isEmpty || safe.contains(where: { $0 == " " || $0 == "\"" || $0 == "'" })
        guard needsQuotes else { return safe }
        return "\"" + safe.replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func elided(_ text: String, limit: Int) -> String {
        guard text.count > limit else { return text }
        let keep = limit / 2
        return "\(text.prefix(keep))…[\(text.count) chars]…\(text.suffix(keep))"
    }

    private static func sanitized(_ text: String) -> String {
        String(text.map { character in
            character.unicodeScalars.allSatisfy(displaySafe) ? character : "\u{FFFD}"
        })
    }

    /// C0/DEL controls, every General_Category=Cf format character, and the
    /// bidi override/isolate set are neutralized so an argument cannot reorder
    /// or spoof the rendered sheet.
    private static func displaySafe(_ scalar: Unicode.Scalar) -> Bool {
        if scalar.value < 0x20 || scalar.value == 0x7F {
            return false
        }
        if (0x202A ... 0x202E).contains(scalar.value) || (0x2066 ... 0x2069).contains(scalar.value) {
            return false
        }
        return scalar.properties.generalCategory != .format
    }
}
