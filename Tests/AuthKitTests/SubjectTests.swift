@testable import AuthKit
import Foundation
import Testing

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

/// Known-answer digests over the frozen origin-bound subject encoding
/// (canonical argv ‖ 0x00 ‖ utf8 origin host, canonical = 8-byte big-endian
/// UTF-8 byte count per argument then the bytes), computed independently.
@Test(arguments: [
    (["dscacheutil", "-flushcache"], "", "533e36c30a841b85ce9a562596dcabde8c251fa62ce9fb87454f008bb3c597b5"),
    (["ab", "c"], "", "7add9366540656f31f5ad408663bf167291ae93f69494c9f9cb178fcc58cd250"),
    (["a", "bc"], "", "c30e79fdcb1292bf0cddaf7cf6d0303b5e96222ba1d33f6f169e82977a3e6fad"),
    ([""], "", "3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d"),
    (["reboot"], "studio", "5634163ce24b126a802815c2035fdb14f0a1720f754c05bb0292240d496d0a13"),
    (["reboot"], "", "4e84672feb5de3b1cb55bbf1d0f6ae934502524a99a0b2c49cd039ae0379a729"),
])
func subjectDigestMatchesKnownAnswers(argv: [String], originHost: String, expected: String) {
    #expect(hex(Subject.digest(argv: argv, originHost: originHost)) == expected)
}

@Test func lengthPrefixingMakesTheEncodingInjective() {
    #expect(Subject.digest(argv: ["ab", "c"], originHost: "") != Subject.digest(argv: ["a", "bc"], originHost: ""))
    #expect(Subject.digest(argv: ["ab", "c"], originHost: "") != Subject.digest(argv: ["abc"], originHost: ""))
    #expect(Subject.digest(argv: [], originHost: "") != Subject.digest(argv: [""], originHost: ""))
}

@Test func originHostBindsIntoTheSubject() {
    let local = Subject.digest(argv: ["reboot"], originHost: "")
    let routed = Subject.digest(argv: ["reboot"], originHost: "studio")
    let spoofed = Subject.digest(argv: ["reboot"], originHost: "laptop")
    #expect(local != routed)
    #expect(routed != spoofed)
}

/// The frozen display digest: SHA-256 over the canonical argv alone.
@Test func argvDigestHexMatchesTheKnownAnswer() {
    #expect(Subject.argvDigestHex(argv: ["dscacheutil", "-flushcache"])
        == "2e6cdafb4ba00749a008271edcfb039d4157001dd7fcd32060366eaa69f3c868")
}

@Test func displayRendersPlainArgvVerbatimPlusTheDigestLine() {
    let reason = Subject.display(argv: ["dscacheutil", "-flushcache"])
    #expect(reason == """
    Run: dscacheutil -flushcache
    sha256: 2e6cdafb4ba00749a008271edcfb039d4157001dd7fcd32060366eaa69f3c868
    """)
}

@Test func displayQuotesArgumentsWithSpaces() {
    #expect(Subject.display(argv: ["echo", "hello world"]).hasPrefix("Run: echo \"hello world\"\n"))
}

@Test func displayAppendsTheRequestingHost() {
    let reason = Subject.display(argv: ["reboot"], requestedFrom: "studio")
    #expect(reason.hasPrefix("Run: reboot — requested from studio\n"))
}

@Test func displayReplacesControlCharactersSoArgvCannotSpoofTheSheet() {
    let reason = Subject.display(argv: ["rm", "-rf", "/tmp/x\r\nls"])
    let commandLine = reason.split(separator: "\n").first.map(String.init) ?? ""
    #expect(!commandLine.contains("\r"))
    #expect(reason.split(separator: "\n").count == 2)
    #expect(reason.contains("\u{FFFD}"))
}

@Test func displayNeutralizesBidiOverridesSoArgvCannotReorderTheSheet() {
    let reason = Subject.display(argv: ["touch", "\u{202E}txt.harmless"])
    #expect(!reason.contains("\u{202E}"))
    #expect(reason.contains("\u{FFFD}"))
}

@Test(arguments: ["\u{2066}", "\u{2069}", "\u{200E}", "\u{00AD}", "\u{FEFF}"])
func displayNeutralizesFormatCharacters(control: String) {
    let reason = Subject.display(argv: ["ls", control + "x"])
    #expect(!reason.contains(control))
    #expect(reason.contains("\u{FFFD}"))
}

@Test func displayMiddleElidesAPathologicallyLongElementWithAVisibleMarker() {
    let long = String(repeating: "a", count: 500) + "TAIL"
    let reason = Subject.display(argv: ["echo", long])
    #expect(reason.contains("…[504 chars]…"))
    #expect(reason.contains("TAIL"))
}

@Test func displayDistinguishesCommandsSharingALongBenignPrefix() {
    let prefix = String(repeating: "a", count: 300)
    let benign = Subject.display(argv: ["echo", prefix + "-benign"])
    let malicious = Subject.display(argv: ["echo", prefix + "; rm -rf /"])
    #expect(benign != malicious)
    #expect(malicious.contains("rm -rf /"))
    #expect(benign.split(separator: "\n").last != malicious.split(separator: "\n").last)
}

@Test func displayReplacesDroppedArgumentsWithAQuantifiedMarker() {
    let argv = (0 ..< 40).map(String.init)
    let reason = Subject.display(argv: argv)
    #expect(reason.contains("(+8 more arguments)"))
    #expect(reason.contains("31"))
    #expect(reason.contains("sha256: \(Subject.argvDigestHex(argv: argv))"))
}

@Test func displayShowsEveryArgumentUnderTheCap() {
    let argv = (0 ..< 32).map { "arg\($0)" }
    let reason = Subject.display(argv: argv)
    #expect(!reason.contains("more arguments"))
    #expect(reason.contains("arg31"))
}

@Test func displayElidesTheHostWithAVisibleMarker() {
    let reason = Subject.display(argv: ["ls"], requestedFrom: String(repeating: "h", count: 200))
    #expect(reason.contains("…[200 chars]…"))
}
