@testable import AuthKit
import Foundation
import Security
import Testing

func fakeCLI(
    callerFails: Bool = false,
    verdict: Verdict = .approved,
    onPrompt: (@Sendable () -> Void)? = nil,
    attest: @escaping @Sendable (Data, Data, String) async throws -> (keyID: String, signature: Data) = { _, _, _ in
        ("fake-key-id", Data([0xAB, 0xCD]))
    },
    vaultStatus: @escaping @Sendable (String) -> (report: String, exitCode: Int32) = { _ in ("", 0) }
) -> CLI {
    CLI(dependencies: .init(
        checkCaller: {
            if callerFails {
                throw CallerCheck.CallerError.notPinned(errSecCSReqFailed)
            }
        },
        consentVerdict: { _ in
            onPrompt?()
            return verdict
        },
        attest: { nonce, subject, reason in
            onPrompt?()
            return try await attest(nonce, subject, reason)
        },
        vaultStatus: vaultStatus
    ))
}

func run(
    _ cli: CLI,
    _ arguments: [String],
    environment: [String: String] = [:],
    stdin: Data = Data()
) async -> (Int32, Data?) {
    await cli.dispatch(arguments: arguments, environment: environment, input: { stdin })
}

let reasonEnv = [CLI.reasonEnvironmentVariable: "test reason"]

// MARK: - Dispatch

@Test func missingSubcommandExits4() async {
    let (code, _) = await run(fakeCLI(), [])
    #expect(code == 4)
}

@Test func unknownSubcommandExits4() async {
    let (code, _) = await run(fakeCLI(), ["frobnicate"])
    #expect(code == 4)
}

@Test(arguments: ["--help", "-h"])
func helpExits0WithUsageOnStdout(flag: String) async {
    let (code, output) = await run(fakeCLI(), [flag])
    #expect(code == 0)
    let text = String(decoding: output ?? Data(), as: UTF8.self)
    #expect(text.contains("usage: authkit <subcommand>"))
    #expect(text.contains("consent-sign"))
}

// MARK: - consent (verdict-only)

@Test(arguments: [
    (Verdict.approved, Int32(0)),
    (.denied, 1),
    (.unavailable, 2),
    (.screenLocked, 3),
])
func consentExitCodeTable(verdict: Verdict, expected: Int32) async {
    let (code, _) = await run(fakeCLI(verdict: verdict), ["consent"], environment: reasonEnv)
    #expect(code == expected)
}

@Test func consentWithoutReasonExits4() async {
    let (code, _) = await run(fakeCLI(), ["consent"])
    #expect(code == 4)
}

@Test func consentWithUnpinnedCallerExits4BeforeAnySheet() async {
    await confirmation("prompt or signature", expectedCount: 0) { prompted in
        let cli = fakeCLI(callerFails: true, verdict: .approved, onPrompt: { prompted() })
        let (code, _) = await run(cli, ["consent"], environment: reasonEnv)
        #expect(code == 4)
    }
}

@Test func consentRejectsPositionalArguments() async {
    let (code, _) = await run(fakeCLI(), ["consent", "extra"], environment: reasonEnv)
    #expect(code == 4)
}

// MARK: - consent-sign

func signRequest(
    nonce: Data = Data((0 ..< 24).map { UInt8($0) }),
    argv: [String] = ["dscacheutil", "-flushcache"],
    requestedFrom: String? = nil
) throws -> Data {
    try JSONEncoder().encode(
        ConsentSignRequest(nonce: nonce.base64EncodedString(), argv: argv, requestedFrom: requestedFrom)
    )
}

@Test func consentSignComputesTheDigestItselfAndEmitsTheSignature() async throws {
    let expectedSubject = Subject.digest(argv: ["dscacheutil", "-flushcache"], originHost: "")
    let cli = fakeCLI(attest: { nonce, subject, reason in
        #expect(nonce == Data((0 ..< 24).map { UInt8($0) }))
        #expect(subject == expectedSubject)
        #expect(reason == """
        Run: dscacheutil -flushcache
        sha256: 2e6cdafb4ba00749a008271edcfb039d4157001dd7fcd32060366eaa69f3c868
        """)
        return ("key-1", Data([0x01, 0x02]))
    })
    let (code, output) = try await run(cli, ["consent-sign"], stdin: signRequest())
    #expect(code == 0)
    let response = try JSONDecoder().decode(ConsentSignResponse.self, from: #require(output))
    #expect(response.keyID == "key-1")
    #expect(response.sig == Data([0x01, 0x02]).base64EncodedString())
}

@Test func consentSignAppendsTheRequestingHostToTheDisplayedReasonAndBindsItIntoTheSubject() async throws {
    let cli = fakeCLI(attest: { _, subject, reason in
        #expect(subject == Subject.digest(argv: ["reboot"], originHost: "studio"))
        #expect(reason.hasPrefix("Run: reboot — requested from studio\n"))
        return ("key-1", Data([0x01]))
    })
    let (code, _) = try await run(cli, ["consent-sign"], stdin: signRequest(argv: ["reboot"], requestedFrom: "studio"))
    #expect(code == 0)
}

@Test func consentSignIgnoresACallerComposedReason() async throws {
    // AUTHKIT_REASON must never influence the attestation sheet: the displayed
    // reason derives only from the argv the digest binds.
    let cli = fakeCLI(attest: { _, subject, reason in
        #expect(subject == Subject.digest(argv: ["ls"], originHost: ""))
        #expect(reason.hasPrefix("Run: ls\n"))
        return ("key-1", Data([0x01]))
    })
    let environment = [CLI.reasonEnvironmentVariable: "totally benign command"]
    let (code, _) = try await run(cli, ["consent-sign"], environment: environment, stdin: signRequest(argv: ["ls"]))
    #expect(code == 0)
}

@Test func consentSignRejectsMalformedJSON() async {
    let (code, output) = await run(fakeCLI(), ["consent-sign"], stdin: Data("not json".utf8))
    #expect(code == 4)
    #expect(output == nil)
}

@Test func consentSignRejectsAnEmptyArgv() async throws {
    let (code, _) = try await run(fakeCLI(), ["consent-sign"], stdin: signRequest(argv: []))
    #expect(code == 4)
}

@Test func consentSignRejectsAShortNonce() async throws {
    let (code, _) = try await run(fakeCLI(), ["consent-sign"], stdin: signRequest(nonce: Data([1, 2, 3])))
    #expect(code == 4)
}

@Test func consentSignRejectsANonBase64Nonce() async {
    let body = Data(#"{"nonce":"not base64!!","argv":["ls"]}"#.utf8)
    let (code, _) = await run(fakeCLI(), ["consent-sign"], stdin: body)
    #expect(code == 4)
}

@Test func consentSignWithUnpinnedCallerExits4BeforeAnySignature() async throws {
    try await confirmation("prompt or signature", expectedCount: 0) { prompted in
        let cli = fakeCLI(callerFails: true, onPrompt: { prompted() })
        let (code, _) = try await run(cli, ["consent-sign"], stdin: signRequest())
        #expect(code == 4)
    }
}

@Test(arguments: [
    (HelperFailure.denied("denied"), Int32(1)),
    (.unavailable("no key"), 2),
    (.screenLocked("locked"), 3),
])
func consentSignMapsAttestationFailuresOntoTheContract(
    failure: HelperFailure,
    expected: Int32
) async throws {
    let cli = fakeCLI(attest: { _, _, _ in throw failure })
    let (code, _) = try await run(cli, ["consent-sign"], stdin: signRequest())
    #expect(code == expected)
}

// MARK: - keygen & vault gating

@Test func keygenWithUnpinnedCallerExits4BeforeAnyPrompt() async {
    await confirmation("prompt or signature", expectedCount: 0) { prompted in
        let cli = fakeCLI(callerFails: true, onPrompt: { prompted() })
        let (code, _) = await run(cli, ["keygen"])
        #expect(code == 4)
    }
}

@Test(arguments: [
    ["vault-retrieve", "svc"],
    ["vault-retrieve-biometric", "svc"],
    ["vault-batch-retrieve", "svc", "src"],
])
func promptingVaultSubcommandsWithUnpinnedCallerExit4BeforeAnyPrompt(arguments: [String]) async {
    await confirmation("prompt or signature", expectedCount: 0) { prompted in
        let cli = fakeCLI(callerFails: true, onPrompt: { prompted() })
        let (code, _) = await run(cli, arguments, environment: reasonEnv)
        #expect(code == 4)
    }
}

/// vault-enroll and cache-* never prompt, but the invoker-pin still gates them:
/// an unpinned caller exits 4 before any keychain or Enclave item is touched
/// (the fakes would trap into the real Vault/SECache otherwise).
@Test func vaultEnrollWithUnpinnedCallerExits4() async {
    let (code, _) = await run(fakeCLI(callerFails: true), ["vault-enroll", "svc", "src"])
    #expect(code == 4)
}

@Test(arguments: ["cache-newkey", "cache-wrap", "cache-unwrap", "cache-dropkey"])
func cacheSubcommandsWithUnpinnedCallerExit4(subcommand: String) async {
    let (code, _) = await run(fakeCLI(callerFails: true), [subcommand, "label"])
    #expect(code == 4)
}

@Test func vaultStatusWithUnpinnedCallerExits4BeforeAnyKeychainQuery() async {
    await confirmation("vault status query", expectedCount: 0) { queried in
        let cli = fakeCLI(callerFails: true, vaultStatus: { _ in
            queried()
            return ("", 0)
        })
        let (code, _) = await run(cli, ["vault-status", "svc"])
        #expect(code == 4)
    }
}

@Test func vaultStatusPassesThroughTheReportAndExitCode() async {
    let cli = fakeCLI(vaultStatus: { service in
        #expect(service == "svc")
        return ("present\n", 0)
    })
    let (code, output) = await run(cli, ["vault-status", "svc"])
    #expect(code == 0)
    #expect(output == Data("present\n".utf8))
}

@Test func vaultStatusRequiresAService() async {
    let (code, _) = await run(fakeCLI(), ["vault-status"])
    #expect(code == 4)
}

@Test(arguments: [
    ["vault-retrieve", "svc"],
    ["vault-retrieve-biometric", "svc"],
    ["vault-batch-retrieve", "svc", "src"],
])
func promptingVaultSubcommandsWithoutReasonExit4(arguments: [String]) async {
    let (code, _) = await run(fakeCLI(), arguments)
    #expect(code == 4)
}

@Test func vaultBatchRetrieveRejectsUnpairedArguments() async {
    let (code, _) = await run(fakeCLI(), ["vault-batch-retrieve", "svc"], environment: reasonEnv)
    #expect(code == 4)
}

@Test func vaultEnrollRequiresBothServices() async {
    let (code, _) = await run(fakeCLI(), ["vault-enroll", "only-one"])
    #expect(code == 4)
}

@Test(arguments: ["cache-newkey", "cache-wrap", "cache-unwrap", "cache-dropkey"])
func cacheSubcommandsRequireALabel(subcommand: String) async {
    let (code, _) = await run(fakeCLI(), [subcommand])
    #expect(code == 4)
}
