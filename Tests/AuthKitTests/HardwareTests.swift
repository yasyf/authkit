@testable import AuthKit
import Foundation
import Testing

/// Hardware-dependent tests: they touch the real Secure Enclave and may raise a
/// Touch ID sheet, and they only pass inside the signed, provisioned .app
/// context. CI (headless, unsigned) skips them via the trait; run locally with
/// AUTHKIT_HARDWARE_TESTS=1 after installing the signed helper.
enum Hardware {
    static var enabled: Bool {
        ProcessInfo.processInfo.environment["AUTHKIT_HARDWARE_TESTS"] == "1"
    }
}

@Test(.enabled(if: Hardware.enabled))
func secureEnclaveAttestationRoundTrip() async throws {
    let attestor = SEAttestor()
    _ = try attestor.ensureKey()
    let (keyID, publicKey) = try attestor.publicKeyInfo()
    #expect(keyID == Attestation.keyID(publicKey: publicKey))

    let nonce = Data((0 ..< 24).map { _ in UInt8.random(in: 0 ... 255) })
    let subject = Subject.digest(argv: ["true"], originHost: "")
    let dependencies = CLI.Dependencies.live
    let (signedKeyID, signature) = try await dependencies.attest(nonce, subject, "authkit hardware test")
    #expect(signedKeyID == keyID)
    #expect(try Attestation.verify(
        signature: signature, nonce: nonce, subject: subject, publicKeyX963: publicKey
    ))
}

@Test(.enabled(if: Hardware.enabled))
func secureEnclaveCacheRoundTrip() throws {
    let label = "authkit-test-\(UUID().uuidString)"
    try SECache.newKey(label)
    defer { SECache.dropKey(label) }

    let plaintext = Data("per-boot secret".utf8)
    let blob = try SECache.wrap(label, plaintext: plaintext)
    #expect(blob != plaintext)
    #expect(try SECache.unwrap(label, blob: blob) == plaintext)
}
