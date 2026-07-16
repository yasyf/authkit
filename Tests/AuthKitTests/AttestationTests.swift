@testable import AuthKit
import CryptoKit
import Foundation
import Security
import Testing

/// A software (non-Enclave, non-keychain) P-256 key pair, so signature paths are
/// provable headless: same curve and algorithm as the Enclave key, no hardware.
func softwareKeyPair() throws -> (privateKey: SecKey, publicKeyX963: Data) {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
          let publicKey = SecKeyCopyPublicKey(privateKey),
          let representation = SecKeyCopyExternalRepresentation(publicKey, &error)
    else {
        throw HelperFailure.failed("could not create a software P-256 key pair")
    }
    return (privateKey, representation as Data)
}

func sign(_ message: Data, with privateKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
    ) else {
        throw HelperFailure.failed("signing failed")
    }
    return signature as Data
}

@Test func messageIsNonceThenSubject() {
    let nonce = Data([1, 2, 3])
    let subject = Data([9, 8])
    #expect(Attestation.message(nonce: nonce, subject: subject) == Data([1, 2, 3, 9, 8]))
}

@Test func signatureRoundTripsThroughTheVerifyHelper() throws {
    let (privateKey, publicKeyX963) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let subject = Subject.digest(argv: ["dscacheutil", "-flushcache"], originHost: "")
    let signature = try sign(Attestation.message(nonce: nonce, subject: subject), with: privateKey)

    #expect(try Attestation.verify(
        signature: signature, nonce: nonce, subject: subject, publicKeyX963: publicKeyX963
    ))
}

@Test func tamperedSubjectFailsVerification() throws {
    let (privateKey, publicKeyX963) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let subject = Subject.digest(argv: ["dscacheutil", "-flushcache"], originHost: "")
    let signature = try sign(Attestation.message(nonce: nonce, subject: subject), with: privateKey)

    let swapped = Subject.digest(argv: ["rm", "-rf", "/"], originHost: "")
    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, subject: swapped, publicKeyX963: publicKeyX963
    ))
}

@Test func replayedNonceFailsVerification() throws {
    let (privateKey, publicKeyX963) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let subject = Subject.digest(argv: ["ls"], originHost: "")
    let signature = try sign(Attestation.message(nonce: nonce, subject: subject), with: privateKey)

    let freshNonce = Data((0 ..< 24).map { UInt8($0 + 1) })
    #expect(try !Attestation.verify(
        signature: signature, nonce: freshNonce, subject: subject, publicKeyX963: publicKeyX963
    ))
}

@Test func wrongKeyFailsVerification() throws {
    let (privateKey, _) = try softwareKeyPair()
    let (_, otherPublicKey) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let subject = Subject.digest(argv: ["ls"], originHost: "")
    let signature = try sign(Attestation.message(nonce: nonce, subject: subject), with: privateKey)

    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, subject: subject, publicKeyX963: otherPublicKey
    ))
}

@Test func verifyAcceptsTheMatchingOriginHostAndRejectsASpoofedOne() throws {
    let (privateKey, publicKeyX963) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let argv = ["reboot"]
    let subject = Subject.digest(argv: argv, originHost: "studio")
    let signature = try sign(Attestation.message(nonce: nonce, subject: subject), with: privateKey)

    #expect(try Attestation.verify(
        signature: signature, nonce: nonce, argv: argv, originHost: "studio", publicKeyX963: publicKeyX963
    ))
    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, argv: argv, originHost: "laptop", publicKeyX963: publicKeyX963
    ))
    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, argv: argv, originHost: "", publicKeyX963: publicKeyX963
    ))
}

@Test func originHostChangesTheSignedMessageForTheSameArgv() throws {
    let (privateKey, _) = try softwareKeyPair()
    let nonce = Data((0 ..< 24).map { UInt8($0) })
    let local = Subject.digest(argv: ["reboot"], originHost: "")
    let routed = Subject.digest(argv: ["reboot"], originHost: "studio")
    #expect(local != routed)
    #expect(try sign(Attestation.message(nonce: nonce, subject: local), with: privateKey)
        != sign(Attestation.message(nonce: nonce, subject: routed), with: privateKey))
}

@Test func malformedPublicKeyThrows() {
    #expect(throws: Attestation.VerificationError.self) {
        try Attestation.publicKey(fromX963: Data([0x04, 0x01, 0x02]))
    }
}

@Test func wellFormedP384PublicKeyIsRejected() {
    let p384Key = P384.Signing.PrivateKey().publicKey.x963Representation
    #expect(p384Key.count == 97)
    #expect(throws: Attestation.VerificationError.self) {
        try Attestation.publicKey(fromX963: p384Key)
    }
}

@Test func keyIDIsTheHexSHA256OfTheKeyBytes() throws {
    let (_, publicKeyX963) = try softwareKeyPair()
    let keyID = Attestation.keyID(publicKey: publicKeyX963)
    #expect(keyID.count == 64)
    #expect(keyID == Attestation.keyID(publicKey: publicKeyX963))
    #expect(keyID != Attestation.keyID(publicKey: publicKeyX963 + Data([0])))
}
