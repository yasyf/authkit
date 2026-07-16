import CryptoKit
import Foundation
import Security

/// Pure Security.framework attestation helpers — no Secure Enclave, no
/// entitlements, no prompts — so any process (cc-sudo's root verifier above all)
/// can verify a helper signature or derive a key ID from an enrolled public key.
public enum Attestation {
    public enum VerificationError: Error, Sendable {
        case malformedPublicKey(String)
        case verificationFailed(String)
    }

    /// The signed message: nonce ‖ subject digest, raw bytes, in that order.
    public static func message(nonce: Data, subject: Data) -> Data {
        nonce + subject
    }

    /// The key ID for an X9.63 P-256 public key: lowercase hex SHA-256 of the
    /// key bytes. Enrollment stores it; consent-sign echoes it so the verifier
    /// picks the right enrolled key.
    public static func keyID(publicKey: Data) -> String {
        SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

    public static func publicKey(fromX963 data: Data) throws -> SecKey {
        // SecKeyCreateWithData infers the EC curve from the data length and
        // ignores kSecAttrKeySizeInBits, so a P-384 key would parse; the strict
        // CryptoKit parse enforces the P-256 invariant (curve and point check).
        do {
            _ = try P256.Signing.PublicKey(x963Representation: data)
        } catch {
            throw VerificationError.malformedPublicKey(String(describing: error))
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            let detail = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
            throw VerificationError.malformedPublicKey(detail)
        }
        return key
    }

    /// Verifies a helper signature against the origin-bound subject recomputed
    /// from the argv and the origin host the verifier ITSELF sent ("" for a
    /// local request) — a tampered or spoofed provenance label fails here.
    public static func verify(
        signature: Data,
        nonce: Data,
        argv: [String],
        originHost: String,
        publicKeyX963: Data
    ) throws -> Bool {
        try verify(
            signature: signature,
            nonce: nonce,
            subject: Subject.digest(argv: argv, originHost: originHost),
            publicKeyX963: publicKeyX963
        )
    }

    /// Verifies an ECDSA-P256-SHA256 signature over nonce ‖ subject against an
    /// X9.63 public key. Returns false on a genuine mismatch; throws only when
    /// the key or signature is malformed.
    public static func verify(
        signature: Data,
        nonce: Data,
        subject: Data,
        publicKeyX963: Data
    ) throws -> Bool {
        let key = try publicKey(fromX963: publicKeyX963)
        var error: Unmanaged<CFError>?
        let valid = SecKeyVerifySignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            message(nonce: nonce, subject: subject) as CFData,
            signature as CFData,
            &error
        )
        if !valid, let error {
            let nsError = error.takeRetainedValue() as Error as NSError
            // errSecVerifyFailed is a plain mismatch, not a malformed input.
            if nsError.code != Int(errSecVerifyFailed) {
                throw VerificationError.verificationFailed(nsError.localizedDescription)
            }
        }
        return valid
    }
}
