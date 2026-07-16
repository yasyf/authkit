import Foundation
import LocalAuthentication
import Security

/// The Secure-Enclave attestation key: a permanent P-256 key whose ACL demands
/// current biometrics or the device passcode for every signature, so the Touch
/// ID sheet IS the signing operation. Keygen requires the signed, provisioned
/// .app bundle — an unsigned build is refused by the Enclave.
public struct SEAttestor: Sendable {
    public init() {}

    /// Loads the attestation key, or creates it on first run. An existing key is
    /// never silently rotated — the public key is the enrolled root of trust.
    public func ensureKey() throws -> SecKey {
        if let existing = try loadKey(context: nil) {
            return existing
        }
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode, .and, .privateKeyUsage],
            &acError
        ) else {
            throw HelperFailure.classify(
                "SecAccessControlCreateWithFlags", error: acError, otherwise: HelperFailure.unavailable
            )
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(Keychain.attestTag.utf8),
                kSecAttrAccessGroup as String: Keychain.accessGroup,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var genError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
            throw HelperFailure.classify("SecKeyCreateRandomKey", error: genError, otherwise: HelperFailure.unavailable)
        }
        return key
    }

    /// Loads the attestation key without UI. `context` (a pre-evaluated
    /// LAContext) attaches user presence for a subsequent signing call.
    public func loadKey(context: LAContext?) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(Keychain.attestTag.utf8),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item else {
                throw HelperFailure.failed("attestation key lookup returned no key")
            }
            return try secKey(from: item)
        case errSecItemNotFound:
            return nil
        default:
            throw HelperFailure.classify("SecItemCopyMatching", status: status, otherwise: HelperFailure.failed)
        }
    }

    /// The enrolled public half: X9.63 bytes plus the derived key ID.
    public func publicKeyInfo() throws -> (keyID: String, publicKey: Data) {
        guard let key = try loadKey(context: nil) else {
            throw HelperFailure.unavailable("no attestation key: run keygen first")
        }
        return try Self.publicKeyInfo(for: key)
    }

    static func publicKeyInfo(for key: SecKey) throws -> (keyID: String, publicKey: Data) {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw HelperFailure.failed("could not derive the attestation public key")
        }
        var error: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw HelperFailure.classify(
                "SecKeyCopyExternalRepresentation", error: error, otherwise: HelperFailure.failed
            )
        }
        let data = representation as Data
        return (Attestation.keyID(publicKey: data), data)
    }

    /// Signs nonce ‖ subject with the Enclave key under a pre-evaluated user
    /// presence context. The caller composes `context` from the SAME reason it
    /// displayed — display-digest binding is enforced one level up, in
    /// consent-sign, which computes both from the argv it received.
    public func sign(nonce: Data, subject: Data, context: LAContext) throws -> (keyID: String, signature: Data) {
        guard let key = try loadKey(context: context) else {
            throw HelperFailure.unavailable("no attestation key: run keygen first")
        }
        let info = try Self.publicKeyInfo(for: key)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            Attestation.message(nonce: nonce, subject: subject) as CFData,
            &error
        ) else {
            throw HelperFailure.classify("SecKeyCreateSignature", error: error, otherwise: HelperFailure.denied)
        }
        return (info.keyID, signature as Data)
    }
}
