import Foundation
import Security

/// The per-boot Secure-Enclave cache: an ephemeral P-256 key that ECIES-wraps
/// small secrets so they survive only until reboot. Ported from
/// cookiesync-keyhelper's cache-* family; keys carry the authkit tag prefix
/// (per-boot keys have no continuity requirement).
public enum SECache {
    static func applicationTag(_ label: String) -> Data {
        Data("\(Keychain.cacheTagPrefix)\(label)".utf8)
    }

    /// A fresh per-boot key makes any prior cache key dead weight whose
    /// ciphertext is unrecoverable; sweep the cache tag namespace. Unlike the
    /// cookiesync original, the sweep must NOT cover the whole access group —
    /// the attestation key (Keychain.attestTag) now shares it, and deleting
    /// that key would destroy the enrolled root of trust.
    static func deleteStaleKeys() {
        var items: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ] as CFDictionary, &items)
        guard status == errSecSuccess, let attributes = items as? [[String: Any]] else {
            return
        }
        let prefix = Data(Keychain.cacheTagPrefix.utf8)
        for entry in attributes {
            guard let tag = entry[kSecAttrApplicationTag as String] as? Data,
                  tag.starts(with: prefix)
            else {
                continue
            }
            SecItemDelete([
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrApplicationTag as String: tag,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecAttrAccessGroup as String: Keychain.accessGroup,
                kSecUseDataProtectionKeychain as String: true,
            ] as CFDictionary)
        }
    }

    static func loadPrivateKey(_ label: String) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag(label),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            if status == errSecItemNotFound {
                throw HelperFailure.failed("no Secure-Enclave cache key for '\(label)'")
            }
            throw HelperFailure.classify("SecItemCopyMatching", status: status, otherwise: HelperFailure.failed)
        }
        return try secKey(from: item)
    }

    public static func newKey(_ label: String) throws {
        deleteStaleKeys()
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
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
                kSecAttrApplicationTag as String: applicationTag(label),
                kSecAttrAccessGroup as String: Keychain.accessGroup,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var genError: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &genError) != nil else {
            throw HelperFailure.classify("SecKeyCreateRandomKey", error: genError, otherwise: HelperFailure.unavailable)
        }
    }

    public static func wrap(_ label: String, plaintext: Data) throws -> Data {
        let privateKey = try loadPrivateKey(label)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HelperFailure.failed("could not derive public key for '\(label)'")
        }
        var error: Unmanaged<CFError>?
        guard let blob = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            plaintext as CFData,
            &error
        ) else {
            throw HelperFailure.classify("SecKeyCreateEncryptedData", error: error, otherwise: HelperFailure.failed)
        }
        return blob as Data
    }

    public static func unwrap(_ label: String, blob: Data) throws -> Data {
        let privateKey = try loadPrivateKey(label)
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionCofactorX963SHA256AESGCM,
            blob as CFData,
            &error
        ) else {
            throw HelperFailure.classify("SecKeyCreateDecryptedData", error: error, otherwise: HelperFailure.failed)
        }
        return plaintext as Data
    }

    /// Deletes the cache key; exits 0 even when already gone, so cleanup is idempotent.
    public static func dropKey(_ label: String) {
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: applicationTag(label),
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ] as CFDictionary)
    }
}
