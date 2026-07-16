import Foundation
import LocalAuthentication
import Security

/// The biometry-bound consent vault, ported from cookiesync-keyhelper: generic
/// passwords in the shared access group whose ACL demands current biometrics or
/// the device passcode. Items keep cookiesync's service names and access group,
/// so existing enrollments survive the migration unchanged.
public enum Vault {
    public struct Item: Sendable {
        public let vaultService: String
        public let sourceService: String

        public init(vaultService: String, sourceService: String) {
            self.vaultService = vaultService
            self.sourceService = sourceService
        }
    }

    /// Reads the source secret from the login keychain (e.g. a browser's Safe
    /// Storage password) for enrollment into the vault.
    static func readSource(_ service: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data
        else {
            return nil
        }
        return data
    }

    static func accessControl() throws -> SecAccessControl {
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .or, .devicePasscode],
            &acError
        ) else {
            throw HelperFailure.classify(
                "SecAccessControlCreateWithFlags", error: acError, otherwise: HelperFailure.unavailable
            )
        }
        return access
    }

    /// A UI-less LAContext: any operation that would need a sheet reports
    /// errSecInteractionNotAllowed instead of prompting. This is the modern
    /// replacement for kSecUseAuthenticationUIFail.
    static func promptFreeContext() -> LAContext {
        let context = LAContext()
        context.interactionNotAllowed = true
        return context
    }

    static func deleteExisting(_ vaultService: String) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: vaultService,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: promptFreeContext(),
        ] as CFDictionary)
        if status == errSecInteractionNotAllowed {
            throw HelperFailure.classify("SecItemDelete", status: status, otherwise: HelperFailure.failed)
        }
    }

    /// Enrolls the source secret into the biometry-bound vault item, replacing
    /// any existing item.
    public static func enroll(vaultService: String, sourceService: String, context: LAContext? = nil) throws {
        guard let secret = readSource(sourceService) else {
            throw HelperFailure.unavailable("could not read '\(sourceService)' from the login keychain")
        }
        // Build the ACL before deleting the old item (keyhelper's
        // build-then-delete-then-add ordering): an ACL-construction failure
        // must never destroy a working enrollment.
        let access = try accessControl()
        try deleteExisting(vaultService)
        var add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: vaultService,
            kSecValueData as String: secret,
            kSecAttrAccessControl as String: access,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
        ]
        if let context {
            add[kSecUseAuthenticationContext as String] = context
        }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw HelperFailure.classify("SecItemAdd", status: status, otherwise: HelperFailure.failed)
        }
    }

    static func copyItem(
        _ vaultService: String, context: LAContext, uiAllowed: Bool
    ) -> (data: Data?, status: OSStatus) {
        if !uiAllowed {
            // The pre-authenticated context satisfies the ACL, so no UI is
            // needed — refuse (never show) a second, passcode-capable prompt.
            context.interactionNotAllowed = true
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: vaultService,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (item as? Data, status)
    }

    static func classifyRead(_ vaultService: String, data: Data?, status: OSStatus) throws -> Data {
        switch status {
        case errSecSuccess:
            guard let data else {
                throw HelperFailure.failed("vault item returned no data")
            }
            return data
        case errSecItemNotFound, errSecAuthFailed:
            // The biometry-bound item is gone or invalidated (the fingerprint
            // set changed, which voids a .biometryCurrentSet ACL): re-enroll.
            throw HelperFailure.unavailable("vault item '\(vaultService)' missing or invalidated: re-enroll")
        case errSecUserCanceled:
            throw HelperFailure.denied("retrieve cancelled by user")
        case errSecInteractionNotAllowed:
            // Keyhelper parity: the keybag refusing interaction on the
            // POST-authentication read is a hard failure (exit 1), never a
            // retryable screen-lock — the user just authenticated.
            throw HelperFailure.failed("SecItemCopyMatching failed: interaction not allowed (OSStatus \(status))")
        default:
            throw HelperFailure.classify("SecItemCopyMatching", status: status, otherwise: HelperFailure.failed)
        }
    }

    /// One deviceOwnerAuthentication sheet, then the vault read.
    public static func retrieve(vaultService: String, reason: String) async throws -> Data {
        let context = LAContext()
        try await evaluate(
            context, policy: .deviceOwnerAuthentication, reason: reason,
            unavailable: HelperFailure.unavailable
        )
        let (data, status) = copyItem(vaultService, context: context, uiAllowed: true)
        return try classifyRead(vaultService, data: data, status: status)
    }

    /// The strict biometrics-only read: no passcode fallback, no second prompt,
    /// fails closed with exit 3 when biometrics cannot approve.
    public static func retrieveBiometric(vaultService: String, reason: String) async throws -> Data {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw HelperFailure.screenLocked(
                "biometrics unavailable: \(policyError?.localizedDescription ?? "no enrolled biometry")"
            )
        }
        switch await LAContextAuthenticator.evaluate(
            context, policy: .deviceOwnerAuthenticationWithBiometrics, reason: reason
        ) {
        case .approved:
            break
        case .denied:
            throw HelperFailure.denied("denied")
        case let .cannotEvaluate(detail):
            throw HelperFailure.screenLocked("biometrics unavailable: \(detail)")
        case let .failedWithCode(code):
            switch code {
            case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout,
                 .notInteractive, .invalidContext, .passcodeNotSet:
                throw HelperFailure.screenLocked("biometrics unavailable: LAError \(code.rawValue)")
            default:
                throw HelperFailure.denied("denied")
            }
        }
        let (data, status) = copyItem(vaultService, context: context, uiAllowed: false)
        return try classifyRead(vaultService, data: data, status: status)
    }

    /// One line of vault-batch-retrieve output: `<index>\t<status>\t<payload>`.
    static func batchLine(_ index: Int, _ status: String, _ payload: String) -> String {
        "\(index)\t\(status)\t\(payload)\n"
    }

    /// Reads every vault item under ONE auth sheet, emitting one line per item.
    /// A missing or invalidated item with a readable source secret is re-enrolled
    /// under the already-authenticated context — no second sheet. A helper
    /// failure during re-enrollment aborts the whole batch at the process level
    /// (keyhelper parity): a locked keybag exits 3, an ACL-construction or
    /// unavailable failure exits 2, via the thrown failure.
    public static func batchRetrieve(
        items: [Item],
        reason: String,
        emit: (String) -> Void
    ) async throws {
        let context = LAContext()
        try await evaluate(
            context, policy: .deviceOwnerAuthentication, reason: reason,
            unavailable: HelperFailure.unavailable
        )
        for (index, item) in items.enumerated() {
            let (data, status) = copyItem(item.vaultService, context: context, uiAllowed: true)
            switch status {
            case errSecSuccess:
                guard let data else {
                    emit(batchLine(index, "error", "\(errSecInternalError)"))
                    continue
                }
                emit(batchLine(index, "ok", data.base64EncodedString()))
            case errSecItemNotFound, errSecAuthFailed:
                try batchEnroll(context: context, index: index, item: item, emit: emit)
            case errSecInteractionNotAllowed:
                throw HelperFailure.classify("SecItemCopyMatching", status: status, otherwise: HelperFailure.failed)
            default:
                emit(batchLine(index, "error", "\(status)"))
            }
        }
    }

    static func batchEnroll(context: LAContext, index: Int, item: Item, emit: (String) -> Void) throws {
        guard let secret = readSource(item.sourceService) else {
            emit(batchLine(index, "missing", "-"))
            return
        }
        try enroll(vaultService: item.vaultService, sourceService: item.sourceService, context: context)
        emit(batchLine(index, "ok", secret.base64EncodedString()))
    }

    /// The read-only, UI-free status probe: reports biometry/passcode/vault
    /// presence on stdout; exit 0 when device auth works and the item exists,
    /// else exit 2. A prompt-free context keeps it UI-free — an auth-gated
    /// read reporting errSecInteractionNotAllowed proves existence.
    public static func status(vaultService: String) -> (report: String, exitCode: Int32) {
        let context = LAContext()
        let biometry = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let deviceAuth = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: vaultService,
            kSecAttrAccessGroup as String: Keychain.accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: promptFreeContext(),
        ] as CFDictionary, nil)
        // The prompt-free context keeps this probe UI-free: an auth-gated read
        // reports errSecInteractionNotAllowed — the item exists.
        let exists = status == errSecSuccess || status == errSecInteractionNotAllowed
        let report = "biometry=\(biometry) passcode=\(deviceAuth) vault=\(exists)\n"
        guard deviceAuth else { return (report, 2) }
        return (report, exists ? 0 : 2)
    }

    static func evaluate(
        _ context: LAContext,
        policy: LAPolicy,
        reason: String,
        unavailable: (String) -> HelperFailure
    ) async throws {
        var policyError: NSError?
        guard context.canEvaluatePolicy(policy, error: &policyError) else {
            throw unavailable(policyError?.localizedDescription ?? "no biometrics or passcode")
        }
        switch await LAContextAuthenticator.evaluate(context, policy: policy, reason: reason) {
        case .approved:
            return
        case .denied:
            throw HelperFailure.denied("denied")
        case let .cannotEvaluate(detail):
            throw unavailable(detail)
        case let .failedWithCode(code):
            switch code {
            case .notInteractive, .invalidContext, .biometryNotAvailable, .passcodeNotSet:
                throw unavailable("LAError \(code.rawValue)")
            default:
                throw HelperFailure.denied("denied")
            }
        }
    }
}
