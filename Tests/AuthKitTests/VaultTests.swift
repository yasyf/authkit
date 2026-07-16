@testable import AuthKit
import Foundation
import Security
import Testing

@Test func classifyReadReturnsTheDataOnSuccess() throws {
    let secret = Data([1, 2, 3])
    #expect(try Vault.classifyRead("svc", data: secret, status: errSecSuccess) == secret)
}

@Test(arguments: [
    (errSecItemNotFound, Int32(2)),
    (errSecAuthFailed, 2),
    (errSecUserCanceled, 1),
    (errSecInteractionNotAllowed, 1),
    (errSecInternalError, 1),
] as [(OSStatus, Int32)])
func classifyReadMapsFailuresOntoTheExitContract(status: OSStatus, expected: Int32) {
    do {
        _ = try Vault.classifyRead("svc", data: nil, status: status)
        Issue.record("classifyRead must throw for OSStatus \(status)")
    } catch let failure as HelperFailure {
        #expect(failure.exitCode == expected)
    } catch {
        Issue.record("classifyRead threw a non-HelperFailure: \(error)")
    }
}

/// Keyhelper parity on the post-authentication read: a keybag refusing
/// interaction is a hard failure, never routed as a retryable screen-lock.
@Test func classifyReadNeverMapsInteractionNotAllowedToScreenLocked() {
    do {
        _ = try Vault.classifyRead("svc", data: nil, status: errSecInteractionNotAllowed)
        Issue.record("classifyRead must throw")
    } catch let failure as HelperFailure {
        if case .screenLocked = failure {
            Issue.record("post-auth read routed errSecInteractionNotAllowed as screenLocked")
        }
    } catch {
        Issue.record("classifyRead threw a non-HelperFailure: \(error)")
    }
}
