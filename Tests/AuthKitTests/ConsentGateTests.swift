@testable import AuthKit
import Foundation
import LocalAuthentication
import Testing

struct FakeAuthenticator: DeviceOwnerAuthenticator {
    let result: AuthenticationResult

    func authenticate(reason _: String) async -> AuthenticationResult {
        result
    }
}

func gate(_ result: AuthenticationResult, locked: Bool = false) -> ConsentGate {
    ConsentGate(authenticator: FakeAuthenticator(result: result), screenIsLocked: { locked })
}

@Test func verdictExitCodesMatchTheContract() {
    #expect(Verdict.approved.exitCode == 0)
    #expect(Verdict.denied.exitCode == 1)
    #expect(Verdict.unavailable.exitCode == 2)
    #expect(Verdict.screenLocked.exitCode == 3)
}

@Test(arguments: [
    (AuthenticationResult.approved, Verdict.approved),
    (.denied, .denied),
    (.cannotEvaluate("no biometrics"), .unavailable),
    (.failedWithCode(.userCancel), .denied),
    (.failedWithCode(.authenticationFailed), .denied),
    (.failedWithCode(.userFallback), .denied),
    (.failedWithCode(.notInteractive), .unavailable),
    (.failedWithCode(.invalidContext), .unavailable),
    (.failedWithCode(.biometryNotAvailable), .unavailable),
    (.failedWithCode(.passcodeNotSet), .unavailable),
])
func consentGateMapsAuthenticationOntoVerdicts(
    result: AuthenticationResult,
    expected: Verdict
) async {
    #expect(await gate(result).verdict(reason: "test") == expected)
}

@Test func lockedScreenShortCircuitsBeforeAnySheet() async {
    let verdict = await gate(.approved, locked: true).verdict(reason: "test")
    #expect(verdict == .screenLocked)
}
