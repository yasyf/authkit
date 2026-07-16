import CoreGraphics
import Foundation
import LocalAuthentication

/// The outcome of one device-owner authentication attempt, as reported by the
/// boundary. Tests fake this; production maps LAContext onto it.
public enum AuthenticationResult: Sendable, Equatable {
    case approved
    case denied
    case cannotEvaluate(String)
    case failedWithCode(LAError.Code)
}

/// The biometric/passcode boundary. The real implementation drives LAContext;
/// tests substitute a fake so verdict mapping is provable headless.
public protocol DeviceOwnerAuthenticator: Sendable {
    func authenticate(reason: String) async -> AuthenticationResult
}

/// ConsentGate turns one `deviceOwnerAuthentication` evaluation into a Verdict
/// on the 0/1/2/3 contract. LAError codes map exactly as cookiesync-keyhelper's
/// evaluateVaultPolicy did: notInteractive / invalidContext /
/// biometryNotAvailable / passcodeNotSet are `unavailable`; everything else that
/// fails is `denied`. A locked screen short-circuits to `screenLocked` before
/// any sheet, so the consent engine can route to a live peer.
public struct ConsentGate: Sendable {
    let authenticator: any DeviceOwnerAuthenticator
    let screenIsLocked: @Sendable () -> Bool

    public init(
        authenticator: any DeviceOwnerAuthenticator = LAContextAuthenticator(),
        screenIsLocked: @escaping @Sendable () -> Bool = ConsentGate.sessionScreenIsLocked
    ) {
        self.authenticator = authenticator
        self.screenIsLocked = screenIsLocked
    }

    public func verdict(reason: String) async -> Verdict {
        guard !screenIsLocked() else { return .screenLocked }
        switch await authenticator.authenticate(reason: reason) {
        case .approved:
            return .approved
        case .denied:
            return .denied
        case let .cannotEvaluate(detail):
            report("unavailable: \(detail)")
            return .unavailable
        case let .failedWithCode(code):
            switch code {
            case .notInteractive, .invalidContext, .biometryNotAvailable, .passcodeNotSet:
                return .unavailable
            default:
                return .denied
            }
        }
    }

    /// Reads the GUI session's lock state. The CGSSessionScreenIsLocked key is
    /// not in headers but is the long-standing way to observe the lock screen;
    /// a missing session dictionary (headless invocation) reports unlocked and
    /// lets the LAContext evaluation classify the failure instead.
    public static func sessionScreenIsLocked() -> Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            return false
        }
        return session["CGSSessionScreenIsLocked"] as? Bool ?? false
    }
}

/// The production DeviceOwnerAuthenticator: one LAContext, one
/// `.deviceOwnerAuthentication` sheet with `reason` as the prompt text.
public struct LAContextAuthenticator: DeviceOwnerAuthenticator {
    public init() {}

    public func authenticate(reason: String) async -> AuthenticationResult {
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            return .cannotEvaluate(policyError?.localizedDescription ?? "no biometrics or passcode")
        }
        return await Self.evaluate(context, policy: .deviceOwnerAuthentication, reason: reason)
    }

    static func evaluate(
        _ context: LAContext,
        policy: LAPolicy,
        reason: String
    ) async -> AuthenticationResult {
        let outcome: Result<Void, any Error> = await withCheckedContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: reason) { approved, error in
                if approved {
                    continuation.resume(returning: .success(()))
                } else {
                    continuation.resume(returning: .failure(error ?? LAError(.authenticationFailed)))
                }
            }
        }
        switch outcome {
        case .success:
            return .approved
        case let .failure(error):
            guard let laError = error as? LAError else { return .denied }
            return .failedWithCode(laError.code)
        }
    }
}
