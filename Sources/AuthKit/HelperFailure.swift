import Foundation
import Security

/// A helper operation failure, classified onto the exit-code contract.
/// `denied`/`failed` exit 1, `unavailable` exits 2, `screenLocked` exits 3.
public enum HelperFailure: Error, Sendable, Equatable {
    case denied(String)
    case failed(String)
    case unavailable(String)
    case screenLocked(String)

    public var exitCode: Int32 {
        switch self {
        case .denied, .failed: 1
        case .unavailable: 2
        case .screenLocked: 3
        }
    }

    public var message: String {
        switch self {
        case let .denied(message), let .failed(message),
             let .unavailable(message), let .screenLocked(message):
            message
        }
    }

    /// Classifies a failed SecItem/SecKey call: errSecInteractionNotAllowed
    /// (-25308) means the data-protection keybag refused the call because no user
    /// is present (locked screen) and maps to `screenLocked`; anything else maps
    /// through `otherwise`.
    static func classify(
        _ operation: String,
        status: OSStatus,
        otherwise: (String) -> HelperFailure
    ) -> HelperFailure {
        let description = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
        let message = "\(operation) failed: \(description) (OSStatus \(status))"
        if status == errSecInteractionNotAllowed {
            return .screenLocked(message)
        }
        return otherwise(message)
    }

    /// CFError overload of `classify(_:status:otherwise:)` for SecKey/SecAccessControl calls.
    static func classify(
        _ operation: String,
        error: Unmanaged<CFError>?,
        otherwise: (String) -> HelperFailure
    ) -> HelperFailure {
        guard let error else {
            return otherwise("\(operation) failed with no error detail")
        }
        let nsError = error.takeRetainedValue() as Error as NSError
        let message = "\(operation) failed: \(nsError.localizedDescription) (OSStatus \(nsError.code))"
        if nsError.domain == NSOSStatusErrorDomain, nsError.code == Int(errSecInteractionNotAllowed) {
            return .screenLocked(message)
        }
        return otherwise(message)
    }
}
