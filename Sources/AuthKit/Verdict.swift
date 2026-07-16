/// The four consent outcomes, one per contract exit code. The exit codes are a
/// wire ABI shared with synckit's Go bridge and cc-sudo's verifier — parity with
/// cookiesync-keyhelper, never renumber:
///
///   0 approved · 1 denied · 2 unavailable · 3 screen-locked / no user present
public enum Verdict: Sendable, Equatable {
    case approved
    case denied
    case unavailable
    case screenLocked

    public var exitCode: Int32 {
        switch self {
        case .approved: 0
        case .denied: 1
        case .unavailable: 2
        case .screenLocked: 3
        }
    }
}
