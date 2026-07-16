import Foundation
import os

extension Logger {
    static let helper = Logger(subsystem: "com.yasyf.authkit", category: "Helper")
    static let caller = Logger(subsystem: "com.yasyf.authkit", category: "CallerCheck")
    static let attest = Logger(subsystem: "com.yasyf.authkit", category: "Attestation")
}

/// Writes a failure to stderr and mirrors it to the unified log. stderr is part
/// of the helper's wire contract — the Go bridge captures it as Result.Stderr —
/// so this is output, not just logging.
func report(_ message: String) {
    FileHandle.standardError.write(Data("authkit: \(message)\n".utf8))
    Logger.helper.error("\(message, privacy: .public)")
}
