import Darwin
import Foundation
import os
import Security

/// Validates the invoking process's code signature before any sheet is shown or
/// signature produced, killing prompt-phishing by unpinned user-level code.
///
/// The caller is resolved from its AUDIT TOKEN — never a bare PID. The token
/// embeds pid + pidversion, so `SecCodeCopyGuestWithAttributes` binds the check
/// to the exact process incarnation and a pid reused between check and use
/// fails validation instead of impersonating the caller.
///
/// The pinned designated requirement is Team ID + identifier — never a cdhash —
/// so a legitimately re-signed release of a pinned caller keeps validating.
public struct CallerCheck: Sendable {
    public enum CallerError: Error, Sendable {
        case tokenUnavailable(pid: pid_t, detail: String)
        case codeUnresolvable(OSStatus)
        case requirementInvalid(OSStatus)
        case notPinned(OSStatus)
    }

    /// All pinned callers ship from this Apple Developer Team.
    public static let pinnedTeamID = "SXKCTF23Q2"

    /// Code-signing identifiers of the binaries allowed to invoke prompting or
    /// signing subcommands. cc-sudo-exec is a root-owned copy of the cc-sudo
    /// binary, so it carries the cc-sudo identifier. cookiesync's goreleaser
    /// pipeline stamps the Go default module-path identifier, not the bare
    /// binary name — the pin matches what actually ships.
    public static let pinnedIdentifiers = ["cc-sudo", "synckitd", "com.github.yasyf.cookiesync"]

    /// The pinned designated requirement: one of the pinned identifiers, signed
    /// Developer ID (leaf and intermediate marker OIDs), under the pinned team.
    public static func requirementString(
        teamID: String = pinnedTeamID,
        identifiers: [String] = pinnedIdentifiers
    ) -> String {
        let anyIdentifier = identifiers
            .map { "identifier \"\($0)\"" }
            .joined(separator: " or ")
        return "(\(anyIdentifier))"
            + " and anchor apple generic"
            + " and certificate 1[field.1.2.840.113635.100.6.2.6]"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13]"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    let requirement: String
    let callerToken: @Sendable () throws -> audit_token_t

    public init(
        requirement: String = CallerCheck.requirementString(),
        callerToken: @escaping @Sendable () throws -> audit_token_t = CallerCheck.parentAuditToken
    ) {
        self.requirement = requirement
        self.callerToken = callerToken
    }

    /// Throws unless the invoker satisfies the pinned requirement. Every failure
    /// path fails closed; the CLI maps any throw to exit 4 (caller-rejected).
    public func validate() throws {
        var token = try callerToken()
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        var code: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(
            nil,
            [kSecGuestAttributeAudit: tokenData] as CFDictionary,
            [],
            &code
        )
        guard guestStatus == errSecSuccess, let code else {
            throw CallerError.codeUnresolvable(guestStatus)
        }

        var secRequirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(requirement as CFString, [], &secRequirement)
        guard requirementStatus == errSecSuccess, let secRequirement else {
            throw CallerError.requirementInvalid(requirementStatus)
        }

        let validity = SecCodeCheckValidity(code, [], secRequirement)
        guard validity == errSecSuccess else {
            Logger.caller.error("caller rejected: OSStatus \(validity, privacy: .public)")
            throw CallerError.notPinned(validity)
        }
    }

    /// The parent process's audit token, via its task NAME port (inspect-level,
    /// same-user) and the TASK_AUDIT_TOKEN info flavor. If the parent already
    /// exited, the helper was reparented and the token names launchd, which then
    /// fails the pinned-requirement check — fail closed either way.
    public static func parentAuditToken() throws -> audit_token_t {
        try auditToken(forPID: getppid())
    }

    public static func auditToken(forPID pid: pid_t) throws -> audit_token_t {
        var name = mach_port_name_t(MACH_PORT_NULL)
        let taskStatus = task_name_for_pid(mach_task_self_, pid, &name)
        guard taskStatus == KERN_SUCCESS else {
            throw CallerError.tokenUnavailable(pid: pid, detail: "task_name_for_pid: \(taskStatus)")
        }
        defer { mach_port_deallocate(mach_task_self_, name) }

        var token = audit_token_t()
        // TASK_AUDIT_TOKEN is a #define (15) in <mach/task_info.h> that the
        // Swift importer does not surface.
        let flavor = task_flavor_t(15)
        var count = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        let infoStatus = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(name, flavor, $0, &count)
            }
        }
        guard infoStatus == KERN_SUCCESS else {
            throw CallerError.tokenUnavailable(pid: pid, detail: "task_info: \(infoStatus)")
        }
        return token
    }
}
