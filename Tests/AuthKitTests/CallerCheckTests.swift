@testable import AuthKit
import Foundation
import Security
import Testing

@Test func requirementPinsTeamIDIdentifiersAndDeveloperIDAnchors() {
    let requirement = CallerCheck.requirementString(teamID: "TEAM123456", identifiers: ["alpha", "beta"])
    #expect(requirement.contains("identifier \"alpha\" or identifier \"beta\""))
    #expect(requirement.contains("certificate leaf[subject.OU] = \"TEAM123456\""))
    #expect(requirement.contains("anchor apple generic"))
    // Developer ID leaf + intermediate marker OIDs — the DR, never a cdhash.
    #expect(requirement.contains("certificate 1[field.1.2.840.113635.100.6.2.6]"))
    #expect(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13]"))
    #expect(!requirement.contains("cdhash"))
}

@Test func pinnedRequirementParsesAsAValidSecRequirement() {
    var requirement: SecRequirement?
    let status = SecRequirementCreateWithString(
        CallerCheck.requirementString() as CFString, [], &requirement
    )
    #expect(status == errSecSuccess)
    #expect(requirement != nil)
}

@Test func ownAuditTokenResolvesToTheCurrentBinary() throws {
    // The test runner's own audit token must resolve, via the same
    // SecCodeCopyGuestWithAttributes path production uses, to this process.
    var token = try CallerCheck.auditToken(forPID: getpid())
    let tokenData = withUnsafeBytes(of: &token) { Data($0) }
    var code: SecCode?
    let status = SecCodeCopyGuestWithAttributes(
        nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &code
    )
    #expect(status == errSecSuccess)

    var staticCode: SecStaticCode?
    #expect(try SecCodeCopyStaticCode(#require(code), [], &staticCode) == errSecSuccess)
    var url: CFURL?
    #expect(try SecCodeCopyPath(#require(staticCode), [], &url) == errSecSuccess)
    let path = try (#require(url) as URL).path
    #expect(path.contains("xctest") || path.contains("swiftpm-testing-helper") || path.contains(".build"))
}

@Test func aDifferentlySignedCallerIsRejected() {
    // The differently-signed-stub rejection: the test runner is not a
    // Developer-ID binary from the pinned team, so validating it against the
    // pinned requirement must fail closed.
    let check = CallerCheck(callerToken: { try CallerCheck.auditToken(forPID: getpid()) })
    #expect(throws: CallerCheck.CallerError.self) {
        try check.validate()
    }
}

@Test func aVanishedProcessYieldsNoToken() {
    // PID 1 is launchd; task_name_for_pid on it fails for a non-root caller, so
    // the resolver throws instead of silently validating a wrong process.
    #expect(throws: CallerCheck.CallerError.self) {
        _ = try CallerCheck.auditToken(forPID: 1)
    }
}

@Test func pinnedIdentifiersCoverTheFleet() {
    #expect(CallerCheck.pinnedTeamID == "SXKCTF23Q2")
    #expect(CallerCheck.pinnedIdentifiers.contains("cc-sudo"))
    #expect(CallerCheck.pinnedIdentifiers.contains("synckitd"))
    #expect(CallerCheck.pinnedIdentifiers.contains("cookiesync"))
}
