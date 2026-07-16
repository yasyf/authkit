import Foundation
import LocalAuthentication

public extension CLI {
    /// One attestation result: the signing key's ID and the raw signature.
    typealias AttestationResult = (keyID: String, signature: Data)

    /// The signing boundary: nonce + subject digest + displayed reason in,
    /// signature out, under user presence.
    typealias Attest = @Sendable (
        _ nonce: Data, _ subject: Data, _ reason: String
    ) async throws -> AttestationResult

    /// The boundaries the CLI talks to. Production wiring is `.live`; tests
    /// substitute fakes so every exit path is provable headless.
    struct Dependencies: Sendable {
        public var checkCaller: @Sendable () throws -> Void
        public var consentVerdict: @Sendable (_ reason: String) async -> Verdict
        public var attest: Attest
        public var vaultStatus: @Sendable (_ vaultService: String) -> (report: String, exitCode: Int32)

        public init(
            checkCaller: @escaping @Sendable () throws -> Void,
            consentVerdict: @escaping @Sendable (_ reason: String) async -> Verdict,
            attest: @escaping Attest,
            vaultStatus: @escaping @Sendable (_ vaultService: String) -> (report: String, exitCode: Int32)
        ) {
            self.checkCaller = checkCaller
            self.consentVerdict = consentVerdict
            self.attest = attest
            self.vaultStatus = vaultStatus
        }

        public static let live = Dependencies(
            checkCaller: { try CallerCheck().validate() },
            consentVerdict: { reason in await ConsentGate().verdict(reason: reason) },
            attest: { nonce, subject, reason in
                if ConsentGate.sessionScreenIsLocked() {
                    throw HelperFailure.screenLocked("screen is locked")
                }
                let context = LAContext()
                try await Vault.evaluate(
                    context, policy: .deviceOwnerAuthentication, reason: reason,
                    unavailable: HelperFailure.unavailable
                )
                return try SEAttestor().sign(nonce: nonce, subject: subject, context: context)
            },
            vaultStatus: { Vault.status(vaultService: $0) }
        )
    }
}
