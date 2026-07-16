import Foundation
import LocalAuthentication

/// The helper's command surface. Subcommand dispatch, argument checks, and the
/// exit-code mapping live here so tests can drive the whole surface with faked
/// boundaries; main.swift is one call into `run`.
///
/// Exit codes (the wire contract; 0–3 are cookiesync-keyhelper parity):
///   0 approved/ok · 1 denied/failed · 2 unavailable (STRICTLY: the device has
///   no biometry/passcode mechanism — the sole code a consumer may degrade on)
///   · 3 screen-locked / no user present · 4 caller-rejected or usage error (a
///   non-pinned caller, bad arity, malformed stdin, a missing reason, any
///   misconfiguration — a hard failure no consumer may degrade on)
public struct CLI: Sendable {
    /// The reason env var for verdict-only consent and vault prompts. Prompting
    /// subcommands REQUIRE it — a blank sheet is a contract violation, so a
    /// missing reason fails loud with exit 4. consent-sign ignores it by design.
    public static let reasonEnvironmentVariable = "AUTHKIT_REASON"

    static let nonceMinimumBytes = 16

    let dependencies: Dependencies

    public init(dependencies: Dependencies = .live) {
        self.dependencies = dependencies
    }

    /// Runs one subcommand: reads stdin where the contract calls for it, writes
    /// stdout, and returns the contract exit code.
    public func run(arguments: [String], environment: [String: String]) async -> Int32 {
        let (code, output) = await dispatch(
            arguments: arguments,
            environment: environment,
            input: { FileHandle.standardInput.readDataToEndOfFile() }
        )
        if let output {
            FileHandle.standardOutput.write(output)
        }
        return code
    }

    func dispatch(
        arguments: [String],
        environment: [String: String],
        input: () -> Data
    ) async -> (Int32, Data?) {
        guard let subcommand = arguments.first else {
            return (usage("missing subcommand"), nil)
        }
        if subcommand == "--help" || subcommand == "-h" {
            return (0, Data((Self.usageText + "\n").utf8))
        }
        let rest = Array(arguments.dropFirst())
        switch subcommand {
        case "consent":
            return await (consent(rest, environment: environment), nil)
        case "consent-sign":
            return await consentSign(rest, input: input)
        case "keygen":
            return keygen(rest)
        case "vault-enroll":
            return (vaultEnroll(rest), nil)
        case "vault-retrieve":
            return await vaultRetrieve(rest, environment: environment, biometricOnly: false)
        case "vault-retrieve-biometric":
            return await vaultRetrieve(rest, environment: environment, biometricOnly: true)
        case "vault-batch-retrieve":
            return await vaultBatchRetrieve(rest, environment: environment)
        case "vault-status":
            return vaultStatus(rest)
        case "cache-newkey", "cache-wrap", "cache-unwrap", "cache-dropkey":
            return cache(subcommand, rest, input: input)
        default:
            return (usage("unknown subcommand '\(subcommand)'"), nil)
        }
    }

    // MARK: - Consent & attestation

    func consent(_ arguments: [String], environment: [String: String]) async -> Int32 {
        guard arguments.isEmpty else { return usage("consent takes no arguments") }
        if let code = deniedCaller() {
            return code
        }
        guard let reason = requiredReason(environment) else { return 4 }
        return await dependencies.consentVerdict(reason).exitCode
    }

    func consentSign(_ arguments: [String], input: () -> Data) async -> (Int32, Data?) {
        guard arguments.isEmpty else { return (usage("consent-sign takes no arguments"), nil) }
        if let code = deniedCaller() {
            return (code, nil)
        }

        let request: ConsentSignRequest
        do {
            request = try JSONDecoder().decode(ConsentSignRequest.self, from: input())
        } catch {
            report("consent-sign: malformed request: \(error.localizedDescription)")
            return (4, nil)
        }
        guard let nonce = Data(base64Encoded: request.nonce), nonce.count >= Self.nonceMinimumBytes else {
            report("consent-sign: nonce must be base64 and at least \(Self.nonceMinimumBytes) bytes")
            return (4, nil)
        }
        guard !request.argv.isEmpty else {
            report("consent-sign: argv must not be empty")
            return (4, nil)
        }

        // Display-digest binding: the digest AND the sheet text both derive from
        // request.argv right here. There is no path for a caller-composed reason.
        // The origin host folds into the SIGNED subject, so the displayed
        // "requested from" provenance is cryptographically bound.
        let subject = Subject.digest(argv: request.argv, originHost: request.requestedFrom ?? "")
        let reason = Subject.display(argv: request.argv, requestedFrom: request.requestedFrom)
        do {
            let (keyID, signature) = try await dependencies.attest(nonce, subject, reason)
            let response = ConsentSignResponse(keyID: keyID, sig: signature.base64EncodedString())
            return try (0, JSONEncoder().encode(response))
        } catch {
            return (reportFailure("consent-sign", error), nil)
        }
    }

    func keygen(_ arguments: [String]) -> (Int32, Data?) {
        guard arguments.isEmpty else { return (usage("keygen takes no arguments"), nil) }
        if let code = deniedCaller() {
            return (code, nil)
        }
        do {
            let attestor = SEAttestor()
            _ = try attestor.ensureKey()
            let (keyID, publicKey) = try attestor.publicKeyInfo()
            let response = KeygenResponse(keyID: keyID, publicKey: publicKey.base64EncodedString())
            return try (0, JSONEncoder().encode(response))
        } catch {
            return (reportFailure("keygen", error), nil)
        }
    }

    // MARK: - Vault

    func vaultEnroll(_ arguments: [String]) -> Int32 {
        guard arguments.count == 2 else {
            return usage("vault-enroll requires <vault-service> <source-service>")
        }
        if let code = deniedCaller() {
            return code
        }
        do {
            try Vault.enroll(vaultService: arguments[0], sourceService: arguments[1])
            return 0
        } catch {
            return reportFailure("vault-enroll", error)
        }
    }

    func vaultRetrieve(
        _ arguments: [String],
        environment: [String: String],
        biometricOnly: Bool
    ) async -> (Int32, Data?) {
        let name = biometricOnly ? "vault-retrieve-biometric" : "vault-retrieve"
        guard arguments.count == 1 else { return (usage("\(name) requires <vault-service>"), nil) }
        if let code = deniedCaller() {
            return (code, nil)
        }
        guard let reason = requiredReason(environment) else { return (4, nil) }
        do {
            let secret = biometricOnly
                ? try await Vault.retrieveBiometric(vaultService: arguments[0], reason: reason)
                : try await Vault.retrieve(vaultService: arguments[0], reason: reason)
            return (0, secret)
        } catch {
            return (reportFailure(name, error), nil)
        }
    }

    func vaultBatchRetrieve(
        _ arguments: [String],
        environment: [String: String]
    ) async -> (Int32, Data?) {
        guard !arguments.isEmpty, arguments.count.isMultiple(of: 2) else {
            return (usage("vault-batch-retrieve requires repeated <vault-service> <source-service> pairs"), nil)
        }
        if let code = deniedCaller() {
            return (code, nil)
        }
        guard let reason = requiredReason(environment) else { return (4, nil) }
        let items = stride(from: 0, to: arguments.count, by: 2).map {
            Vault.Item(vaultService: arguments[$0], sourceService: arguments[$0 + 1])
        }
        var output = Data()
        do {
            try await Vault.batchRetrieve(items: items, reason: reason) { line in
                output.append(Data(line.utf8))
            }
            return (0, output)
        } catch {
            // Per-item failures ride the emitted lines; a thrown failure aborts
            // the batch, but the lines already emitted still describe progress.
            return (reportFailure("vault-batch-retrieve", error), output)
        }
    }

    func vaultStatus(_ arguments: [String]) -> (Int32, Data?) {
        guard arguments.count == 1 else { return (usage("vault-status requires <vault-service>"), nil) }
        if let code = deniedCaller() {
            return (code, nil)
        }
        let (line, code) = dependencies.vaultStatus(arguments[0])
        return (code, Data(line.utf8))
    }

    // MARK: - Secure-Enclave cache

    func cache(_ subcommand: String, _ arguments: [String], input: () -> Data) -> (Int32, Data?) {
        guard arguments.count == 1 else { return (usage("\(subcommand) requires <label>"), nil) }
        if let code = deniedCaller() {
            return (code, nil)
        }
        let label = arguments[0]
        do {
            switch subcommand {
            case "cache-newkey":
                try SECache.newKey(label)
                return (0, nil)
            case "cache-wrap":
                return try (0, SECache.wrap(label, plaintext: input()))
            case "cache-unwrap":
                return try (0, SECache.unwrap(label, blob: input()))
            default:
                SECache.dropKey(label)
                return (0, nil)
            }
        } catch {
            return (reportFailure(subcommand, error), nil)
        }
    }

    // MARK: - Shared checks

    /// CallerCheck gates every prompting, signing, vault, and cache subcommand;
    /// any failure is exit 4 (caller-rejected — a hard failure, distinct from
    /// 2 unavailable), before a sheet could possibly appear or a keychain item
    /// could be touched.
    func deniedCaller() -> Int32? {
        do {
            try dependencies.checkCaller()
            return nil
        } catch {
            report("caller validation failed: \(error)")
            return 4
        }
    }

    func requiredReason(_ environment: [String: String]) -> String? {
        guard let reason = environment[Self.reasonEnvironmentVariable], !reason.isEmpty else {
            report("\(Self.reasonEnvironmentVariable) must be set for prompting subcommands")
            return nil
        }
        return reason
    }

    static var usageText: String {
        """
        usage: authkit <subcommand>
          consent                                      (reads \(reasonEnvironmentVariable))
          consent-sign                                 (stdin: {nonce, argv, requested_from?})
          keygen
          vault-enroll <vault-service> <source-service>
          vault-retrieve <vault-service>               (reads \(reasonEnvironmentVariable))
          vault-retrieve-biometric <vault-service>     (reads \(reasonEnvironmentVariable))
          vault-batch-retrieve <vault> <source> [...]  (reads \(reasonEnvironmentVariable))
          vault-status <vault-service>
          cache-newkey|cache-wrap|cache-unwrap|cache-dropkey <label>
        """
    }

    func usage(_ problem: String) -> Int32 {
        report(problem)
        report(Self.usageText)
        return 4
    }

    func reportFailure(_ operation: String, _ error: any Error) -> Int32 {
        if let failure = error as? HelperFailure {
            report("\(operation): \(failure.message)")
            return failure.exitCode
        }
        report("\(operation): \(error)")
        return 1
    }
}
