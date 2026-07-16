# authkit

**One signed binary that talks to Touch ID and the Secure Enclave for the fleet.** cc-sudo, synckit, and cookiesync all need the same thing — a native consent sheet whose approval is provable — without holding Enclave keys themselves; authkit is that helper.

[![CI](https://img.shields.io/github/actions/workflow/status/yasyf/authkit/ci.yml?branch=main&label=ci)](https://github.com/yasyf/authkit/actions/workflows/ci.yml)
[![License: PolyForm-Noncommercial-1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](https://github.com/yasyf/authkit/blob/main/LICENSE)

## Get started

```bash
brew install yasyf/tap/authkit
```

The cask stages `authkit.app` in the Homebrew Caskroom and leaves it there — the bundle must stay intact because the embedded provisioning profile that authorizes the Secure Enclave is bundle-relative. You don't invoke it by hand: cc-sudo and cookiesync resolve the inner binary (by globbing the Caskroom, or from `AUTHKIT_HELPER` when set) and drive its subcommands. Every prompting, signing, vault, and cache subcommand validates its caller's code signature and refuses an unpinned invoker — a shell included — with exit 4, before any sheet appears.

Driving with an agent? Paste this:

```text
authkit is the fleet's signed Touch ID / Secure Enclave helper — a dependency of cc-sudo and cookiesync, not a standalone CLI. Read AGENTS.md and STYLEGUIDE.md, then `swift build && swift test`; hardware-dependent Enclave tests skip themselves headless.
```

---

## Use cases

### Prove a consent decision, don't just report it

A verdict message on an attacker-controllable socket proves nothing. authkit's `consent-sign` reads `{nonce, argv, requested_from?}` on stdin, signs `nonce ‖ sha256(argv)` with a Secure Enclave key whose ACL demands current biometrics or the device passcode, and writes `{key_id, sig}`. The Touch ID sheet *is* the signing operation — a transport can carry the signature but cannot mint one. Verification needs no privileged binary: the `AuthKit` SPM library ships plain-Security.framework helpers (`Attestation.verify`) any process can call.

### Show the human exactly what they authorize

`consent-sign` computes the subject digest from the argv it received and renders that same argv in the sheet with no silent truncation: control and Unicode format/bidi characters are neutralized, an over-long element is middle-elided with a visible `[N chars]` marker, dropped arguments become a quantified `(+K more arguments)` marker, and the full 64-hex `sha256(canonical argv)` prints on its own line. The origin host folds into the signed subject, so a spoofed "requested from" label fails verification. It never accepts a caller-composed reason — a lying transport cannot show `ls` while `rm -rf /` gets signed.

### Read one exit code across three languages

Every subcommand reports its verdict as the process exit code — a wire ABI shared with the Go bridge in synckit and the root verifier in cc-sudo. Codes 0–3 match cookiesync-keyhelper's; 4 is authkit's addition for the caller pin keyhelper never had.

| Exit | Meaning |
|------|---------|
| 0 | approved / ok |
| 1 | denied, cancelled, or the operation failed |
| 2 | unavailable: the device has no biometry or passcode mechanism — the sole code a consumer may degrade on |
| 3 | screen locked / no user present — retry after unlock, or route to a peer |
| 4 | caller rejected or usage error: an unpinned invoker, bad arity, malformed stdin, missing `AUTHKIT_REASON` — a hard failure no consumer may degrade on |

### Hold biometry-bound secrets for cookiesync

The `vault-*` subcommands are a biometry-bound Keychain vault (cookiesync-keyhelper parity), and `cache-*` is a per-boot Secure-Enclave ECIES cache. authkit carries cookiesync-keyhelper's keychain access group verbatim, so an existing cookiesync install swaps helpers with no vault re-enrollment.

<details>
<summary><strong>Subcommand reference</strong></summary>

| Subcommand | Does |
|------------|------|
| `consent` | Verdict-only Touch ID sheet; prompt text from `AUTHKIT_REASON` (required) |
| `consent-sign` | Reads `{nonce, argv, requested_from?}` on stdin, signs `nonce ‖ sha256(argv)` under user presence, writes `{key_id, sig}` |
| `keygen` | Creates the Enclave attestation key on first run and emits `{key_id, public_key}` for root-owned enrollment |
| `vault-enroll` / `vault-retrieve` / `vault-retrieve-biometric` / `vault-batch-retrieve` / `vault-status` | Biometry-bound Keychain vault |
| `cache-newkey` / `cache-wrap` / `cache-unwrap` / `cache-dropkey` | Per-boot Secure-Enclave ECIES cache |

The subject digest is SHA-256 over a length-prefixed argv encoding (8-byte big-endian byte count per argument), a `0x00` separator, and the UTF-8 origin host (`requested_from`, empty for a local request) — see `Sources/AuthKit/Subject.swift`. `key_id` is the hex SHA-256 of the X9.63 public key.

</details>

## Security model

- **Callers are pinned by audit token, not PID.** Every prompting, signing, vault, and cache subcommand resolves its invoker from the audit token (which binds the exact process incarnation) and validates it against a pinned Team ID + designated requirement. An unpinned invoker gets exit 4 and no sheet. The pin is a DR, not a bare cdhash, so a legitimately re-signed release keeps validating while a differently-signed stub fails closed.
- **Nothing sensitive runs unsigned.** authkit ships only as a hardened-runtime, Developer-ID-signed, notarized `.app` with library validation on and the minimal entitlement set: the keychain access group and the app identifier. An unsigned build cannot touch the Enclave at all.
- **The helper is defense-in-depth, not the boundary.** Under the exec/stdin transport an audit token is self-reported, so authkit's caller pin raises the bar on prompt-phishing but is not the escalation boundary; in cc-sudo that role belongs to the root-side path pin, the Touch ID tap, and the root-generated nonce.

## Development

```bash
swift build && swift test          # hardware-dependent tests skip themselves headless
bash build-app.sh SXKCTF23Q2       # assemble the UNSIGNED .app bundle locally
AUTHKIT_HARDWARE_TESTS=1 swift test   # Enclave round-trips, needs the signed helper
```

Signing, notarization, stapling, and the cask push happen in `.github/workflows/release.yml` on a `v*` tag. Conventions live in [AGENTS.md](AGENTS.md) and [STYLEGUIDE.md](STYLEGUIDE.md).

Licensed under [PolyForm-Noncommercial-1.0.0](LICENSE).
