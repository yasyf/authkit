# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-11-17

### Fixed
- The vault enrolls on a Mac with no usable Touch ID (no Touch ID keyboard
  connected, or no enrolled fingerprints). Its items now
  require user presence (biometrics or the passcode) instead of the current
  biometry set, which macOS cannot bind without a biometry database: every
  enrollment failed with OSStatus -25293 after a successful passcode entry, and
  cookiesync reported it as a cancelled Touch ID prompt.
- A failed authentication names its LAError code on stderr (`denied (LAError -2)`)
  instead of a bare `denied`.

## [0.3.0] - 2026-11-03

### Added
- `cci` is a pinned caller, so cc-inbox can endorse its mesh node key with one
  `consent-sign` under the Secure Enclave key.
- `AuthKitSubject` library product with the subject digest, display cleaning
  (`Subject.sanitized`), and `Attestation`, building for iOS 18 as well as macOS,
  so a phone approver signs the same bytes a Mac's helper signs. `AuthKit`
  re-exports it, so existing imports keep compiling.

### Fixed
- The consent sheet escapes control, format, and bidi characters reversibly
  (`\n`, `\r`, `\t`, `\u{XXXX}`, and a backslash as `\\`) instead of drawing
  U+FFFD, so a script with a hidden newline no longer renders like a harmless
  one with a literal replacement character.

## [0.1.0] - 2026-07-16

### Added
- First release of the signed Touch ID / Secure Enclave helper for the fleet,
  generalized from cookiesync-keyhelper so cc-sudo and cookiesync share one
  implementation. Ships as a Developer-ID-signed, notarized `.app` cask.
- `consent-sign` mints a Secure Enclave attestation under Touch ID over
  `nonce ‖ sha256(canonical(argv) ‖ 0x00 ‖ origin_host)`, displaying the exact
  argv it signs with no silent truncation and neutralizing Unicode format/bidi
  controls; `consent` (verdict-only), `keygen`, the biometry-bound `vault-*`
  subcommands, and the per-boot Secure-Enclave `cache-*` cache.
- The 0/1/2/3/4 exit-code wire ABI (4 = caller-rejected/usage error, distinct
  from 2 = no device auth mechanism) and an audit-token caller pin (Team ID + DR)
  in front of every prompting, signing, vault, and cache subcommand.
- The `AuthKit` SPM library ships plain-Security.framework verification helpers
  (`Attestation.verify`) so any process can check a signature without the helper.

[0.1.0]: https://github.com/yasyf/authkit/releases/tag/v0.1.0
