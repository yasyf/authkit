# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
