# authkit Development Guide

A signed macOS helper for Touch ID consent and Secure Enclave attestation.

## Repository Structure

```
authkit/
├── Package.swift               # SPM manifest — targets, products, dependencies
├── Sources/
│   ├── AuthKitLib/        # the library — all logic lives here
│   └── authkit/       # the executable — a thin ArgumentParser shell
├── Tests/AuthKitLibTests/ # Swift Testing (@Test / #expect) against the library
├── .github/                    # GitHub Actions workflows
├── AGENTS.md                   # This file — shared conventions
└── README.md                   # Project overview
```
