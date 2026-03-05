# Changelog

## v0.7.0 — 2026-03-04

**AST Analysis for Python and JavaScript/TypeScript**

- Add tree-sitter AST analysis running in parallel with regex pattern matching
- 18 AST patterns (11 Python + 7 JavaScript) with `verified` confidence level
- Alias-aware detection — resolves `import rsa as r` and `const { createHash: hash } = require('crypto')`
- Multiline pattern matching — catches `subtle.generateKey()` calls spanning multiple lines
- Scope-aware risk signals — test functions, pytest fixtures, `describe`/`it` blocks flagged as test code
- Zero-regression merge — AST upgrades overlapping findings, regex-only pass through unchanged
- Import resolver for Python (`import`, `from...import`, aliases) and JS (`import`, `require`, destructuring)
- Variable resolver tracks local string/number assignments for indirect algorithm references
- Add `--no-ast` flag to disable AST analysis
- Add `ScopeInfo` type with `functionName`, `className`, `isTestCode`, `isConditionalPath`
- Add `ast-scope` context signal type for risk assessment integration

## v0.6.0 — 2026-03-04

- PQC readiness flag (`pqcDetected`) on every scan
- 16 PQC detection patterns across 6 languages (liboqs, pqcrypto, circl, Bouncy Castle PQC)
- C/C++ and Rust language support (OpenSSL, libsodium, wolfSSL, mbedTLS, ring, RustCrypto)
- Context-aware grading overhaul with +/- modifiers
- Hybrid PQC detection (X25519MLKEM768) via OpenSSL probing
- Security hardening with two-layer input validation

## v0.5.0 — 2026-03-03

- C/C++ and Rust pattern coverage
- Key-size-aware risk for AES patterns

## v0.4.0 — 2026-03-03

- Hybrid PQC key exchange detection (X25519Kyber768 / X25519+ML-KEM-768)
- OpenSSL version warnings

## v0.3.0 — 2026-03-03

- Context-aware risk assessment
- SARIF and CycloneDX CBOM output formats
- GitHub Actions integration

## v0.2.0 — 2026-03-02

- Code scanner with pattern matching across Python, JavaScript, Go, Java
- 81 classical crypto detection patterns

## v0.1.0 — 2026-03-02

- TLS scanner CLI with quantum readiness grading (A+ through F)
- Certificate, key exchange, cipher, and hash algorithm analysis
