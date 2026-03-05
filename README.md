# PostQuant

**Scan your TLS endpoints and source code for quantum-vulnerable cryptography. Get a letter grade. Know your risk. Plan your migration.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/postquant)](https://www.npmjs.com/package/postquant)

PostQuant scans TLS connections and source code, reports which algorithms are vulnerable to quantum attacks, grades them A+ through F, and tells you what to migrate to. Supports Python, JavaScript/TypeScript, Go, Java, C/C++, and Rust.

## What's New in v0.7.0

PostQuant now includes **AST analysis** for Python and JavaScript/TypeScript, running in parallel with regex pattern matching for higher-confidence detection and new capabilities that regex alone cannot achieve.

- **Tree-sitter AST analysis** — Parses Python and JS/TS source code into syntax trees for structural pattern matching. Findings from AST get `verified` confidence, the highest level.
- **Alias-aware detection** — `from cryptography import rsa as r; r.generate_private_key(...)` is now caught. Regex misses aliased imports; AST resolves them.
- **Multiline pattern matching** — WebCrypto `subtle.generateKey()` calls spanning multiple lines are now detected via AST.
- **Scope-aware risk signals** — Crypto calls inside test functions, pytest fixtures, or `describe`/`it` blocks are flagged as test code, reducing false-positive noise.
- **Zero-regression merge** — Both engines run independently. AST upgrades overlapping findings; regex-only findings pass through unchanged. Use `--no-ast` to disable.
- **18 AST patterns** — 11 Python + 7 JavaScript patterns covering RSA, ECDSA, DH, MD5, SHA-1, and WebCrypto.

### Previous: v0.6.0

- PQC readiness flag and 16 PQC detection patterns across 6 languages.
- C/C++ and Rust support. Context-aware risk assessment. Hybrid PQC detection.

## TLS Scan Results

| Site | Grade | Certificate | Key Exchange | Cipher | Hash |
|------|-------|-------------|--------------|--------|------|
| google.com | **C+** | RSA-2048 | X25519MLKEM768 :white_check_mark: | AES-256 | SHA-384 |
| cloudflare.com | **C+** | ECDSA P-256 | X25519MLKEM768 :white_check_mark: | AES-256 | SHA-384 |
| apple.com | **C+** | ECDSA P-256 | X25519MLKEM768 :white_check_mark: | AES-256 | SHA-384 |
| anthropic.com | **C+** | ECDSA P-256 | X25519MLKEM768 :white_check_mark: | AES-256 | SHA-384 |
| fbi.gov | **C+** | ECDSA P-256 | X25519MLKEM768 :white_check_mark: | AES-256 | SHA-384 |
| chase.com | **C** | RSA-2048 | X25519 :x: | AES-256 | SHA-256 |
| nsa.gov | **C+** | RSA-2048 | X25519 :x: | AES-256 | SHA-384 |
| irs.gov | **C-** | RSA-4096 | secp384r1 :x: | AES-256 | SHA-256 |

> Scanned with PostQuant v0.4.1+ on March 4, 2026. 24 of 55+ sites scanned have hybrid PQC deployed. No site scores above C+ — PQC certificates don't exist yet.

## Framework Scan Results

We scanned popular open-source frameworks with PostQuant v0.3.0:

| Project | Language | Grade | Critical | What We Found |
|---------|----------|-------|----------|---------------|
| Django | Python | **D+** | 2 | MD5 in auth hashers, SHA-1 in file uploads |
| FastAPI | Python | **A** | 0 | No quantum-vulnerable crypto detected |
| Express | JS | **A** | 0 | No quantum-vulnerable crypto detected |
| Gin | Go | **A** | 0 | No quantum-vulnerable crypto detected |

> Scanned with PostQuant v0.3.0 on March 3, 2026. Run `npx postquant analyze <path>` to scan your own projects.

> **Note:** v0.7.0 adds AST analysis for Python and JS/TS. Other languages use regex pattern matching only. Results may miss obfuscated or indirect crypto usage in non-AST languages.

## Package Scan Results

We scanned popular npm and PyPI packages. Context-aware risk assessment separates real threats from protocol compliance:

### npm Packages

| Package | Grade | Raw Findings | Adjusted Risk | What We Found |
|---------|-------|-------------|---------------|---------------|
| uuid | **A** | 4 critical | 4 low | MD5/SHA-1 for RFC 4122 checksums — not security |
| express-session | **A** | 2 critical | 2 low | SHA-1 for integrity checks — not auth |
| node-forge | **C+** | 4 critical | 4 critical | RSA in encryption — intentional crypto library |
| pg | **D+** | 4 critical | 4 critical | MD5 in PostgreSQL auth protocol |
| mysql2 | **D+** | 2 critical | 2 high | SHA-1 in MySQL auth_41 protocol |
| ssh2 | **D+** | 18 critical | 12 critical | DH, ECDH, Ed25519 in SSH key exchange |

### Python Packages

| Package | Grade | Raw Findings | Adjusted Risk | What We Found |
|---------|-------|-------------|---------------|---------------|
| requests | **A** | 5 critical | 3 low | MD5/SHA-1 in HTTP digest auth checksums |
| boto3 | **A** | 1 critical | 1 informational | MD5 for S3 protocol compliance |
| werkzeug | **C+** | 1 critical | 1 high | RSA in dev server TLS certificate |
| aiohttp | **D+** | 3 critical | 2 critical | Crypto usage in client fingerprinting |
| django | **D+** | 2 critical | 2 critical | MD5 in auth hashers, SHA-1 in uploads |
| paramiko | **D-** | 10 critical | 10 critical | ECDSA, X25519, DH throughout SSH protocol |

> Scanned with PostQuant v0.3.0 on March 3, 2026. "Raw Findings" = pattern matching only. "Adjusted Risk" = after context analysis.

## Risk Assessment

PostQuant v0.3.0 introduces context-aware risk assessment. Instead of blindly flagging every MD5 or SHA-1 as critical, the scanner reads surrounding code to understand *how* the algorithm is being used.

**How it works:**

1. **Pattern matching** finds cryptographic algorithm usage (MD5, SHA-1, RSA, ECDSA, etc.)
2. **Context analysis** examines the surrounding code — file paths, variable names, function calls, API patterns
3. **Risk adjustment** raises or lowers the finding's severity based on context signals

**Context signals that decrease risk:**
- Nearby code references `checksum`, `digest`, `fingerprint`, `uuid`
- File paths suggest test fixtures or protocol compliance
- API patterns match known non-security uses (e.g., PostgreSQL MD5 auth marked as legacy-support)

**Context signals that increase risk:**
- Nearby code references `password`, `authenticate`, `encrypt`, `secret`
- File paths contain `auth/`, `security/`, `crypto/`
- Algorithm used for digital signatures, key exchange, or session management

**Result:** `uuid` using MD5 for checksums scores **A**. Django using MD5 for password hashing scores **D+**. Same algorithm, different risk.

To disable context analysis and use raw pattern matching only:

```bash
npx postquant analyze . --no-context
```

## Why

NIST will **deprecate** RSA, ECC, and other quantum-vulnerable algorithms by **2030** and **disallow** them by **2035**. Adversaries are already harvesting encrypted traffic to decrypt later with quantum computers.

PostQuant shows you what's exposed.

## Quick Start

### TLS Scanning

```bash
npx postquant scan example.com
```

Output:

```
  Overall Grade:  C+

  Certificate
    Algorithm:    ECDSA P-256          🔴 Quantum Vulnerable

  Connection
    Protocol:     TLS 1.3              🟢 Current
    Key Exchange: X25519               🔴 Quantum Vulnerable
    Cipher:       AES-256              🟢 Quantum Safe
    MAC:          SHA-384              🟢 Quantum Safe
```

Most sites today score C+ or C. That's expected — almost nobody has deployed post-quantum cryptography yet.

### Code Scanner

Scan source code for quantum-vulnerable cryptographic patterns. 97 detection patterns across 6 languages (Python, JavaScript/TypeScript, Go, Java, C/C++, Rust) with context-aware risk assessment and AST analysis for Python and JS/TS.

```bash
# Scan your project
npx postquant analyze .

# Show all findings including low-risk ones
npx postquant analyze . --show-all

# Skip context analysis, raw pattern matching only
npx postquant analyze . --no-context

# Disable AST analysis (regex-only)
npx postquant analyze . --no-ast

# SARIF output for GitHub Code Scanning
npx postquant analyze ./src --format sarif

# CycloneDX CBOM for compliance
npx postquant analyze . --format cbom
```

Output with context labels:

```
  Overall Grade:  D+

  Findings

  django/contrib/auth/hashers.py (python)
    L669: MD5              🔴 Critical — authentication

  tests/file_uploads/tests.py (python)
    L120: SHA-1            🔴 Critical — digital signature

  Adjusted Risk (with context)
    🔴 2 critical
    🟢 4 low
    🟢 2 informational
```

## Usage

### TLS Scanning

```bash
# Scan a single host
postquant scan example.com

# Scan with explicit port
postquant scan example.com:8443

# Scan multiple hosts
postquant scan example.com api.example.com

# JSON output
postquant scan example.com --format json

# Read hosts from a file (one per line)
postquant scan --file hosts.txt

# Set connection timeout
postquant scan example.com --timeout 5000
```

### Code Scanning

```bash
# Scan a directory
postquant analyze ./src

# Scan a single file
postquant analyze ./src/auth.py

# Filter by language
postquant analyze ./src --language python
postquant analyze ./src --language c
postquant analyze ./src --language rust

# JSON output
postquant analyze ./src --format json

# SARIF output (for GitHub Code Scanning)
postquant analyze ./src --format sarif > results.sarif

# CycloneDX CBOM output
postquant analyze ./src --format cbom > cbom.json

# Exclude directories
postquant analyze . --ignore "vendor/**" --ignore "test/**"

# Set fail threshold for CI
postquant analyze ./src --fail-grade D

# Show all findings including low and informational risk
postquant analyze ./src --show-all

# Skip context analysis, use raw pattern matching only
postquant analyze ./src --no-context

# Disable AST analysis (regex-only, faster)
postquant analyze ./src --no-ast

# Show all findings including safe ones (legacy)
postquant analyze ./src --verbose
```

## Grading

| Grade | Meaning |
|-------|---------|
| **A+** | All quantum-safe algorithms (PQC key exchange + signatures) |
| **A** | Quantum-safe with minor observations |
| **B** | Mostly safe, some moderate-risk items (e.g., AES-128) |
| **C+** | Quantum-vulnerable, but best classical crypto (AES-256, SHA-384) |
| **C** | Quantum-vulnerable with some moderate items (SHA-256) |
| **C-** | Quantum-vulnerable with multiple moderate items |
| **D** | Multiple quantum-vulnerable components |
| **F** | Critical vulnerabilities + legacy protocols |

+/- modifiers reflect classical crypto hygiene within each grade band.

Starting in v0.6.0, scan output includes a `pqcDetected` flag indicating whether post-quantum algorithms were found, independent of the letter grade.

## GitHub Actions

Add quantum vulnerability scanning to your CI/CD pipeline:

```yaml
name: PostQuant Scan
on: [push, pull_request]
jobs:
  quantum-check:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: npx postquant analyze . --format sarif > postquant.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: postquant.sarif
```

Results appear directly in GitHub's **Security > Code scanning alerts** tab.

## Development

```bash
npm install        # Install dependencies
npm run build      # Compile TypeScript
npm test           # Run tests
npm run dev -- scan example.com      # TLS scan from source
npm run dev -- analyze ./src         # Code scan from source
```

## Roadmap

| Phase | Target | Status |
|-------|--------|--------|
| TLS scanner CLI | March 2026 | :white_check_mark: v0.1.0 |
| Code scanner + CBOM | March 2026 | :white_check_mark: v0.2.0 |
| Context-aware risk assessment | March 2026 | :white_check_mark: v0.3.0 |
| Hybrid PQC detection | March 2026 | :white_check_mark: v0.4.0 |
| Security hardening + input validation | March 2026 | :white_check_mark: v0.4.2 |
| C/C++ and Rust support | March 2026 | :white_check_mark: v0.5.0 |
| PQC detection patterns + readiness flag | March 2026 | :white_check_mark: v0.6.0 |
| AST analysis for Python and JS/TS | March 2026 | :white_check_mark: v0.7.0 |
| Migration playbook engine | April 2026 | Planned |
| Web dashboard + Enterprise tier | May 2026 | Planned |
| GitHub Actions Marketplace | June 2026 | Planned |

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.

## Limitations

PostQuant uses regex pattern matching for all 6 languages and tree-sitter AST analysis for Python and JavaScript/TypeScript. Known blind spots:

- **AST coverage is Python and JS/TS only** — Go, Java, C/C++, and Rust use regex-only detection. Aliased imports and multiline calls may be missed in those languages.
- **No cross-function data flow** — If a key size is defined in one function and used in another, the scanner won't correlate them.
- **No runtime analysis** — Crypto operations triggered by configuration files, environment variables, or runtime logic are not visible.
- **Key size extraction is best-effort** — Some patterns detect the algorithm but not the key size, especially for indirect parameter passing.

Context-aware risk assessment (v0.3.0+) and AST analysis (v0.7.0+) reduce false positives but cannot eliminate them entirely. When in doubt, PostQuant errs on the side of flagging (false positives over false negatives).

For the TLS scanner, detection accuracy depends on the server's TLS configuration and the local OpenSSL version. Hybrid PQC detection requires OpenSSL 3.5+.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

## Links

- [postquant.dev](https://postquant.dev)
- [@postquantdev](https://x.com/postquantdev)
- [npm](https://www.npmjs.com/package/postquant)
