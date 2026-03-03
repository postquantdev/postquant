# PostQuant

**Scan your TLS endpoints and source code for quantum-vulnerable cryptography. Get a letter grade. Know your risk. Plan your migration.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/postquant)](https://www.npmjs.com/package/postquant)

PostQuant scans TLS connections and source code, reports which algorithms are vulnerable to quantum attacks, grades them A+ through F, and tells you what to migrate to. Supports Python, JavaScript/TypeScript, Go, and Java.

## Framework Scan Results

We scanned popular open-source frameworks with PostQuant v0.2.0. Here's what we found:

| Project | Language | Grade | Critical Findings | What We Found |
|---------|----------|-------|-------------------|---------------|
| Go stdlib | Go | F | 161 | ECDSA, RSA, DH throughout the crypto package |
| Spring Boot | Java | D+ | 7 | RSA in OAuth2 auth server, SHA-1 in DevTools |
| Django | Python | D+ | 7 | MD5 in auth hashers, SHA-1 in template caching |
| Next.js | JS | D+ | 4 | MD5 + SHA-1 in Turbopack runtime |
| Node.js | JS | D+ | 6 | DH + ECDH in crypto.js, SHA-1 in TLS |
| Flask | Python | D+ | 1 | SHA-1 in session management |
| FastAPI | Python | A | 0 | No quantum-vulnerable crypto detected |
| Express | JS | A | 0 | No quantum-vulnerable crypto detected |
| Gin | Go | A | 0 | No quantum-vulnerable crypto detected |

> Scanned with PostQuant v0.2.0 on March 2, 2026. Run `npx postquant analyze <path>` to scan your own projects.

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

Scan source code for quantum-vulnerable cryptographic patterns. 54 detection patterns across 4 languages (Python, JavaScript/TypeScript, Go, Java) with zero new runtime dependencies.

```bash
# Scan your project
npx postquant analyze .

# SARIF output for GitHub Code Scanning
npx postquant analyze ./src --format sarif

# CycloneDX CBOM for compliance
npx postquant analyze . --format cbom

# Filter by language with verbose output
npx postquant analyze . --language python --verbose
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

# Show all findings including safe ones
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
| TLS scanner CLI | March 2026 | v0.2.0 |
| Code scanner + CBOM | March 2026 | v0.2.0 |
| Migration playbook engine | April 2026 | Planned |
| Web dashboard + Enterprise tier | May 2026 | Planned |
| GitHub Actions Marketplace + CI/CD | June 2026 | Planned |

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.

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
