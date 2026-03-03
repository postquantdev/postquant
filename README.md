# PostQuant

**Find quantum-vulnerable cryptography in your TLS endpoints and source code.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/postquant)](https://www.npmjs.com/package/postquant)

PostQuant scans TLS connections and source code, reports which algorithms are vulnerable to quantum attacks, grades them A+ through F, and tells you what to migrate to. Supports Python, JavaScript/TypeScript, Go, and Java.

## Why

NIST will **deprecate** RSA, ECC, and other quantum-vulnerable algorithms by **2030** and **disallow** them by **2035**. Adversaries are already harvesting encrypted traffic to decrypt later with quantum computers.

PostQuant shows you what's exposed.

## Quick Start

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

### Scan Source Code

```bash
npx postquant analyze ./src
```

Scans Python, JavaScript/TypeScript, Go, and Java files for quantum-vulnerable cryptographic patterns (RSA, ECDSA, ECDH, DH, DSA, MD5, SHA-1, DES/3DES, AES-128) and reports findings with migration recommendations.

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

### GitHub Actions

```yaml
- run: npx postquant analyze . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: postquant
```

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
| TLS scanner CLI | March 2026 | v0.1.0 |
| Code scanner (Python, JS, Go, Java) | March 2026 | v0.2.0 |
| Migration playbook engine | April 2026 | Planned |
| Web dashboard | May 2026 | Planned |

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
