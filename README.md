# PostQuant

**Find quantum-vulnerable cryptography in your TLS endpoints.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/postquant)](https://www.npmjs.com/package/postquant)

PostQuant scans TLS connections and reports which algorithms are vulnerable to quantum attacks. It grades endpoints A+ through F and tells you what to migrate to.

> **Early development.** The TLS scanner works. Code scanning and CBOM generation are planned.

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

## Usage

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

## Development

```bash
npm install        # Install dependencies
npm run build      # Compile TypeScript
npm test           # Run tests
npm run dev -- scan example.com   # Run from source
```

## Roadmap

| Phase | Target | Status |
|-------|--------|--------|
| TLS scanner CLI | March 2026 | v0.1.0 |
| Code scanner (Python, JS, Go, Java) | April 2026 | Planned |
| CBOM generation + risk scoring | May 2026 | Planned |
| Web dashboard | June 2026 | Planned |

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
