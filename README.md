# 🔐 PostQuant

**Scan your code and infrastructure for quantum-vulnerable cryptography.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/postquant)](https://www.npmjs.com/package/postquant)

PostQuant finds RSA, ECC, ECDH, ECDSA, and other quantum-vulnerable cryptography in your codebase and infrastructure. It tells you exactly what's at risk and how to migrate to NIST post-quantum standards (ML-KEM, ML-DSA, SLH-DSA).

> ⚠️ **Early development.** The scanner is being built. Star this repo to follow progress.

## Why This Matters

NIST has set hard deadlines. Quantum-vulnerable algorithms will be **deprecated by 2030** and **disallowed by 2035**. The "harvest now, decrypt later" threat means adversaries are already collecting encrypted data today to crack with quantum computers tomorrow.

Most organizations don't even know where their cryptography lives. PostQuant finds it for you.

## What It Will Do

- 🔍 **TLS Scanner** . Probe any endpoint and grade its quantum readiness
- 📝 **Code Scanner** . Detect crypto calls across Python, JavaScript, Go, and Java
- 📋 **CBOM Generator** . Produce a Cryptographic Bill of Materials
- 🎯 **Risk Scoring** . Prioritize findings by sensitivity, exposure, and data lifespan
- 🗺️ **Migration Roadmap** . Actionable steps to reach quantum safety

## Quick Start

```bash
# Install (coming soon)
npm install -g postquant

# Scan a TLS endpoint
postquant scan tls example.com

# Scan a codebase
postquant scan code ./my-project

# Generate a report
postquant report --format pdf
```

## Roadmap

| Phase | Target | Status |
|-------|--------|--------|
| TLS endpoint scanner | March 2026 | 🔨 Building |
| Code scanner (4 languages) | April 2026 | 📋 Planned |
| CBOM generation + risk scoring | May 2026 | 📋 Planned |
| Web dashboard + enterprise tier | June 2026 | 📋 Planned |

See [docs/ROADMAP.md](docs/ROADMAP.md) for details.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[MIT](LICENSE)

## Links

- 🌐 [postquant.dev](https://postquant.dev)
- 🐦 [@postquantdev](https://x.com/postquantdev)
- 📦 [npm](https://www.npmjs.com/package/postquant)
