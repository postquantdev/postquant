# TLS Scanner CLI — Design Document

**Date:** 2026-03-02
**Status:** Approved
**Phase:** 1

## Overview

PostQuant's first feature: a CLI that scans TLS endpoints and grades their quantum readiness A+ through F using Node's built-in `tls` module.

## Decisions

- **Scanner approach:** Pure Node `tls` module. No openssl dependency.
- **Multi-host scanning:** Sequential (one at a time).
- **Host file parsing:** Blank lines and `#` comments silently skipped.
- **Error handling:** Print error for failed host, continue to next. Non-zero exit if any host failed.
- **Verbosity:** `--verbose` flag shows raw TLS handshake details.
- **Exit codes:** Grade-based. A+/A/B = exit 0, C/D/F = exit 1. Configurable via `--fail-grade`.
- **Test framework:** Vitest with mocked TLS layer for unit tests.

## Dependencies

**Runtime:**
- `commander` — CLI argument parsing
- `chalk` — colored terminal output

**Dev:**
- `typescript` — build
- `tsx` — local dev (run TS without building)
- `vitest` — testing

**Node:** 18+ minimum.

**Module format:** ESM (`"type": "module"`).

## Architecture

```
CLI Input (commander)
    │
    ▼
scan.ts (command handler)
    │  parses hosts, reads --file, validates input
    │
    ▼
tls.ts (scanner)
    │  tls.connect() → extracts raw TLS data from socket
    │  Returns: TlsScanResult
    │
    ▼
classifier.ts
    │  Classifies each component's quantum risk
    │  Returns: ClassifiedResult
    │
    ▼
grader.ts
    │  Computes overall A+ through F grade
    │  Returns: GradedResult
    │
    ▼
terminal.ts or json.ts (output formatters)
    │  Renders final report to stdout
    │
    ▼
Exit code (grade-based)
```

### File Structure

```
src/
  index.ts              # CLI entry point (commander setup)
  commands/
    scan.ts             # scan command handler
  scanner/
    tls.ts              # TLS connection + data extraction
    classifier.ts       # Quantum risk classification
    grader.ts           # A-F grade calculation
  types/
    index.ts            # TypeScript interfaces
  output/
    terminal.ts         # Colored terminal output
    json.ts             # JSON output formatter
```

## TLS Scanner (`tls.ts`)

Connects via `tls.connect(port, host, { rejectUnauthorized: false })` with configurable timeout (default 10000ms). Scans regardless of cert validity — expired certs still have quantum-relevant algorithms.

**Data extracted:**

| Source | Data |
|---|---|
| `socket.getPeerCertificate(true)` | Cert algorithm, key size, curve, issuer, expiry, chain |
| `socket.getCipher()` | Cipher suite name, version, bits |
| `socket.getProtocol()` | Protocol version (TLSv1.3, TLSv1.2, etc.) |
| `socket.getEphemeralKeyInfo()` | Key exchange type, size, curve name |

**Edge case:** `getEphemeralKeyInfo()` can return null on some Node versions with TLS 1.3. Handle gracefully by falling back to cipher suite string parsing for key exchange info.

**Hybrid PQC detection:** Check `getEphemeralKeyInfo()` and `getCipher()` for strings containing `Kyber`, `MLKEM`, or `ML-KEM`. If found, key exchange classified as safe.

**Cipher suite parsing:** TLS 1.3 names follow `TLS_<bulk>_<mac>` (e.g., `TLS_AES_256_GCM_SHA384`). TLS 1.2 names include key exchange (e.g., `ECDHE-RSA-AES256-GCM-SHA384`).

## Classifier (`classifier.ts`)

Pure function. Takes raw TLS data, returns a list of classified findings.

**Five findings per scan:**

1. **Protocol version** — TLS 1.3 = safe, TLS 1.2 = moderate, TLS 1.1 and below = critical
2. **Certificate algorithm** — RSA/ECDSA/Ed25519 = critical, ML-DSA = safe
3. **Key exchange** — X25519/ECDHE/DHE = critical, X25519Kyber768 = safe
4. **Bulk cipher** — AES-256/ChaCha20 = safe, AES-128 = moderate
5. **Hash/MAC** — SHA-384/SHA-512 = safe, SHA-256 = moderate, SHA-1/MD5 = critical

**Each finding contains:** component name, algorithm, key size/curve, risk level (critical/moderate/safe), reason, migration recommendation.

**Unknown algorithms default to critical.** False positives are better than false negatives for a security tool.

### Full Classification Table

| Algorithm/Type | Risk | Reason |
|---|---|---|
| RSA (any size) | critical | Broken by Shor's algorithm |
| ECDSA / ECDH / Ed25519 / X25519 | critical | Broken by Shor's algorithm |
| DHE / DH | critical | Broken by Shor's algorithm |
| DSA | critical | Broken by Shor's algorithm |
| AES-256 / ChaCha20-Poly1305 | safe | Quantum-resistant at current key sizes |
| AES-128 | moderate | Grover's reduces to 64-bit effective security |
| SHA-384 / SHA-512 | safe | Sufficient post-quantum security margin |
| SHA-256 | moderate | Grover's reduces to 128-bit effective |
| SHA-1 / MD5 | critical | Already broken (not quantum-specific) |
| ML-KEM / ML-DSA / SLH-DSA / HQC | safe | NIST PQC standards |
| X25519Kyber768 (hybrid) | safe | PQC hybrid key exchange |
| TLS 1.3 | safe | Current protocol |
| TLS 1.2 | moderate | Aging but functional |
| TLS 1.1 and below | critical | Already insecure |

## Grader (`grader.ts`)

Takes classified findings, returns an overall grade. Rule-based, first match wins:

| Grade | Rule |
|---|---|
| **F** | Any critical protocol finding (TLS 1.1 or below), or hash is SHA-1/MD5 |
| **D** | 3+ critical findings |
| **C** | 1-2 critical findings |
| **B** | Zero critical, 1+ moderate findings |
| **A** | Zero critical, zero moderate |
| **A+** | Zero critical, zero moderate, and at least one PQC algorithm detected |

Most sites today score C (quantum-vulnerable cert + key exchange, but TLS 1.3 + AES-256-GCM + SHA-384).

**Migration notes:** Static recommendations mapped to finding type (e.g., critical cert = "Migrate to ML-DSA (FIPS 204)").

**Exit codes:** A+/A/B = 0, C/D/F = 1. `--fail-grade` adjusts the threshold.

## Output Formatters

**Terminal (`terminal.ts`):**
Colored output with chalk. Red for critical, yellow for moderate, green for safe. Sections: header, grade, certificate, connection, summary, migration notes. Verbose mode adds raw TLS details section.

**JSON (`json.ts`):**
Structured output with version, timestamp, target, grade, findings array, summary counts. Verbose mode adds `rawDetails` object.

**Multi-host:** Terminal format separates hosts with blank lines. JSON outputs an array.

## CLI Interface

```
postquant scan <hosts...> [options]

Options:
  --format <terminal|json>   Output format (default: terminal)
  --file <path>              Read hosts from file
  --timeout <ms>             Connection timeout (default: 10000)
  --verbose                  Show raw TLS details
  --fail-grade <grade>       Exit threshold (default: C)
  --version                  Show version
  --help                     Show help
```

## Testing Strategy

**Unit tests (mocked, deterministic):**
- `classifier.test.ts` — Every row in the classification table. Unknown algorithm handling.
- `grader.test.ts` — One test per grade level (A+ through F). Exit code threshold logic.
- `tls.test.ts` — Mocked `tls.connect()` with fake socket objects. Null `getEphemeralKeyInfo()` case.
- `terminal.test.ts` / `json.test.ts` — Output format validation against known inputs.

**Integration tests (network-dependent, skippable):**
- Scan 2-3 known hosts, assert valid `ScanReport` structure. Gated behind `RUN_INTEGRATION=true`.

**Coverage goal:** Classifier and grader at 100%. Scanner and formatters tested for structure.
