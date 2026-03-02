# PostQuant Phase 2: Code Scanner — Technical Specification

**Version:** 1.0  
**Date:** March 2, 2026  
**Status:** Draft  
**Author:** Bobby (AI assistant to Marco Figueroa)  
**Audience:** Claude Code / Windsurf (implementation agent)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [CLI Interface](#3-cli-interface)
4. [Detection Engine: What It Detects](#4-detection-engine-what-it-detects)
5. [Pattern Matching Strategy](#5-pattern-matching-strategy)
6. [Grading System](#6-grading-system)
7. [CBOM Output (Cryptographic Bill of Materials)](#7-cbom-output)
8. [SARIF Output (GitHub Code Scanning)](#8-sarif-output)
9. [Migration Recommendations](#9-migration-recommendations)
10. [Type System Integration](#10-type-system-integration)
11. [Testing Strategy](#11-testing-strategy)
12. [Implementation Plan](#12-implementation-plan)
13. [Competitive Analysis](#13-competitive-analysis)
14. [Future Considerations](#14-future-considerations)

---

## 1. Executive Summary

Phase 2 adds source code scanning to PostQuant. While the TLS scanner (Phase 1) tells organizations "your connections are quantum-vulnerable," the code scanner tells them "here's exactly where in your code, and here's how to fix it."

**The value proposition:** TLS grades are something nobody can currently improve (no CA issues PQC certs yet). Code findings are *actionable today* — developers can replace RSA key generation with ML-DSA, swap ECDH for ML-KEM, upgrade AES-128 to AES-256, etc.

**Scope:** Scan source code files for quantum-vulnerable cryptographic patterns across Python, JavaScript/TypeScript, Go, and Java. Output findings with grades, migration recommendations, and optional CBOM/SARIF reports.

**Non-goals for v1:**
- Binary/bytecode scanning (IBM Quantum Safe Explorer does this; we focus on source)
- Runtime/dynamic analysis (SandboxAQ does this with their Application Analyzer)
- Dependency graph resolution (future: detect transitive crypto via package manifests)
- Auto-fix/auto-remediation (Phase 3: Migration Playbook Engine)

---

## 2. Architecture Overview

### 2.1 Existing Architecture (Phase 1)

The current PostQuant codebase follows a 5-layer pipeline:

```
Input → Scanner → Classifier → Grader → Formatter → Exit Code
```

- **Scanner** (`src/scanner/tls.ts`): Connects to TLS endpoints, extracts raw data
- **Classifier** (`src/scanner/classifier.ts`): Converts raw data into `ClassifiedFinding[]`
- **Grader** (`src/scanner/grader.ts`): Converts `ClassifiedResult` into `GradedResult` with A+–F grade
- **Formatter** (`src/output/terminal.ts`, `src/output/json.ts`): Renders output
- **Command** (`src/commands/scan.ts`): Orchestrates the pipeline

### 2.2 Phase 2 Architecture

The code scanner follows the same 5-layer pattern but with a different scanner layer:

```
File Discovery → Pattern Matching → Classification → Grading → Formatting
```

```
src/
├── types/
│   └── index.ts              # Extended with code scanner types
├── scanner/
│   ├── tls.ts                # Phase 1 (unchanged)
│   ├── classifier.ts         # Phase 1 classifier (unchanged)
│   ├── grader.ts             # Phase 1 grader (unchanged)
│   └── code/
│       ├── discovery.ts      # File discovery + language detection
│       ├── patterns/
│       │   ├── index.ts      # Pattern registry
│       │   ├── python.ts     # Python crypto patterns
│       │   ├── javascript.ts # JS/TS crypto patterns
│       │   ├── go.ts         # Go crypto patterns
│       │   └── java.ts       # Java crypto patterns
│       ├── matcher.ts        # Pattern matching engine
│       ├── classifier.ts     # Code finding classifier
│       └── grader.ts         # Code-specific grading logic
├── output/
│   ├── terminal.ts           # Extended for code findings
│   ├── json.ts               # Extended for code findings
│   ├── sarif.ts              # NEW: SARIF 2.1.0 output
│   └── cbom.ts               # NEW: CycloneDX CBOM output
├── commands/
│   ├── scan.ts               # Phase 1 (unchanged)
│   └── analyze.ts            # NEW: Code scanning command
└── index.ts                  # Extended with `analyze` command
```

### 2.3 Design Principles

1. **Zero dependencies for scanning.** Pattern matching uses only Node.js built-ins (fs, path, readline). No tree-sitter, no semgrep dependency.
2. **Language-agnostic core.** The matcher engine is generic; language-specific knowledge lives entirely in pattern definition files.
3. **Streaming file processing.** Read files line-by-line for memory efficiency. Don't load entire codebases into memory.
4. **Deterministic output.** Same input always produces same output. No network calls, no randomness.
5. **Type-safe pipeline.** Every layer has typed inputs/outputs. Findings flow through the same `ClassifiedFinding` → `GradedResult` pattern as Phase 1.

---

## 3. CLI Interface

### 3.1 Command: `postquant analyze`

```bash
# Scan a directory or file
postquant analyze <path>

# Scan current directory
postquant analyze .

# Scan with language filter
postquant analyze <path> --language python
postquant analyze <path> --language javascript
postquant analyze <path> --language go
postquant analyze <path> --language java

# Output formats
postquant analyze <path> --format terminal    # Default: colored terminal output
postquant analyze <path> --format json        # JSON report
postquant analyze <path> --format sarif       # SARIF 2.1.0 for GitHub Code Scanning
postquant analyze <path> --format cbom        # CycloneDX CBOM 1.6

# Control behavior
postquant analyze <path> --fail-grade C       # Exit non-zero at grade C or worse (default: C)
postquant analyze <path> --ignore "vendor/**" # Glob patterns to exclude
postquant analyze <path> --ignore-file .postquantignore  # Read ignore patterns from file
postquant analyze <path> --max-files 1000     # Limit file count (default: 10000)
postquant analyze <path> --verbose            # Show all findings including safe ones
postquant analyze <path> --no-migration       # Hide migration recommendations

# Combine with TLS scanning
postquant scan google.com && postquant analyze ./src
```

### 3.2 Options Specification

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `<path>` | positional | required | Directory or file to scan |
| `--format, -f` | string | `terminal` | Output format: `terminal`, `json`, `sarif`, `cbom` |
| `--language, -l` | string | (auto) | Filter: `python`, `javascript`, `go`, `java` |
| `--fail-grade` | string | `C` | Exit 1 at this grade or worse |
| `--ignore` | string[] | `[]` | Glob patterns to exclude |
| `--ignore-file` | string | `.postquantignore` | File with ignore patterns (like .gitignore) |
| `--max-files` | number | `10000` | Maximum files to scan |
| `--verbose` | boolean | `false` | Show safe findings too |
| `--no-migration` | boolean | `false` | Hide migration notes |

### 3.3 Exit Codes

Consistent with Phase 1 TLS scanner:

| Code | Meaning |
|------|---------|
| `0` | Scan completed, grade above threshold |
| `1` | Scan completed, grade at or below threshold (or errors occurred) |

### 3.4 `.postquantignore` File

Follows `.gitignore` syntax. Default ignores (built-in):

```gitignore
# Default ignores (always applied)
node_modules/
vendor/
.git/
dist/
build/
__pycache__/
*.min.js
*.bundle.js
*.map
package-lock.json
yarn.lock
go.sum
```

---

## 4. Detection Engine: What It Detects

### 4.1 Quantum Vulnerability Categories

Every finding is classified into one of these categories:

| Category | Risk | Quantum Threat | Examples |
|----------|------|----------------|----------|
| `asymmetric-encryption` | critical | Shor's algorithm breaks it completely | RSA encryption, ElGamal |
| `digital-signature` | critical | Shor's algorithm breaks it completely | RSA-PSS, ECDSA, EdDSA |
| `key-exchange` | critical | Shor's algorithm breaks it completely | ECDH, DH, X25519 |
| `weak-symmetric` | moderate | Grover's reduces security by half | AES-128 (→ 64-bit effective) |
| `weak-hash` | critical | Already broken classically | MD5, SHA-1 in any context |
| `hash-in-signature` | moderate | Safe for hashing, quantum implications for signature schemes | SHA-256 when used within a signature |
| `safe-symmetric` | safe | Quantum-resistant | AES-256, ChaCha20 |
| `safe-hash` | safe | Quantum-resistant | SHA-384, SHA-512, SHA-3 |
| `pqc-algorithm` | safe | Post-quantum standard | ML-KEM, ML-DSA, SLH-DSA |

### 4.2 Python Patterns

#### 4.2.1 `cryptography` library (pyca/cryptography)

```python
# RSA Key Generation — CRITICAL
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa.generate_private_key(public_exponent=65537, key_size=4096)

# RSA Signing — CRITICAL  
from cryptography.hazmat.primitives.asymmetric import padding
private_key.sign(data, padding.PSS(...), hashes.SHA256())
private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

# RSA Encryption — CRITICAL
public_key.encrypt(data, padding.OAEP(...))

# EC Key Generation — CRITICAL
from cryptography.hazmat.primitives.asymmetric import ec
ec.generate_private_key(ec.SECP256R1())
ec.generate_private_key(ec.SECP384R1())
ec.generate_private_key(ec.SECP521R1())

# ECDSA Signing — CRITICAL
private_key.sign(data, ec.ECDSA(hashes.SHA256()))

# ECDH Key Exchange — CRITICAL
private_key.exchange(ec.ECDH(), peer_public_key)

# X25519 Key Exchange — CRITICAL
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
X25519PrivateKey.generate()
private_key.exchange(peer_public_key)

# Ed25519 Signing — CRITICAL
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
Ed25519PrivateKey.generate()

# X448/Ed448 — CRITICAL
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

# DSA (legacy) — CRITICAL
from cryptography.hazmat.primitives.asymmetric import dsa
dsa.generate_private_key(key_size=2048)

# DH Key Exchange — CRITICAL
from cryptography.hazmat.primitives.asymmetric import dh
dh.generate_parameters(generator=2, key_size=2048)

# AES (check key size) — MODERATE if 128, SAFE if 256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
Cipher(algorithms.AES(key), ...)  # key length determines risk
algorithms.AES128(key)  # MODERATE
algorithms.AES256(key)  # SAFE

# Hashing — varies
from cryptography.hazmat.primitives import hashes
hashes.MD5()     # CRITICAL
hashes.SHA1()    # CRITICAL
hashes.SHA256()  # SAFE (for hashing), MODERATE (in signatures)
hashes.SHA384()  # SAFE
hashes.SHA512()  # SAFE
hashes.SHA3_256()  # SAFE
hashes.SHA3_384()  # SAFE
hashes.SHA3_512()  # SAFE
```

#### 4.2.2 `pycryptodome` / `pycryptodomex`

```python
# RSA — CRITICAL
from Crypto.PublicKey import RSA
RSA.generate(2048)
RSA.generate(4096)
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15, pss

# ECC — CRITICAL
from Crypto.PublicKey import ECC
ECC.generate(curve='P-256')
ECC.generate(curve='P-384')
ECC.generate(curve='Ed25519')
from Crypto.Signature import DSS

# DSA — CRITICAL
from Crypto.PublicKey import DSA
DSA.generate(2048)

# AES — check key size
from Crypto.Cipher import AES
AES.new(key, AES.MODE_GCM)

# Hashing
from Crypto.Hash import MD5, SHA1, SHA256, SHA384, SHA512, SHA3_256
```

#### 4.2.3 `hashlib`

```python
import hashlib
hashlib.md5(data)         # CRITICAL
hashlib.sha1(data)        # CRITICAL
hashlib.sha256(data)      # SAFE
hashlib.sha384(data)      # SAFE
hashlib.sha512(data)      # SAFE
hashlib.sha3_256(data)    # SAFE
hashlib.new('md5', data)  # CRITICAL
hashlib.new('sha1', data) # CRITICAL
hashlib.pbkdf2_hmac('sha256', ...)  # SAFE (symmetric derivation)
```

#### 4.2.4 `ssl` module

```python
import ssl
ssl.create_default_context()  # INFO: uses system TLS (likely quantum-vulnerable key exchange)
ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # Same
```

### 4.3 JavaScript / TypeScript Patterns

#### 4.3.1 Node.js `crypto` / `node:crypto`

```javascript
// RSA Key Generation — CRITICAL
import { generateKeyPairSync, generateKeyPair } from 'crypto';
import { generateKeyPairSync, generateKeyPair } from 'node:crypto';
const { generateKeyPairSync } = require('crypto');

generateKeyPairSync('rsa', { modulusLength: 2048 })
generateKeyPairSync('rsa', { modulusLength: 4096 })
generateKeyPairSync('rsa-pss', { modulusLength: 2048 })
generateKeyPair('rsa', { modulusLength: 2048 }, callback)

// EC Key Generation — CRITICAL
generateKeyPairSync('ec', { namedCurve: 'P-256' })
generateKeyPairSync('ec', { namedCurve: 'secp256k1' })
generateKeyPairSync('ec', { namedCurve: 'P-384' })

// Ed25519/Ed448 — CRITICAL
generateKeyPairSync('ed25519')
generateKeyPairSync('ed448')
generateKeyPairSync('x25519')
generateKeyPairSync('x448')

// DSA — CRITICAL
generateKeyPairSync('dsa', { modulusLength: 2048 })

// DH Key Exchange — CRITICAL
import { createDiffieHellman, createECDH, diffieHellman } from 'crypto';
createDiffieHellman(2048)
createECDH('secp256k1')
createECDH('prime256v1')

// Signing — CRITICAL (when using RSA/EC)
import { createSign, createVerify, sign, verify } from 'crypto';
createSign('SHA256')    // Algorithm inferred from key type
sign('sha256', data, privateKey)

// Hashing
import { createHash, createHmac } from 'crypto';
createHash('md5')       // CRITICAL
createHash('sha1')      // CRITICAL
createHash('sha256')    // SAFE
createHash('sha384')    // SAFE
createHash('sha512')    # SAFE

// Cipher (check algorithm string)
import { createCipheriv, createDecipheriv } from 'crypto';
createCipheriv('aes-128-gcm', key, iv)  // MODERATE
createCipheriv('aes-256-gcm', key, iv)  // SAFE
createCipheriv('aes-128-cbc', key, iv)  // MODERATE
createCipheriv('aes-256-cbc', key, iv)  // SAFE
createCipheriv('des-ede3-cbc', key, iv) // CRITICAL (3DES)
```

#### 4.3.2 Web Crypto API

```javascript
// SubtleCrypto — works in browsers AND Node.js
// RSA Key Generation — CRITICAL
crypto.subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 2048, ... }, ...)
crypto.subtle.generateKey(
  { name: 'RSA-PSS', modulusLength: 2048, ... }, ...)
crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, ... }, ...)

// EC Key Generation — CRITICAL
crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' }, ...)
crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-384' }, ...)

// Signing — CRITICAL (RSA/EC based)
crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, data)
crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data)

// Hashing
crypto.subtle.digest('SHA-1', data)   // CRITICAL
crypto.subtle.digest('SHA-256', data) // SAFE
crypto.subtle.digest('SHA-384', data) // SAFE
crypto.subtle.digest('SHA-512', data) // SAFE

// Key Import — CRITICAL (importing RSA/EC keys)
crypto.subtle.importKey('jwk', jwkKey, { name: 'RSA-OAEP' }, ...)
crypto.subtle.importKey('raw', key, { name: 'ECDH', namedCurve: 'P-256' }, ...)

// AES
crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, ...) // MODERATE
crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, ...) // SAFE
```

#### 4.3.3 JWT Libraries (`jose`, `jsonwebtoken`)

```javascript
// jsonwebtoken — CRITICAL (RSA/EC signatures)
import jwt from 'jsonwebtoken';
jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS256' })  // RSA — CRITICAL
jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS384' })  // RSA — CRITICAL
jwt.sign(payload, rsaPrivateKey, { algorithm: 'RS512' })  // RSA — CRITICAL
jwt.sign(payload, ecPrivateKey, { algorithm: 'ES256' })   // ECDSA — CRITICAL
jwt.sign(payload, ecPrivateKey, { algorithm: 'ES384' })   // ECDSA — CRITICAL
jwt.sign(payload, ecPrivateKey, { algorithm: 'ES512' })   // ECDSA — CRITICAL
jwt.sign(payload, secret, { algorithm: 'HS256' })         // HMAC — SAFE (symmetric)
jwt.sign(payload, edKey, { algorithm: 'EdDSA' })          // EdDSA — CRITICAL

// jose library
import { SignJWT, jwtVerify, CompactEncrypt } from 'jose';
new SignJWT(payload).setProtectedHeader({ alg: 'RS256' })   // CRITICAL
new SignJWT(payload).setProtectedHeader({ alg: 'ES256' })   // CRITICAL
new SignJWT(payload).setProtectedHeader({ alg: 'PS256' })   // CRITICAL (RSA-PSS)
new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA' })   // CRITICAL
new SignJWT(payload).setProtectedHeader({ alg: 'HS256' })   // SAFE

// jose key generation
import { generateKeyPair } from 'jose';
generateKeyPair('RS256')  // CRITICAL
generateKeyPair('ES256')  // CRITICAL
generateKeyPair('EdDSA')  // CRITICAL
```

### 4.4 Go Patterns

#### 4.4.1 Standard Library (`crypto/*`)

```go
// RSA — CRITICAL
import "crypto/rsa"
rsa.GenerateKey(rand.Reader, 2048)
rsa.GenerateKey(rand.Reader, 4096)
rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed, opts)
rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
rsa.DecryptOAEP(...)
rsa.DecryptPKCS1v15(...)

// ECDSA — CRITICAL
import "crypto/ecdsa"
ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
ecdsa.Sign(rand.Reader, privateKey, hash)
ecdsa.SignASN1(rand.Reader, privateKey, hash)
ecdsa.Verify(publicKey, hash, r, s)
ecdsa.VerifyASN1(publicKey, hash, sig)

// Elliptic curves — CRITICAL (direct usage implies ECC)
import "crypto/elliptic"
elliptic.P224()
elliptic.P256()
elliptic.P384()
elliptic.P521()
elliptic.GenerateKey(curve, rand.Reader)
elliptic.Marshal(curve, x, y)

// Ed25519 — CRITICAL
import "crypto/ed25519"
ed25519.GenerateKey(rand.Reader)
ed25519.Sign(privateKey, message)

// DSA (legacy) — CRITICAL
import "crypto/dsa"
dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
dsa.GenerateKey(&privateKey, rand.Reader)

// Hashing
import "crypto/md5"    // CRITICAL
import "crypto/sha1"   // CRITICAL
import "crypto/sha256" // SAFE
import "crypto/sha512" // SAFE
md5.New()
md5.Sum(data)
sha1.New()
sha1.Sum(data)
sha256.New()
sha256.Sum256(data)
sha512.New()

// AES (key size from usage)
import "crypto/aes"
aes.NewCipher(key)  // Key length determines risk: 16=MODERATE, 32=SAFE

// TLS config
import "crypto/tls"
tls.Config{...}  // INFO: TLS config detected, consider PQC key exchange
```

#### 4.4.2 Extended Library (`golang.org/x/crypto`)

```go
// Curve25519 — CRITICAL
import "golang.org/x/crypto/curve25519"
curve25519.ScalarMult(dst, scalar, point)
curve25519.X25519(scalar, point)

// Ed25519 (extended) — CRITICAL
import "golang.org/x/crypto/ed25519"

// NaCl box/sign — CRITICAL (uses Curve25519/Ed25519)
import "golang.org/x/crypto/nacl/box"
import "golang.org/x/crypto/nacl/sign"
box.GenerateKey(rand.Reader)
box.Seal(out, message, nonce, peerPublic, privateKey)

// ChaCha20-Poly1305 — SAFE (symmetric, 256-bit key)
import "golang.org/x/crypto/chacha20poly1305"

// Argon2, bcrypt, scrypt — SAFE (password hashing, symmetric)
import "golang.org/x/crypto/argon2"
import "golang.org/x/crypto/bcrypt"
import "golang.org/x/crypto/scrypt"

// SSH — INFO (transport uses quantum-vulnerable key exchange)
import "golang.org/x/crypto/ssh"
```

### 4.5 Java Patterns

#### 4.5.1 JCA (Java Cryptography Architecture)

```java
// RSA Key Generation — CRITICAL
import java.security.KeyPairGenerator;
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
kpg.initialize(4096);
kpg.generateKeyPair();

// EC Key Generation — CRITICAL
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
kpg.initialize(256);

// DSA — CRITICAL
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");

// DH — CRITICAL
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");

// EdDSA — CRITICAL
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EdDSA");
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448");

// Signing — CRITICAL
import java.security.Signature;
Signature sig = Signature.getInstance("SHA256withRSA");
Signature sig = Signature.getInstance("SHA256withECDSA");
Signature sig = Signature.getInstance("SHA256withDSA");
Signature sig = Signature.getInstance("Ed25519");
Signature sig = Signature.getInstance("RSASSA-PSS");

// Key Agreement — CRITICAL
import javax.crypto.KeyAgreement;
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
KeyAgreement ka = KeyAgreement.getInstance("DH");
KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
KeyAgreement ka = KeyAgreement.getInstance("X25519");
KeyAgreement ka = KeyAgreement.getInstance("X448");
KeyAgreement ka = KeyAgreement.getInstance("XDH");

// Cipher — check algorithm
import javax.crypto.Cipher;
Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");      // CRITICAL
Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");       // CRITICAL
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");         // Check key size
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");      // Check key size
Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");   // CRITICAL (3DES)
Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");      // CRITICAL

// Key Generation (symmetric) — check size
import javax.crypto.KeyGenerator;
KeyGenerator kg = KeyGenerator.getInstance("AES");
kg.init(128);  // MODERATE
kg.init(256);  // SAFE

// Hashing
import java.security.MessageDigest;
MessageDigest md = MessageDigest.getInstance("MD5");       // CRITICAL
MessageDigest md = MessageDigest.getInstance("SHA-1");     // CRITICAL
MessageDigest md = MessageDigest.getInstance("SHA-256");   // SAFE
MessageDigest md = MessageDigest.getInstance("SHA-384");   // SAFE
MessageDigest md = MessageDigest.getInstance("SHA-512");   // SAFE
MessageDigest md = MessageDigest.getInstance("SHA3-256");  // SAFE

// MAC
import javax.crypto.Mac;
Mac mac = Mac.getInstance("HmacMD5");     // CRITICAL
Mac mac = Mac.getInstance("HmacSHA1");    // CRITICAL
Mac mac = Mac.getInstance("HmacSHA256");  // SAFE
```

#### 4.5.2 BouncyCastle

```java
// BouncyCastle RSA — CRITICAL
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
generator.init(new RSAKeyGenerationParameters(publicExponent, random, 2048, certainty));

// BouncyCastle EC — CRITICAL
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");

// BouncyCastle Ed25519 — CRITICAL
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.signers.Ed25519Signer;

// BouncyCastle X25519 — CRITICAL
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;

// BouncyCastle PQC — SAFE (these are good!)
import org.bouncycastle.pqc.crypto.mlkem.*;     // ML-KEM (Kyber)
import org.bouncycastle.pqc.crypto.mldsa.*;     // ML-DSA (Dilithium)
import org.bouncycastle.pqc.crypto.slhdsa.*;    // SLH-DSA (SPHINCS+)
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

// BouncyCastle Digests — check type
import org.bouncycastle.crypto.digests.MD5Digest;     // CRITICAL
import org.bouncycastle.crypto.digests.SHA1Digest;    // CRITICAL
import org.bouncycastle.crypto.digests.SHA256Digest;  // SAFE
import org.bouncycastle.crypto.digests.SHA3Digest;    // SAFE
```

### 4.6 Pattern Summary Table

| Algorithm/Usage | Python | JavaScript/TypeScript | Go | Java | Risk |
|----------------|--------|----------------------|-----|------|------|
| RSA key gen | `rsa.generate_private_key()` | `generateKeyPairSync('rsa')` | `rsa.GenerateKey()` | `KeyPairGenerator.getInstance("RSA")` | critical |
| RSA sign | `private_key.sign()` w/ RSA | `createSign()` w/ RSA key | `rsa.SignPKCS1v15()` | `Signature.getInstance("SHA256withRSA")` | critical |
| RSA encrypt | `public_key.encrypt()` | `crypto.subtle.encrypt('RSA-OAEP')` | `rsa.EncryptOAEP()` | `Cipher.getInstance("RSA/...")` | critical |
| ECDSA key gen | `ec.generate_private_key()` | `generateKeyPairSync('ec')` | `ecdsa.GenerateKey()` | `KeyPairGenerator.getInstance("EC")` | critical |
| ECDH exchange | `.exchange(ec.ECDH(), ...)` | `createECDH()` | `elliptic.GenerateKey()` | `KeyAgreement.getInstance("ECDH")` | critical |
| X25519 | `X25519PrivateKey.generate()` | `generateKeyPairSync('x25519')` | `curve25519.X25519()` | `KeyAgreement.getInstance("X25519")` | critical |
| Ed25519 | `Ed25519PrivateKey.generate()` | `generateKeyPairSync('ed25519')` | `ed25519.GenerateKey()` | `KeyPairGenerator.getInstance("Ed25519")` | critical |
| DH | `dh.generate_parameters()` | `createDiffieHellman()` | N/A (use x/crypto) | `KeyPairGenerator.getInstance("DH")` | critical |
| DSA | `dsa.generate_private_key()` | `generateKeyPairSync('dsa')` | `dsa.GenerateKey()` | `KeyPairGenerator.getInstance("DSA")` | critical |
| AES-128 | `algorithms.AES(key_16b)` | `createCipheriv('aes-128-*')` | `aes.NewCipher(key_16b)` | `KeyGenerator.init(128)` | moderate |
| AES-256 | `algorithms.AES(key_32b)` | `createCipheriv('aes-256-*')` | `aes.NewCipher(key_32b)` | `KeyGenerator.init(256)` | safe |
| 3DES | N/A | `createCipheriv('des-ede3-*')` | N/A | `Cipher.getInstance("DESede")` | critical |
| MD5 | `hashlib.md5()` | `createHash('md5')` | `md5.New()` | `MessageDigest.getInstance("MD5")` | critical |
| SHA-1 | `hashlib.sha1()` | `createHash('sha1')` | `sha1.New()` | `MessageDigest.getInstance("SHA-1")` | critical |
| SHA-256 | `hashlib.sha256()` | `createHash('sha256')` | `sha256.New()` | `MessageDigest.getInstance("SHA-256")` | safe |
| SHA-384+ | `hashlib.sha384()` | `createHash('sha384')` | `sha512.New384()` | `MessageDigest.getInstance("SHA-384")` | safe |
| JWT RS256 | N/A | `jwt.sign({}, key, {alg:'RS256'})` | N/A | N/A | critical |
| JWT ES256 | N/A | `jwt.sign({}, key, {alg:'ES256'})` | N/A | N/A | critical |
| JWT HS256 | N/A | `jwt.sign({}, secret, {alg:'HS256'})` | N/A | N/A | safe |

---

## 5. Pattern Matching Strategy

### 5.1 Approach: Multi-Layer Regex (NOT AST Parsing)

**Decision: Use regex-based pattern matching, not AST parsing.**

#### Tradeoff Analysis

| Approach | Pros | Cons |
|----------|------|------|
| **Regex** | Zero dependencies, fast, works on all languages with same engine, easy to add patterns | Can't resolve variables/types, false positives from comments/strings, no cross-file tracking |
| **AST (tree-sitter)** | Precise, understands code structure, can resolve local variables | Requires tree-sitter + language grammars (~50MB+ deps), slow for large repos, different parser per language |
| **Semgrep-style** | Pattern looks like code, good balance of precision/speed | Requires semgrep binary (~200MB), external dependency, licensing concerns |

**Why regex wins for PostQuant v1:**

1. **Zero dependencies.** PostQuant is an npm package. Adding tree-sitter or semgrep bloats install size by 50-200MB and introduces native compilation issues.
2. **Speed.** Regex scanning processes ~10,000 files/second. AST parsing is 10-100x slower.
3. **Good enough for crypto detection.** Crypto APIs have distinctive patterns (import paths, function names, string constants). False positive rate for `rsa.generate_private_key()` or `KeyPairGenerator.getInstance("RSA")` is near zero.
4. **Incremental improvement path.** Start with regex, add AST refinement later as an optional enhancement.

**Mitigations for regex limitations:**

1. **Comment/string filtering:** Pre-filter lines to skip comments and string literals where possible (simple heuristic, not perfect).
2. **Import tracking:** Track imports at file scope to reduce false positives (e.g., only flag `generate_private_key()` if `from cryptography.hazmat.primitives.asymmetric import rsa` appears in the file).
3. **Confidence scoring:** Each pattern match gets a confidence score (high/medium/low). Import + function call = high. Function call only = medium. String constant only = low.

### 5.2 Pattern Definition Schema

Each pattern is defined as:

```typescript
interface CryptoPattern {
  id: string;                    // Unique ID: 'python-rsa-keygen'
  language: Language;            // 'python' | 'javascript' | 'go' | 'java'
  category: CryptoCategory;     // 'asymmetric-encryption' | 'digital-signature' | etc.
  algorithm: string;            // 'RSA-2048', 'ECDSA', 'AES-128', etc.
  risk: RiskLevel;              // 'critical' | 'moderate' | 'safe'
  confidence: 'high' | 'medium' | 'low';
  
  // Matching rules (at least one must match)
  importPatterns?: RegExp[];     // Import/require/use statements
  callPatterns: RegExp[];        // Function call / instantiation patterns
  contextPatterns?: RegExp[];    // Nearby lines that increase confidence
  
  // Optional: key size extraction
  keySizeExtractor?: RegExp;     // Extract key size from matched line
  keySizeRisk?: (size: number) => RiskLevel;  // Evaluate key size
  
  // Metadata
  description: string;
  migration: string;             // Migration recommendation
  nistRef?: string;              // NIST standard reference
  cweId?: string;                // CWE identifier
}
```

### 5.3 Matching Algorithm

```
For each file in the scan:
  1. Detect language from file extension
  2. Get patterns for that language
  3. Pre-scan for imports (first pass)
  4. For each line:
     a. Skip if inside block comment
     b. Strip inline comments
     c. Match against call patterns
     d. If match found:
        - Check if corresponding import exists → high confidence
        - Extract key size if extractor defined
        - Apply key size risk function if defined
        - Create CodeFinding
  5. Return all findings for the file
```

### 5.4 File Extension → Language Mapping

| Language | Extensions |
|----------|-----------|
| Python | `.py`, `.pyw`, `.pyi` |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` |
| TypeScript | `.ts`, `.mts`, `.cts`, `.tsx` |
| Go | `.go` |
| Java | `.java` |

---

## 6. Grading System

### 6.1 Code Quantum Readiness Grade

The grading system evaluates an entire codebase (not individual files). It's designed to be actionable and comparable over time.

```
Grade Assignment Algorithm:

1. Collect all findings across all files
2. Count by risk level:
   - criticalCount = findings where risk == 'critical'
   - moderateCount = findings where risk == 'moderate'
   - safeCount = findings where risk == 'safe'
   - pqcCount = findings where category == 'pqc-algorithm'

3. Determine base grade:
   - If criticalCount == 0 AND moderateCount == 0:
     - If pqcCount > 0: A+
     - Else: A  (no crypto found, or all safe)
   - If criticalCount == 0 AND moderateCount > 0: B
   - If criticalCount >= 1 AND criticalCount <= 5: C
   - If criticalCount >= 6 AND criticalCount <= 20: D
   - If criticalCount > 20: F

4. Apply modifiers (same logic as TLS scanner):
   - 0 moderate = + modifier
   - 1 moderate = plain
   - 2+ moderate = - modifier
   - A+, A, and F get no modifiers

5. Special cases:
   - If MD5 or SHA-1 found in any context: cap at D (already broken)
   - If 3DES or DES found: cap at D (already broken)
```

### 6.2 Grade Interpretation

| Grade | Meaning | Action Required |
|-------|---------|-----------------|
| **A+** | PQC algorithms detected, no vulnerable crypto | Congratulations! Leading the pack. |
| **A** | No cryptographic usage detected (or all safe hashes/symmetric) | Good — but verify no crypto is hiding in dependencies |
| **B+/B/B-** | Only moderate-risk findings (AES-128, etc.) | Low priority — upgrade AES-128 to AES-256 when convenient |
| **C+/C/C-** | 1–5 critical findings (RSA, ECDSA, ECDH, etc.) | Plan migration. These algorithms will break with quantum computers. |
| **D+/D/D-** | 6–20 critical findings, or broken hash/cipher usage | Urgent. Significant quantum attack surface. Begin migration now. |
| **F** | 20+ critical findings | Critical. Major cryptographic overhaul needed. |

### 6.3 Per-File vs Codebase Grade

- **Terminal output** shows the overall codebase grade + per-file breakdown (files with findings only)
- **JSON output** includes both per-file findings and aggregate grade
- **SARIF output** is per-finding (individual alerts in GitHub)
- **CBOM output** is an inventory (no grade, just the catalog)

---

## 7. CBOM Output

### 7.1 Standard: CycloneDX CBOM 1.6

PostQuant generates CBOM in [CycloneDX 1.6 format](https://cyclonedx.org/docs/1.6/json/) using the `cryptographic-asset` component type. This is the same format used by IBM's Sonar Cryptography Plugin (CBOMkit-hyperion) and is the emerging industry standard.

### 7.2 Output Schema

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:<random-uuid>",
  "metadata": {
    "timestamp": "2026-03-02T12:00:00Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "postquant",
          "version": "0.2.0",
          "description": "Quantum readiness scanner",
          "externalReferences": [
            {
              "type": "website",
              "url": "https://postquant.dev"
            }
          ]
        }
      ]
    },
    "component": {
      "type": "application",
      "name": "<scanned-project-name>",
      "bom-ref": "scanned-project"
    }
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "RSA-2048",
      "bom-ref": "<uuid>",
      "evidence": {
        "occurrences": [
          {
            "location": "src/auth/keys.py",
            "line": 42,
            "additionalContext": "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
          },
          {
            "location": "src/api/encryption.py",
            "line": 15,
            "additionalContext": "rsa.generate_private_key(public_exponent=65537, key_size=2048)"
          }
        ]
      },
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "cryptoFunctions": ["keygen", "encrypt", "decrypt"],
          "classicalSecurityLevel": 112,
          "nistQuantumSecurityLevel": 0
        }
      }
    },
    {
      "type": "cryptographic-asset",
      "name": "ECDSA-P256",
      "bom-ref": "<uuid>",
      "evidence": {
        "occurrences": [
          {
            "location": "src/auth/jwt.ts",
            "line": 23,
            "additionalContext": "generateKeyPairSync('ec', { namedCurve: 'P-256' })"
          }
        ]
      },
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "signature",
          "parameterSetIdentifier": "P-256",
          "curve": "secp256r1",
          "cryptoFunctions": ["sign", "verify"],
          "classicalSecurityLevel": 128,
          "nistQuantumSecurityLevel": 0
        }
      }
    },
    {
      "type": "cryptographic-asset",
      "name": "AES-256-GCM",
      "bom-ref": "<uuid>",
      "evidence": {
        "occurrences": [
          {
            "location": "src/storage/encrypt.go",
            "line": 87,
            "additionalContext": "aes.NewCipher(key) // 32-byte key"
          }
        ]
      },
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "ae",
          "mode": "gcm",
          "parameterSetIdentifier": "256",
          "cryptoFunctions": ["encrypt", "decrypt"],
          "classicalSecurityLevel": 256,
          "nistQuantumSecurityLevel": 5
        }
      }
    }
  ],
  "dependencies": [
    {
      "ref": "scanned-project",
      "dependsOn": ["<rsa-2048-ref>", "<ecdsa-p256-ref>", "<aes-256-ref>"]
    }
  ]
}
```

### 7.3 CBOM Primitive Types

Map PostQuant findings to CycloneDX `algorithmProperties.primitive`:

| PostQuant Category | CycloneDX Primitive | Description |
|-------------------|-------------------|-------------|
| `asymmetric-encryption` | `pke` | Public Key Encryption |
| `digital-signature` | `signature` | Digital Signature |
| `key-exchange` | `kem` / `kex` | Key Encapsulation / Key Exchange |
| `weak-symmetric`, `safe-symmetric` | `ae` or `blockcipher` | Authenticated Encryption / Block Cipher |
| `weak-hash`, `safe-hash` | `hash` | Hash function |
| `pqc-algorithm` | varies by algorithm | ML-KEM → `kem`, ML-DSA → `signature` |

### 7.4 NIST Quantum Security Levels

| Level | Equivalent Security | Algorithms |
|-------|-------------------|------------|
| 0 | Broken by quantum computer | RSA, ECDSA, ECDH, DH, DSA, Ed25519, X25519 |
| 1 | ≥ AES-128 security | ML-KEM-512, ML-DSA-44 |
| 3 | ≥ AES-192 security | ML-KEM-768, ML-DSA-65 |
| 5 | ≥ AES-256 security | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384, SHA-512 |

---

## 8. SARIF Output

### 8.1 Standard: SARIF 2.1.0

[SARIF (Static Analysis Results Interchange Format)](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning) is the standard for GitHub Code Scanning integration. Uploading SARIF files to GitHub creates inline annotations on PRs.

### 8.2 SARIF Schema

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "PostQuant",
          "version": "0.2.0",
          "informationUri": "https://postquant.dev",
          "rules": [
            {
              "id": "PQ001",
              "name": "QuantumVulnerableRSA",
              "shortDescription": {
                "text": "RSA key generation detected"
              },
              "fullDescription": {
                "text": "RSA is vulnerable to Shor's algorithm on a quantum computer. Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key encapsulation."
              },
              "helpUri": "https://postquant.dev/docs/findings/rsa",
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": ["security", "quantum", "cryptography", "pqc"],
                "precision": "high"
              }
            },
            {
              "id": "PQ002",
              "name": "QuantumVulnerableECDSA",
              "shortDescription": {
                "text": "ECDSA key generation or signing detected"
              },
              "fullDescription": {
                "text": "ECDSA is vulnerable to Shor's algorithm. Migrate to ML-DSA (FIPS 204)."
              },
              "helpUri": "https://postquant.dev/docs/findings/ecdsa",
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ003",
              "name": "QuantumVulnerableECDH",
              "shortDescription": {
                "text": "ECDH / X25519 key exchange detected"
              },
              "fullDescription": {
                "text": "ECDH/X25519 key exchange is vulnerable to Shor's algorithm. Migrate to ML-KEM (FIPS 203)."
              },
              "helpUri": "https://postquant.dev/docs/findings/ecdh",
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ004",
              "name": "QuantumVulnerableDH",
              "shortDescription": {
                "text": "Classic Diffie-Hellman key exchange detected"
              },
              "fullDescription": {
                "text": "DH is vulnerable to Shor's algorithm. Migrate to ML-KEM (FIPS 203)."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ005",
              "name": "QuantumVulnerableDSA",
              "shortDescription": {
                "text": "DSA signing detected"
              },
              "fullDescription": {
                "text": "DSA is vulnerable to Shor's algorithm and is also deprecated classically. Migrate to ML-DSA (FIPS 204)."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ006",
              "name": "WeakSymmetricKey",
              "shortDescription": {
                "text": "AES-128 or other sub-256-bit symmetric key detected"
              },
              "fullDescription": {
                "text": "Grover's algorithm reduces AES-128 to 64-bit effective security. Upgrade to AES-256."
              },
              "defaultConfiguration": {
                "level": "warning"
              }
            },
            {
              "id": "PQ007",
              "name": "BrokenHash",
              "shortDescription": {
                "text": "MD5 or SHA-1 hash usage detected"
              },
              "fullDescription": {
                "text": "MD5 and SHA-1 are already broken classically (collision attacks). Replace with SHA-256 or stronger."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ008",
              "name": "BrokenCipher",
              "shortDescription": {
                "text": "DES or 3DES cipher detected"
              },
              "fullDescription": {
                "text": "DES and 3DES are deprecated and weak. Replace with AES-256-GCM."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ009",
              "name": "QuantumVulnerableJWT",
              "shortDescription": {
                "text": "JWT signed with quantum-vulnerable algorithm"
              },
              "fullDescription": {
                "text": "RS256/ES256/PS256/EdDSA JWT signatures are vulnerable to quantum attacks. Consider HMAC (HS256) for symmetric use cases, or plan migration to PQC-based JWT."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ010",
              "name": "QuantumVulnerableEdDSA",
              "shortDescription": {
                "text": "Ed25519/Ed448 signing detected"
              },
              "fullDescription": {
                "text": "EdDSA (Ed25519/Ed448) is vulnerable to Shor's algorithm. Migrate to ML-DSA (FIPS 204)."
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "PQ100",
              "name": "PQCAlgorithmDetected",
              "shortDescription": {
                "text": "Post-quantum cryptographic algorithm detected"
              },
              "fullDescription": {
                "text": "This code uses a NIST-standardized post-quantum algorithm. No migration needed."
              },
              "defaultConfiguration": {
                "level": "note"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "PQ001",
          "level": "error",
          "message": {
            "text": "RSA-2048 key generation detected. Vulnerable to Shor's algorithm. Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key encapsulation."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/auth/keys.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 1
                }
              }
            }
          ],
          "fixes": [
            {
              "description": {
                "text": "Replace RSA with ML-DSA (FIPS 204) from a PQC library"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### 8.3 SARIF Rule ID Mapping

| Rule ID | Finding | SARIF Level | CWE |
|---------|---------|-------------|-----|
| PQ001 | RSA usage | error | CWE-327 |
| PQ002 | ECDSA usage | error | CWE-327 |
| PQ003 | ECDH/X25519 key exchange | error | CWE-327 |
| PQ004 | Classic DH | error | CWE-327 |
| PQ005 | DSA usage | error | CWE-327 |
| PQ006 | AES-128 / weak symmetric | warning | CWE-326 |
| PQ007 | MD5/SHA-1 | error | CWE-328 |
| PQ008 | DES/3DES | error | CWE-327 |
| PQ009 | JWT w/ RSA/EC | error | CWE-327 |
| PQ010 | EdDSA (Ed25519/Ed448) | error | CWE-327 |
| PQ100 | PQC algorithm (positive) | note | N/A |

### 8.4 GitHub Actions Integration

```yaml
# .github/workflows/pqc-scan.yml
name: PostQuant Code Scan
on: [push, pull_request]

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx postquant analyze . --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: postquant
```

---

## 9. Migration Recommendations

### 9.1 Migration Matrix

| Current Algorithm | Usage | PQC Replacement | NIST Standard | Timeline |
|-------------------|-------|-----------------|---------------|----------|
| **RSA-2048/4096** | Signatures | **ML-DSA-65** (Dilithium) | FIPS 204 | Deprecated 2030, disallowed 2035 |
| **RSA-2048/4096** | Encryption/Key Encapsulation | **ML-KEM-768** (Kyber) | FIPS 203 | Deprecated 2030, disallowed 2035 |
| **ECDSA (P-256/P-384)** | Signatures | **ML-DSA-44/65** | FIPS 204 | Deprecated 2030, disallowed 2035 |
| **ECDH (P-256/P-384)** | Key Exchange | **ML-KEM-512/768** | FIPS 203 | Deprecated 2030, disallowed 2035 |
| **Ed25519** | Signatures | **ML-DSA-44** | FIPS 204 | Deprecated 2030, disallowed 2035 |
| **X25519** | Key Exchange | **ML-KEM-512** | FIPS 203 | Deprecated 2030, disallowed 2035 |
| **Ed448** | Signatures | **ML-DSA-65** | FIPS 204 | Deprecated 2030, disallowed 2035 |
| **X448** | Key Exchange | **ML-KEM-768** | FIPS 203 | Deprecated 2030, disallowed 2035 |
| **DH (classic)** | Key Exchange | **ML-KEM-768** | FIPS 203 | Already deprecated |
| **DSA** | Signatures | **ML-DSA-65** | FIPS 204 | Already deprecated |
| **AES-128** | Symmetric Encryption | **AES-256** | Already NIST-approved | Upgrade when convenient |
| **3DES / DES** | Symmetric Encryption | **AES-256-GCM** | Already NIST-approved | Immediate |
| **MD5** | Hashing | **SHA-256** or **SHA-3** | Already NIST-approved | Immediate |
| **SHA-1** | Hashing | **SHA-256** or **SHA-3** | Already NIST-approved | Immediate |
| **SHA-256** | Hashing (standalone) | No change needed | Already quantum-safe for hashing | N/A |
| **HMAC-SHA-256** | Authentication | No change needed | Already quantum-safe | N/A |

### 9.2 Migration Recommendation Strings

Each finding's `migration` field contains an actionable string:

```typescript
const MIGRATION_RECOMMENDATIONS: Record<string, string> = {
  // Critical — Shor's algorithm
  'rsa-signature': 'Replace with ML-DSA (FIPS 204). Python: use oqs-python. JS: use liboqs-node. Go: use circl. Java: use BouncyCastle PQC provider.',
  'rsa-encryption': 'Replace with ML-KEM (FIPS 203) for key encapsulation. Do NOT encrypt directly with ML-KEM — use KEM + AES-256-GCM hybrid construction.',
  'ecdsa': 'Replace with ML-DSA (FIPS 204). Same API pattern: generate key pair, sign, verify. Key and signature sizes will increase.',
  'ecdh': 'Replace with ML-KEM (FIPS 203). Note: ML-KEM is a KEM, not interactive DH. Use encapsulate/decapsulate instead of exchange.',
  'x25519': 'Replace with ML-KEM-512 (FIPS 203) or hybrid X25519+ML-KEM-768 for defense-in-depth.',
  'ed25519': 'Replace with ML-DSA-44 (FIPS 204). Similar security level with quantum resistance.',
  'dh-classic': 'Replace with ML-KEM-768 (FIPS 203). Classic DH is already deprecated by NIST.',
  'dsa': 'Replace with ML-DSA (FIPS 204). DSA is already deprecated classically.',
  
  // Critical — Already broken
  'md5': 'Replace with SHA-256 or SHA-3-256 immediately. MD5 has known collision attacks.',
  'sha1': 'Replace with SHA-256 or SHA-3-256 immediately. SHA-1 has known collision attacks (SHAttered, 2017).',
  'des': 'Replace with AES-256-GCM immediately. DES has only 56-bit key — trivially breakable.',
  '3des': 'Replace with AES-256-GCM. 3DES is deprecated by NIST (NIST SP 800-131A Rev 2).',
  
  // Moderate — Grover's algorithm
  'aes-128': "Upgrade to AES-256. Grover's algorithm reduces AES-128 to ~64-bit effective security. AES-256 retains 128-bit security post-quantum.",
  
  // JWT-specific
  'jwt-rsa': 'JWT RS256/RS384/RS512: Plan migration to PQC-based JWT signing. In the interim, consider HS256 (HMAC-SHA-256) for service-to-service where shared secrets are feasible.',
  'jwt-ecdsa': 'JWT ES256/ES384/ES512: Plan migration to PQC-based JWT signing. IETF is working on PQC JWT standards.',
  'jwt-eddsa': 'JWT EdDSA: Plan migration to PQC-based JWT signing.',
};
```

### 9.3 PQC Library References (per language)

Included in verbose migration output:

| Language | Library | Status | Notes |
|----------|---------|--------|-------|
| **Python** | `oqs-python` (liboqs) | Stable | Open Quantum Safe project. ML-KEM, ML-DSA, SLH-DSA. |
| **Python** | `pqcrypto` | Experimental | Pure Python PQC implementations. |
| **JavaScript** | `liboqs-node` | Stable | Node.js bindings for liboqs. |
| **JavaScript** | `crystals-kyber-js` | Stable | Pure JS ML-KEM implementation. |
| **Go** | `circl` (Cloudflare) | Production | Used in Cloudflare's production TLS. ML-KEM, ML-DSA. |
| **Go** | `crypto/mlkem` | Go 1.24+ | Standard library ML-KEM support (landed 2025). |
| **Java** | BouncyCastle 1.78+ | Production | `bcprov-jdk18on`. Full ML-KEM, ML-DSA, SLH-DSA support. |
| **Java** | SunJCE (JDK 24+) | Preview | Oracle adding PQC to standard JCA providers. |

---

## 10. Type System Integration

### 10.1 New Types

Add these to `src/types/index.ts`:

```typescript
// === Code Scanner Types ===

export type Language = 'python' | 'javascript' | 'go' | 'java';

export type CryptoCategory =
  | 'asymmetric-encryption'
  | 'digital-signature'
  | 'key-exchange'
  | 'weak-symmetric'
  | 'weak-hash'
  | 'broken-cipher'
  | 'safe-symmetric'
  | 'safe-hash'
  | 'pqc-algorithm';

export type AnalyzeOutputFormat = 'terminal' | 'json' | 'sarif' | 'cbom';

export interface CodeFinding {
  /** Pattern ID that matched */
  patternId: string;
  
  /** Source file path (relative to scan root) */
  file: string;
  
  /** Line number (1-indexed) */
  line: number;
  
  /** The matched line content (trimmed) */
  matchedLine: string;
  
  /** Detected language */
  language: Language;
  
  /** Crypto category */
  category: CryptoCategory;
  
  /** Algorithm name (e.g., 'RSA-2048', 'ECDSA-P256', 'AES-128') */
  algorithm: string;
  
  /** Key size if detected */
  keySize?: number;
  
  /** Elliptic curve name if detected */
  curve?: string;
  
  /** Risk level */
  risk: RiskLevel;
  
  /** Human-readable reason */
  reason: string;
  
  /** Migration recommendation */
  migration?: string;
  
  /** Match confidence */
  confidence: 'high' | 'medium' | 'low';
}

export interface CodeScanResult {
  /** Root directory that was scanned */
  scanRoot: string;
  
  /** All findings */
  findings: CodeFinding[];
  
  /** Files scanned count */
  filesScanned: number;
  
  /** Files with findings count */
  filesWithFindings: number;
  
  /** Languages detected */
  languagesDetected: Language[];
  
  /** Scan duration in milliseconds */
  durationMs: number;
}

export interface CodeGradedResult {
  /** Root directory */
  scanRoot: string;
  
  /** Overall grade */
  grade: Grade;
  
  /** Base grade without modifier */
  baseGrade: Grade;
  
  /** Grade modifier */
  modifier: '+' | '-' | '';
  
  /** All findings */
  findings: CodeFinding[];
  
  /** Migration notes (unique) */
  migrationNotes: string[];
  
  /** Summary counts */
  summary: {
    critical: number;
    moderate: number;
    safe: number;
    total: number;
    filesScanned: number;
    filesWithFindings: number;
  };
  
  /** Per-file breakdown */
  fileBreakdown: FileBreakdown[];
}

export interface FileBreakdown {
  file: string;
  language: Language;
  findings: CodeFinding[];
  criticalCount: number;
  moderateCount: number;
  safeCount: number;
}

export interface AnalyzeOptions {
  format: AnalyzeOutputFormat;
  language?: Language;
  failGrade: Grade;
  ignore: string[];
  ignoreFile: string;
  maxFiles: number;
  verbose: boolean;
  noMigration: boolean;
}
```

### 10.2 Reusing Existing Types

The code scanner reuses these Phase 1 types:
- `RiskLevel` ('critical' | 'moderate' | 'safe')
- `Grade` ('A+' | 'A' | 'B' | 'C' | 'D' | 'F')

The grading function signature:
```typescript
export function gradeCode(scanResult: CodeScanResult): CodeGradedResult;
```

---

## 11. Testing Strategy

### 11.1 Test Structure

```
src/
├── scanner/code/
│   ├── __tests__/
│   │   ├── discovery.test.ts
│   │   ├── matcher.test.ts
│   │   ├── classifier.test.ts
│   │   ├── grader.test.ts
│   │   └── patterns/
│   │       ├── python.test.ts
│   │       ├── javascript.test.ts
│   │       ├── go.test.ts
│   │       └── java.test.ts
│   └── __fixtures__/        # Test fixture files
│       ├── python/
│       │   ├── vulnerable.py
│       │   ├── safe.py
│       │   └── mixed.py
│       ├── javascript/
│       │   ├── vulnerable.js
│       │   ├── vulnerable.ts
│       │   ├── safe.js
│       │   ├── jwt-vulnerable.ts
│       │   └── webcrypto.js
│       ├── go/
│       │   ├── vulnerable.go
│       │   ├── safe.go
│       │   └── mixed.go
│       └── java/
│           ├── Vulnerable.java
│           ├── Safe.java
│           ├── BouncyCastle.java
│           └── Mixed.java
├── output/
│   ├── __tests__/
│   │   ├── sarif.test.ts
│   │   └── cbom.test.ts
```

### 11.2 Test Fixtures

#### Python — `__fixtures__/python/vulnerable.py`

```python
"""Test fixture: Python code with quantum-vulnerable cryptography."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA as PycryptoRSA, ECC
from Crypto.Hash import MD5, SHA as SHA1_legacy
import hashlib

# RSA key generation (CRITICAL)
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# EC key generation (CRITICAL)
ec_key = ec.generate_private_key(ec.SECP256R1())

# Ed25519 (CRITICAL)
ed_key = Ed25519PrivateKey.generate()

# X25519 (CRITICAL)
x_key = X25519PrivateKey.generate()

# DSA (CRITICAL)
dsa_key = dsa.generate_private_key(key_size=2048)

# DH (CRITICAL)
dh_params = dh.generate_parameters(generator=2, key_size=2048)

# Pycryptodome RSA (CRITICAL)
pycrypto_rsa = PycryptoRSA.generate(2048)

# Pycryptodome ECC (CRITICAL)
pycrypto_ec = ECC.generate(curve='P-256')

# MD5 (CRITICAL)
md5_hash = hashlib.md5(b"data")

# SHA-1 (CRITICAL)
sha1_hash = hashlib.sha1(b"data")

# AES-128 (MODERATE)
# Using a 16-byte key implies AES-128
cipher = Cipher(algorithms.AES(b'\x00' * 16), modes.GCM(b'\x00' * 12))
```

#### Python — `__fixtures__/python/safe.py`

```python
"""Test fixture: Python code with quantum-safe cryptography."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import hashlib

# AES-256 (SAFE)
cipher = Cipher(algorithms.AES(b'\x00' * 32), modes.GCM(b'\x00' * 12))

# SHA-256 (SAFE)
sha256_hash = hashlib.sha256(b"data")

# SHA-384 (SAFE)
sha384_hash = hashlib.sha384(b"data")

# SHA-512 (SAFE)
sha512_hash = hashlib.sha512(b"data")

# SHA-3 (SAFE)
sha3_hash = hashlib.sha3_256(b"data")

# HMAC-SHA256 (SAFE - symmetric)
import hmac
mac = hmac.new(b"secret", b"data", hashlib.sha256)
```

#### JavaScript — `__fixtures__/javascript/vulnerable.js`

```javascript
/**
 * Test fixture: JavaScript code with quantum-vulnerable cryptography.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// RSA key generation (CRITICAL)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// EC key generation (CRITICAL)
const ecKeys = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
});

// Ed25519 (CRITICAL)
const edKeys = crypto.generateKeyPairSync('ed25519');

// X25519 key exchange (CRITICAL)
const x25519Keys = crypto.generateKeyPairSync('x25519');

// ECDH (CRITICAL)
const ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();

// DH (CRITICAL)
const dh = crypto.createDiffieHellman(2048);

// MD5 hash (CRITICAL)
const md5 = crypto.createHash('md5');

// SHA-1 hash (CRITICAL)
const sha1 = crypto.createHash('sha1');

// AES-128 cipher (MODERATE)
const cipher128 = crypto.createCipheriv('aes-128-gcm', key16, iv);

// JWT with RSA (CRITICAL)
const token = jwt.sign({ sub: '1234' }, privateKey, { algorithm: 'RS256' });

// JWT with ECDSA (CRITICAL)
const ecToken = jwt.sign({ sub: '1234' }, ecPrivateKey, { algorithm: 'ES256' });
```

#### JavaScript — `__fixtures__/javascript/safe.js`

```javascript
/**
 * Test fixture: JavaScript code with quantum-safe cryptography.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// AES-256 (SAFE)
const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv);

// SHA-256 (SAFE)
const hash = crypto.createHash('sha256');

// SHA-384 (SAFE)
const hash384 = crypto.createHash('sha384');

// HMAC-SHA256 (SAFE)
const hmac = crypto.createHmac('sha256', secret);

// JWT with HMAC (SAFE — symmetric)
const token = jwt.sign({ sub: '1234' }, 'shared-secret', { algorithm: 'HS256' });
```

#### Go — `__fixtures__/go/vulnerable.go`

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/md5"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha1"
    "crypto/ed25519"
    "golang.org/x/crypto/curve25519"
)

func main() {
    // RSA key generation (CRITICAL)
    rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    _ = rsaKey

    // ECDSA key generation (CRITICAL)
    ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = ecKey

    // Ed25519 (CRITICAL)
    _, edPriv, _ := ed25519.GenerateKey(rand.Reader)
    _ = edPriv

    // X25519 (CRITICAL)
    var scalar, point [32]byte
    curve25519.ScalarMult(&scalar, &scalar, &point)

    // MD5 (CRITICAL)
    h := md5.New()
    _ = h

    // SHA-1 (CRITICAL)
    h1 := sha1.New()
    _ = h1
}
```

#### Java — `__fixtures__/java/Vulnerable.java`

```java
package fixtures;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class Vulnerable {
    public void vulnerablePatterns() throws Exception {
        // RSA key generation (CRITICAL)
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);

        // EC key generation (CRITICAL)
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");

        // DSA (CRITICAL)
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");

        // DH (CRITICAL)
        KeyPairGenerator dhKpg = KeyPairGenerator.getInstance("DH");

        // ECDH key agreement (CRITICAL)
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");

        // RSA signing (CRITICAL)
        Signature rsaSig = Signature.getInstance("SHA256withRSA");

        // RSA cipher (CRITICAL)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // MD5 (CRITICAL)
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // SHA-1 (CRITICAL)
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // AES-128 (MODERATE)
        KeyGenerator aes128 = KeyGenerator.getInstance("AES");
        aes128.init(128);

        // 3DES (CRITICAL)
        Cipher des3 = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        // HmacMD5 (CRITICAL)
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
    }
}
```

### 11.3 Test Cases Per Module

#### Pattern Tests (per language, ~30 tests each)

```typescript
// Example: python.test.ts
describe('Python crypto patterns', () => {
  // RSA
  it('detects rsa.generate_private_key() as critical', ...);
  it('detects RSA.generate() from pycryptodome as critical', ...);
  it('extracts key size from rsa.generate_private_key(key_size=4096)', ...);
  
  // ECDSA/ECDH
  it('detects ec.generate_private_key() as critical', ...);
  it('detects ECDSA signing as critical', ...);
  it('detects ECDH exchange as critical', ...);
  it('identifies curve name from ec.SECP256R1()', ...);
  
  // Ed25519/X25519
  it('detects Ed25519PrivateKey.generate() as critical', ...);
  it('detects X25519PrivateKey.generate() as critical', ...);
  
  // Hashing
  it('detects hashlib.md5() as critical', ...);
  it('detects hashlib.sha1() as critical', ...);
  it('detects hashlib.sha256() as safe', ...);
  it('detects hashes.SHA3_256() as safe', ...);
  
  // AES
  it('detects AES with 16-byte key as moderate', ...);
  it('detects AES with 32-byte key as safe', ...);
  
  // False positive prevention
  it('ignores crypto mentions in comments', ...);
  it('ignores crypto mentions in string literals', ...);
  it('does not flag safe hashlib.sha256 usage', ...);
});
```

#### Matcher Tests (~20 tests)

```typescript
describe('Matcher', () => {
  it('scans a file and returns findings', ...);
  it('tracks imports and sets high confidence when import + call match', ...);
  it('sets medium confidence when call matches without import', ...);
  it('skips lines in block comments', ...);
  it('handles files with no crypto as empty findings', ...);
  it('handles binary files gracefully (skip)', ...);
  it('handles very large files within memory limits', ...);
});
```

#### Grader Tests (~15 tests)

```typescript
describe('Code Grader', () => {
  it('returns A+ when PQC detected and no vulnerabilities', ...);
  it('returns A when no crypto found', ...);
  it('returns B when only moderate findings', ...);
  it('returns C when 1-5 critical findings', ...);
  it('returns D when 6-20 critical findings', ...);
  it('returns F when >20 critical findings', ...);
  it('caps at D when MD5/SHA-1 found', ...);
  it('applies + modifier when 0 moderate findings', ...);
  it('applies - modifier when 2+ moderate findings', ...);
  it('does not modify A+ or F grades', ...);
});
```

#### Discovery Tests (~10 tests)

```typescript
describe('File Discovery', () => {
  it('discovers .py files', ...);
  it('discovers .js and .ts files', ...);
  it('discovers .go files', ...);
  it('discovers .java files', ...);
  it('respects .postquantignore', ...);
  it('respects --ignore glob patterns', ...);
  it('skips node_modules by default', ...);
  it('skips vendor/ by default', ...);
  it('respects --max-files limit', ...);
  it('filters by --language when specified', ...);
});
```

#### Output Format Tests (~15 tests each for SARIF and CBOM)

```typescript
describe('SARIF output', () => {
  it('produces valid SARIF 2.1.0 JSON', ...);
  it('includes correct rule definitions', ...);
  it('maps findings to correct rule IDs', ...);
  it('includes file location and line number', ...);
  it('sets error level for critical findings', ...);
  it('sets warning level for moderate findings', ...);
  it('sets note level for PQC findings', ...);
});

describe('CBOM output', () => {
  it('produces valid CycloneDX 1.6 JSON', ...);
  it('groups same-algorithm findings under one component', ...);
  it('includes evidence with file/line occurrences', ...);
  it('sets correct cryptoProperties for RSA', ...);
  it('sets correct cryptoProperties for ECDSA', ...);
  it('sets correct nistQuantumSecurityLevel', ...);
  it('includes dependencies section', ...);
});
```

#### Integration Tests (~10 tests)

```typescript
describe('Integration: analyze command', () => {
  it('scans fixture directory and produces correct grade', ...);
  it('vulnerable Python fixture grades D or worse', ...);
  it('safe Python fixture grades A', ...);
  it('mixed fixture produces per-file breakdown', ...);
  it('--language python only scans .py files', ...);
  it('--format json produces valid JSON output', ...);
  it('--format sarif produces valid SARIF', ...);
  it('--format cbom produces valid CycloneDX', ...);
  it('exit code 1 when grade meets --fail-grade threshold', ...);
  it('exit code 0 when grade is above --fail-grade threshold', ...);
});
```

### 11.4 Target Test Count

| Module | Test Count |
|--------|-----------|
| Python patterns | ~30 |
| JavaScript patterns | ~35 |
| Go patterns | ~25 |
| Java patterns | ~30 |
| Matcher engine | ~20 |
| Grader | ~15 |
| Discovery | ~10 |
| SARIF output | ~15 |
| CBOM output | ~15 |
| Terminal output (code) | ~10 |
| JSON output (code) | ~10 |
| Integration | ~10 |
| **Total** | **~225 tests** |

---

## 12. Implementation Plan

### 12.1 Build Order (TDD, 8 Batches)

#### Batch 1: Types + Discovery (Foundation)
1. Add all new types to `src/types/index.ts`
2. Implement `src/scanner/code/discovery.ts` — file discovery with language detection, gitignore-style filtering
3. Tests: discovery tests (10 tests)

#### Batch 2: Pattern Definitions
4. Implement `src/scanner/code/patterns/python.ts`
5. Implement `src/scanner/code/patterns/javascript.ts`
6. Implement `src/scanner/code/patterns/go.ts`
7. Implement `src/scanner/code/patterns/java.ts`
8. Implement `src/scanner/code/patterns/index.ts` — pattern registry
9. Tests: pattern unit tests (120 tests)

#### Batch 3: Matching Engine
10. Create test fixtures (vulnerable.py, safe.py, etc.)
11. Implement `src/scanner/code/matcher.ts` — line-by-line matching with import tracking
12. Tests: matcher tests (20 tests)

#### Batch 4: Classifier + Grader
13. Implement `src/scanner/code/classifier.ts` — maps raw matches to CodeFinding[]
14. Implement `src/scanner/code/grader.ts` — aggregates findings into CodeGradedResult
15. Tests: classifier + grader tests (15 tests)

#### Batch 5: Terminal + JSON Output
16. Extend `src/output/terminal.ts` with code-specific formatting (or create `terminal-code.ts`)
17. Extend `src/output/json.ts` with code findings output
18. Tests: output tests (20 tests)

#### Batch 6: SARIF Output
19. Implement `src/output/sarif.ts`
20. Tests: SARIF output tests (15 tests)

#### Batch 7: CBOM Output
21. Implement `src/output/cbom.ts`
22. Tests: CBOM output tests (15 tests)

#### Batch 8: CLI Wiring + Integration
23. Implement `src/commands/analyze.ts` — command handler
24. Wire up in `src/index.ts` — add `analyze` subcommand
25. Integration tests (10 tests)
26. Update README.md

### 12.2 Git Strategy

- Branch: `feature/code-scanner`
- Commit per batch (8 commits)
- Squash merge to `main` when complete
- Tag: `v0.2.0`

### 12.3 Estimated Effort

With Claude Code assistance: **4-6 hours** (one focused build session)

---

## 13. Competitive Analysis

### 13.1 Landscape Overview

| Tool | Type | Languages | Source Code Scan | CBOM | Grading | Cost | Open Source |
|------|------|-----------|-----------------|------|---------|------|-------------|
| **PostQuant** (us) | CLI | Python, JS/TS, Go, Java | ✅ Regex-based | ✅ CycloneDX 1.6 | ✅ A+-F | Free | ✅ MIT |
| **IBM Quantum Safe Explorer** | Enterprise | Java, Python, Go + bytecode | ✅ AST + bytecode | ✅ CycloneDX | ❌ | $$$$ (enterprise) | ❌ |
| **IBM Sonar Cryptography (CBOMkit)** | SonarQube Plugin | Java, Python, Go | ✅ AST-based | ✅ CycloneDX 1.6 | ❌ | Free | ✅ Apache 2.0 |
| **SandboxAQ Security Suite** | Enterprise Platform | Multiple | ✅ Runtime + static + network | ✅ Proprietary | ❌ | $$$$ (enterprise) | ❌ |
| **Mini PQC Scanner** | CLI (Go) | N/A (system scan) | ❌ (scans infrastructure) | ❌ | ❌ | Free (enterprise upsell) | ✅ |
| **pqcscan** (Anvil Secure) | CLI (Rust) | N/A (network) | ❌ (scans SSH/TLS servers) | ❌ | ❌ | Free | ✅ |
| **Semgrep** | SAST Platform | 30+ | ✅ (community rules) | ❌ | ❌ | Freemium | Partial |

### 13.2 What We Do That They Don't

| Differentiator | PostQuant | IBM QSE | IBM CBOMkit | SandboxAQ | Mini PQC | Semgrep |
|---------------|-----------|---------|-------------|-----------|----------|---------|
| **One-command install** (`npx postquant analyze .`) | ✅ | ❌ | ❌ (needs SonarQube) | ❌ | ❌ (build from source) | ✅ |
| **Letter grades (A+-F)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **SARIF for GitHub Code Scanning** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Migration recommendations per finding** | ✅ | Partial | ❌ | ✅ | ❌ | ❌ |
| **Zero dependencies** | ✅ | ❌ (Java runtime) | ❌ (SonarQube) | ❌ (agent install) | ❌ (Go build) | ❌ (200MB+) |
| **TLS + Code scanning in one tool** | ✅ | ❌ | ❌ | ✅ | Partial | ❌ |
| **CycloneDX CBOM output** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **GitHub Actions ready** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Free forever (MIT license)** | ✅ | ❌ | ✅ | ❌ | ✅* | Partial |

### 13.3 What They Do That We Don't (Yet)

| Capability | IBM QSE | SandboxAQ | Why We Don't (Yet) |
|------------|---------|-----------|-------------------|
| Bytecode/binary scanning | ✅ | ✅ | Adds complexity; source code is higher value for devs |
| Runtime analysis | ❌ | ✅ | Requires agent; out of scope for CLI |
| Network traffic scanning | ❌ | ✅ | Phase 1 TLS scanner covers endpoints |
| Dependency resolution | ✅ | ✅ | Future: scan package manifests for transitive crypto deps |
| Auto-remediation | ❌ | ✅ | Phase 3: Migration Playbook Engine |
| Enterprise dashboard | ✅ | ✅ | Phase 4: SaaS platform |
| Compliance mapping (NSM-10, CNSA 2.0) | ✅ | ✅ | Future: enterprise feature |

### 13.4 Positioning

**PostQuant is the "SSL Labs for PQC" — developer-first, zero-friction, actionable.**

| Them | Us |
|------|----|
| Enterprise sales motion (talk to a human, get a demo, sign a contract) | `npm install -g postquant && postquant analyze .` |
| PDF reports you email to compliance | SARIF files that show up as GitHub annotations |
| "Contact us for pricing" | Free. Forever. |
| 6-month deployment timeline | 30 seconds to first result |
| Finding: "RSA-2048 detected" | Finding: "RSA-2048 detected → Replace with ML-DSA (FIPS 204). Python: use oqs-python. Go: use circl." |

---

## 14. Future Considerations

### 14.1 Phase 3: Migration Playbook Engine (The Moat)

The code scanner *finds* vulnerable crypto. The migration engine *fixes* it.

For each finding, generate a language-specific code diff showing:
- What to remove
- What to add (with the actual PQC library import and API call)
- How to test the migration

This is what nobody else does. IBM finds. SandboxAQ finds. Nobody generates the actual migration code.

### 14.2 Dependency Scanning

Scan `package.json`, `requirements.txt`, `go.mod`, `pom.xml` for dependencies that use quantum-vulnerable crypto:
- `node-forge` → uses RSA/ECDSA internally
- `python-jose` → JWT with RSA/EC
- `crypto/tls` → quantum-vulnerable key exchange

### 14.3 Configuration File Scanning

Detect quantum-vulnerable crypto in config files:
- `nginx.conf` → SSL cipher suites
- `sshd_config` → host key algorithms
- `openssl.cnf` → default algorithms
- `.env` files → key material (warn about storage)

### 14.4 AST Enhancement Layer (Optional)

For users who want higher precision, offer an optional AST mode:
- Uses `tree-sitter` via WASM bindings (no native deps)
- Resolves variable assignments (e.g., `key_size = 2048; rsa.generate_private_key(key_size=key_size)`)
- Tracks function parameters across scopes
- Reduces false positives from ~5% to <1%
- Activated with `--precise` flag

### 14.5 CI/CD Integrations

Beyond GitHub Actions:
- GitLab CI template
- CircleCI orb
- Jenkins plugin
- Bitbucket Pipelines
- Azure DevOps extension

### 14.6 IDE Extensions

- VS Code extension (inline warnings)
- JetBrains plugin
- Neovim/Vim LSP integration

---

## Appendix A: Quick Reference for Implementation

### File to Create

| File | Purpose | Priority |
|------|---------|----------|
| `src/types/index.ts` | Extend with code scanner types | Batch 1 |
| `src/scanner/code/discovery.ts` | File discovery + language detection | Batch 1 |
| `src/scanner/code/patterns/python.ts` | Python crypto patterns | Batch 2 |
| `src/scanner/code/patterns/javascript.ts` | JS/TS crypto patterns | Batch 2 |
| `src/scanner/code/patterns/go.ts` | Go crypto patterns | Batch 2 |
| `src/scanner/code/patterns/java.ts` | Java crypto patterns | Batch 2 |
| `src/scanner/code/patterns/index.ts` | Pattern registry | Batch 2 |
| `src/scanner/code/matcher.ts` | Pattern matching engine | Batch 3 |
| `src/scanner/code/classifier.ts` | Finding classifier | Batch 4 |
| `src/scanner/code/grader.ts` | Code grading logic | Batch 4 |
| `src/output/sarif.ts` | SARIF 2.1.0 formatter | Batch 6 |
| `src/output/cbom.ts` | CycloneDX CBOM formatter | Batch 7 |
| `src/commands/analyze.ts` | CLI command handler | Batch 8 |

### Dependencies to Add

**None.** Zero new runtime dependencies. Only devDependencies for testing (vitest already in place).

Optional: `uuid` package for CBOM serial numbers — or use `crypto.randomUUID()` (Node 19+).

### npm Version Bump

`0.1.1` → `0.2.0` (minor version: new feature, backward compatible)

---

## Appendix B: SARIF Rule Summary

| ID | Name | Algorithm | Level |
|----|------|-----------|-------|
| PQ001 | QuantumVulnerableRSA | RSA (any usage) | error |
| PQ002 | QuantumVulnerableECDSA | ECDSA | error |
| PQ003 | QuantumVulnerableECDH | ECDH, X25519, X448 | error |
| PQ004 | QuantumVulnerableDH | Classic DH | error |
| PQ005 | QuantumVulnerableDSA | DSA | error |
| PQ006 | WeakSymmetricKey | AES-128, other <256-bit | warning |
| PQ007 | BrokenHash | MD5, SHA-1 | error |
| PQ008 | BrokenCipher | DES, 3DES | error |
| PQ009 | QuantumVulnerableJWT | JWT RS*/ES*/PS*/EdDSA | error |
| PQ010 | QuantumVulnerableEdDSA | Ed25519, Ed448 | error |
| PQ100 | PQCAlgorithmDetected | ML-KEM, ML-DSA, SLH-DSA | note |

---

*This spec is comprehensive enough to build the entire Phase 2 feature. Read it top to bottom, then follow the 8-batch implementation plan in Section 12. TDD all the way — write tests first, make them pass, commit.*
