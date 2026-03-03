import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { CodeGradedResult, CodeFinding, CryptoCategory } from '../types/index.js';

function getVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'),
    );
    return pkg.version;
  } catch {
    return '0.1.1';
  }
}

// --- Category → CycloneDX primitive mapping (Section 7.3) ---

function categoryToPrimitive(category: CryptoCategory): string {
  switch (category) {
    case 'asymmetric-encryption':
      return 'pke';
    case 'digital-signature':
      return 'signature';
    case 'key-exchange':
      return 'kex';
    case 'weak-symmetric':
    case 'safe-symmetric':
    case 'broken-cipher':
      return 'ae';
    case 'weak-hash':
    case 'safe-hash':
      return 'hash';
    case 'pqc-algorithm':
      return 'kem'; // default for PQC; could vary by algorithm
  }
}

// --- NIST Quantum Security Level mapping (Section 7.4) ---

function nistQuantumSecurityLevel(finding: CodeFinding): number {
  // Level 0: broken by quantum computer (all critical asymmetric, weak-hash, broken-cipher)
  if (finding.risk === 'critical') return 0;

  // Level 5: AES-256, SHA-384, SHA-512, SHA-3, ChaCha20
  const algoUpper = finding.algorithm.toUpperCase();
  if (
    algoUpper.includes('AES-256') ||
    algoUpper.includes('SHA-384') ||
    algoUpper.includes('SHA-512') ||
    algoUpper.includes('SHA3') ||
    algoUpper.includes('SHA-3') ||
    algoUpper.includes('CHACHA20')
  ) {
    return 5;
  }

  // Moderate (AES-128): effectively ~level 1 post-Grover
  if (algoUpper.includes('AES-128')) return 1;

  // PQC algorithms
  if (finding.category === 'pqc-algorithm') {
    if (algoUpper.includes('512') || algoUpper.includes('-44')) return 1;
    if (algoUpper.includes('768') || algoUpper.includes('-65')) return 3;
    if (algoUpper.includes('1024') || algoUpper.includes('-87')) return 5;
    return 3; // default PQC
  }

  // Safe hash/symmetric defaults
  if (finding.risk === 'safe') return 5;

  return 0;
}

// --- Public API ---

export function formatCbom(result: CodeGradedResult): string {
  // Group findings by algorithm name
  const byAlgorithm = new Map<string, CodeFinding[]>();
  for (const f of result.findings) {
    const list = byAlgorithm.get(f.algorithm) ?? [];
    list.push(f);
    byAlgorithm.set(f.algorithm, list);
  }

  // Build components
  const components: Record<string, unknown>[] = [];
  const componentRefs: string[] = [];

  for (const [algorithm, findings] of byAlgorithm) {
    const ref = randomUUID();
    componentRefs.push(ref);

    const representative = findings[0];
    const occurrences = findings.map((f) => ({
      location: f.file,
      line: f.line,
      additionalContext: f.matchedLine,
    }));

    components.push({
      type: 'cryptographic-asset',
      name: algorithm,
      'bom-ref': ref,
      evidence: { occurrences },
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: categoryToPrimitive(representative.category),
          parameterSetIdentifier: extractParameterSet(representative),
          cryptoFunctions: inferCryptoFunctions(representative),
          classicalSecurityLevel: classicalSecurityLevel(representative),
          nistQuantumSecurityLevel: nistQuantumSecurityLevel(representative),
        },
      },
    });
  }

  const cbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    serialNumber: `urn:uuid:${randomUUID()}`,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'postquant',
            version: getVersion(),
            description: 'Quantum readiness scanner',
            externalReferences: [
              {
                type: 'website',
                url: 'https://postquant.dev',
              },
            ],
          },
        ],
      },
      component: {
        type: 'application',
        name: extractProjectName(result.scanRoot),
        'bom-ref': 'scanned-project',
      },
    },
    components,
    dependencies: [
      {
        ref: 'scanned-project',
        dependsOn: componentRefs,
      },
    ],
  };

  return JSON.stringify(cbom, null, 2);
}

// --- Helpers ---

function extractProjectName(scanRoot: string): string {
  const parts = scanRoot.split('/').filter(Boolean);
  return parts[parts.length - 1] || 'unknown-project';
}

function extractParameterSet(finding: CodeFinding): string {
  if (finding.keySize) return String(finding.keySize);
  // Try to pull numbers from algorithm name (e.g., "RSA-2048" → "2048")
  const match = finding.algorithm.match(/(\d+)/);
  return match ? match[1] : '';
}

function inferCryptoFunctions(finding: CodeFinding): string[] {
  const id = finding.patternId.toLowerCase();
  if (id.includes('keygen') || id.includes('generate')) return ['keygen'];
  if (id.includes('sign')) return ['sign', 'verify'];
  if (id.includes('encrypt') || id.includes('cipher')) return ['encrypt', 'decrypt'];
  if (id.includes('exchange') || id.includes('dh') || id.includes('ecdh')) return ['keyexchange'];
  if (id.includes('hash') || id.includes('md5') || id.includes('sha')) return ['digest'];
  // Default based on category
  switch (finding.category) {
    case 'asymmetric-encryption':
      return ['keygen', 'encrypt', 'decrypt'];
    case 'digital-signature':
      return ['sign', 'verify'];
    case 'key-exchange':
      return ['keyexchange'];
    case 'weak-hash':
    case 'safe-hash':
      return ['digest'];
    case 'weak-symmetric':
    case 'safe-symmetric':
    case 'broken-cipher':
      return ['encrypt', 'decrypt'];
    case 'pqc-algorithm':
      return ['keygen'];
    default:
      return ['unknown'];
  }
}

function classicalSecurityLevel(finding: CodeFinding): number {
  const algoUpper = finding.algorithm.toUpperCase();
  // RSA key sizes
  if (algoUpper.includes('RSA')) {
    if (algoUpper.includes('4096')) return 140;
    if (algoUpper.includes('3072')) return 128;
    if (algoUpper.includes('2048')) return 112;
    if (algoUpper.includes('1024')) return 80;
    return 112;
  }
  // ECC curves
  if (algoUpper.includes('P-521') || algoUpper.includes('SECP521')) return 256;
  if (algoUpper.includes('P-384') || algoUpper.includes('SECP384')) return 192;
  if (algoUpper.includes('P-256') || algoUpper.includes('SECP256') || algoUpper.includes('ED25519') || algoUpper.includes('X25519')) return 128;
  // Symmetric
  if (algoUpper.includes('AES-256') || algoUpper.includes('CHACHA20')) return 256;
  if (algoUpper.includes('AES-192')) return 192;
  if (algoUpper.includes('AES-128')) return 128;
  if (algoUpper.includes('3DES')) return 112;
  if (algoUpper.includes('DES')) return 56;
  // Hashes
  if (algoUpper.includes('SHA-512') || algoUpper.includes('SHA3-512')) return 256;
  if (algoUpper.includes('SHA-384') || algoUpper.includes('SHA3-384')) return 192;
  if (algoUpper.includes('SHA-256') || algoUpper.includes('SHA3-256')) return 128;
  if (algoUpper.includes('SHA-1') || algoUpper === 'SHA1') return 80;
  if (algoUpper.includes('MD5')) return 64;
  return 0;
}
