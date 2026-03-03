import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { CodeGradedResult, CodeFinding, CryptoCategory, RiskLevel } from '../types/index.js';

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

// --- Rule definitions (Section 8.3) ---

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[]; cwe: string };
  relationships?: Array<{ target: { id: string; toolComponent: { name: string } } }>;
}

const RULES: SarifRule[] = [
  {
    id: 'PQ001',
    name: 'QuantumVulnerableRSA',
    shortDescription: { text: 'RSA key generation detected' },
    fullDescription: {
      text: "RSA is vulnerable to Shor's algorithm on a quantum computer. Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key encapsulation.",
    },
    helpUri: 'https://postquant.dev/docs/findings/rsa',
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ002',
    name: 'QuantumVulnerableECDSA',
    shortDescription: { text: 'ECDSA key generation or signing detected' },
    fullDescription: {
      text: "ECDSA is vulnerable to Shor's algorithm. Migrate to ML-DSA (FIPS 204).",
    },
    helpUri: 'https://postquant.dev/docs/findings/ecdsa',
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ003',
    name: 'QuantumVulnerableECDH',
    shortDescription: { text: 'ECDH / X25519 key exchange detected' },
    fullDescription: {
      text: "ECDH/X25519 key exchange is vulnerable to Shor's algorithm. Migrate to ML-KEM (FIPS 203).",
    },
    helpUri: 'https://postquant.dev/docs/findings/ecdh',
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ004',
    name: 'QuantumVulnerableDH',
    shortDescription: { text: 'Classic Diffie-Hellman key exchange detected' },
    fullDescription: {
      text: "DH is vulnerable to Shor's algorithm. Migrate to ML-KEM (FIPS 203).",
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ005',
    name: 'QuantumVulnerableDSA',
    shortDescription: { text: 'DSA signing detected' },
    fullDescription: {
      text: "DSA is vulnerable to Shor's algorithm and is also deprecated classically. Migrate to ML-DSA (FIPS 204).",
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ006',
    name: 'WeakSymmetricKey',
    shortDescription: { text: 'AES-128 or other sub-256-bit symmetric key detected' },
    fullDescription: {
      text: "Grover's algorithm reduces AES-128 to 64-bit effective security. Upgrade to AES-256.",
    },
    defaultConfiguration: { level: 'warning' },
    properties: { tags: ['security', 'quantum', 'cryptography'], cwe: 'CWE-326' },
    relationships: [{ target: { id: 'CWE-326', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ007',
    name: 'BrokenHash',
    shortDescription: { text: 'MD5 or SHA-1 hash usage detected' },
    fullDescription: {
      text: 'MD5 and SHA-1 are already broken classically (collision attacks). Replace with SHA-256 or stronger.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'cryptography'], cwe: 'CWE-328' },
    relationships: [{ target: { id: 'CWE-328', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ008',
    name: 'BrokenCipher',
    shortDescription: { text: 'DES or 3DES cipher detected' },
    fullDescription: {
      text: 'DES and 3DES are deprecated and weak. Replace with AES-256-GCM.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'cryptography'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ009',
    name: 'QuantumVulnerableJWT',
    shortDescription: { text: 'JWT signed with quantum-vulnerable algorithm' },
    fullDescription: {
      text: 'RS256/ES256/PS256/EdDSA JWT signatures are vulnerable to quantum attacks. Consider HMAC (HS256) for symmetric use cases, or plan migration to PQC-based JWT.',
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'jwt'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ010',
    name: 'QuantumVulnerableEdDSA',
    shortDescription: { text: 'Ed25519/Ed448 signing detected' },
    fullDescription: {
      text: "EdDSA (Ed25519/Ed448) is vulnerable to Shor's algorithm. Migrate to ML-DSA (FIPS 204).",
    },
    defaultConfiguration: { level: 'error' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: 'CWE-327' },
    relationships: [{ target: { id: 'CWE-327', toolComponent: { name: 'CWE' } } }],
  },
  {
    id: 'PQ100',
    name: 'PQCAlgorithmDetected',
    shortDescription: { text: 'Post-quantum cryptographic algorithm detected' },
    fullDescription: {
      text: 'This code uses a NIST-standardized post-quantum algorithm. No migration needed.',
    },
    defaultConfiguration: { level: 'note' },
    properties: { tags: ['security', 'quantum', 'cryptography', 'pqc'], cwe: '' },
  },
];

// --- Category → Rule ID mapping ---

/** Map a finding's category + patternId to a SARIF rule ID. */
function mapToRuleId(finding: CodeFinding): string {
  // JWT-specific patterns
  if (finding.patternId.includes('jwt')) return 'PQ009';

  // EdDSA-specific: ed25519/ed448 patterns that are digital-signature category
  if (
    finding.patternId.includes('ed25519') ||
    finding.patternId.includes('ed448') ||
    finding.patternId.includes('eddsa')
  ) {
    return 'PQ010';
  }

  // Category-based mapping
  const categoryMap: Record<string, string> = {
    'asymmetric-encryption': 'PQ001',
    'digital-signature': 'PQ002',
    'key-exchange': 'PQ003',
    'weak-symmetric': 'PQ006',
    'weak-hash': 'PQ007',
    'broken-cipher': 'PQ008',
    'safe-symmetric': 'PQ100',
    'safe-hash': 'PQ100',
    'pqc-algorithm': 'PQ100',
  };

  const ruleId = categoryMap[finding.category];
  if (ruleId) return ruleId;

  // Fallback: try algorithm name for DH/DSA distinction
  const algoUpper = finding.algorithm.toUpperCase();
  if (algoUpper.includes('DSA') && !algoUpper.includes('ECDSA')) return 'PQ005';
  if (algoUpper.includes('DH') && !algoUpper.includes('ECDH')) return 'PQ004';

  return 'PQ001';
}

/** Map risk level to SARIF level. */
function riskToLevel(risk: RiskLevel): 'error' | 'warning' | 'note' {
  switch (risk) {
    case 'critical':
      return 'error';
    case 'moderate':
      return 'warning';
    case 'safe':
      return 'note';
  }
}

// --- Public API ---

export function formatSarif(result: CodeGradedResult): string {
  const sarifResults = result.findings.map((f) => {
    const ruleId = mapToRuleId(f);
    const entry: Record<string, unknown> = {
      ruleId,
      level: riskToLevel(f.risk),
      message: {
        text: `${f.algorithm} detected. ${f.reason}.${f.migration ? ` ${f.migration}.` : ''}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.line,
              startColumn: 1,
            },
          },
        },
      ],
    };

    if (f.migration) {
      entry.fixes = [
        {
          description: {
            text: f.migration,
          },
        },
      ];
    }

    return entry;
  });

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PostQuant',
            version: getVersion(),
            informationUri: 'https://postquant.dev',
            rules: RULES,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
