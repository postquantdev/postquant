/**
 * Risk Assessment Layer for PostQuant v0.3.0
 *
 * Analyzes the CONTEXT of each cryptographic finding to determine
 * whether the algorithm usage is security-critical or benign.
 * MD5 in password hashing is critical; MD5 in UUID v3 is informational.
 */

import type {
  CodeFinding,
  Language,
  RiskLevel,
  UsageContext,
  AdjustedRisk,
  ContextSignal,
  RiskContext,
  AssessedFinding,
} from '../../types/index.js';

// ── Exported helper type ────────────────────────────────────────

export interface ResolvedContext {
  context: UsageContext;
  influence: 'increases-risk' | 'decreases-risk' | 'neutral';
}

// ── Context priority map ────────────────────────────────────────

const CONTEXT_PRIORITY: Record<UsageContext, number> = {
  'authentication': 10,
  'encryption': 9,
  'key-exchange': 9,
  'digital-signature': 8,
  'legacy-support': 5,
  'integrity-check': 4,
  'protocol-compliance': 3,
  'test-fixture': 2,
  'documentation': 1,
  'unknown': 0,
};

// ── Signal-to-context mapping ───────────────────────────────────
// Maps signal value keywords to their UsageContext.

function inferContextFromSignalValue(value: string): UsageContext {
  const v = value.toLowerCase();

  // increases-risk contexts
  if (/password|passwd|pwd|hmac|token|jwt|bearer|oauth/.test(v)) return 'authentication';
  if (/encrypt|decrypt|cipher/.test(v)) return 'encryption';
  if (/key_exchange|kex|handshake/.test(v)) return 'key-exchange';
  if (/sign|verify|signature/.test(v)) return 'digital-signature';

  // decreases-risk contexts
  if (/uuid|rfc4122|rfc-4122|content-md5|content_md5/.test(v)) return 'protocol-compliance';
  if (/checksum|digest|fingerprint|etag|cache|dedup|lookup|index|md5sum|md5_checksum|file_hash|compute_hash|content_hash|cache_key|compute_etag/.test(v)) return 'integrity-check';
  if (/legacy|compat|fallback|deprecated|vendor|node_modules|third_party|migrations/.test(v)) return 'legacy-support';
  if (/test|mock|stub|fixture|assert|spec|__tests__/.test(v)) return 'test-fixture';
  if (/docs|examples|readme/.test(v)) return 'documentation';

  // Import-based contexts
  if (/boto3|botocore|aws-sdk|@aws-sdk/.test(v)) return 'protocol-compliance';
  if (/\bpg\b|postgres|psycopg|node-postgres|mysql|mysqlclient/.test(v)) return 'legacy-support';
  if (/\bgit\b/.test(v)) return 'protocol-compliance';
  if (/passlib|bcrypt|argon2|pyjwt|jsonwebtoken|jose|paramiko|ssh2|libssh/.test(v)) return 'authentication';

  // Function-name increases-risk
  if (/hash_password|check_password|verify_password/.test(v)) return 'authentication';
  if (/generate_key|create_key|new_key/.test(v)) return 'encryption';
  if (/sign_/.test(v)) return 'digital-signature';
  if (/verify_/.test(v)) return 'digital-signature';

  // File path contexts
  if (/auth|authentication|session|login|password/.test(v)) return 'authentication';
  if (/security|crypto|certs/.test(v)) return 'encryption';

  return 'unknown';
}

// ── 1. detectFilePathSignals ────────────────────────────────────

interface FilePathRule {
  pattern: RegExp;
  influence: 'increases-risk' | 'decreases-risk';
  label: string;
}

const FILE_PATH_RULES: FilePathRule[] = [
  // increases-risk
  { pattern: /(?:^|\/)(auth|authentication)\//, influence: 'increases-risk', label: 'auth/' },
  { pattern: /(?:^|\/)(security|crypto|certs)\//, influence: 'increases-risk', label: 'security/' },
  { pattern: /(?:^|\/)(session|login|password)\//, influence: 'increases-risk', label: 'session/' },

  // decreases-risk: directories
  { pattern: /(?:^|\/)(test|tests|__tests__|spec)\//, influence: 'decreases-risk', label: 'test/' },
  { pattern: /(?:^|\/)(vendor|node_modules|third_party)\//, influence: 'decreases-risk', label: 'vendor/' },
  { pattern: /(?:^|\/)(docs|examples)\//, influence: 'decreases-risk', label: 'docs/' },
  { pattern: /README/, influence: 'decreases-risk', label: 'README' },
  { pattern: /(?:^|\/)(migrations|compat|legacy)\//, influence: 'decreases-risk', label: 'legacy/' },

  // decreases-risk: file suffixes
  { pattern: /_test\.go$/, influence: 'decreases-risk', label: '_test.go' },
  { pattern: /\.test\.[tj]s$/, influence: 'decreases-risk', label: '.test.ts/js' },
  { pattern: /\.spec\.[tj]s$/, influence: 'decreases-risk', label: '.spec.ts/js' },
];

export function detectFilePathSignals(filePath: string): ContextSignal[] {
  const signals: ContextSignal[] = [];

  for (const rule of FILE_PATH_RULES) {
    if (rule.pattern.test(filePath)) {
      signals.push({
        type: 'file-path',
        value: rule.label,
        influence: rule.influence,
      });
    }
  }

  return signals;
}

// ── 2. detectNearbyCodeSignals ──────────────────────────────────

interface NearbyCodeRule {
  pattern: RegExp;
  influence: 'increases-risk' | 'decreases-risk';
  label: string;
}

const NEARBY_CODE_RULES: NearbyCodeRule[] = [
  // increases-risk
  { pattern: /password|passwd|pwd/i, influence: 'increases-risk', label: 'password' },
  { pattern: /\bsign\b|verify|signature/i, influence: 'increases-risk', label: 'sign/verify' },
  { pattern: /encrypt|decrypt|cipher/i, influence: 'increases-risk', label: 'encrypt' },
  { pattern: /key_exchange|kex|handshake/i, influence: 'increases-risk', label: 'key_exchange' },
  { pattern: /\bhmac\b|\bHMAC\b/, influence: 'increases-risk', label: 'hmac' },
  { pattern: /\btoken\b|jwt|bearer|oauth/i, influence: 'increases-risk', label: 'token/jwt' },

  // decreases-risk
  { pattern: /checksum|digest|fingerprint|etag/i, influence: 'decreases-risk', label: 'checksum' },
  { pattern: /\bcache\b|\bdedup\b|\blookup\b|\bindex\b/i, influence: 'decreases-risk', label: 'cache' },
  { pattern: /\buuid\b|\bUUID\b|rfc4122|rfc-4122/, influence: 'decreases-risk', label: 'uuid' },
  { pattern: /Content-MD5|content_md5/i, influence: 'decreases-risk', label: 'Content-MD5' },
  { pattern: /legacy|compat|fallback|deprecated/i, influence: 'decreases-risk', label: 'legacy' },
  { pattern: /\btest\b|\bmock\b|\bstub\b|\bfixture\b|\bassert\b/i, influence: 'decreases-risk', label: 'test' },
];

export function detectNearbyCodeSignals(
  lines: string[],
  lineNumber: number,
  windowSize: number = 5,
): ContextSignal[] {
  // lineNumber is 1-indexed
  const idx = lineNumber - 1;
  const start = Math.max(0, idx - windowSize);
  const end = Math.min(lines.length - 1, idx + windowSize);

  const window = lines.slice(start, end + 1).join('\n');
  const seen = new Set<string>();
  const signals: ContextSignal[] = [];

  for (const rule of NEARBY_CODE_RULES) {
    if (rule.pattern.test(window) && !seen.has(rule.label)) {
      seen.add(rule.label);
      signals.push({
        type: 'nearby-code',
        value: rule.label,
        influence: rule.influence,
      });
    }
  }

  return signals;
}

// ── 3. detectImportSignals ──────────────────────────────────────

interface ImportRule {
  libraryPattern: RegExp;
  influence: 'increases-risk' | 'decreases-risk';
  label: string;
}

const IMPORT_RULES: ImportRule[] = [
  // decreases-risk
  { libraryPattern: /\buuid\b/i, influence: 'decreases-risk', label: 'uuid' },
  { libraryPattern: /boto3|botocore|aws-sdk|@aws-sdk/, influence: 'decreases-risk', label: 'boto3/aws-sdk' },
  { libraryPattern: /\bpg\b|postgres|psycopg|node-postgres/, influence: 'decreases-risk', label: 'pg/psycopg/postgres' },
  { libraryPattern: /mysql2|mysql|mysqlclient/, influence: 'decreases-risk', label: 'mysql' },
  { libraryPattern: /\bgit\b/, influence: 'decreases-risk', label: 'git' },

  // increases-risk
  { libraryPattern: /passlib|bcrypt|argon2/, influence: 'increases-risk', label: 'passlib/bcrypt/argon2' },
  { libraryPattern: /pyjwt|jsonwebtoken|jose|\bjwt\b/, influence: 'increases-risk', label: 'pyjwt/jsonwebtoken/jose' },
  { libraryPattern: /paramiko|ssh2|libssh/, influence: 'increases-risk', label: 'paramiko/ssh2/libssh' },
];

// Language-specific import statement patterns
const IMPORT_LINE_PATTERNS: Record<Language, RegExp[]> = {
  python: [
    /^\s*import\s+(.+)/,
    /^\s*from\s+(\S+)\s+import/,
  ],
  javascript: [
    /^\s*import\s+.+\s+from\s+['"]([^'"]+)['"]/,
    /^\s*import\s+['"]([^'"]+)['"]/,
    /^\s*import\s*\{[^}]+\}\s*from\s*['"]([^'"]+)['"]/,
    /(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/,
  ],
  go: [
    /^\s*"([^"]+)"/,
    /^\s*\w+\s+"([^"]+)"/,
  ],
  java: [
    /^\s*import\s+([\w.]+)/,
  ],
};

export function detectImportSignals(content: string, language: Language): ContextSignal[] {
  const lines = content.split('\n').slice(0, 50);
  const signals: ContextSignal[] = [];
  const seen = new Set<string>();

  const patterns = IMPORT_LINE_PATTERNS[language] || [];

  for (const line of lines) {
    for (const importPattern of patterns) {
      const match = importPattern.exec(line);
      if (!match) continue;

      const importedModule = match[1] || line;

      for (const rule of IMPORT_RULES) {
        if (rule.libraryPattern.test(importedModule) && !seen.has(rule.label)) {
          seen.add(rule.label);
          signals.push({
            type: 'import-context',
            value: rule.label,
            influence: rule.influence,
          });
        }
      }
    }
  }

  return signals;
}

// ── 4. detectFunctionNameSignals ────────────────────────────────

interface FunctionNameRule {
  pattern: RegExp;
  influence: 'increases-risk' | 'decreases-risk';
  label: string;
}

const FUNCTION_NAME_RULES: FunctionNameRule[] = [
  // increases-risk
  { pattern: /hash_password|check_password|verify_password/, influence: 'increases-risk', label: 'hash_password' },
  { pattern: /generate_key|create_key|new_key/, influence: 'increases-risk', label: 'generate_key' },
  { pattern: /\bsign_\w+/, influence: 'increases-risk', label: 'sign_*' },
  { pattern: /\bverify_\w+/, influence: 'increases-risk', label: 'verify_*' },

  // decreases-risk
  { pattern: /md5sum|md5_checksum|file_hash|compute_hash/, influence: 'decreases-risk', label: 'md5sum/file_hash' },
  { pattern: /cache_key|compute_etag|content_hash/, influence: 'decreases-risk', label: 'cache_key/etag' },
  { pattern: /\betag\b/, influence: 'decreases-risk', label: 'etag' },
];

export function detectFunctionNameSignals(matchedLine: string): ContextSignal[] {
  const signals: ContextSignal[] = [];
  const seen = new Set<string>();

  for (const rule of FUNCTION_NAME_RULES) {
    if (rule.pattern.test(matchedLine) && !seen.has(rule.label)) {
      seen.add(rule.label);
      signals.push({
        type: 'function-name',
        value: rule.label,
        influence: rule.influence,
      });
    }
  }

  return signals;
}

// ── 5. detectProtocolPattern ────────────────────────────────────

interface ProtocolRule {
  algorithm: string;
  contextPatterns: RegExp[];
  importHints: RegExp[];
  protocolName: string;
  contextOverride: UsageContext;
}

const PROTOCOL_RULES: ProtocolRule[] = [
  {
    algorithm: 'MD5',
    contextPatterns: [/\buuid\b|\bUUID\b|uuid3|NAMESPACE|rfc4122/],
    importHints: [/\buuid\b/],
    protocolName: 'UUID v3 (RFC 4122)',
    contextOverride: 'protocol-compliance',
  },
  {
    algorithm: 'SHA-1',
    contextPatterns: [/\buuid\b|\bUUID\b|uuid5|NAMESPACE|rfc4122/],
    importHints: [/\buuid\b/],
    protocolName: 'UUID v5 (RFC 4122)',
    contextOverride: 'protocol-compliance',
  },
  {
    algorithm: 'MD5',
    contextPatterns: [/Content-MD5|content_md5|ContentMD5/],
    importHints: [/boto3|aws|s3/],
    protocolName: 'HTTP/S3 Content-MD5',
    contextOverride: 'protocol-compliance',
  },
  {
    algorithm: 'MD5',
    contextPatterns: [/postgres|postgresql|pg_|md5.*password/i],
    importHints: [/\bpg\b|postgres|psycopg/],
    protocolName: 'PostgreSQL MD5 auth',
    contextOverride: 'legacy-support',
  },
  {
    algorithm: 'SHA-1',
    contextPatterns: [/\bgit\b|object_hash|blob|commit|tree/],
    importHints: [/\bgit\b/],
    protocolName: 'Git object hashing',
    contextOverride: 'protocol-compliance',
  },
];

export function detectProtocolPattern(
  finding: CodeFinding,
  nearbyLines: string[],
  imports: string,
): ContextSignal | null {
  const nearbyText = nearbyLines.join('\n');

  for (const rule of PROTOCOL_RULES) {
    if (finding.algorithm !== rule.algorithm) continue;

    const contextMatch = rule.contextPatterns.some(p => p.test(nearbyText));
    const importMatch = rule.importHints.some(p => p.test(imports));

    if (contextMatch || importMatch) {
      return {
        type: 'api-pattern',
        value: `${rule.protocolName} (${rule.contextOverride})`,
        influence: 'decreases-risk',
      };
    }
  }

  return null;
}

// ── 6. resolveContext ───────────────────────────────────────────

export function resolveContext(signals: ContextSignal[]): ResolvedContext {
  if (signals.length === 0) {
    return { context: 'unknown', influence: 'neutral' };
  }

  const increasesRisk = signals.filter(s => s.influence === 'increases-risk');
  const decreasesRisk = signals.filter(s => s.influence === 'decreases-risk');

  // increases-risk wins
  if (increasesRisk.length > 0) {
    const context = pickHighestPriority(increasesRisk);
    return { context, influence: 'increases-risk' };
  }

  if (decreasesRisk.length > 0) {
    const context = pickHighestPriority(decreasesRisk);
    return { context, influence: 'decreases-risk' };
  }

  // All neutral
  return { context: 'unknown', influence: 'neutral' };
}

function pickHighestPriority(signals: ContextSignal[]): UsageContext {
  let bestContext: UsageContext = 'unknown';
  let bestPriority = -1;

  for (const signal of signals) {
    const ctx = inferContextFromSignalValue(signal.value);
    const priority = CONTEXT_PRIORITY[ctx];
    if (priority > bestPriority) {
      bestPriority = priority;
      bestContext = ctx;
    }
  }

  return bestContext;
}

// ── 7. computeAdjustedRisk ──────────────────────────────────────

const RISK_MATRIX: Record<RiskLevel, Record<UsageContext, AdjustedRisk>> = {
  critical: {
    'authentication': 'critical',
    'encryption': 'critical',
    'key-exchange': 'critical',
    'digital-signature': 'critical',
    'integrity-check': 'low',
    'protocol-compliance': 'informational',
    'legacy-support': 'medium',
    'test-fixture': 'informational',
    'documentation': 'informational',
    'unknown': 'high',
  },
  moderate: {
    'authentication': 'medium',
    'encryption': 'medium',
    'key-exchange': 'medium',
    'digital-signature': 'medium',
    'integrity-check': 'low',
    'protocol-compliance': 'informational',
    'legacy-support': 'low',
    'test-fixture': 'informational',
    'documentation': 'informational',
    'unknown': 'medium',
  },
  safe: {
    'authentication': 'informational',
    'encryption': 'informational',
    'key-exchange': 'informational',
    'digital-signature': 'informational',
    'integrity-check': 'informational',
    'protocol-compliance': 'informational',
    'legacy-support': 'informational',
    'test-fixture': 'informational',
    'documentation': 'informational',
    'unknown': 'informational',
  },
};

export function computeAdjustedRisk(
  originalRisk: RiskLevel,
  context: UsageContext,
): AdjustedRisk {
  return RISK_MATRIX[originalRisk][context];
}

// ── 8. assessFindings (main entry point) ────────────────────────

export function assessFindings(
  findings: CodeFinding[],
  fileContents: Map<string, string>,
): AssessedFinding[] {
  return findings.map(finding => assessSingleFinding(finding, fileContents));
}

function assessSingleFinding(
  finding: CodeFinding,
  fileContents: Map<string, string>,
): AssessedFinding {
  const content = fileContents.get(finding.file) ?? '';
  const lines = content.split('\n');

  // 1. Collect all signals
  const filePathSignals = detectFilePathSignals(finding.file);
  const nearbyCodeSignals = detectNearbyCodeSignals(lines, finding.line);
  const importSignals = detectImportSignals(content, finding.language);
  const functionNameSignals = detectFunctionNameSignals(finding.matchedLine);

  // 2. Check protocol pattern
  const windowSize = 5;
  const idx = finding.line - 1;
  const start = Math.max(0, idx - windowSize);
  const end = Math.min(lines.length - 1, idx + windowSize);
  const nearbyLines = lines.slice(start, end + 1);
  const importText = lines.slice(0, 50).join('\n');

  const protocolSignal = detectProtocolPattern(finding, nearbyLines, importText);

  // 3. Merge all signals
  const allSignals: ContextSignal[] = [
    ...filePathSignals,
    ...nearbyCodeSignals,
    ...importSignals,
    ...functionNameSignals,
  ];
  if (protocolSignal) {
    allSignals.push(protocolSignal);
  }

  // 4. Resolve context
  let usageContext: UsageContext;
  const hasIncreasesRisk = allSignals.some(s => s.influence === 'increases-risk');

  if (protocolSignal && !hasIncreasesRisk) {
    // Protocol pattern detected with no security-increasing signals => use protocol's context
    const protocolRule = PROTOCOL_RULES.find(r => {
      if (r.algorithm !== finding.algorithm) return false;
      const nearbyText = nearbyLines.join('\n');
      const contextMatch = r.contextPatterns.some(p => p.test(nearbyText));
      const importMatch = r.importHints.some(p => p.test(importText));
      return contextMatch || importMatch;
    });
    usageContext = protocolRule?.contextOverride ?? resolveContext(allSignals).context;
  } else {
    usageContext = resolveContext(allSignals).context;
  }

  // 5. Compute adjusted risk
  const adjustedRisk = computeAdjustedRisk(finding.risk, usageContext);

  // 6. Build context evidence
  const contextEvidence = allSignals.map(signal => {
    const arrow = signal.influence === 'increases-risk' ? '\u2191' : signal.influence === 'decreases-risk' ? '\u2193' : '\u2022';
    return `${arrow} ${signal.type}: ${signal.value}`;
  });

  // 7. Build AssessedFinding
  const riskContext: RiskContext = {
    usageContext,
    adjustedRisk,
    contextEvidence,
    signals: allSignals,
  };

  return {
    ...finding,
    originalRisk: finding.risk,
    riskContext,
  };
}
