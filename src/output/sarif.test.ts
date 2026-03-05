import { describe, it, expect } from 'vitest';
import { formatSarif } from './sarif.js';
import type { CodeGradedResult, CodeFinding } from '../types/index.js';

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'python-rsa-keygen',
    file: 'src/auth.py',
    line: 42,
    matchedLine: 'rsa.generate_private_key(public_exponent=65537, key_size=2048)',
    language: 'python',
    category: 'asymmetric-encryption',
    algorithm: 'RSA-2048',
    risk: 'critical',
    reason: "Vulnerable to Shor's algorithm",
    migration: 'Replace with ML-DSA (FIPS 204)',
    confidence: 'high',
    ...overrides,
  };
}

function makeResult(findings: CodeFinding[]): CodeGradedResult {
  const uniqueFiles = new Set(findings.map((f) => f.file));
  return {
    scanRoot: '/project',
    grade: 'C',
    baseGrade: 'C',
    modifier: '',
    pqcDetected: false,
    findings,
    migrationNotes: [...new Set(findings.filter((f) => f.migration).map((f) => f.migration!))],
    summary: {
      critical: findings.filter((f) => f.risk === 'critical').length,
      moderate: findings.filter((f) => f.risk === 'moderate').length,
      safe: findings.filter((f) => f.risk === 'safe').length,
      total: findings.length,
      filesScanned: 10,
      filesWithFindings: uniqueFiles.size,
    },
    fileBreakdown: [],
  };
}

describe('formatSarif', () => {
  it('produces valid JSON', () => {
    const output = formatSarif(makeResult([makeFinding()]));
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes SARIF 2.1.0 schema and version', () => {
    const parsed = JSON.parse(formatSarif(makeResult([makeFinding()])));
    expect(parsed.$schema).toContain('sarif-schema-2.1.0');
    expect(parsed.version).toBe('2.1.0');
  });

  it('includes tool driver with name and informationUri', () => {
    const parsed = JSON.parse(formatSarif(makeResult([makeFinding()])));
    const driver = parsed.runs[0].tool.driver;
    expect(driver.name).toBe('PostQuant');
    expect(driver.informationUri).toBe('https://postquant.dev');
    expect(driver.version).toBeDefined();
  });

  it('includes all rule definitions PQ001-PQ010 and PQ100', () => {
    const parsed = JSON.parse(formatSarif(makeResult([makeFinding()])));
    const rules = parsed.runs[0].tool.driver.rules;
    const ruleIds = rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain('PQ001');
    expect(ruleIds).toContain('PQ002');
    expect(ruleIds).toContain('PQ003');
    expect(ruleIds).toContain('PQ004');
    expect(ruleIds).toContain('PQ005');
    expect(ruleIds).toContain('PQ006');
    expect(ruleIds).toContain('PQ007');
    expect(ruleIds).toContain('PQ008');
    expect(ruleIds).toContain('PQ009');
    expect(ruleIds).toContain('PQ010');
    expect(ruleIds).toContain('PQ100');
  });

  it('maps RSA finding to PQ001', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'asymmetric-encryption', algorithm: 'RSA-2048' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ001');
  });

  it('maps ECDSA finding to PQ002', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'digital-signature', algorithm: 'ECDSA-P256' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ002');
  });

  it('maps key-exchange finding to PQ003', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'key-exchange', algorithm: 'X25519' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ003');
  });

  it('maps weak-symmetric finding to PQ006 with warning level', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'weak-symmetric', algorithm: 'AES-128', risk: 'moderate' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ006');
    expect(parsed.runs[0].results[0].level).toBe('warning');
  });

  it('maps weak-hash finding to PQ007', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'weak-hash', algorithm: 'MD5' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ007');
  });

  it('maps broken-cipher finding to PQ008', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'broken-cipher', algorithm: '3DES' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ008');
  });

  it('maps pqc-algorithm finding to PQ100 with note level', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ category: 'pqc-algorithm', algorithm: 'ML-KEM-768', risk: 'safe' }),
    ])));
    expect(parsed.runs[0].results[0].ruleId).toBe('PQ100');
    expect(parsed.runs[0].results[0].level).toBe('note');
  });

  it('sets error level for critical findings', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ risk: 'critical' }),
    ])));
    expect(parsed.runs[0].results[0].level).toBe('error');
  });

  it('includes physical location with file path and line number', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ file: 'src/crypto/keys.py', line: 99 }),
    ])));
    const loc = parsed.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/crypto/keys.py');
    expect(loc.artifactLocation.uriBaseId).toBe('%SRCROOT%');
    expect(loc.region.startLine).toBe(99);
  });

  it('includes fix suggestion from migration field', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ migration: 'Replace with ML-DSA (FIPS 204)' }),
    ])));
    const fixes = parsed.runs[0].results[0].fixes;
    expect(fixes).toHaveLength(1);
    expect(fixes[0].description.text).toContain('ML-DSA');
  });

  it('includes CWE in rule properties', () => {
    const parsed = JSON.parse(formatSarif(makeResult([makeFinding()])));
    const rules = parsed.runs[0].tool.driver.rules;
    const pq001 = rules.find((r: { id: string }) => r.id === 'PQ001');
    expect(pq001.properties.tags).toContain('security');
    // CWE-327 for asymmetric crypto
    const cweTag = pq001.relationships?.[0]?.target?.id ?? pq001.properties?.cwe;
    expect(cweTag).toContain('327');
  });

  it('handles multiple findings producing multiple results', () => {
    const parsed = JSON.parse(formatSarif(makeResult([
      makeFinding({ file: 'src/a.py', line: 10, algorithm: 'RSA-2048' }),
      makeFinding({ file: 'src/b.py', line: 20, category: 'weak-hash', algorithm: 'MD5' }),
      makeFinding({ file: 'src/c.py', line: 30, category: 'pqc-algorithm', algorithm: 'ML-KEM-768', risk: 'safe' }),
    ])));
    expect(parsed.runs[0].results).toHaveLength(3);
  });

  it('handles empty findings producing zero results', () => {
    const parsed = JSON.parse(formatSarif(makeResult([])));
    expect(parsed.runs[0].results).toHaveLength(0);
  });

  it('formats with 2-space indentation', () => {
    const output = formatSarif(makeResult([makeFinding()]));
    expect(output).toContain('\n  ');
  });
});
