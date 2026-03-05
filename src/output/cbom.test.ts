import { describe, it, expect } from 'vitest';
import { formatCbom } from './cbom.js';
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
    migrationNotes: [],
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

describe('formatCbom', () => {
  it('produces valid JSON', () => {
    const output = formatCbom(makeResult([makeFinding()]));
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('includes CycloneDX 1.6 envelope fields', () => {
    const parsed = JSON.parse(formatCbom(makeResult([makeFinding()])));
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.6');
    expect(parsed.version).toBe(1);
    expect(parsed.serialNumber).toMatch(/^urn:uuid:/);
  });

  it('includes metadata with timestamp and tool info', () => {
    const parsed = JSON.parse(formatCbom(makeResult([makeFinding()])));
    expect(parsed.metadata.timestamp).toBeDefined();
    const tool = parsed.metadata.tools.components[0];
    expect(tool.name).toBe('postquant');
    expect(tool.type).toBe('application');
    expect(tool.version).toBeDefined();
    expect(tool.externalReferences[0].url).toBe('https://postquant.dev');
  });

  it('includes scanned project component in metadata', () => {
    const parsed = JSON.parse(formatCbom(makeResult([makeFinding()])));
    expect(parsed.metadata.component.type).toBe('application');
    expect(parsed.metadata.component['bom-ref']).toBe('scanned-project');
  });

  it('creates one component per unique algorithm', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ algorithm: 'RSA-2048', file: 'src/a.py', line: 10 }),
      makeFinding({ algorithm: 'RSA-2048', file: 'src/b.py', line: 20 }),
      makeFinding({ algorithm: 'ECDSA-P256', file: 'src/c.py', line: 30, category: 'digital-signature' }),
    ])));
    expect(parsed.components).toHaveLength(2);
    const names = parsed.components.map((c: { name: string }) => c.name);
    expect(names).toContain('RSA-2048');
    expect(names).toContain('ECDSA-P256');
  });

  it('groups same-algorithm findings as multiple occurrences', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ algorithm: 'RSA-2048', file: 'src/a.py', line: 10, matchedLine: 'rsa.generate(2048)' }),
      makeFinding({ algorithm: 'RSA-2048', file: 'src/b.py', line: 20, matchedLine: 'rsa.generate(2048)' }),
    ])));
    const rsaComponent = parsed.components.find((c: { name: string }) => c.name === 'RSA-2048');
    expect(rsaComponent.evidence.occurrences).toHaveLength(2);
    expect(rsaComponent.evidence.occurrences[0].location).toBe('src/a.py');
    expect(rsaComponent.evidence.occurrences[0].line).toBe(10);
    expect(rsaComponent.evidence.occurrences[1].location).toBe('src/b.py');
  });

  it('sets type to cryptographic-asset on components', () => {
    const parsed = JSON.parse(formatCbom(makeResult([makeFinding()])));
    expect(parsed.components[0].type).toBe('cryptographic-asset');
  });

  it('sets bom-ref as a unique string on each component', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ algorithm: 'RSA-2048' }),
      makeFinding({ algorithm: 'AES-128', category: 'weak-symmetric', risk: 'moderate', file: 'src/b.py' }),
    ])));
    const refs = parsed.components.map((c: { 'bom-ref': string }) => c['bom-ref']);
    expect(refs[0]).toBeDefined();
    expect(refs[1]).toBeDefined();
    expect(refs[0]).not.toBe(refs[1]);
  });

  it('maps asymmetric-encryption to pke primitive', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'asymmetric-encryption' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.primitive).toBe('pke');
  });

  it('maps digital-signature to signature primitive', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'digital-signature', algorithm: 'ECDSA-P256' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.primitive).toBe('signature');
  });

  it('maps key-exchange to kex primitive', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'key-exchange', algorithm: 'X25519' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.primitive).toBe('kex');
  });

  it('maps weak-symmetric to ae primitive', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'weak-symmetric', algorithm: 'AES-128', risk: 'moderate' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.primitive).toBe('ae');
  });

  it('maps weak-hash to hash primitive', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'weak-hash', algorithm: 'MD5' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.primitive).toBe('hash');
  });

  it('sets nistQuantumSecurityLevel 0 for quantum-vulnerable algorithms', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'asymmetric-encryption', algorithm: 'RSA-2048', risk: 'critical' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(0);
  });

  it('sets nistQuantumSecurityLevel 5 for AES-256 / SHA-384+', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ category: 'safe-symmetric', algorithm: 'AES-256', risk: 'safe' }),
    ])));
    expect(parsed.components[0].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(5);
  });

  it('includes dependencies section referencing scanned-project', () => {
    const parsed = JSON.parse(formatCbom(makeResult([
      makeFinding({ algorithm: 'RSA-2048' }),
    ])));
    expect(parsed.dependencies).toHaveLength(1);
    expect(parsed.dependencies[0].ref).toBe('scanned-project');
    expect(parsed.dependencies[0].dependsOn).toHaveLength(1);
  });

  it('handles empty findings with zero components', () => {
    const parsed = JSON.parse(formatCbom(makeResult([])));
    expect(parsed.components).toHaveLength(0);
    expect(parsed.dependencies[0].dependsOn).toHaveLength(0);
  });

  it('formats with 2-space indentation', () => {
    const output = formatCbom(makeResult([makeFinding()]));
    expect(output).toContain('\n  ');
  });
});
