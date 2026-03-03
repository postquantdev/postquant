import { describe, it, expect } from 'vitest';
import { gradeCodeScan, shouldFailForCodeGrade } from '../grader.js';
import type {
  CodeFinding,
  CodeScanResult,
  Language,
  RiskLevel,
  AdjustedRisk,
  UsageContext,
  AssessedFinding,
} from '../../../types/index.js';

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'test-pattern',
    file: 'src/auth.py',
    line: 10,
    matchedLine: 'some_call()',
    language: 'python' as Language,
    category: 'asymmetric-encryption',
    algorithm: 'RSA-2048',
    risk: 'critical',
    reason: 'Vulnerable',
    migration: 'Use ML-KEM',
    confidence: 'high',
    ...overrides,
  };
}

function makeScanResult(findings: CodeFinding[]): CodeScanResult {
  const uniqueFiles = new Set(findings.map((f) => f.file));
  const uniqueLangs = [...new Set(findings.map((f) => f.language))];
  return {
    scanRoot: '/project',
    findings,
    filesScanned: 10,
    filesWithFindings: uniqueFiles.size,
    languagesDetected: uniqueLangs,
    durationMs: 100,
  };
}

function makeAssessedFinding(opts: {
  algorithm?: string;
  risk?: RiskLevel;
  adjustedRisk: AdjustedRisk;
  usageContext: UsageContext;
  file?: string;
  category?: CodeFinding['category'];
}): AssessedFinding {
  return {
    patternId: 'test',
    file: opts.file ?? 'test.py',
    line: 1,
    matchedLine: 'md5(x)',
    language: 'python' as Language,
    category: opts.category ?? 'weak-hash',
    algorithm: opts.algorithm ?? 'MD5',
    risk: opts.risk ?? 'critical',
    reason: 'test',
    migration: 'test',
    confidence: 'medium',
    originalRisk: opts.risk ?? 'critical',
    riskContext: {
      usageContext: opts.usageContext,
      adjustedRisk: opts.adjustedRisk,
      contextEvidence: [],
      signals: [],
    },
  };
}

describe('gradeCodeScan', () => {
  // --- Base grade tests ---

  it('grades A when no findings at all', () => {
    const result = gradeCodeScan(makeScanResult([]));
    expect(result.grade).toBe('A');
    expect(result.baseGrade).toBe('A');
  });

  it('grades A+ when only PQC findings present', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ category: 'pqc-algorithm', risk: 'safe', algorithm: 'ML-KEM-768' }),
    ]));
    expect(result.grade).toBe('A+');
    expect(result.baseGrade).toBe('A+');
  });

  it('grades A when only safe (non-PQC) findings present', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ category: 'safe-symmetric', risk: 'safe', algorithm: 'AES-256' }),
      makeFinding({ category: 'safe-hash', risk: 'safe', algorithm: 'SHA-512', file: 'src/hash.py' }),
    ]));
    expect(result.grade).toBe('A');
    expect(result.baseGrade).toBe('A');
  });

  it('grades B when 0 critical and moderate only', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ category: 'weak-symmetric', risk: 'moderate', algorithm: 'AES-128' }),
    ]));
    expect(result.grade).toBe('B');
    expect(result.baseGrade).toBe('B');
  });

  it('grades C with 1 critical finding', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
    ]));
    expect(result.baseGrade).toBe('C');
  });

  it('grades C with 5 critical findings', () => {
    const findings = Array.from({ length: 5 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.baseGrade).toBe('C');
  });

  it('grades D with 6 critical findings', () => {
    const findings = Array.from({ length: 6 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.baseGrade).toBe('D');
  });

  it('grades D with 20 critical findings', () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.baseGrade).toBe('D');
  });

  it('grades F with 21+ critical findings', () => {
    const findings = Array.from({ length: 21 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.grade).toBe('F');
    expect(result.baseGrade).toBe('F');
  });

  // --- Modifier tests ---

  it('assigns + modifier when 0 moderate in C band', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
    ]));
    expect(result.grade).toBe('C+');
    expect(result.modifier).toBe('+');
  });

  it('assigns empty modifier when 1 moderate in C band', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
      makeFinding({ risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128', file: 'src/enc.py' }),
    ]));
    expect(result.grade).toBe('C');
    expect(result.modifier).toBe('');
  });

  it('assigns - modifier when 2+ moderate in C band', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
      makeFinding({ risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128', file: 'src/enc.py' }),
      makeFinding({ risk: 'moderate', category: 'weak-hash', algorithm: 'SHA-256', file: 'src/hash.py' }),
    ]));
    expect(result.grade).toBe('C-');
    expect(result.modifier).toBe('-');
  });

  it('assigns no modifier to A or A+', () => {
    const result = gradeCodeScan(makeScanResult([]));
    expect(result.modifier).toBe('');
  });

  it('assigns no modifier to F', () => {
    const findings = Array.from({ length: 21 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.modifier).toBe('');
  });

  // --- Special cases: broken hash/cipher caps at D ---

  it('caps grade at D when MD5 is found (would otherwise be C)', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical', algorithm: 'MD5', category: 'weak-hash' }),
    ]));
    // 1 critical would be C, but MD5 caps at D
    expect(result.baseGrade).toBe('D');
  });

  it('caps grade at D when SHA-1 is found (would otherwise be C)', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical', algorithm: 'SHA-1', category: 'weak-hash' }),
    ]));
    expect(result.baseGrade).toBe('D');
  });

  it('caps grade at D when DES is found (would otherwise be C)', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical', algorithm: 'DES', category: 'broken-cipher' }),
    ]));
    expect(result.baseGrade).toBe('D');
  });

  it('caps grade at D when 3DES is found (would otherwise be C)', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical', algorithm: '3DES', category: 'broken-cipher' }),
    ]));
    expect(result.baseGrade).toBe('D');
  });

  it('does not cap F grade (already worse than D)', () => {
    const findings = Array.from({ length: 21 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    findings.push(makeFinding({ risk: 'critical', algorithm: 'MD5', category: 'weak-hash', file: 'src/md5.py' }));
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.baseGrade).toBe('F');
  });

  // --- Summary and structural tests ---

  it('computes correct summary counts', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
      makeFinding({ risk: 'critical', file: 'src/b.py' }),
      makeFinding({ risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128', file: 'src/c.py' }),
      makeFinding({ risk: 'safe', category: 'safe-hash', algorithm: 'SHA-512', file: 'src/d.py' }),
    ]));
    expect(result.summary.critical).toBe(2);
    expect(result.summary.moderate).toBe(1);
    expect(result.summary.safe).toBe(1);
    expect(result.summary.total).toBe(4);
  });

  it('collects unique migration notes', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ migration: 'Use ML-KEM' }),
      makeFinding({ migration: 'Use ML-KEM', file: 'src/b.py' }),
      makeFinding({ migration: 'Use ML-DSA', file: 'src/c.py' }),
    ]));
    expect(result.migrationNotes).toContain('Use ML-KEM');
    expect(result.migrationNotes).toContain('Use ML-DSA');
    expect(result.migrationNotes).toHaveLength(2);
  });

  it('produces per-file breakdown', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ file: 'src/a.py', risk: 'critical' }),
      makeFinding({ file: 'src/a.py', risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128', line: 20 }),
      makeFinding({ file: 'src/b.py', risk: 'safe', category: 'safe-hash', algorithm: 'SHA-512' }),
    ]));
    expect(result.fileBreakdown).toHaveLength(2);

    const fileA = result.fileBreakdown.find((fb) => fb.file === 'src/a.py');
    expect(fileA).toBeDefined();
    expect(fileA!.criticalCount).toBe(1);
    expect(fileA!.moderateCount).toBe(1);
    expect(fileA!.safeCount).toBe(0);
    expect(fileA!.language).toBe('python');

    const fileB = result.fileBreakdown.find((fb) => fb.file === 'src/b.py');
    expect(fileB).toBeDefined();
    expect(fileB!.criticalCount).toBe(0);
    expect(fileB!.safeCount).toBe(1);
  });

  it('preserves filesScanned in summary', () => {
    const scan = makeScanResult([]);
    scan.filesScanned = 42;
    const result = gradeCodeScan(scan);
    expect(result.summary.filesScanned).toBe(42);
  });

  it('assigns + modifier in D band with 0 moderate', () => {
    const findings = Array.from({ length: 6 }, (_, i) =>
      makeFinding({ risk: 'critical', file: `src/file${i}.py`, line: i + 1 }),
    );
    const result = gradeCodeScan(makeScanResult(findings));
    expect(result.grade).toBe('D+');
    expect(result.modifier).toBe('+');
  });

  it('assigns - modifier in B band with 2+ moderate', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128' }),
      makeFinding({ risk: 'moderate', category: 'weak-hash', algorithm: 'SHA-256', file: 'src/hash.py' }),
    ]));
    expect(result.grade).toBe('B-');
    expect(result.modifier).toBe('-');
  });
});

describe('gradeCodeScan — adjusted risk (AssessedFinding)', () => {
  it('excludes informational findings from grade → A', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        adjustedRisk: 'informational',
        usageContext: 'test-fixture',
        risk: 'critical',
      }),
    ]));
    expect(result.baseGrade).toBe('A');
  });

  it('counts critical adjustedRisk as critical → C range', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'RSA-2048',
        adjustedRisk: 'critical',
        usageContext: 'authentication',
        risk: 'critical',
        category: 'asymmetric-encryption',
      }),
    ]));
    expect(result.baseGrade).toBe('C');
  });

  it('counts high adjustedRisk as critical → C range', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'RSA-2048',
        adjustedRisk: 'high',
        usageContext: 'encryption',
        risk: 'critical',
        category: 'asymmetric-encryption',
      }),
    ]));
    expect(result.baseGrade).toBe('C');
  });

  it('counts medium adjustedRisk as moderate → B range', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        adjustedRisk: 'medium',
        usageContext: 'integrity-check',
        risk: 'critical',
      }),
    ]));
    expect(result.baseGrade).toBe('B');
  });

  it('excludes low adjustedRisk from grade → A', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        adjustedRisk: 'low',
        usageContext: 'legacy-support',
        risk: 'critical',
      }),
    ]));
    expect(result.baseGrade).toBe('A');
  });

  it('broken algo cap applies when adjustedRisk is critical', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'MD5',
        adjustedRisk: 'critical',
        usageContext: 'authentication',
        risk: 'critical',
        category: 'weak-hash',
      }),
    ]));
    // 1 critical → C, but MD5 caps at D
    expect(result.baseGrade).toBe('D');
  });

  it('broken algo cap applies when adjustedRisk is high', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'SHA-1',
        adjustedRisk: 'high',
        usageContext: 'encryption',
        risk: 'critical',
        category: 'weak-hash',
      }),
    ]));
    // 1 critical → C, but SHA-1 caps at D
    expect(result.baseGrade).toBe('D');
  });

  it('broken algo cap does NOT apply when adjustedRisk is informational', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'MD5',
        adjustedRisk: 'informational',
        usageContext: 'test-fixture',
        risk: 'critical',
        category: 'weak-hash',
      }),
    ]));
    // MD5 present but informational, so no cap and no critical count → A
    expect(result.baseGrade).toBe('A');
  });

  it('broken algo cap does NOT apply when adjustedRisk is low', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        algorithm: 'MD5',
        adjustedRisk: 'low',
        usageContext: 'documentation',
        risk: 'critical',
        category: 'weak-hash',
      }),
    ]));
    expect(result.baseGrade).toBe('A');
  });

  it('raw findings (no riskContext) still work correctly', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
      makeFinding({ risk: 'moderate', category: 'weak-symmetric', algorithm: 'AES-128', file: 'src/enc.py' }),
    ]));
    expect(result.baseGrade).toBe('C');
    expect(result.summary.critical).toBe(1);
    expect(result.summary.moderate).toBe(1);
  });

  it('mixes raw and assessed findings correctly', () => {
    const result = gradeCodeScan(makeScanResult([
      makeFinding({ risk: 'critical' }),
      makeAssessedFinding({
        adjustedRisk: 'informational',
        usageContext: 'test-fixture',
        risk: 'critical',
        file: 'tests/test_crypto.py',
      }),
    ]));
    // 1 raw critical + 1 assessed informational (excluded) → C
    expect(result.baseGrade).toBe('C');
    expect(result.summary.critical).toBe(1);
  });

  it('file breakdown uses adjusted risk for counts', () => {
    const result = gradeCodeScan(makeScanResult([
      makeAssessedFinding({
        adjustedRisk: 'informational',
        usageContext: 'test-fixture',
        risk: 'critical',
        file: 'tests/test_crypto.py',
      }),
      makeAssessedFinding({
        adjustedRisk: 'medium',
        usageContext: 'integrity-check',
        risk: 'critical',
        file: 'tests/test_crypto.py',
      }),
    ]));
    const fb = result.fileBreakdown.find((f) => f.file === 'tests/test_crypto.py');
    expect(fb).toBeDefined();
    // informational → excluded (safe bucket), medium → moderate
    expect(fb!.criticalCount).toBe(0);
    expect(fb!.moderateCount).toBe(1);
    expect(fb!.safeCount).toBe(1);
  });
});

describe('shouldFailForCodeGrade', () => {
  it('fails C grade at default threshold C', () => {
    expect(shouldFailForCodeGrade('C', 'C')).toBe(true);
  });

  it('passes B grade at default threshold C', () => {
    expect(shouldFailForCodeGrade('B', 'C')).toBe(false);
  });

  it('fails F grade at threshold D', () => {
    expect(shouldFailForCodeGrade('F', 'D')).toBe(true);
  });

  it('passes A+ at any threshold', () => {
    expect(shouldFailForCodeGrade('A+', 'F')).toBe(false);
  });
});
