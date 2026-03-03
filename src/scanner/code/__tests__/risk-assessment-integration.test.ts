import { describe, test, expect } from 'vitest';
import { analyzeCommand } from '../../../commands/analyze.js';
import type { AnalyzeOptions } from '../../../types/index.js';
import { resolve } from 'node:path';

const fixturesDir = resolve('test/fixtures/risk-assessment');

/** Build a full AnalyzeOptions object with sensible defaults. */
function opts(overrides: Partial<AnalyzeOptions> = {}): AnalyzeOptions {
  return {
    format: 'json',
    failGrade: 'F',
    ignore: [],
    ignoreFile: '.postquantignore',
    maxFiles: 10000,
    verbose: false,
    noMigration: false,
    ...overrides,
  };
}

/** Strip ANSI escape codes from a string for plain-text matching. */
function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[0-9;]*m/g, '');
}

describe('risk assessment integration', () => {
  // ── 1. auth file MD5 → critical / authentication ──────────────
  test('auth file MD5 is assessed as critical/authentication', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'auth_login.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    const md5 = json.findings.find((f: any) => f.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5.riskContext).toBeDefined();
    expect(md5.riskContext.adjustedRisk).toBe('critical');
    expect(md5.riskContext.usageContext).toBe('authentication');
  });

  // ── 2. uuid file MD5 → informational / protocol-compliance ────
  test('uuid file MD5 is assessed as informational/protocol-compliance', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'uuid_utils.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    const md5 = json.findings.find((f: any) => f.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5.riskContext).toBeDefined();
    expect(md5.riskContext.adjustedRisk).toBe('informational');
    expect(md5.riskContext.usageContext).toBe('protocol-compliance');
  });

  // ── 3. cache file MD5 → low / integrity-check ────────────────
  test('cache file MD5 is assessed as low/integrity-check', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'cache_utils.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    const md5 = json.findings.find((f: any) => f.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5.riskContext).toBeDefined();
    expect(md5.riskContext.adjustedRisk).toBe('low');
    expect(md5.riskContext.usageContext).toBe('integrity-check');
  });

  // ── 4. test file MD5 → informational / test-fixture ───────────
  test('test file MD5 is assessed as informational/test-fixture', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'test_crypto.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    const md5 = json.findings.find((f: any) => f.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5.riskContext).toBeDefined();
    expect(md5.riskContext.adjustedRisk).toBe('informational');
    expect(md5.riskContext.usageContext).toBe('test-fixture');
  });

  // ── 5. --no-context produces raw findings (no riskContext) ────
  test('--no-context produces raw findings without riskContext', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'auth_login.py'),
      opts({ noContext: true }),
    );
    const json = JSON.parse(result.output);
    const md5 = json.findings.find((f: any) => f.algorithm === 'MD5');
    expect(md5).toBeDefined();
    expect(md5.riskContext).toBeUndefined();
    expect(md5.originalRisk).toBeUndefined();
  });

  // ── 6. Grade improves for protocol-compliance ─────────────────
  test('uuid file grade improves with context vs --no-context', async () => {
    const [assessed, raw] = await Promise.all([
      analyzeCommand(resolve(fixturesDir, 'uuid_utils.py'), opts()),
      analyzeCommand(resolve(fixturesDir, 'uuid_utils.py'), opts({ noContext: true })),
    ]);
    const assessedJson = JSON.parse(assessed.output);
    const rawJson = JSON.parse(raw.output);

    // With context, uuid file should get A (informational findings excluded)
    // Without context, raw MD5 is critical → grade capped at D
    expect(assessedJson.grade).toBe('A');
    expect(rawJson.baseGrade).toBe('D');
  });

  // ── 7. JSON output has adjustedSummary when assessed ──────────
  test('JSON output includes adjustedSummary when context assessment is active', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'auth_login.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    expect(json.adjustedSummary).toBeDefined();
    expect(typeof json.adjustedSummary.critical).toBe('number');
    expect(typeof json.adjustedSummary.high).toBe('number');
    expect(typeof json.adjustedSummary.medium).toBe('number');
    expect(typeof json.adjustedSummary.low).toBe('number');
    expect(typeof json.adjustedSummary.informational).toBe('number');
    expect(typeof json.adjustedSummary.total).toBe('number');
  });

  // ── 8. JSON output has riskContext on findings when assessed ───
  test('JSON findings contain riskContext fields when assessed', async () => {
    const result = await analyzeCommand(
      resolve(fixturesDir, 'cache_utils.py'),
      opts(),
    );
    const json = JSON.parse(result.output);
    for (const finding of json.findings) {
      expect(finding.riskContext).toBeDefined();
      expect(finding.riskContext.usageContext).toBeDefined();
      expect(finding.riskContext.adjustedRisk).toBeDefined();
      expect(Array.isArray(finding.riskContext.contextEvidence)).toBe(true);
      expect(Array.isArray(finding.riskContext.signals)).toBe(true);
      expect(finding.originalRisk).toBeDefined();
    }
  });

  // ── 9. --show-all includes informational findings in terminal ─
  test('--show-all includes informational findings in terminal output', async () => {
    const withShowAll = await analyzeCommand(
      resolve(fixturesDir, 'test_crypto.py'),
      opts({ format: 'terminal', showAll: true }),
    );
    const withoutShowAll = await analyzeCommand(
      resolve(fixturesDir, 'test_crypto.py'),
      opts({ format: 'terminal' }),
    );

    const plainWithShowAll = stripAnsi(withShowAll.output);
    const plainWithout = stripAnsi(withoutShowAll.output);

    // With --show-all, the Findings section should appear with "MD5" and "test fixture"
    expect(plainWithShowAll).toContain('Findings');
    expect(plainWithShowAll).toContain('MD5');
    expect(plainWithShowAll).toContain('test fixture');

    // Without --show-all, informational findings should NOT show in findings section
    // (the file only has informational findings, so no Findings section at all)
    expect(plainWithout).not.toContain('test fixture');
  });
});
