import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { analyzeCommand } from './analyze.js';
import type { AnalyzeOptions } from '../types/index.js';

const FIXTURES = join(import.meta.dirname, '..', 'scanner', 'code', '__fixtures__');

function defaultOptions(overrides: Partial<AnalyzeOptions> = {}): AnalyzeOptions {
  return {
    format: 'terminal',
    failGrade: 'C',
    ignore: [],
    ignoreFile: '.postquantignore',
    maxFiles: 10000,
    verbose: false,
    noMigration: false,
    ...overrides,
  };
}

describe('analyzeCommand', () => {
  it('scans Python vulnerable fixture and returns exit 1 (grade >= C)', async () => {
    const { exitCode, grade } = await analyzeCommand(
      join(FIXTURES, 'python'),
      defaultOptions(),
    );
    // vulnerable.py has many critical findings → grade C or worse
    expect(exitCode).toBe(1);
    expect(['C', 'C+', 'C-', 'D', 'D+', 'D-', 'F']).toContain(grade);
  });

  it('scans Python no-crypto fixture and returns exit 0 (grade A)', async () => {
    const { exitCode, grade } = await analyzeCommand(
      join(FIXTURES, 'python', 'no-crypto.py'),
      defaultOptions(),
    );
    expect(exitCode).toBe(0);
    expect(grade).toBe('A');
  });

  it('returns exit 0 when grade is above fail-grade threshold', async () => {
    const { exitCode } = await analyzeCommand(
      join(FIXTURES, 'python'),
      defaultOptions({ failGrade: 'F' }),
    );
    // With threshold F, only F fails — our fixture is D-ish
    expect(exitCode).toBe(0);
  });

  it('filters by --language python and only scans .py files', async () => {
    const { output } = await analyzeCommand(
      FIXTURES,
      defaultOptions({ format: 'json', language: 'python' }),
    );
    const parsed = JSON.parse(output);
    // All findings should be python
    for (const f of parsed.findings) {
      expect(f.language).toBe('python');
    }
  });

  it('produces valid JSON with --format json', async () => {
    const { output } = await analyzeCommand(
      join(FIXTURES, 'python'),
      defaultOptions({ format: 'json' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.grade).toBeDefined();
    expect(parsed.findings).toBeDefined();
    expect(parsed.summary).toBeDefined();
    expect(parsed.fileBreakdown).toBeDefined();
  });

  it('produces valid SARIF with --format sarif', async () => {
    const { output } = await analyzeCommand(
      join(FIXTURES, 'python'),
      defaultOptions({ format: 'sarif' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].tool.driver.name).toBe('PostQuant');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });

  it('produces valid CBOM with --format cbom', async () => {
    const { output } = await analyzeCommand(
      join(FIXTURES, 'python'),
      defaultOptions({ format: 'cbom' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.6');
    expect(parsed.components.length).toBeGreaterThan(0);
  });

  it('respects --max-files limit', async () => {
    const { output } = await analyzeCommand(
      FIXTURES,
      defaultOptions({ format: 'json', maxFiles: 1 }),
    );
    const parsed = JSON.parse(output);
    // With only 1 file scanned, findings should be limited
    expect(parsed.summary.filesScanned).toBeLessThanOrEqual(1);
  });

  it('scans a single file path', async () => {
    const { output } = await analyzeCommand(
      join(FIXTURES, 'go', 'safe.go'),
      defaultOptions({ format: 'json' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.summary.filesScanned).toBe(1);
  });

  it('returns exit 1 for nonexistent path', async () => {
    const { exitCode } = await analyzeCommand(
      '/nonexistent/path/does/not/exist',
      defaultOptions(),
    );
    expect(exitCode).toBe(1);
  });

  it('includes migration notes in terminal output by default', async () => {
    const { output } = await analyzeCommand(
      join(FIXTURES, 'python', 'vulnerable.py'),
      defaultOptions({ format: 'terminal' }),
    );
    // Strip ANSI for matching
    const plain = output.replace(/\u001b\[[0-9;]*m/g, '');
    expect(plain).toContain('Migration');
  });

  it('scans a single C file path', async () => {
    const { output, exitCode } = await analyzeCommand(
      join(FIXTURES, 'c', 'vulnerable.c'),
      defaultOptions({ format: 'json' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.summary.filesScanned).toBe(1);
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.findings[0].language).toBe('c');
  });

  it('scans a single Rust file path', async () => {
    const { output, exitCode } = await analyzeCommand(
      join(FIXTURES, 'rust', 'vulnerable.rs'),
      defaultOptions({ format: 'json' }),
    );
    const parsed = JSON.parse(output);
    expect(parsed.summary.filesScanned).toBe(1);
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.findings[0].language).toBe('rust');
  });
});
