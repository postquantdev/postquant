import { describe, it, expect } from 'vitest';
import { analyzeCommand } from '../analyze.js';
import * as path from 'node:path';
import type { AnalyzeOptions } from '../../types/index.js';

const FIXTURES = path.resolve(__dirname, '..', '..', 'scanner', 'code', '__fixtures__');

function defaultOptions(overrides: Partial<AnalyzeOptions> = {}): AnalyzeOptions {
  return {
    format: 'json',
    failGrade: 'F',
    ignore: [],
    ignoreFile: '.postquantignore',
    maxFiles: 1000,
    verbose: false,
    noMigration: false,
    ...overrides,
  };
}

describe('analyze with AST integration', () => {
  it('Python findings include verified confidence', async () => {
    const { output } = await analyzeCommand(
      path.join(FIXTURES, 'python', 'vulnerable.py'),
      defaultOptions(),
    );
    const parsed = JSON.parse(output);
    const verified = parsed.findings.filter((f: any) => f.confidence === 'verified');
    expect(verified.length).toBeGreaterThan(0);
  });

  it('JavaScript findings include verified confidence', async () => {
    const { output } = await analyzeCommand(
      path.join(FIXTURES, 'javascript', 'vulnerable.js'),
      defaultOptions(),
    );
    const parsed = JSON.parse(output);
    const verified = parsed.findings.filter((f: any) => f.confidence === 'verified');
    expect(verified.length).toBeGreaterThan(0);
  });

  it('Go findings are regex-only (no AST)', async () => {
    const { output } = await analyzeCommand(
      path.join(FIXTURES, 'go', 'vulnerable.go'),
      defaultOptions(),
    );
    const parsed = JSON.parse(output);
    const verified = parsed.findings.filter((f: any) => f.confidence === 'verified');
    expect(verified.length).toBe(0);
  });

  it('--no-ast disables AST analysis', async () => {
    const { output } = await analyzeCommand(
      path.join(FIXTURES, 'python', 'vulnerable.py'),
      defaultOptions({ noAst: true }),
    );
    const parsed = JSON.parse(output);
    const verified = parsed.findings.filter((f: any) => f.confidence === 'verified');
    expect(verified.length).toBe(0);
  });

  it('produces at least as many findings as regex-only', async () => {
    const { output: withAst } = await analyzeCommand(
      path.join(FIXTURES, 'python', 'vulnerable.py'),
      defaultOptions(),
    );
    const { output: withoutAst } = await analyzeCommand(
      path.join(FIXTURES, 'python', 'vulnerable.py'),
      defaultOptions({ noAst: true }),
    );
    const withAstParsed = JSON.parse(withAst);
    const withoutAstParsed = JSON.parse(withoutAst);
    expect(withAstParsed.findings.length).toBeGreaterThanOrEqual(withoutAstParsed.findings.length);
  });
});
