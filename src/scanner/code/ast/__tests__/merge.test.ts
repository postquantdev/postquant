import { describe, it, expect } from 'vitest';
import { mergeFindings } from '../merge.js';
import type { CodeFinding } from '../../../../types/index.js';

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'python-rsa-keygen',
    file: 'vulnerable.py',
    line: 12,
    matchedLine: 'rsa.generate_private_key(key_size=2048)',
    language: 'python',
    category: 'asymmetric-encryption',
    algorithm: 'RSA',
    risk: 'critical',
    reason: 'RSA is vulnerable',
    confidence: 'high',
    ...overrides,
  };
}

describe('mergeFindings', () => {
  it('keeps AST version when both engines find same thing', () => {
    const regex = [makeFinding({ confidence: 'high' })];
    const ast = [makeFinding({ confidence: 'verified', astEnriched: true, keySize: 2048 })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(1);
    expect(merged[0].confidence).toBe('verified');
    expect(merged[0].astEnriched).toBe(true);
    expect(merged[0].keySize).toBe(2048);
  });

  it('includes regex-only findings', () => {
    const regex = [makeFinding({ patternId: 'python-md5', line: 30 })];
    const ast: CodeFinding[] = [];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(1);
    expect(merged[0].patternId).toBe('python-md5');
  });

  it('includes AST-only findings', () => {
    const regex: CodeFinding[] = [];
    const ast = [makeFinding({ confidence: 'verified', astEnriched: true })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(1);
    expect(merged[0].confidence).toBe('verified');
  });

  it('handles line drift of +/-1', () => {
    const regex = [makeFinding({ line: 12 })];
    const ast = [makeFinding({ line: 11, confidence: 'verified', astEnriched: true })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(1);
    expect(merged[0].confidence).toBe('verified');
  });

  it('does not merge findings with different patternIds', () => {
    const regex = [makeFinding({ patternId: 'python-rsa-keygen', line: 12 })];
    const ast = [makeFinding({ patternId: 'python-md5', line: 12, confidence: 'verified' })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(2);
  });

  it('does not merge findings in different files', () => {
    const regex = [makeFinding({ file: 'a.py' })];
    const ast = [makeFinding({ file: 'b.py', confidence: 'verified' })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(2);
  });

  it('handles empty inputs', () => {
    expect(mergeFindings([], [])).toHaveLength(0);
  });

  it('preserves order: regex findings first, then AST-only', () => {
    const regex = [makeFinding({ line: 20, patternId: 'python-md5' })];
    const ast = [makeFinding({ line: 5, patternId: 'python-rsa-keygen', confidence: 'verified' })];
    const merged = mergeFindings(regex, ast);
    expect(merged).toHaveLength(2);
    expect(merged[0].patternId).toBe('python-md5');
    expect(merged[1].patternId).toBe('python-rsa-keygen');
  });
});
