import { describe, it, expect, beforeAll } from 'vitest';
import { getParser, getLanguage, resetParser } from '../parser.js';

describe('AST Parser', () => {
  beforeAll(() => {
    resetParser();
  });

  it('initializes and returns a parser instance', async () => {
    const parser = await getParser();
    expect(parser).toBeDefined();
    expect(parser).not.toBeNull();
  });

  it('returns the same parser on subsequent calls', async () => {
    const p1 = await getParser();
    const p2 = await getParser();
    expect(p1).toBe(p2);
  });

  it('loads Python grammar', async () => {
    const lang = await getLanguage('python');
    expect(lang).not.toBeNull();
  });

  it('loads TypeScript grammar', async () => {
    const lang = await getLanguage('javascript');
    expect(lang).not.toBeNull();
  });

  it('caches loaded grammars', async () => {
    const l1 = await getLanguage('python');
    const l2 = await getLanguage('python');
    expect(l1).toBe(l2);
  });

  it('returns null for unsupported language', async () => {
    const lang = await getLanguage('go' as any);
    expect(lang).toBeNull();
  });

  it('can parse Python source code', async () => {
    const parser = await getParser();
    const lang = await getLanguage('python');
    expect(lang).not.toBeNull();
    parser.setLanguage(lang!);
    const tree = parser.parse('x = 1\n');
    expect(tree).toBeDefined();
    expect(tree.rootNode.type).toBe('module');
  });
});
