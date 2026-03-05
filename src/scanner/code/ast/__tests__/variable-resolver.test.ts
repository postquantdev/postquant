import { describe, it, expect } from 'vitest';
import { resolveVariables, type VariableMap } from '../variable-resolver.js';
import { getParser, getLanguage } from '../parser.js';

async function getVars(source: string, lang: 'python' | 'javascript'): Promise<VariableMap> {
  const parser = await getParser();
  const language = await getLanguage(lang);
  parser.setLanguage(language!);
  const tree = parser.parse(source);
  return resolveVariables(tree, lang);
}

describe('Variable Resolver — Python', () => {
  it('resolves string assignment', async () => {
    const vars = await getVars('algo = "RSA"\n', 'python');
    expect(vars.getString('algo')).toBe('RSA');
  });

  it('resolves integer assignment', async () => {
    const vars = await getVars('key_size = 2048\n', 'python');
    expect(vars.getNumber('key_size')).toBe(2048);
  });

  it('tracks last assignment on reassignment', async () => {
    const vars = await getVars('algo = "AES"\nalgo = "RSA"\n', 'python');
    expect(vars.getString('algo')).toBe('RSA');
  });

  it('returns undefined for unknown variable', async () => {
    const vars = await getVars('x = 1\n', 'python');
    expect(vars.getString('unknown')).toBeUndefined();
  });

  it('resolves variable at specific line', async () => {
    const vars = await getVars('algo = "AES"\nhash = hashlib.new(algo)\nalgo = "RSA"\n', 'python');
    expect(vars.getStringAtLine('algo', 2)).toBe('AES');
  });
});

describe('Variable Resolver — JavaScript', () => {
  it('resolves const string assignment', async () => {
    const vars = await getVars("const algo = 'RSA';\n", 'javascript');
    expect(vars.getString('algo')).toBe('RSA');
  });

  it('resolves const number assignment', async () => {
    const vars = await getVars('const keySize = 2048;\n', 'javascript');
    expect(vars.getNumber('keySize')).toBe(2048);
  });

  it('resolves let with reassignment', async () => {
    const vars = await getVars("let algo = 'AES';\nalgo = 'RSA';\n", 'javascript');
    expect(vars.getString('algo')).toBe('RSA');
  });
});
