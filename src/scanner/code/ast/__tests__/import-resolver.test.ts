import { describe, it, expect } from 'vitest';
import { resolveImports, type ImportMap } from '../import-resolver.js';
import { getParser, getLanguage } from '../parser.js';
import type { Parser } from 'web-tree-sitter';

async function parseSource(source: string, lang: 'python' | 'javascript'): Promise<Parser.Tree> {
  const parser = await getParser();
  const language = await getLanguage(lang);
  parser.setLanguage(language!);
  return parser.parse(source);
}

describe('Import Resolver — Python', () => {
  it('resolves basic import', async () => {
    const tree = await parseSource('import hashlib\n', 'python');
    const imports = resolveImports(tree, 'python');
    expect(imports.modules.has('hashlib')).toBe(true);
  });

  it('resolves from...import', async () => {
    const tree = await parseSource(
      'from cryptography.hazmat.primitives.asymmetric import rsa\n',
      'python',
    );
    const imports = resolveImports(tree, 'python');
    expect(imports.symbols.get('rsa')).toBe('cryptography.hazmat.primitives.asymmetric.rsa');
  });

  it('resolves aliased import', async () => {
    const tree = await parseSource(
      'from cryptography.hazmat.primitives.asymmetric import rsa as r\n',
      'python',
    );
    const imports = resolveImports(tree, 'python');
    expect(imports.aliases.get('r')).toBe('rsa');
    expect(imports.symbols.get('r')).toBe('cryptography.hazmat.primitives.asymmetric.rsa');
  });

  it('resolves module alias', async () => {
    const tree = await parseSource('import hashlib as hl\n', 'python');
    const imports = resolveImports(tree, 'python');
    expect(imports.aliases.get('hl')).toBe('hashlib');
    expect(imports.modules.has('hl')).toBe(true);
  });

  it('resolves multiple symbols from one import', async () => {
    const tree = await parseSource(
      'from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa\n',
      'python',
    );
    const imports = resolveImports(tree, 'python');
    expect(imports.symbols.has('rsa')).toBe(true);
    expect(imports.symbols.has('ec')).toBe(true);
    expect(imports.symbols.has('dsa')).toBe(true);
  });

  it('resolves original name from alias', async () => {
    const tree = await parseSource(
      'from Crypto.PublicKey import RSA as PycryptoRSA\n',
      'python',
    );
    const imports = resolveImports(tree, 'python');
    expect(imports.getOriginalName('PycryptoRSA')).toBe('RSA');
  });

  it('returns identity for non-aliased name', async () => {
    const tree = await parseSource(
      'from cryptography.hazmat.primitives.asymmetric import rsa\n',
      'python',
    );
    const imports = resolveImports(tree, 'python');
    expect(imports.getOriginalName('rsa')).toBe('rsa');
  });

  it('returns identity for unknown name', async () => {
    const tree = await parseSource('import hashlib\n', 'python');
    const imports = resolveImports(tree, 'python');
    expect(imports.getOriginalName('unknown')).toBe('unknown');
  });
});
