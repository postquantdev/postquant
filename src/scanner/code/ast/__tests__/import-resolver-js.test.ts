import { describe, it, expect } from 'vitest';
import { resolveImports } from '../import-resolver.js';
import { getParser, getLanguage } from '../parser.js';
import type { Parser } from 'web-tree-sitter';

async function parseSource(source: string): Promise<Parser.Tree> {
  const parser = await getParser();
  const language = await getLanguage('javascript');
  parser.setLanguage(language!);
  return parser.parse(source);
}

describe('Import Resolver — JavaScript', () => {
  it('resolves default import', async () => {
    const tree = await parseSource("import crypto from 'crypto';\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.symbols.get('crypto')).toBe('crypto');
  });

  it('resolves named import', async () => {
    const tree = await parseSource("import { generateKeyPairSync } from 'crypto';\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.symbols.get('generateKeyPairSync')).toBe('crypto.generateKeyPairSync');
  });

  it('resolves aliased named import', async () => {
    const tree = await parseSource("import { createHash as hash } from 'crypto';\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.aliases.get('hash')).toBe('createHash');
    expect(imports.symbols.get('hash')).toBe('crypto.createHash');
  });

  it('resolves require', async () => {
    const tree = await parseSource("const crypto = require('crypto');\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.modules.has('crypto')).toBe(true);
  });

  it('resolves destructured require', async () => {
    const tree = await parseSource("const { createHash, createHmac } = require('crypto');\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.symbols.get('createHash')).toBe('crypto.createHash');
    expect(imports.symbols.get('createHmac')).toBe('crypto.createHmac');
  });

  it('resolves original name from alias', async () => {
    const tree = await parseSource("import { createHash as hash } from 'crypto';\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.getOriginalName('hash')).toBe('createHash');
  });

  it('returns identity for non-aliased name', async () => {
    const tree = await parseSource("import { createHash } from 'crypto';\n");
    const imports = resolveImports(tree, 'javascript');
    expect(imports.getOriginalName('createHash')).toBe('createHash');
  });
});
