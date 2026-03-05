import { describe, it, expect } from 'vitest';
import { detectScope } from '../scope-detector.js';
import { getParser, getLanguage } from '../parser.js';
import type { ScopeInfo } from '../../../../types/index.js';

async function getScopeAt(source: string, lang: 'python' | 'javascript', line: number): Promise<ScopeInfo> {
  const parser = await getParser();
  const language = await getLanguage(lang);
  parser.setLanguage(language!);
  const tree = parser.parse(source);
  return detectScope(tree, line, lang);
}

describe('Scope Detector — Python', () => {
  it('detects enclosing function name', async () => {
    const source = `def my_function():\n    hashlib.md5(b"data")\n`;
    const scope = await getScopeAt(source, 'python', 2);
    expect(scope.functionName).toBe('my_function');
  });

  it('detects enclosing class name', async () => {
    const source = `class MyClass:\n    def method(self):\n        hashlib.md5(b"data")\n`;
    const scope = await getScopeAt(source, 'python', 3);
    expect(scope.className).toBe('MyClass');
    expect(scope.functionName).toBe('method');
  });

  it('detects test function by name prefix', async () => {
    const source = `def test_crypto():\n    hashlib.md5(b"data")\n`;
    const scope = await getScopeAt(source, 'python', 2);
    expect(scope.isTestCode).toBe(true);
  });

  it('detects test class', async () => {
    const source = `class TestCrypto:\n    def test_md5(self):\n        hashlib.md5(b"data")\n`;
    const scope = await getScopeAt(source, 'python', 3);
    expect(scope.isTestCode).toBe(true);
  });

  it('detects pytest fixture decorator', async () => {
    const source = `@pytest.fixture\ndef crypto_key():\n    return rsa.generate_private_key()\n`;
    const scope = await getScopeAt(source, 'python', 3);
    expect(scope.isTestCode).toBe(true);
  });

  it('detects conditional path (try/except)', async () => {
    const source = `try:\n    hashlib.md5(b"data")\nexcept:\n    pass\n`;
    const scope = await getScopeAt(source, 'python', 2);
    expect(scope.isConditionalPath).toBe(true);
  });

  it('returns empty scope for top-level code', async () => {
    const source = `hashlib.md5(b"data")\n`;
    const scope = await getScopeAt(source, 'python', 1);
    expect(scope.functionName).toBeUndefined();
    expect(scope.className).toBeUndefined();
    expect(scope.isTestCode).toBe(false);
  });
});

describe('Scope Detector — JavaScript', () => {
  it('detects enclosing function name', async () => {
    const source = `function myFunc() {\n  crypto.createHash('md5');\n}\n`;
    const scope = await getScopeAt(source, 'javascript', 2);
    expect(scope.functionName).toBe('myFunc');
  });

  it('detects arrow function assigned to const', async () => {
    const source = `const myFunc = () => {\n  crypto.createHash('md5');\n};\n`;
    const scope = await getScopeAt(source, 'javascript', 2);
    expect(scope.functionName).toBe('myFunc');
  });

  it('detects describe/it test blocks', async () => {
    const source = `describe('crypto', () => {\n  it('uses md5', () => {\n    crypto.createHash('md5');\n  });\n});\n`;
    const scope = await getScopeAt(source, 'javascript', 3);
    expect(scope.isTestCode).toBe(true);
  });

  it('detects conditional path (try/catch)', async () => {
    const source = `try {\n  crypto.createHash('md5');\n} catch(e) {}\n`;
    const scope = await getScopeAt(source, 'javascript', 2);
    expect(scope.isConditionalPath).toBe(true);
  });
});
