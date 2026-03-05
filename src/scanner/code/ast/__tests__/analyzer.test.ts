import { describe, it, expect } from 'vitest';
import { astAnalyze } from '../analyzer.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const fixturesDir = path.resolve(__dirname, '..', '..', '__fixtures__');

describe('AST Analyzer', () => {
  describe('Python', () => {
    it('finds RSA keygen in vulnerable.py', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'python', 'vulnerable.py'), 'utf-8');
      const findings = await astAnalyze(content, 'python', 'vulnerable.py');
      const rsa = findings.filter(f => f.patternId === 'python-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].confidence).toBe('verified');
      expect(rsa[0].astEnriched).toBe(true);
    });

    it('finds MD5 in vulnerable.py', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'python', 'vulnerable.py'), 'utf-8');
      const findings = await astAnalyze(content, 'python', 'vulnerable.py');
      const md5 = findings.filter(f => f.patternId === 'python-md5');
      expect(md5.length).toBeGreaterThanOrEqual(1);
    });

    it('returns empty for no-crypto.py', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'python', 'no-crypto.py'), 'utf-8');
      const findings = await astAnalyze(content, 'python', 'no-crypto.py');
      expect(findings).toHaveLength(0);
    });

    it('returns empty for comments.py', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'python', 'comments.py'), 'utf-8');
      const findings = await astAnalyze(content, 'python', 'comments.py');
      expect(findings).toHaveLength(0);
    });

    it('attaches scope info', async () => {
      const content = `import hashlib\ndef my_function():\n    hashlib.md5(b"data")\n`;
      const findings = await astAnalyze(content, 'python', 'test.py');
      const md5 = findings.find(f => f.patternId === 'python-md5');
      expect(md5?.scopeInfo?.functionName).toBe('my_function');
    });

    it('detects aliased import', async () => {
      const content = `from cryptography.hazmat.primitives.asymmetric import rsa as r\nkey = r.generate_private_key(public_exponent=65537, key_size=2048)\n`;
      const findings = await astAnalyze(content, 'python', 'aliased.py');
      const rsa = findings.filter(f => f.patternId === 'python-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('JavaScript', () => {
    it('finds RSA keygen in vulnerable.js', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'javascript', 'vulnerable.js'), 'utf-8');
      const findings = await astAnalyze(content, 'javascript', 'vulnerable.js');
      const rsa = findings.filter(f => f.patternId === 'js-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].confidence).toBe('verified');
    });

    it('finds MD5 in vulnerable.js', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'javascript', 'vulnerable.js'), 'utf-8');
      const findings = await astAnalyze(content, 'javascript', 'vulnerable.js');
      const md5 = findings.filter(f => f.patternId === 'js-md5-hash');
      expect(md5.length).toBeGreaterThanOrEqual(1);
    });

    it('returns empty for comments.js', async () => {
      const content = fs.readFileSync(path.join(fixturesDir, 'javascript', 'comments.js'), 'utf-8');
      const findings = await astAnalyze(content, 'javascript', 'comments.js');
      expect(findings).toHaveLength(0);
    });
  });

  describe('unsupported language', () => {
    it('returns empty for Go', async () => {
      const findings = await astAnalyze('package main\n', 'go', 'main.go');
      expect(findings).toHaveLength(0);
    });
  });

  describe('graceful degradation', () => {
    it('returns empty on parse error without crashing', async () => {
      const findings = await astAnalyze('def (((broken syntax', 'python', 'broken.py');
      expect(Array.isArray(findings)).toBe(true);
    });
  });
});
