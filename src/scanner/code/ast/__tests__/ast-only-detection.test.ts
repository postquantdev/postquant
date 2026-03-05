import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { matchFileContent } from '../../matcher.js';
import { astAnalyze } from '../analyzer.js';

const fixturesDir = path.resolve(__dirname, '..', '..', '__fixtures__');

describe('AST-only detections (things regex cannot find)', () => {
  describe('Python aliased imports', () => {
    const content = fs.readFileSync(path.join(fixturesDir, 'python', 'aliased_imports.py'), 'utf-8');

    it('regex misses aliased rsa import', () => {
      const findings = matchFileContent(content, 'python', 'aliased_imports.py');
      const rsa = findings.filter(f => f.patternId === 'python-rsa-keygen');
      // Regex looks for 'rsa.generate_private_key' but code uses 'r.generate_private_key'
      expect(rsa).toHaveLength(0);
    });

    it('AST catches aliased rsa import', async () => {
      const findings = await astAnalyze(content, 'python', 'aliased_imports.py');
      const rsa = findings.filter(f => f.patternId === 'python-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].confidence).toBe('verified');
    });

    it('AST catches aliased ec import', async () => {
      const findings = await astAnalyze(content, 'python', 'aliased_imports.py');
      const ec = findings.filter(f => f.patternId === 'python-ec-keygen');
      expect(ec.length).toBeGreaterThanOrEqual(1);
      expect(ec[0].confidence).toBe('verified');
    });
  });

  describe('Python test scope detection', () => {
    const content = fs.readFileSync(path.join(fixturesDir, 'python', 'test_scope.py'), 'utf-8');

    it('AST detects test scope for crypto calls', async () => {
      const findings = await astAnalyze(content, 'python', 'test_scope.py');
      const testFindings = findings.filter(f => f.scopeInfo?.isTestCode);
      expect(testFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('AST identifies function names in test scope', async () => {
      const findings = await astAnalyze(content, 'python', 'test_scope.py');
      const md5 = findings.find(f => f.patternId === 'python-md5');
      expect(md5?.scopeInfo?.functionName).toBe('test_md5_behavior');
    });

    it('AST identifies class names in test scope', async () => {
      const findings = await astAnalyze(content, 'python', 'test_scope.py');
      const rsa = findings.find(f => f.patternId === 'python-rsa-keygen');
      expect(rsa?.scopeInfo?.className).toBe('TestCryptoMigration');
    });
  });
});
