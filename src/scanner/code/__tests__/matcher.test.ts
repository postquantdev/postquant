import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { matchFile, matchFileContent } from '../matcher.js';
import type { CodeFinding, Language } from '../../../types/index.js';

const fixturesDir = path.resolve(__dirname, '..', '__fixtures__');
const fixture = (lang: string, file: string) => path.join(fixturesDir, lang, file);

describe('Matcher', () => {
  // --- Python fixture tests ---

  describe('Python vulnerable fixture', () => {
    it('finds critical findings in vulnerable.py', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA key generation', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.filter((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
      expect(rsa[0].language).toBe('python');
    });

    it('detects MD5 usage', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const md5 = findings.filter((f) => f.patternId === 'python-md5');
      expect(md5.length).toBeGreaterThanOrEqual(1);
      expect(md5[0].risk).toBe('critical');
    });

    it('detects AES-128 as moderate', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const aes = findings.filter((f) => f.patternId === 'python-aes');
      expect(aes.length).toBeGreaterThanOrEqual(1);
      expect(aes[0].risk).toBe('moderate');
    });
  });

  describe('Python safe fixture', () => {
    it('finds only safe findings in safe.py', async () => {
      const findings = await matchFile(fixture('python', 'safe.py'), 'python');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Python no-crypto fixture', () => {
    it('returns empty findings for code with no crypto', async () => {
      const findings = await matchFile(fixture('python', 'no-crypto.py'), 'python');
      expect(findings).toHaveLength(0);
    });
  });

  // --- JavaScript fixture tests ---

  describe('JavaScript vulnerable fixture', () => {
    it('finds critical findings in vulnerable.js', async () => {
      const findings = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA key generation via generateKeyPairSync', async () => {
      const findings = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const rsa = findings.filter((f) => f.patternId === 'js-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });

    it('detects JWT signing with RS256', async () => {
      const findings = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const jwt = findings.filter((f) => f.patternId === 'js-jwt-sign');
      expect(jwt.length).toBeGreaterThanOrEqual(1);
      expect(jwt[0].risk).toBe('critical');
    });
  });

  describe('JavaScript safe fixture', () => {
    it('finds only safe findings in safe.js', async () => {
      const findings = await matchFile(fixture('javascript', 'safe.js'), 'javascript');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  // --- Go fixture tests ---

  describe('Go vulnerable fixture', () => {
    it('finds critical findings in vulnerable.go', async () => {
      const findings = await matchFile(fixture('go', 'vulnerable.go'), 'go');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(4);
    });

    it('detects RSA GenerateKey', async () => {
      const findings = await matchFile(fixture('go', 'vulnerable.go'), 'go');
      const rsa = findings.filter((f) => f.patternId === 'go-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });
  });

  describe('Go safe fixture', () => {
    it('finds only safe findings in safe.go', async () => {
      const findings = await matchFile(fixture('go', 'safe.go'), 'go');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
    });
  });

  // --- Java fixture tests ---

  describe('Java vulnerable fixture', () => {
    it('finds critical findings in Vulnerable.java', async () => {
      const findings = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA KeyPairGenerator', async () => {
      const findings = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const rsa = findings.filter((f) => f.patternId === 'java-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });

    it('detects 3DES cipher', async () => {
      const findings = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const des3 = findings.filter((f) => f.patternId === 'java-3des');
      expect(des3.length).toBeGreaterThanOrEqual(1);
      expect(des3[0].risk).toBe('critical');
    });
  });

  describe('Java safe fixture', () => {
    it('finds only safe findings in Safe.java', async () => {
      const findings = await matchFile(fixture('java', 'Safe.java'), 'java');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  // --- Import tracking / confidence ---

  describe('confidence scoring', () => {
    it('sets high confidence when import and call both match', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.confidence).toBe('high');
    });

    it('sets medium confidence when call matches without corresponding import', async () => {
      const content = `# No imports at top\nkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n`;
      const findings = matchFileContent(content, 'python', 'test.py');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.confidence).toBe('medium');
    });
  });

  // --- Block comment skipping ---

  describe('block comment handling', () => {
    it('skips Python triple-quote docstrings', async () => {
      const findings = await matchFile(fixture('python', 'comments.py'), 'python');
      expect(findings).toHaveLength(0);
    });

    it('skips JavaScript block comments', async () => {
      const findings = await matchFile(fixture('javascript', 'comments.js'), 'javascript');
      expect(findings).toHaveLength(0);
    });

    it('skips Go block comments', async () => {
      const findings = await matchFile(fixture('go', 'comments.go'), 'go');
      expect(findings).toHaveLength(0);
    });
  });

  // --- Finding metadata ---

  describe('finding metadata', () => {
    it('includes correct line numbers', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.line).toBeGreaterThan(0);
      expect(rsa!.file).toBe('vulnerable.py');
    });

    it('includes trimmed matched line content', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.matchedLine).toContain('rsa.generate_private_key');
    });

    it('includes migration recommendation from pattern', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.migration).toBeTruthy();
    });

    it('extracts key size when extractor is defined', async () => {
      const findings = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.keySize).toBe(2048);
    });
  });

  // --- matchFileContent (synchronous, in-memory) ---

  describe('matchFileContent', () => {
    it('matches against content string without file IO', () => {
      const content = `import hashlib\nhash = hashlib.md5(b"data")\n`;
      const findings = matchFileContent(content, 'python', 'inline.py');
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].patternId).toBe('python-md5');
    });

    it('returns empty for content with no patterns', () => {
      const content = `print("hello world")\n`;
      const findings = matchFileContent(content, 'python', 'hello.py');
      expect(findings).toHaveLength(0);
    });
  });

  // --- Edge cases ---

  describe('edge cases', () => {
    it('handles empty file gracefully', () => {
      const findings = matchFileContent('', 'python', 'empty.py');
      expect(findings).toHaveLength(0);
    });

    it('handles single-line comments (Python # comments)', () => {
      const content = `# hashlib.md5(b"data")\n`;
      const findings = matchFileContent(content, 'python', 'comment.py');
      expect(findings).toHaveLength(0);
    });

    it('handles single-line comments (JS // comments)', () => {
      const content = `// crypto.createHash('md5')\n`;
      const findings = matchFileContent(content, 'javascript', 'comment.js');
      expect(findings).toHaveLength(0);
    });

    it('handles single-line comments (Go // comments)', () => {
      const content = `// md5.New()\n`;
      const findings = matchFileContent(content, 'go', 'comment.go');
      expect(findings).toHaveLength(0);
    });

    it('handles single-line comments (Java // comments)', () => {
      const content = `// MessageDigest.getInstance("MD5")\n`;
      const findings = matchFileContent(content, 'java', 'Comment.java');
      expect(findings).toHaveLength(0);
    });
  });
});
