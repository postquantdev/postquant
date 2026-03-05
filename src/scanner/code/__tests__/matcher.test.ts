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
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA key generation', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.filter((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
      expect(rsa[0].language).toBe('python');
    });

    it('detects MD5 usage', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const md5 = findings.filter((f) => f.patternId === 'python-md5');
      expect(md5.length).toBeGreaterThanOrEqual(1);
      expect(md5[0].risk).toBe('critical');
    });

    it('detects AES-128 as moderate', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const aes = findings.filter((f) => f.patternId === 'python-aes');
      expect(aes.length).toBeGreaterThanOrEqual(1);
      expect(aes[0].risk).toBe('moderate');
    });
  });

  describe('Python safe fixture', () => {
    it('finds only safe findings in safe.py', async () => {
      const { findings } = await matchFile(fixture('python', 'safe.py'), 'python');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Python no-crypto fixture', () => {
    it('returns empty findings for code with no crypto', async () => {
      const { findings } = await matchFile(fixture('python', 'no-crypto.py'), 'python');
      expect(findings).toHaveLength(0);
    });
  });

  // --- JavaScript fixture tests ---

  describe('JavaScript vulnerable fixture', () => {
    it('finds critical findings in vulnerable.js', async () => {
      const { findings } = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA key generation via generateKeyPairSync', async () => {
      const { findings } = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const rsa = findings.filter((f) => f.patternId === 'js-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });

    it('detects JWT signing with RS256', async () => {
      const { findings } = await matchFile(fixture('javascript', 'vulnerable.js'), 'javascript');
      const jwt = findings.filter((f) => f.patternId === 'js-jwt-sign');
      expect(jwt.length).toBeGreaterThanOrEqual(1);
      expect(jwt[0].risk).toBe('critical');
    });
  });

  describe('JavaScript safe fixture', () => {
    it('finds only safe findings in safe.js', async () => {
      const { findings } = await matchFile(fixture('javascript', 'safe.js'), 'javascript');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  // --- Go fixture tests ---

  describe('Go vulnerable fixture', () => {
    it('finds critical findings in vulnerable.go', async () => {
      const { findings } = await matchFile(fixture('go', 'vulnerable.go'), 'go');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(4);
    });

    it('detects RSA GenerateKey', async () => {
      const { findings } = await matchFile(fixture('go', 'vulnerable.go'), 'go');
      const rsa = findings.filter((f) => f.patternId === 'go-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });
  });

  describe('Go safe fixture', () => {
    it('finds only safe findings in safe.go', async () => {
      const { findings } = await matchFile(fixture('go', 'safe.go'), 'go');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
    });
  });

  // --- Java fixture tests ---

  describe('Java vulnerable fixture', () => {
    it('finds critical findings in Vulnerable.java', async () => {
      const { findings } = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(8);
    });

    it('detects RSA KeyPairGenerator', async () => {
      const { findings } = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const rsa = findings.filter((f) => f.patternId === 'java-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
    });

    it('detects 3DES cipher', async () => {
      const { findings } = await matchFile(fixture('java', 'Vulnerable.java'), 'java');
      const des3 = findings.filter((f) => f.patternId === 'java-3des');
      expect(des3.length).toBeGreaterThanOrEqual(1);
      expect(des3[0].risk).toBe('critical');
    });
  });

  describe('Java safe fixture', () => {
    it('finds only safe findings in Safe.java', async () => {
      const { findings } = await matchFile(fixture('java', 'Safe.java'), 'java');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  // --- Import tracking / confidence ---

  describe('confidence scoring', () => {
    it('sets high confidence when import and call both match', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
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
      const { findings } = await matchFile(fixture('python', 'comments.py'), 'python');
      expect(findings).toHaveLength(0);
    });

    it('skips JavaScript block comments', async () => {
      const { findings } = await matchFile(fixture('javascript', 'comments.js'), 'javascript');
      expect(findings).toHaveLength(0);
    });

    it('skips Go block comments', async () => {
      const { findings } = await matchFile(fixture('go', 'comments.go'), 'go');
      expect(findings).toHaveLength(0);
    });
  });

  // --- Finding metadata ---

  describe('finding metadata', () => {
    it('includes correct line numbers', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.line).toBeGreaterThan(0);
      expect(rsa!.file).toBe('vulnerable.py');
    });

    it('includes trimmed matched line content', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.matchedLine).toContain('rsa.generate_private_key');
    });

    it('includes migration recommendation from pattern', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
      const rsa = findings.find((f) => f.patternId === 'python-rsa-keygen');
      expect(rsa).toBeDefined();
      expect(rsa!.migration).toBeTruthy();
    });

    it('extracts key size when extractor is defined', async () => {
      const { findings } = await matchFile(fixture('python', 'vulnerable.py'), 'python');
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

  // --- C fixture tests ---

  describe('C vulnerable fixture', () => {
    it('finds critical findings in vulnerable.c', async () => {
      const { findings } = await matchFile(fixture('c', 'vulnerable.c'), 'c');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(6);
    });

    it('detects RSA key generation', async () => {
      const { findings } = await matchFile(fixture('c', 'vulnerable.c'), 'c');
      const rsa = findings.filter((f) => f.patternId === 'c-rsa-keygen');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
      expect(rsa[0].language).toBe('c');
    });

    it('detects MD5 usage', async () => {
      const { findings } = await matchFile(fixture('c', 'vulnerable.c'), 'c');
      const md5 = findings.filter((f) => f.patternId === 'c-md5');
      expect(md5.length).toBeGreaterThanOrEqual(1);
      expect(md5[0].risk).toBe('critical');
    });
  });

  describe('C safe fixture', () => {
    it('finds only safe findings in safe.c', async () => {
      const { findings } = await matchFile(fixture('c', 'safe.c'), 'c');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('C no-crypto fixture', () => {
    it('returns empty findings for code with no crypto', async () => {
      const { findings } = await matchFile(fixture('c', 'no-crypto.c'), 'c');
      expect(findings).toHaveLength(0);
    });
  });

  describe('C comments fixture', () => {
    it('does not match crypto calls inside comments', async () => {
      const { findings } = await matchFile(fixture('c', 'comments.c'), 'c');
      expect(findings).toHaveLength(0);
    });
  });

  // --- Rust fixture tests ---

  describe('Rust vulnerable fixture', () => {
    it('finds critical findings in vulnerable.rs', async () => {
      const { findings } = await matchFile(fixture('rust', 'vulnerable.rs'), 'rust');
      const critical = findings.filter((f) => f.risk === 'critical');
      expect(critical.length).toBeGreaterThanOrEqual(4);
    });

    it('detects RSA key generation', async () => {
      const { findings } = await matchFile(fixture('rust', 'vulnerable.rs'), 'rust');
      const rsa = findings.filter((f) => f.patternId === 'rust-rsa-crate');
      expect(rsa.length).toBeGreaterThanOrEqual(1);
      expect(rsa[0].risk).toBe('critical');
      expect(rsa[0].language).toBe('rust');
    });

    it('detects MD5 usage', async () => {
      const { findings } = await matchFile(fixture('rust', 'vulnerable.rs'), 'rust');
      const md5 = findings.filter((f) => f.patternId === 'rust-md5-crate');
      expect(md5.length).toBeGreaterThanOrEqual(1);
      expect(md5[0].risk).toBe('critical');
    });
  });

  describe('Rust safe fixture', () => {
    it('finds only safe findings in safe.rs', async () => {
      const { findings } = await matchFile(fixture('rust', 'safe.rs'), 'rust');
      const nonSafe = findings.filter((f) => f.risk !== 'safe');
      expect(nonSafe.length).toBe(0);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Rust no-crypto fixture', () => {
    it('returns empty findings for code with no crypto', async () => {
      const { findings } = await matchFile(fixture('rust', 'no-crypto.rs'), 'rust');
      expect(findings).toHaveLength(0);
    });
  });

  describe('Rust comments fixture', () => {
    it('does not match crypto calls inside comments', async () => {
      const { findings } = await matchFile(fixture('rust', 'comments.rs'), 'rust');
      expect(findings).toHaveLength(0);
    });
  });

  // --- C/C++ comment handling tests ---

  describe('C comment handling', () => {
    it('skips single-line comments in C', () => {
      const findings = matchFileContent(
        '// RSA_generate_key_ex(rsa, 2048, e, NULL)\n',
        'c',
        'test.c',
      );
      expect(findings).toHaveLength(0);
    });

    it('skips block comments in C', () => {
      const findings = matchFileContent(
        '/* RSA_generate_key_ex(rsa, 2048, e, NULL) */\n',
        'c',
        'test.c',
      );
      expect(findings).toHaveLength(0);
    });

    it('skips multi-line block comments in C', () => {
      const findings = matchFileContent(
        '/*\n * RSA_generate_key_ex(rsa, 2048, e, NULL)\n */\n',
        'c',
        'test.c',
      );
      expect(findings).toHaveLength(0);
    });

    it('matches real C code (not in comments)', () => {
      const findings = matchFileContent(
        '#include <openssl/rsa.h>\nRSA_generate_key_ex(rsa, 2048, e, NULL);\n',
        'c',
        'test.c',
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].patternId).toBe('c-rsa-keygen');
    });

    it('skips C string literals', () => {
      const findings = matchFileContent(
        'const char *msg = "RSA_generate_key_ex is deprecated";\n',
        'c',
        'test.c',
      );
      expect(findings).toHaveLength(0);
    });

    it('strips inline comments in C', () => {
      const findings = matchFileContent(
        'EVP_sha256(); // safe hash\n',
        'c',
        'test.c',
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].patternId).toBe('c-sha256');
    });
  });

  describe('Rust comment handling', () => {
    it('skips single-line comments in Rust', () => {
      const findings = matchFileContent(
        '// Rsa::generate(2048)\n',
        'rust',
        'test.rs',
      );
      expect(findings).toHaveLength(0);
    });

    it('skips doc comments in Rust', () => {
      const findings = matchFileContent(
        '/// Rsa::generate(2048) creates a key\n',
        'rust',
        'test.rs',
      );
      expect(findings).toHaveLength(0);
    });

    it('skips block comments in Rust', () => {
      const findings = matchFileContent(
        '/* Rsa::generate(2048) */\n',
        'rust',
        'test.rs',
      );
      expect(findings).toHaveLength(0);
    });

    it('skips multi-line block comments in Rust', () => {
      const findings = matchFileContent(
        '/*\n * Rsa::generate(2048)\n */\n',
        'rust',
        'test.rs',
      );
      expect(findings).toHaveLength(0);
    });

    it('matches real Rust code (not in comments)', () => {
      const findings = matchFileContent(
        'use openssl::rsa::Rsa;\nlet rsa = Rsa::generate(2048).unwrap();\n',
        'rust',
        'test.rs',
      );
      expect(findings.length).toBeGreaterThanOrEqual(1);
      expect(findings[0].patternId).toBe('rust-openssl-rsa');
    });

    it('skips Rust string literals', () => {
      const findings = matchFileContent(
        'let msg = "Rsa::generate is deprecated";\n',
        'rust',
        'test.rs',
      );
      expect(findings).toHaveLength(0);
    });

    it('strips inline comments in Rust', () => {
      const findings = matchFileContent(
        'use sha2::{Sha256, Digest};\nSha256::digest(b"data"); // compute hash\n',
        'rust',
        'test.rs',
      );
      const sha = findings.filter((f) => f.patternId === 'rust-sha-crate');
      expect(sha.length).toBeGreaterThanOrEqual(1);
    });
  });
});
