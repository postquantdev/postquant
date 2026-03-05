import { describe, it, expect } from 'vitest';
import { getASTPatterns } from '../patterns/index.js';

describe('Python AST patterns', () => {
  const patterns = getASTPatterns('python');

  it('has patterns defined', () => {
    expect(patterns.length).toBeGreaterThan(0);
  });

  it('every pattern has a valid query string', () => {
    for (const p of patterns) {
      expect(p.query.trim().length).toBeGreaterThan(0);
      expect(p.id).toBeTruthy();
      expect(p.language).toBe('python');
    }
  });

  it('pattern IDs match existing regex pattern IDs', () => {
    const expectedIds = [
      'python-rsa-keygen',
      'python-ec-keygen',
      'python-md5',
      'python-sha1',
    ];
    const actualIds = patterns.map(p => p.id);
    for (const id of expectedIds) {
      expect(actualIds).toContain(id);
    }
  });

  it('covers key exchange patterns', () => {
    const actualIds = patterns.map(p => p.id);
    expect(actualIds).toContain('python-dh-keygen');
    expect(actualIds).toContain('python-x25519');
  });

  it('covers digital signature patterns', () => {
    const actualIds = patterns.map(p => p.id);
    expect(actualIds).toContain('python-ed25519');
    expect(actualIds).toContain('python-dsa-keygen');
  });
});
