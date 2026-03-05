import { describe, it, expect } from 'vitest';
import { getASTPatterns } from '../patterns/index.js';

describe('JavaScript AST patterns', () => {
  const patterns = getASTPatterns('javascript');

  it('has patterns defined', () => {
    expect(patterns.length).toBeGreaterThan(0);
  });

  it('every pattern has a valid query string', () => {
    for (const p of patterns) {
      expect(p.query.trim().length).toBeGreaterThan(0);
      expect(p.id).toBeTruthy();
      expect(p.language).toBe('javascript');
    }
  });

  it('pattern IDs match existing regex pattern IDs', () => {
    const expectedIds = [
      'js-rsa-keygen',
      'js-md5-hash',
      'js-sha1-hash',
      'js-dh-exchange',
    ];
    const actualIds = patterns.map(p => p.id);
    for (const id of expectedIds) {
      expect(actualIds).toContain(id);
    }
  });
});
