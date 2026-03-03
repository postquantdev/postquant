import { describe, it, expect } from 'vitest';
import { getPatterns, getAllPatterns } from '../patterns/index.js';

describe('Pattern registry', () => {
  it('returns Python patterns for python language', () => {
    const patterns = getPatterns('python');
    expect(patterns.length).toBeGreaterThan(0);
    patterns.forEach((p) => expect(p.language).toBe('python'));
  });

  it('returns JavaScript patterns for javascript language', () => {
    const patterns = getPatterns('javascript');
    expect(patterns.length).toBeGreaterThan(0);
    patterns.forEach((p) => expect(p.language).toBe('javascript'));
  });

  it('returns Go patterns for go language', () => {
    const patterns = getPatterns('go');
    expect(patterns.length).toBeGreaterThan(0);
    patterns.forEach((p) => expect(p.language).toBe('go'));
  });

  it('returns Java patterns for java language', () => {
    const patterns = getPatterns('java');
    expect(patterns.length).toBeGreaterThan(0);
    patterns.forEach((p) => expect(p.language).toBe('java'));
  });

  it('getAllPatterns returns all patterns from all languages', () => {
    const all = getAllPatterns();
    const python = getPatterns('python');
    const js = getPatterns('javascript');
    const go = getPatterns('go');
    const java = getPatterns('java');
    expect(all).toHaveLength(python.length + js.length + go.length + java.length);
  });

  it('all pattern IDs are unique', () => {
    const all = getAllPatterns();
    const ids = all.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
