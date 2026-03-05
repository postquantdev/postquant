import { describe, it, expect } from 'vitest';
import { getVersion } from './version.js';

describe('getVersion', () => {
  it('returns a semver-like string', () => {
    const version = getVersion();
    expect(version).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('matches package.json version', async () => {
    const { readFileSync } = await import('node:fs');
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'));
    expect(getVersion()).toBe(pkg.version);
  });
});
