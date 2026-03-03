import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { discoverFiles } from '../discovery.js';

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'pq-discovery-'));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

/** Helper: create a file at a relative path inside tempDir */
async function createFile(relativePath: string, content = ''): Promise<void> {
  const fullPath = join(tempDir, relativePath);
  const dir = fullPath.substring(0, fullPath.lastIndexOf('/'));
  await mkdir(dir, { recursive: true });
  await writeFile(fullPath, content);
}

describe('discoverFiles', () => {
  it('discovers .py files', async () => {
    await createFile('app.py');
    await createFile('lib/utils.py');

    const files = await discoverFiles(tempDir);
    const pyFiles = files.filter((f) => f.language === 'python');

    expect(pyFiles).toHaveLength(2);
    expect(pyFiles.map((f) => f.path).sort()).toEqual(['app.py', 'lib/utils.py']);
  });

  it('discovers .js and .ts files as javascript', async () => {
    await createFile('index.js');
    await createFile('app.ts');
    await createFile('utils.mjs');
    await createFile('config.cjs');
    await createFile('Component.tsx');
    await createFile('Component.jsx');

    const files = await discoverFiles(tempDir);
    const jsFiles = files.filter((f) => f.language === 'javascript');

    expect(jsFiles).toHaveLength(6);
  });

  it('discovers .go files', async () => {
    await createFile('main.go');
    await createFile('pkg/server.go');

    const files = await discoverFiles(tempDir);
    const goFiles = files.filter((f) => f.language === 'go');

    expect(goFiles).toHaveLength(2);
    expect(goFiles.map((f) => f.path).sort()).toEqual(['main.go', 'pkg/server.go']);
  });

  it('discovers .java files', async () => {
    await createFile('src/Main.java');

    const files = await discoverFiles(tempDir);
    const javaFiles = files.filter((f) => f.language === 'java');

    expect(javaFiles).toHaveLength(1);
    expect(javaFiles[0].path).toBe('src/Main.java');
  });

  it('respects .postquantignore file', async () => {
    await createFile('app.py');
    await createFile('generated/output.py');
    await writeFile(join(tempDir, '.postquantignore'), 'generated/\n');

    const files = await discoverFiles(tempDir, { ignoreFile: '.postquantignore' });
    const paths = files.map((f) => f.path);

    expect(paths).toContain('app.py');
    expect(paths).not.toContain('generated/output.py');
  });

  it('respects --ignore glob patterns', async () => {
    await createFile('app.py');
    await createFile('test_app.py');
    await createFile('tests/test_utils.py');

    const files = await discoverFiles(tempDir, { ignore: ['test_*', 'tests/**'] });
    const paths = files.map((f) => f.path);

    expect(paths).toContain('app.py');
    expect(paths).not.toContain('test_app.py');
    expect(paths).not.toContain('tests/test_utils.py');
  });

  it('skips node_modules by default', async () => {
    await createFile('app.js');
    await createFile('node_modules/pkg/index.js');

    const files = await discoverFiles(tempDir);
    const paths = files.map((f) => f.path);

    expect(paths).toContain('app.js');
    expect(paths).not.toContain('node_modules/pkg/index.js');
  });

  it('skips vendor/ by default', async () => {
    await createFile('main.go');
    await createFile('vendor/lib/dep.go');

    const files = await discoverFiles(tempDir);
    const paths = files.map((f) => f.path);

    expect(paths).toContain('main.go');
    expect(paths).not.toContain('vendor/lib/dep.go');
  });

  it('respects --max-files limit', async () => {
    await createFile('a.py');
    await createFile('b.py');
    await createFile('c.py');
    await createFile('d.py');
    await createFile('e.py');

    const files = await discoverFiles(tempDir, { maxFiles: 3 });

    expect(files).toHaveLength(3);
  });

  it('filters by --language when specified', async () => {
    await createFile('app.py');
    await createFile('index.js');
    await createFile('main.go');
    await createFile('App.java');

    const files = await discoverFiles(tempDir, { language: 'python' });

    expect(files).toHaveLength(1);
    expect(files[0].language).toBe('python');
    expect(files[0].path).toBe('app.py');
  });
});
