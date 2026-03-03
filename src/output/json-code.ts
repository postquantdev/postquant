import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { CodeGradedResult } from '../types/index.js';

function getVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'),
    );
    return pkg.version;
  } catch {
    return '0.1.1';
  }
}

export function formatCodeJson(result: CodeGradedResult): string {
  const output = {
    version: getVersion(),
    timestamp: new Date().toISOString(),
    scanRoot: result.scanRoot,
    grade: result.grade,
    baseGrade: result.baseGrade,
    modifier: result.modifier,
    findings: result.findings,
    summary: result.summary,
    migrationNotes: result.migrationNotes,
    fileBreakdown: result.fileBreakdown,
  };

  return JSON.stringify(output, null, 2);
}
