import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { GradedResult } from '../types/index.js';

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

export function formatJson(results: GradedResult[]): string {
  const output = {
    version: getVersion(),
    timestamp: new Date().toISOString(),
    results: results.map((r) => ({
      target: `${r.host}:${r.port}`,
      grade: r.grade,
      baseGrade: r.baseGrade,
      modifier: r.modifier,
      findings: r.findings,
      summary: r.summary,
      migrationNotes: r.migrationNotes,
    })),
  };

  return JSON.stringify(output, null, 2);
}
