import type { GradedResult } from '../types/index.js';
import { getVersion } from '../utils/version.js';

export function formatJson(results: GradedResult[]): string {
  const output = {
    version: getVersion(),
    timestamp: new Date().toISOString(),
    results: results.map((r) => ({
      target: `${r.host}:${r.port}`,
      grade: r.grade,
      baseGrade: r.baseGrade,
      modifier: r.modifier,
      pqcDetected: r.pqcDetected,
      findings: r.findings,
      summary: r.summary,
      migrationNotes: r.migrationNotes,
    })),
  };

  return JSON.stringify(output, null, 2);
}
