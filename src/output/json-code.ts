import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { CodeGradedResult, AssessedFinding } from '../types/index.js';

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

function isAssessedFinding(f: unknown): f is AssessedFinding {
  return typeof f === 'object' && f !== null && 'riskContext' in f;
}

export function formatCodeJson(result: CodeGradedResult): string {
  const hasAssessment = result.findings.some(f => isAssessedFinding(f));

  const output: Record<string, unknown> = {
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

  if (hasAssessment) {
    const adjCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
    for (const f of result.findings) {
      if (isAssessedFinding(f)) {
        adjCounts[f.riskContext.adjustedRisk]++;
        adjCounts.total++;
      }
    }
    output.adjustedSummary = adjCounts;
  }

  return JSON.stringify(output, null, 2);
}
