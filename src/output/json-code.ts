import type { CodeGradedResult, AssessedFinding } from '../types/index.js';
import { isAssessedFinding } from '../types/index.js';
import { getVersion } from '../utils/version.js';

export function formatCodeJson(result: CodeGradedResult): string {
  const hasAssessment = result.findings.some(f => isAssessedFinding(f));

  const output: Record<string, unknown> = {
    version: getVersion(),
    timestamp: new Date().toISOString(),
    scanRoot: result.scanRoot,
    grade: result.grade,
    baseGrade: result.baseGrade,
    modifier: result.modifier,
    pqcDetected: result.pqcDetected,
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
