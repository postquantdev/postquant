import type { CodeFinding, CodeScanResult, Language } from '../../types/index.js';

/**
 * Aggregate raw CodeFinding[] into a CodeScanResult.
 * This is the code scanner equivalent of the TLS classifier —
 * it collects metadata (files scanned, languages detected, etc.)
 * around the raw findings from the matcher.
 */
export function classifyCodeFindings(
  findings: CodeFinding[],
  scanRoot: string,
  filesScanned: number,
  durationMs: number,
): CodeScanResult {
  const uniqueFiles = new Set(findings.map((f) => f.file));
  const uniqueLanguages = [...new Set(findings.map((f) => f.language))];

  return {
    scanRoot,
    findings,
    filesScanned,
    filesWithFindings: uniqueFiles.size,
    languagesDetected: uniqueLanguages,
    durationMs,
  };
}
