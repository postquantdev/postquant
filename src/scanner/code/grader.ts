import type {
  CodeScanResult,
  CodeGradedResult,
  CodeFinding,
  FileBreakdown,
  Grade,
  BaseGrade,
  GradeModifier,
} from '../../types/index.js';

const BASE_GRADE_ORDER: BaseGrade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

/** Algorithms that are already broken classically — cap grade at D. */
const BROKEN_ALGORITHMS = ['MD5', 'SHA-1', 'SHA1', 'DES', '3DES', 'TRIPLE-DES'];

/**
 * Grade a code scan result.
 *
 * Grading logic (from spec Section 6.1):
 *   0 critical + 0 moderate → A (A+ if PQC detected)
 *   0 critical + moderate only → B
 *   1-5 critical → C
 *   6-20 critical → D
 *   21+ critical → F
 *
 * Special cases:
 *   MD5/SHA-1/DES/3DES → cap at D
 *
 * Modifiers (same as TLS grader):
 *   0 moderate → +
 *   1 moderate → (none)
 *   2+ moderate → -
 *   A+, A, F → no modifier
 */
export function gradeCodeScan(scan: CodeScanResult): CodeGradedResult {
  const { findings } = scan;

  const critical = findings.filter((f) => f.risk === 'critical');
  const moderate = findings.filter((f) => f.risk === 'moderate');
  const safe = findings.filter((f) => f.risk === 'safe');

  // Determine base grade from critical/moderate counts
  let baseGrade: BaseGrade;

  if (critical.length === 0 && moderate.length === 0) {
    const hasPqc = findings.some((f) => f.category === 'pqc-algorithm');
    baseGrade = hasPqc ? 'A+' : 'A';
  } else if (critical.length === 0) {
    baseGrade = 'B';
  } else if (critical.length <= 5) {
    baseGrade = 'C';
  } else if (critical.length <= 20) {
    baseGrade = 'D';
  } else {
    baseGrade = 'F';
  }

  // Special case: broken algorithms cap at D
  const hasBrokenAlgo = findings.some((f) =>
    BROKEN_ALGORITHMS.some((broken) =>
      f.algorithm.toUpperCase() === broken.toUpperCase(),
    ),
  );
  if (hasBrokenAlgo && gradeRank(baseGrade) < gradeRank('D')) {
    baseGrade = 'D';
  }

  // Compute modifier (same logic as TLS grader)
  let modifier: GradeModifier = '';
  if (baseGrade !== 'A+' && baseGrade !== 'A' && baseGrade !== 'F') {
    if (moderate.length === 0) {
      modifier = '+';
    } else if (moderate.length >= 2) {
      modifier = '-';
    }
  }

  const displayGrade = (baseGrade + modifier) as Grade;

  // Collect unique migration notes
  const migrationSet = new Set<string>();
  for (const f of findings) {
    if (f.migration) migrationSet.add(f.migration);
  }

  // Build per-file breakdown
  const fileBreakdown = buildFileBreakdown(findings);

  return {
    scanRoot: scan.scanRoot,
    grade: displayGrade,
    baseGrade,
    modifier,
    findings,
    migrationNotes: [...migrationSet],
    summary: {
      critical: critical.length,
      moderate: moderate.length,
      safe: safe.length,
      total: findings.length,
      filesScanned: scan.filesScanned,
      filesWithFindings: scan.filesWithFindings,
    },
    fileBreakdown,
  };
}

function buildFileBreakdown(findings: CodeFinding[]): FileBreakdown[] {
  const byFile = new Map<string, CodeFinding[]>();
  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  return [...byFile.entries()].map(([file, fileFindgs]) => ({
    file,
    language: fileFindgs[0].language,
    findings: fileFindgs,
    criticalCount: fileFindgs.filter((f) => f.risk === 'critical').length,
    moderateCount: fileFindgs.filter((f) => f.risk === 'moderate').length,
    safeCount: fileFindgs.filter((f) => f.risk === 'safe').length,
  }));
}

/** Return numeric rank for a base grade (higher = worse). */
function gradeRank(g: BaseGrade): number {
  return BASE_GRADE_ORDER.indexOf(g);
}

/**
 * Determine if a scan should fail CI based on grade threshold.
 * Reuses the same logic as the TLS grader.
 */
export function shouldFailForCodeGrade(
  actual: BaseGrade,
  threshold: BaseGrade,
): boolean {
  return gradeRank(actual) >= gradeRank(threshold);
}
