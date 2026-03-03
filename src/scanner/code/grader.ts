import type {
  CodeScanResult,
  CodeGradedResult,
  CodeFinding,
  AssessedFinding,
  FileBreakdown,
  Grade,
  BaseGrade,
  GradeModifier,
} from '../../types/index.js';
import { isAssessedFinding } from '../../types/index.js';

const BASE_GRADE_ORDER: BaseGrade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

/** Algorithms that are already broken classically — cap grade at D. */
const BROKEN_ALGORITHMS = ['MD5', 'SHA-1', 'SHA1', 'DES', '3DES', 'TRIPLE-DES'];

/**
 * Map a finding to a grade bucket using adjusted risk when available,
 * falling back to the raw `risk` field for unassessed findings.
 */
function getEffectiveGradeBucket(f: CodeFinding): 'critical' | 'moderate' | 'safe' | 'excluded' {
  if (isAssessedFinding(f)) {
    switch (f.riskContext.adjustedRisk) {
      case 'critical':
      case 'high':
        return 'critical';
      case 'medium':
        return 'moderate';
      case 'low':
      case 'informational':
        return 'excluded';
    }
  }
  // Raw finding — use original risk
  return f.risk === 'critical' ? 'critical' : f.risk === 'moderate' ? 'moderate' : 'safe';
}

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

  // Count findings by effective grade bucket (uses adjustedRisk when available)
  let critical = 0;
  let moderate = 0;
  let safe = 0;
  for (const f of findings) {
    const bucket = getEffectiveGradeBucket(f);
    if (bucket === 'critical') critical++;
    else if (bucket === 'moderate') moderate++;
    else if (bucket === 'safe' || bucket === 'excluded') safe++;
  }

  // Determine base grade from critical/moderate counts
  let baseGrade: BaseGrade;

  if (critical === 0 && moderate === 0) {
    const hasPqc = findings.some((f) => f.category === 'pqc-algorithm');
    baseGrade = hasPqc ? 'A+' : 'A';
  } else if (critical === 0) {
    baseGrade = 'B';
  } else if (critical <= 5) {
    baseGrade = 'C';
  } else if (critical <= 20) {
    baseGrade = 'D';
  } else {
    baseGrade = 'F';
  }

  // Special case: broken algorithms cap at D
  // Only applies when the finding's adjusted risk is critical or high
  const hasBrokenAlgo = findings.some((f) => {
    const isBroken = BROKEN_ALGORITHMS.some((broken) =>
      f.algorithm.toUpperCase() === broken.toUpperCase(),
    );
    if (!isBroken) return false;
    if (isAssessedFinding(f)) {
      return f.riskContext.adjustedRisk === 'critical' || f.riskContext.adjustedRisk === 'high';
    }
    return true; // Raw finding — cap as before
  });
  if (hasBrokenAlgo && gradeRank(baseGrade) < gradeRank('D')) {
    baseGrade = 'D';
  }

  // Compute modifier (same logic as TLS grader)
  let modifier: GradeModifier = '';
  if (baseGrade !== 'A+' && baseGrade !== 'A' && baseGrade !== 'F') {
    if (moderate === 0) {
      modifier = '+';
    } else if (moderate >= 2) {
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
      critical,
      moderate,
      safe,
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

  return [...byFile.entries()].map(([file, fileFindgs]) => {
    let criticalCount = 0;
    let moderateCount = 0;
    let safeCount = 0;
    for (const f of fileFindgs) {
      const bucket = getEffectiveGradeBucket(f);
      if (bucket === 'critical') criticalCount++;
      else if (bucket === 'moderate') moderateCount++;
      else safeCount++;
    }
    return {
      file,
      language: fileFindgs[0].language,
      findings: fileFindgs,
      criticalCount,
      moderateCount,
      safeCount,
    };
  });
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
