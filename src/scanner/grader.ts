import type {
  ClassifiedResult,
  GradedResult,
  Grade,
  BaseGrade,
  GradeModifier,
} from '../types/index.js';

const PQC_KEYWORDS = ['KYBER', 'MLKEM', 'ML-KEM', 'ML-DSA', 'SLH-DSA', 'HQC'];

const BASE_GRADE_ORDER: BaseGrade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

export function grade(classified: ClassifiedResult): GradedResult {
  const { findings } = classified;

  const critical = findings.filter((f) => f.risk === 'critical');
  const moderate = findings.filter((f) => f.risk === 'moderate');
  const safe = findings.filter((f) => f.risk === 'safe');

  const protocolFinding = findings.find((f) => f.component === 'protocol');
  const hashFinding = findings.find((f) => f.component === 'hash');

  let baseGrade: BaseGrade;

  if (protocolFinding?.risk === 'critical' || hashFinding?.risk === 'critical') {
    baseGrade = 'F';
  } else if (critical.length >= 3) {
    baseGrade = 'D';
  } else if (critical.length >= 1) {
    baseGrade = 'C';
  } else if (moderate.length >= 1) {
    baseGrade = 'B';
  } else {
    const hasPqc = findings.some((f) =>
      PQC_KEYWORDS.some((kw) => f.algorithm.toUpperCase().includes(kw)),
    );
    baseGrade = hasPqc ? 'A+' : 'A';
  }

  // Compute modifier: A+, A, and F get no modifier
  let modifier: GradeModifier = '';
  if (baseGrade !== 'A+' && baseGrade !== 'A' && baseGrade !== 'F') {
    if (moderate.length === 0) {
      modifier = '+';
    } else if (moderate.length >= 2) {
      modifier = '-';
    }
  }

  const displayGrade = (baseGrade + modifier) as Grade;

  const pqcDetected = findings.some((f) =>
    PQC_KEYWORDS.some((kw) => f.algorithm.toUpperCase().includes(kw)),
  );

  const migrationNotes = findings
    .filter((f) => f.migration)
    .map((f) => f.migration!);

  return {
    host: classified.host,
    port: classified.port,
    grade: displayGrade,
    baseGrade,
    modifier,
    pqcDetected,
    findings,
    migrationNotes,
    summary: {
      critical: critical.length,
      moderate: moderate.length,
      safe: safe.length,
      total: findings.length,
    },
  };
}

export function shouldFailForGrade(actual: BaseGrade, threshold: BaseGrade): boolean {
  const actualIndex = BASE_GRADE_ORDER.indexOf(actual);
  const thresholdIndex = BASE_GRADE_ORDER.indexOf(threshold);
  return actualIndex >= thresholdIndex;
}
