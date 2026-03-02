import type {
  ClassifiedResult,
  GradedResult,
  Grade,
} from '../types/index.js';

const PQC_KEYWORDS = ['KYBER', 'MLKEM', 'ML-KEM', 'ML-DSA', 'SLH-DSA', 'HQC'];

const GRADE_ORDER: Grade[] = ['A+', 'A', 'B', 'C', 'D', 'F'];

export function grade(classified: ClassifiedResult): GradedResult {
  const { findings } = classified;

  const critical = findings.filter((f) => f.risk === 'critical');
  const moderate = findings.filter((f) => f.risk === 'moderate');
  const safe = findings.filter((f) => f.risk === 'safe');

  const protocolFinding = findings.find((f) => f.component === 'protocol');
  const hashFinding = findings.find((f) => f.component === 'hash');

  let computedGrade: Grade;

  if (protocolFinding?.risk === 'critical' || hashFinding?.risk === 'critical') {
    computedGrade = 'F';
  } else if (critical.length >= 3) {
    computedGrade = 'D';
  } else if (critical.length >= 1) {
    computedGrade = 'C';
  } else if (moderate.length >= 1) {
    computedGrade = 'B';
  } else {
    const hasPqc = findings.some((f) =>
      PQC_KEYWORDS.some((kw) => f.algorithm.toUpperCase().includes(kw)),
    );
    computedGrade = hasPqc ? 'A+' : 'A';
  }

  const migrationNotes = findings
    .filter((f) => f.migration)
    .map((f) => f.migration!);

  return {
    host: classified.host,
    port: classified.port,
    grade: computedGrade,
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

export function shouldFailForGrade(actual: Grade, threshold: Grade): boolean {
  const actualIndex = GRADE_ORDER.indexOf(actual);
  const thresholdIndex = GRADE_ORDER.indexOf(threshold);
  return actualIndex >= thresholdIndex;
}
