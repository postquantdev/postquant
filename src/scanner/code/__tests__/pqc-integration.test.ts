import { describe, it, expect } from 'vitest';
import { matchFile } from '../matcher.js';
import { classifyCodeFindings } from '../classifier.js';
import { gradeCodeScan } from '../grader.js';
import { resolve } from 'node:path';

describe('PQC detection integration', () => {
  it('detects PQC usage and sets pqcDetected true', async () => {
    const fixturePath = resolve(__dirname, '../../../../tests/fixtures/pqc-python');
    const filePath = resolve(fixturePath, 'pqc_example.py');

    // Run the file through the matcher → classifier → grader pipeline
    const { findings } = await matchFile(filePath, 'python');
    const classified = classifyCodeFindings(findings, fixturePath, 1, 0);
    const graded = gradeCodeScan(classified);

    expect(graded.pqcDetected).toBe(true);
    expect(graded.findings.some(f => f.category === 'pqc-algorithm')).toBe(true);
  });
});
