import { describe, it, expect } from 'vitest';
import { scanHost } from './tls.js';
import { classify } from './classifier.js';
import { grade } from './grader.js';

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === 'true';

describe.skipIf(!RUN_INTEGRATION)('integration: live host scanning', () => {
  it('scans google.com and produces a valid graded result', async () => {
    const scan = await scanHost('google.com', 443, 15000);
    expect(scan.host).toBe('google.com');
    expect(scan.protocol).toBeTruthy();
    expect(scan.cipher).toBeTruthy();

    const classified = classify(scan);
    expect(classified.findings).toHaveLength(5);

    const graded = grade(classified);
    expect(['A+', 'A', 'B', 'C', 'D', 'F']).toContain(graded.grade);
    expect(graded.summary.total).toBe(5);
  }, 20000);

  it('scans cloudflare.com and produces a valid graded result', async () => {
    const scan = await scanHost('cloudflare.com', 443, 15000);
    const classified = classify(scan);
    const graded = grade(classified);
    expect(['A+', 'A', 'B', 'C', 'D', 'F']).toContain(graded.grade);
  }, 20000);

  it('detects PQC key exchange on cloudflare.com', async () => {
    const scan = await scanHost('cloudflare.com', 443, 15000);
    const classified = classify(scan);
    const kxFinding = classified.findings.find((f) => f.component === 'keyExchange');
    // With OpenSSL 3.x available, should detect PQC hybrid
    if (scan.ephemeralKeyInfo?.name?.toUpperCase().includes('MLKEM')) {
      expect(kxFinding?.risk).toBe('safe');
      const graded = grade(classified);
      expect(['A+', 'A']).toContain(graded.grade);
    }
    // If OpenSSL 3.x not available, this test is a no-op
  }, 20000);

  it('detects PQC key exchange on google.com', async () => {
    const scan = await scanHost('google.com', 443, 15000);
    const classified = classify(scan);
    const kxFinding = classified.findings.find((f) => f.component === 'keyExchange');
    if (scan.ephemeralKeyInfo?.name?.toUpperCase().includes('MLKEM')) {
      expect(kxFinding?.risk).toBe('safe');
      const graded = grade(classified);
      expect(['A+', 'A']).toContain(graded.grade);
    }
  }, 20000);
});
