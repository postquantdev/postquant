import { describe, it, expect } from 'vitest';
import { grade, shouldFailForGrade } from './grader.js';
import type { ClassifiedFinding, ClassifiedResult } from '../types/index.js';

function makeResult(findings: ClassifiedFinding[]): ClassifiedResult {
  return { host: 'example.com', port: 443, findings };
}

function finding(
  component: ClassifiedFinding['component'],
  risk: ClassifiedFinding['risk'],
  algorithm = 'TestAlgo',
): ClassifiedFinding {
  return { component, algorithm, risk, reason: 'test' };
}

describe('grade', () => {
  it('grades A+ when all safe and PQC key exchange detected', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe', 'TLS 1.3'),
        finding('certificate', 'safe', 'ML-DSA'),
        finding('keyExchange', 'safe', 'X25519Kyber768'),
        finding('cipher', 'safe', 'AES-256'),
        finding('hash', 'safe', 'SHA-384'),
      ]),
    );
    expect(result.grade).toBe('A+');
  });

  it('grades A when all safe but no PQC algorithm', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('A');
  });

  it('grades B when zero critical but has moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'moderate', 'AES-128'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('B');
  });

  it('grades C+ with 1 critical finding and 0 moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical', 'RSA'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('C+');
    expect(result.baseGrade).toBe('C');
    expect(result.modifier).toBe('+');
  });

  it('grades C+ with 2 critical findings and 0 moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical', 'ECDSA'),
        finding('keyExchange', 'critical', 'X25519'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('C+');
    expect(result.baseGrade).toBe('C');
    expect(result.modifier).toBe('+');
  });

  it('grades D+ with 3 critical findings and 0 moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical'),
        finding('keyExchange', 'critical'),
        finding('cipher', 'critical'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('D+');
    expect(result.baseGrade).toBe('D');
    expect(result.modifier).toBe('+');
  });

  it('grades F with critical protocol (TLS 1.1)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'critical', 'TLS 1.1'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('F');
  });

  it('grades F with critical hash (SHA-1)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'critical', 'SHA-1'),
      ]),
    );
    expect(result.grade).toBe('F');
  });

  it('grades F with critical hash (MD5)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'critical', 'MD5'),
      ]),
    );
    expect(result.grade).toBe('F');
  });

  it('computes correct summary counts', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical'),
        finding('keyExchange', 'critical'),
        finding('cipher', 'safe'),
        finding('hash', 'moderate'),
      ]),
    );
    expect(result.summary).toEqual({
      critical: 2,
      moderate: 1,
      safe: 2,
      total: 5,
    });
  });

  it('includes migration notes for critical findings', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        { ...finding('certificate', 'critical'), migration: 'Use ML-DSA' },
        { ...finding('keyExchange', 'critical'), migration: 'Use ML-KEM' },
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.migrationNotes).toContain('Use ML-DSA');
    expect(result.migrationNotes).toContain('Use ML-KEM');
  });

  it('assigns + modifier when 0 moderate findings (C band)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical', 'ECDSA'),
        finding('keyExchange', 'critical', 'X25519'),
        finding('cipher', 'safe', 'AES-256'),
        finding('hash', 'safe', 'SHA-384'),
      ]),
    );
    expect(result.grade).toBe('C+');
    expect(result.baseGrade).toBe('C');
    expect(result.modifier).toBe('+');
  });

  it('assigns empty modifier when 1 moderate finding (C band)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical', 'ECDSA'),
        finding('keyExchange', 'critical', 'X25519'),
        finding('cipher', 'safe', 'AES-256'),
        finding('hash', 'moderate', 'SHA-256'),
      ]),
    );
    expect(result.grade).toBe('C');
    expect(result.baseGrade).toBe('C');
    expect(result.modifier).toBe('');
  });

  it('assigns - modifier when 2+ moderate findings (C band)', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical', 'ECDSA'),
        finding('keyExchange', 'critical', 'X25519'),
        finding('cipher', 'moderate', 'AES-128'),
        finding('hash', 'moderate', 'SHA-256'),
      ]),
    );
    expect(result.grade).toBe('C-');
    expect(result.baseGrade).toBe('C');
    expect(result.modifier).toBe('-');
  });

  it('assigns no modifier in B band with 1 moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'moderate', 'AES-128'),
        finding('hash', 'safe', 'SHA-384'),
      ]),
    );
    expect(result.grade).toBe('B');
    expect(result.baseGrade).toBe('B');
    expect(result.modifier).toBe('');
  });

  it('assigns - modifier in B band with 2+ moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'moderate'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'moderate', 'AES-128'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('B-');
    expect(result.baseGrade).toBe('B');
    expect(result.modifier).toBe('-');
  });

  it('does not add modifier to A+ grade', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe', 'TLS 1.3'),
        finding('certificate', 'safe', 'ML-DSA'),
        finding('keyExchange', 'safe', 'X25519Kyber768'),
        finding('cipher', 'safe', 'AES-256'),
        finding('hash', 'safe', 'SHA-384'),
      ]),
    );
    expect(result.grade).toBe('A+');
    expect(result.baseGrade).toBe('A+');
    expect(result.modifier).toBe('');
  });

  it('does not add modifier to A grade', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('A');
    expect(result.baseGrade).toBe('A');
    expect(result.modifier).toBe('');
  });

  it('does not add modifier to F grade', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'critical', 'TLS 1.1'),
        finding('certificate', 'safe'),
        finding('keyExchange', 'safe'),
        finding('cipher', 'safe'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('F');
    expect(result.baseGrade).toBe('F');
    expect(result.modifier).toBe('');
  });

  it('assigns + modifier in D band with 0 moderate', () => {
    const result = grade(
      makeResult([
        finding('protocol', 'safe'),
        finding('certificate', 'critical'),
        finding('keyExchange', 'critical'),
        finding('cipher', 'critical'),
        finding('hash', 'safe'),
      ]),
    );
    expect(result.grade).toBe('D+');
    expect(result.baseGrade).toBe('D');
    expect(result.modifier).toBe('+');
  });

  it('preserves host and port', () => {
    const classified = makeResult([
      finding('protocol', 'safe'),
      finding('certificate', 'safe'),
      finding('keyExchange', 'safe'),
      finding('cipher', 'safe'),
      finding('hash', 'safe'),
    ]);
    classified.host = 'test.io';
    classified.port = 8443;
    const result = grade(classified);
    expect(result.host).toBe('test.io');
    expect(result.port).toBe(8443);
  });
});

describe('shouldFailForGrade', () => {
  it('fails C grade at default threshold C', () => {
    expect(shouldFailForGrade('C', 'C')).toBe(true);
  });

  it('fails D grade at default threshold C', () => {
    expect(shouldFailForGrade('D', 'C')).toBe(true);
  });

  it('fails F grade at default threshold C', () => {
    expect(shouldFailForGrade('F', 'C')).toBe(true);
  });

  it('passes A grade at default threshold C', () => {
    expect(shouldFailForGrade('A', 'C')).toBe(false);
  });

  it('passes B grade at default threshold C', () => {
    expect(shouldFailForGrade('B', 'C')).toBe(false);
  });

  it('passes C grade at threshold D', () => {
    expect(shouldFailForGrade('C', 'D')).toBe(false);
  });

  it('fails D grade at threshold D', () => {
    expect(shouldFailForGrade('D', 'D')).toBe(true);
  });

  it('passes A+ grade at any threshold', () => {
    expect(shouldFailForGrade('A+', 'F')).toBe(false);
  });
});
