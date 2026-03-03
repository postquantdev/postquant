import { describe, it, expect } from 'vitest';
import {
  detectFilePathSignals,
  detectNearbyCodeSignals,
  detectImportSignals,
  detectFunctionNameSignals,
  detectProtocolPattern,
  resolveContext,
  computeAdjustedRisk,
  assessFindings,
} from '../risk-assessor.js';
import type { CodeFinding, Language, ContextSignal } from '../../../types/index.js';

// ── Test helpers ──────────────────────────────────────────────────

function makeFinding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    patternId: 'python-md5',
    file: 'src/utils.py',
    line: 10,
    matchedLine: 'hashlib.md5(data)',
    language: 'python' as Language,
    category: 'weak-hash',
    algorithm: 'MD5',
    risk: 'critical',
    reason: 'MD5 is broken',
    migration: 'Use SHA-256 or SHA-3',
    confidence: 'high',
    ...overrides,
  };
}

// ── detectFilePathSignals ────────────────────────────────────────

describe('detectFilePathSignals', () => {
  it('detects auth/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('src/auth/login.py');
    expect(signals.length).toBeGreaterThanOrEqual(1);
    const authSignal = signals.find(s => s.value.includes('auth'));
    expect(authSignal).toBeDefined();
    expect(authSignal!.influence).toBe('increases-risk');
  });

  it('detects authentication/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('src/authentication/handler.py');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects security/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('lib/security/encrypt.ts');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects crypto/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('pkg/crypto/keys.go');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects certs/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('config/certs/server.pem');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects session/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('src/session/manager.py');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects login/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('src/login/handler.ts');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects password/ directory as increases-risk', () => {
    const signals = detectFilePathSignals('src/password/reset.py');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects test/ directory as decreases-risk', () => {
    const signals = detectFilePathSignals('test/unit/crypto.test.ts');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects tests/ directory as decreases-risk', () => {
    const signals = detectFilePathSignals('tests/integration/auth.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects __tests__/ directory as decreases-risk', () => {
    const signals = detectFilePathSignals('src/__tests__/crypto.test.ts');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects spec/ directory as decreases-risk', () => {
    const signals = detectFilePathSignals('spec/auth_spec.rb');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects _test.go suffix as decreases-risk', () => {
    const signals = detectFilePathSignals('pkg/crypto/hash_test.go');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects .test.ts suffix as decreases-risk', () => {
    const signals = detectFilePathSignals('src/crypto.test.ts');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects .test.js suffix as decreases-risk', () => {
    const signals = detectFilePathSignals('lib/hash.test.js');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects .spec.ts suffix as decreases-risk', () => {
    const signals = detectFilePathSignals('src/auth.spec.ts');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects .spec.js suffix as decreases-risk', () => {
    const signals = detectFilePathSignals('lib/hash.spec.js');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects vendor/ as decreases-risk', () => {
    const signals = detectFilePathSignals('vendor/github.com/crypto/md5.go');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects node_modules/ as decreases-risk', () => {
    const signals = detectFilePathSignals('node_modules/crypto-js/md5.js');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects third_party/ as decreases-risk', () => {
    const signals = detectFilePathSignals('third_party/legacy/hash.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects docs/ as decreases-risk', () => {
    const signals = detectFilePathSignals('docs/crypto-examples.md');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects examples/ as decreases-risk', () => {
    const signals = detectFilePathSignals('examples/hash_demo.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects README in path as decreases-risk', () => {
    const signals = detectFilePathSignals('README.md');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects migrations/ as decreases-risk', () => {
    const signals = detectFilePathSignals('db/migrations/001_add_hash.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects compat/ as decreases-risk', () => {
    const signals = detectFilePathSignals('lib/compat/old_crypto.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects legacy/ as decreases-risk', () => {
    const signals = detectFilePathSignals('src/legacy/md5_auth.py');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('returns empty for neutral path', () => {
    const signals = detectFilePathSignals('src/utils/helpers.py');
    expect(signals).toEqual([]);
  });

  it('returns multiple signals for paths matching multiple rules', () => {
    // test/ + auth/ both match
    const signals = detectFilePathSignals('test/auth/handler.test.ts');
    const increases = signals.filter(s => s.influence === 'increases-risk');
    const decreases = signals.filter(s => s.influence === 'decreases-risk');
    expect(increases.length).toBeGreaterThanOrEqual(1);
    expect(decreases.length).toBeGreaterThanOrEqual(1);
  });

  it('all signals have type file-path', () => {
    const signals = detectFilePathSignals('test/auth/handler.py');
    for (const signal of signals) {
      expect(signal.type).toBe('file-path');
    }
  });
});

// ── detectNearbyCodeSignals ──────────────────────────────────────

describe('detectNearbyCodeSignals', () => {
  const makeLines = (center: string, above: string[] = [], below: string[] = []): string[] => {
    return [...above, center, ...below];
  };

  it('detects password in nearby lines as increases-risk', () => {
    const lines = makeLines(
      'hashlib.md5(data)',
      ['password = get_user_password()'],
      ['return hashed_password']
    );
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('password'))).toBe(true);
  });

  it('detects passwd as increases-risk', () => {
    const lines = ['check_passwd(user)', 'md5(data)', 'return result'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects sign/verify/signature as increases-risk', () => {
    const lines = ['data = load_data()', 'rsa_sign(data)', 'verify_signature(result)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('sign'))).toBe(true);
  });

  it('detects encrypt/decrypt/cipher as increases-risk', () => {
    const lines = ['cipher = AES.new(key)', 'encrypted = cipher.encrypt(data)', 'return encrypted'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects key_exchange/kex/handshake as increases-risk', () => {
    const lines = ['key_exchange_result = kex.perform()', 'md5(shared_secret)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects hmac/HMAC as increases-risk', () => {
    const lines = ['import hmac', 'hmac.new(key, msg, hashlib.md5)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('hmac'))).toBe(true);
  });

  it('detects token/jwt/bearer/oauth as increases-risk', () => {
    const lines = ['token = create_jwt(payload)', 'md5_hash = hash(token)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects checksum/digest/fingerprint/etag as decreases-risk', () => {
    const lines = ['checksum = md5(file_data)', 'return checksum'];
    const signals = detectNearbyCodeSignals(lines, 1);
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('checksum'))).toBe(true);
  });

  it('detects cache/dedup/lookup/index as decreases-risk', () => {
    const lines = ['cache_key = md5(query)', 'cache.set(cache_key, result)'];
    const signals = detectNearbyCodeSignals(lines, 1);
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects uuid/UUID/rfc4122 as decreases-risk', () => {
    const lines = ['import uuid', 'result = uuid.uuid3(uuid.NAMESPACE_DNS, name)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects Content-MD5 as decreases-risk', () => {
    const lines = ['headers["Content-MD5"] = base64(md5(body))'];
    const signals = detectNearbyCodeSignals(lines, 1);
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects legacy/compat/fallback/deprecated as decreases-risk', () => {
    const lines = ['# legacy compatibility fallback', 'md5_hash = hashlib.md5(data)'];
    const signals = detectNearbyCodeSignals(lines, 2);
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects test/mock/stub/fixture/assert as decreases-risk', () => {
    const lines = ['def test_md5_hash():', '    assert md5(data) == expected'];
    const signals = detectNearbyCodeSignals(lines, 1);
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('deduplicates signals by value', () => {
    const lines = [
      'password = input()',
      'password_hash = md5(password)',
      'check_password(password_hash)',
    ];
    const signals = detectNearbyCodeSignals(lines, 2);
    const passwordSignals = signals.filter(s => s.value.includes('password'));
    // Should be deduplicated to one
    expect(passwordSignals.length).toBe(1);
  });

  it('respects custom windowSize', () => {
    // 10 lines above, target at line 11, 10 lines below
    const lines = Array(21).fill('normal code');
    lines[0] = 'password = secret'; // line 1, far from line 11
    lines[20] = 'checksum = hash()'; // line 21, far from line 11
    // windowSize 2 means only scan lines 9-13 (2 above, 2 below)
    const signals = detectNearbyCodeSignals(lines, 11, 2);
    expect(signals.length).toBe(0);
  });

  it('handles lineNumber at start of file', () => {
    const lines = ['password = "test"', 'md5(data)'];
    const signals = detectNearbyCodeSignals(lines, 1);
    expect(signals.some(s => s.value.includes('password'))).toBe(true);
  });

  it('handles lineNumber at end of file', () => {
    const lines = ['normal code', 'normal code', 'checksum = md5(data)'];
    const signals = detectNearbyCodeSignals(lines, 3);
    expect(signals.some(s => s.value.includes('checksum'))).toBe(true);
  });

  it('all signals have type nearby-code', () => {
    const lines = ['password = "test"', 'md5(data)'];
    const signals = detectNearbyCodeSignals(lines, 1);
    for (const signal of signals) {
      expect(signal.type).toBe('nearby-code');
    }
  });
});

// ── detectImportSignals ──────────────────────────────────────────

describe('detectImportSignals', () => {
  it('detects Python uuid import as decreases-risk', () => {
    const content = 'import uuid\nhashlib.md5(data)\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects Python from-import for uuid', () => {
    const content = 'from uuid import uuid3\nhashlib.md5(data)\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects JavaScript import of uuid', () => {
    const content = "import { v3 } from 'uuid';\nconst hash = md5(data);\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects JavaScript require of uuid', () => {
    const content = "const uuid = require('uuid');\nconst hash = md5(data);\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects Go import of uuid-like package', () => {
    const content = 'import (\n  "github.com/google/uuid"\n)\nmd5.Sum(data)\n';
    const signals = detectImportSignals(content, 'go');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects Java import of uuid', () => {
    const content = 'import java.util.UUID;\nMessageDigest.getInstance("MD5");\n';
    const signals = detectImportSignals(content, 'java');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('uuid'))).toBe(true);
  });

  it('detects boto3 import as decreases-risk (protocol-compliance)', () => {
    const content = 'import boto3\nhashlib.md5(data)\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('boto3'))).toBe(true);
  });

  it('detects @aws-sdk import in JavaScript', () => {
    const content = "import { S3Client } from '@aws-sdk/client-s3';\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('aws-sdk'))).toBe(true);
  });

  it('detects pg/postgres import as decreases-risk (legacy-support)', () => {
    const content = "import pg from 'pg';\nconst hash = md5(password);\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('pg'))).toBe(true);
  });

  it('detects psycopg import in Python', () => {
    // Note: psycopg matches the pg/psycopg/postgres rule
    const content = 'import psycopg2\nhashlib.md5(data)\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('psycopg'))).toBe(true);
  });

  it('detects mysql import as decreases-risk', () => {
    const content = "const mysql = require('mysql2');\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('mysql'))).toBe(true);
  });

  it('detects passlib import as increases-risk (authentication)', () => {
    const content = 'from passlib.hash import md5_crypt\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('passlib'))).toBe(true);
  });

  it('detects bcrypt import as increases-risk', () => {
    const content = "const bcrypt = require('bcrypt');\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('bcrypt'))).toBe(true);
  });

  it('detects jsonwebtoken import as increases-risk', () => {
    const content = "import jwt from 'jsonwebtoken';\n";
    const signals = detectImportSignals(content, 'javascript');
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('jsonwebtoken'))).toBe(true);
  });

  it('detects pyjwt import in Python', () => {
    const content = 'import jwt\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('jwt'))).toBe(true);
  });

  it('detects paramiko import as increases-risk', () => {
    const content = 'import paramiko\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'increases-risk' && s.value.includes('paramiko'))).toBe(true);
  });

  it('detects git import as decreases-risk', () => {
    const content = 'import git\nsha1_hash = hash(data)\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals.some(s => s.influence === 'decreases-risk' && s.value.includes('git'))).toBe(true);
  });

  it('only scans first 50 lines', () => {
    const padding = Array(55).fill('# normal code').join('\n');
    const content = padding + '\nimport paramiko\n';
    const signals = detectImportSignals(content, 'python');
    // paramiko is on line 56+, should not be detected
    expect(signals.some(s => s.value.includes('paramiko'))).toBe(false);
  });

  it('returns empty for unrecognized imports', () => {
    const content = 'import os\nimport sys\n';
    const signals = detectImportSignals(content, 'python');
    expect(signals).toEqual([]);
  });

  it('all signals have type import-context', () => {
    const content = 'import uuid\nimport paramiko\n';
    const signals = detectImportSignals(content, 'python');
    for (const signal of signals) {
      expect(signal.type).toBe('import-context');
    }
  });
});

// ── detectFunctionNameSignals ────────────────────────────────────

describe('detectFunctionNameSignals', () => {
  it('detects hash_password as increases-risk', () => {
    const signals = detectFunctionNameSignals('result = hash_password(user_input)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects check_password as increases-risk', () => {
    const signals = detectFunctionNameSignals('if check_password(pwd):');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects verify_password as increases-risk', () => {
    const signals = detectFunctionNameSignals('verify_password(hash, input)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects generate_key as increases-risk', () => {
    const signals = detectFunctionNameSignals('key = generate_key(2048)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects create_key as increases-risk', () => {
    const signals = detectFunctionNameSignals('create_key(algorithm="RSA")');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects new_key as increases-risk', () => {
    const signals = detectFunctionNameSignals('new_key(size=4096)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects sign_ prefix as increases-risk', () => {
    const signals = detectFunctionNameSignals('sign_document(doc, key)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects verify_ prefix as increases-risk', () => {
    const signals = detectFunctionNameSignals('verify_signature(data, sig)');
    expect(signals.some(s => s.influence === 'increases-risk')).toBe(true);
  });

  it('detects md5sum as decreases-risk', () => {
    const signals = detectFunctionNameSignals('result = md5sum(file_path)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects md5_checksum as decreases-risk', () => {
    const signals = detectFunctionNameSignals('cs = md5_checksum(data)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects file_hash as decreases-risk', () => {
    const signals = detectFunctionNameSignals('h = file_hash(path)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects compute_hash as decreases-risk', () => {
    const signals = detectFunctionNameSignals('compute_hash(buffer)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects cache_key as decreases-risk', () => {
    const signals = detectFunctionNameSignals('key = cache_key(query)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects etag as decreases-risk', () => {
    const signals = detectFunctionNameSignals('tag = compute_etag(response)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('detects content_hash as decreases-risk', () => {
    const signals = detectFunctionNameSignals('h = content_hash(body)');
    expect(signals.some(s => s.influence === 'decreases-risk')).toBe(true);
  });

  it('returns empty for generic function names', () => {
    const signals = detectFunctionNameSignals('result = process_data(input)');
    expect(signals).toEqual([]);
  });

  it('all signals have type function-name', () => {
    const signals = detectFunctionNameSignals('hash_password(pw)');
    for (const signal of signals) {
      expect(signal.type).toBe('function-name');
    }
  });
});

// ── detectProtocolPattern ────────────────────────────────────────

describe('detectProtocolPattern', () => {
  it('detects MD5 + uuid context as UUID v3 protocol', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['result = uuid.uuid3(uuid.NAMESPACE_DNS, name)'];
    const imports = 'import uuid';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
    expect(signal!.value).toContain('UUID');
  });

  it('detects SHA-1 + uuid context as UUID v5 protocol', () => {
    const finding = makeFinding({ algorithm: 'SHA-1' });
    const nearbyLines = ['result = uuid.uuid5(uuid.NAMESPACE_URL, url)'];
    const imports = 'import uuid';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
    expect(signal!.value).toContain('UUID');
  });

  it('detects MD5 + Content-MD5 as HTTP Content-MD5 protocol', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['headers["Content-MD5"] = base64(md5(body))'];
    const imports = 'import boto3';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
    expect(signal!.value).toContain('Content-MD5');
  });

  it('detects MD5 + S3/AWS as Content-MD5 protocol', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['s3_client.put_object(Body=data)'];
    const imports = 'import boto3';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
  });

  it('detects MD5 + postgres as PostgreSQL MD5 auth', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['conn = psycopg2.connect(host="localhost")'];
    const imports = 'import psycopg2';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
    expect(signal!.value).toContain('PostgreSQL');
  });

  it('detects SHA-1 + git as Git object hashing', () => {
    const finding = makeFinding({ algorithm: 'SHA-1' });
    const nearbyLines = ['object_hash = sha1(blob_data)'];
    const imports = 'import git';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).not.toBeNull();
    expect(signal!.influence).toBe('decreases-risk');
    expect(signal!.value).toContain('Git');
  });

  it('returns null when no protocol pattern matches', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['result = md5(data)'];
    const imports = 'import os';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).toBeNull();
  });

  it('returns null for non-matching algorithm', () => {
    const finding = makeFinding({ algorithm: 'AES-128' });
    const nearbyLines = ['uuid.uuid3(uuid.NAMESPACE_DNS, name)'];
    const imports = 'import uuid';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal).toBeNull();
  });

  it('signal has type api-pattern', () => {
    const finding = makeFinding({ algorithm: 'MD5' });
    const nearbyLines = ['uuid.uuid3(uuid.NAMESPACE_DNS, name)'];
    const imports = 'import uuid';
    const signal = detectProtocolPattern(finding, nearbyLines, imports);
    expect(signal!.type).toBe('api-pattern');
  });
});

// ── resolveContext ───────────────────────────────────────────────

describe('resolveContext', () => {
  it('returns unknown/neutral for empty signals', () => {
    const result = resolveContext([]);
    expect(result.context).toBe('unknown');
    expect(result.influence).toBe('neutral');
  });

  it('increases-risk wins over decreases-risk', () => {
    const signals: ContextSignal[] = [
      { type: 'file-path', value: 'test/', influence: 'decreases-risk' },
      { type: 'nearby-code', value: 'password', influence: 'increases-risk' },
    ];
    const result = resolveContext(signals);
    expect(result.influence).toBe('increases-risk');
    expect(result.context).toBe('authentication');
  });

  it('picks highest-priority context among increases-risk signals', () => {
    const signals: ContextSignal[] = [
      { type: 'nearby-code', value: 'encrypt', influence: 'increases-risk' },
      { type: 'nearby-code', value: 'password', influence: 'increases-risk' },
    ];
    const result = resolveContext(signals);
    // authentication(10) > encryption(9)
    expect(result.context).toBe('authentication');
  });

  it('picks highest-priority context among decreases-risk signals when no increases', () => {
    const signals: ContextSignal[] = [
      { type: 'file-path', value: 'test/', influence: 'decreases-risk' },
      { type: 'nearby-code', value: 'checksum', influence: 'decreases-risk' },
    ];
    const result = resolveContext(signals);
    expect(result.influence).toBe('decreases-risk');
    // legacy-support(5) > integrity-check(4) > test-fixture(2)
    // checksum -> integrity-check(4), test -> test-fixture(2)
    // So integrity-check wins
    expect(result.context).toBe('integrity-check');
  });

  it('handles single signal', () => {
    const signals: ContextSignal[] = [
      { type: 'file-path', value: 'docs/', influence: 'decreases-risk' },
    ];
    const result = resolveContext(signals);
    expect(result.context).toBe('documentation');
    expect(result.influence).toBe('decreases-risk');
  });

  it('handles all neutral signals as unknown', () => {
    const signals: ContextSignal[] = [
      { type: 'nearby-code', value: 'some random code', influence: 'neutral' },
    ];
    const result = resolveContext(signals);
    expect(result.context).toBe('unknown');
    expect(result.influence).toBe('neutral');
  });
});

// ── computeAdjustedRisk ─────────────────────────────────────────

describe('computeAdjustedRisk', () => {
  // critical + security contexts remain critical
  it('critical + authentication = critical', () => {
    expect(computeAdjustedRisk('critical', 'authentication')).toBe('critical');
  });
  it('critical + encryption = critical', () => {
    expect(computeAdjustedRisk('critical', 'encryption')).toBe('critical');
  });
  it('critical + key-exchange = critical', () => {
    expect(computeAdjustedRisk('critical', 'key-exchange')).toBe('critical');
  });
  it('critical + digital-signature = critical', () => {
    expect(computeAdjustedRisk('critical', 'digital-signature')).toBe('critical');
  });

  // critical + non-security contexts downgrade
  it('critical + integrity-check = low', () => {
    expect(computeAdjustedRisk('critical', 'integrity-check')).toBe('low');
  });
  it('critical + protocol-compliance = informational', () => {
    expect(computeAdjustedRisk('critical', 'protocol-compliance')).toBe('informational');
  });
  it('critical + legacy-support = medium', () => {
    expect(computeAdjustedRisk('critical', 'legacy-support')).toBe('medium');
  });
  it('critical + test-fixture = informational', () => {
    expect(computeAdjustedRisk('critical', 'test-fixture')).toBe('informational');
  });
  it('critical + documentation = informational', () => {
    expect(computeAdjustedRisk('critical', 'documentation')).toBe('informational');
  });
  it('critical + unknown = high', () => {
    expect(computeAdjustedRisk('critical', 'unknown')).toBe('high');
  });

  // moderate contexts
  it('moderate + authentication = medium', () => {
    expect(computeAdjustedRisk('moderate', 'authentication')).toBe('medium');
  });
  it('moderate + encryption = medium', () => {
    expect(computeAdjustedRisk('moderate', 'encryption')).toBe('medium');
  });
  it('moderate + key-exchange = medium', () => {
    expect(computeAdjustedRisk('moderate', 'key-exchange')).toBe('medium');
  });
  it('moderate + digital-signature = medium', () => {
    expect(computeAdjustedRisk('moderate', 'digital-signature')).toBe('medium');
  });
  it('moderate + integrity-check = low', () => {
    expect(computeAdjustedRisk('moderate', 'integrity-check')).toBe('low');
  });
  it('moderate + protocol-compliance = informational', () => {
    expect(computeAdjustedRisk('moderate', 'protocol-compliance')).toBe('informational');
  });
  it('moderate + legacy-support = low', () => {
    expect(computeAdjustedRisk('moderate', 'legacy-support')).toBe('low');
  });
  it('moderate + test-fixture = informational', () => {
    expect(computeAdjustedRisk('moderate', 'test-fixture')).toBe('informational');
  });
  it('moderate + documentation = informational', () => {
    expect(computeAdjustedRisk('moderate', 'documentation')).toBe('informational');
  });
  it('moderate + unknown = medium', () => {
    expect(computeAdjustedRisk('moderate', 'unknown')).toBe('medium');
  });

  // safe always informational
  it('safe + authentication = informational', () => {
    expect(computeAdjustedRisk('safe', 'authentication')).toBe('informational');
  });
  it('safe + unknown = informational', () => {
    expect(computeAdjustedRisk('safe', 'unknown')).toBe('informational');
  });
  it('safe + encryption = informational', () => {
    expect(computeAdjustedRisk('safe', 'encryption')).toBe('informational');
  });
});

// ── assessFindings (integration) ─────────────────────────────────

describe('assessFindings', () => {
  it('MD5 in auth file with password context => critical', () => {
    const finding = makeFinding({
      file: 'src/auth/login.py',
      line: 5,
      matchedLine: 'hash = hashlib.md5(password.encode())',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import hashlib',
      '',
      'def authenticate(user, password):',
      '    # Hash the password',
      '    hash = hashlib.md5(password.encode())',
      '    return check_db(user, hash)',
    ].join('\n');
    const fileContents = new Map([['src/auth/login.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results).toHaveLength(1);
    expect(results[0].riskContext.adjustedRisk).toBe('critical');
    expect(results[0].riskContext.usageContext).toBe('authentication');
  });

  it('MD5 in test file => informational', () => {
    const finding = makeFinding({
      file: 'tests/test_hash.py',
      line: 3,
      matchedLine: 'result = hashlib.md5(b"test")',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import hashlib',
      'def test_md5():',
      '    result = hashlib.md5(b"test")',
      '    assert result == expected',
    ].join('\n');
    const fileContents = new Map([['tests/test_hash.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results).toHaveLength(1);
    expect(results[0].riskContext.adjustedRisk).toBe('informational');
  });

  it('MD5 in uuid context => informational (protocol-compliance)', () => {
    const finding = makeFinding({
      file: 'src/id_generator.py',
      line: 4,
      matchedLine: 'result = uuid.uuid3(uuid.NAMESPACE_DNS, name)',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import uuid',
      '',
      'def generate_id(name):',
      '    result = uuid.uuid3(uuid.NAMESPACE_DNS, name)',
      '    return str(result)',
    ].join('\n');
    const fileContents = new Map([['src/id_generator.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results).toHaveLength(1);
    expect(results[0].riskContext.usageContext).toBe('protocol-compliance');
    expect(results[0].riskContext.adjustedRisk).toBe('informational');
  });

  it('MD5 with no context => high (conservative)', () => {
    const finding = makeFinding({
      file: 'src/utils.py',
      line: 2,
      matchedLine: 'h = hashlib.md5(data)',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import hashlib',
      'h = hashlib.md5(data)',
      'print(h)',
    ].join('\n');
    const fileContents = new Map([['src/utils.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results).toHaveLength(1);
    // unknown context => critical downgraded to high
    expect(results[0].riskContext.adjustedRisk).toBe('high');
    expect(results[0].riskContext.usageContext).toBe('unknown');
  });

  it('preserves all original CodeFinding fields', () => {
    const finding = makeFinding({
      patternId: 'python-md5',
      file: 'src/app.py',
      line: 5,
      matchedLine: 'md5(x)',
      language: 'python',
      category: 'weak-hash',
      algorithm: 'MD5',
      keySize: undefined,
      risk: 'critical',
      reason: 'MD5 is broken',
      migration: 'Use SHA-256',
      confidence: 'high',
    });
    const fileContents = new Map([['src/app.py', 'import os\ndata\ncode\nmore\nmd5(x)\n']]);

    const results = assessFindings([finding], fileContents);
    const r = results[0];
    expect(r.patternId).toBe('python-md5');
    expect(r.file).toBe('src/app.py');
    expect(r.line).toBe(5);
    expect(r.matchedLine).toBe('md5(x)');
    expect(r.language).toBe('python');
    expect(r.category).toBe('weak-hash');
    expect(r.algorithm).toBe('MD5');
    expect(r.risk).toBe('critical');
    expect(r.reason).toBe('MD5 is broken');
    expect(r.migration).toBe('Use SHA-256');
    expect(r.confidence).toBe('high');
    expect(r.originalRisk).toBe('critical');
  });

  it('contextEvidence has human-readable strings with arrows', () => {
    const finding = makeFinding({
      file: 'src/auth/login.py',
      line: 3,
      matchedLine: 'hash = hashlib.md5(password)',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import hashlib',
      'def login(password):',
      '    hash = hashlib.md5(password)',
    ].join('\n');
    const fileContents = new Map([['src/auth/login.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    const evidence = results[0].riskContext.contextEvidence;
    expect(evidence.length).toBeGreaterThan(0);
    // Should contain arrows: up for increases, down for decreases
    const hasArrow = evidence.some(e => e.includes('\u2191') || e.includes('\u2193'));
    expect(hasArrow).toBe(true);
  });

  it('signals array is populated', () => {
    const finding = makeFinding({
      file: 'src/auth/login.py',
      line: 3,
      matchedLine: 'hash = hashlib.md5(password)',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContent = [
      'import hashlib',
      'def login(password):',
      '    hash = hashlib.md5(password)',
    ].join('\n');
    const fileContents = new Map([['src/auth/login.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results[0].riskContext.signals.length).toBeGreaterThan(0);
  });

  it('handles missing file content gracefully', () => {
    const finding = makeFinding({
      file: 'missing/file.py',
      line: 1,
      matchedLine: 'md5(data)',
      algorithm: 'MD5',
      risk: 'critical',
    });
    const fileContents = new Map<string, string>();

    const results = assessFindings([finding], fileContents);
    expect(results).toHaveLength(1);
    expect(results[0].riskContext).toBeDefined();
    expect(results[0].originalRisk).toBe('critical');
  });

  it('handles multiple findings from different files', () => {
    const findings = [
      makeFinding({
        file: 'src/auth/login.py',
        line: 3,
        matchedLine: 'hash_password(pw)',
        algorithm: 'MD5',
        risk: 'critical',
      }),
      makeFinding({
        file: 'tests/test_util.py',
        line: 5,
        matchedLine: 'assert md5(data)',
        algorithm: 'MD5',
        risk: 'critical',
      }),
    ];
    const fileContents = new Map([
      ['src/auth/login.py', 'import hashlib\ndef auth(pw):\n    hash_password(pw)\n'],
      ['tests/test_util.py', 'import hashlib\nimport pytest\ndef test_hash():\n    expected = "abc"\n    assert md5(data)\n'],
    ]);

    const results = assessFindings(findings, fileContents);
    expect(results).toHaveLength(2);
    // Auth context should be critical
    expect(results[0].riskContext.adjustedRisk).toBe('critical');
    // Test context should be informational
    expect(results[1].riskContext.adjustedRisk).toBe('informational');
  });

  it('safe original risk always maps to informational', () => {
    const finding = makeFinding({
      file: 'src/auth/crypto.py',
      line: 3,
      matchedLine: 'AES256.encrypt(data)',
      algorithm: 'AES-256',
      risk: 'safe',
      category: 'safe-symmetric',
    });
    const fileContent = 'import crypto\ndef secure(data):\n    AES256.encrypt(data)\n';
    const fileContents = new Map([['src/auth/crypto.py', fileContent]]);

    const results = assessFindings([finding], fileContents);
    expect(results[0].riskContext.adjustedRisk).toBe('informational');
  });
});
