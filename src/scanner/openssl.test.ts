import { describe, it, expect, vi, beforeEach } from 'vitest';
import { parseOpensslOutput, probeWithOpenssl } from './openssl.js';

describe('parseOpensslOutput', () => {
  it('parses X25519MLKEM768 negotiated group', () => {
    const output = `
CONNECTED(00000003)
depth=2 C=US, O=Google Trust Services LLC, CN=GTS Root R1
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group: X25519MLKEM768
---
`;
    const result = parseOpensslOutput(output);
    expect(result.group).toBe('X25519MLKEM768');
    expect(result.peerTempKey).toBeNull();
  });

  it('parses Peer Temp Key for classical key exchange', () => {
    const output = `
CONNECTED(00000003)
Peer Temp Key: ECDH, X25519, 253 bits
---
`;
    const result = parseOpensslOutput(output);
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toEqual({
      type: 'ECDH',
      name: 'X25519',
      size: 253,
    });
  });

  it('parses Server Temp Key (LibreSSL variant)', () => {
    const output = `
Server Temp Key: ECDH, prime256v1, 256 bits
`;
    const result = parseOpensslOutput(output);
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toEqual({
      type: 'ECDH',
      name: 'prime256v1',
      size: 256,
    });
  });

  it('parses both group and temp key when both present', () => {
    const output = `
Peer Temp Key: ECDH, X25519, 253 bits
Negotiated TLS1.3 group: X25519MLKEM768
`;
    const result = parseOpensslOutput(output);
    expect(result.group).toBe('X25519MLKEM768');
    expect(result.peerTempKey).toEqual({
      type: 'ECDH',
      name: 'X25519',
      size: 253,
    });
  });

  it('returns nulls when no relevant lines present', () => {
    const output = `
CONNECTED(00000003)
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
---
`;
    const result = parseOpensslOutput(output);
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toBeNull();
  });

  it('returns nulls for empty output', () => {
    const result = parseOpensslOutput('');
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toBeNull();
  });

  it('handles various PQC group names', () => {
    const output = 'Negotiated TLS1.3 group: MLKEM768';
    const result = parseOpensslOutput(output);
    expect(result.group).toBe('MLKEM768');
  });
});

describe('probeWithOpenssl input validation', () => {
  it('returns null result for hostname with shell metacharacters', async () => {
    const result = await probeWithOpenssl(';whoami', 443);
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toBeNull();
  });

  it('returns null result for invalid port', async () => {
    const result = await probeWithOpenssl('example.com', 0);
    expect(result.group).toBeNull();
    expect(result.peerTempKey).toBeNull();
  });
});
