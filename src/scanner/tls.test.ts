import { describe, it, expect, vi, beforeEach } from 'vitest';
import tls from 'node:tls';
import { scanHost, _resetOpensslWarning } from './tls.js';
import { findOpenssl3 } from './openssl.js';
import { EventEmitter } from 'node:events';

vi.mock('node:tls');
vi.mock('./openssl.js', () => ({
  probeWithOpenssl: vi.fn().mockResolvedValue({ group: null, peerTempKey: null }),
  findOpenssl3: vi.fn().mockResolvedValue(null),
}));

function createMockSocket() {
  const socket = new EventEmitter() as any;
  socket.authorized = true;
  socket.destroy = vi.fn();

  socket.getCipher = vi.fn().mockReturnValue({
    name: 'TLS_AES_256_GCM_SHA384',
    standardName: 'TLS_AES_256_GCM_SHA384',
    version: 'TLSv1.3',
  });

  socket.getProtocol = vi.fn().mockReturnValue('TLSv1.3');

  socket.getPeerCertificate = vi.fn().mockReturnValue({
    subject: { CN: 'example.com' },
    issuer: { CN: 'Example CA', O: 'Example' },
    valid_from: 'Jan  1 00:00:00 2025 GMT',
    valid_to: 'Jan  1 00:00:00 2026 GMT',
    serialNumber: 'ABC123',
    fingerprint256: 'AA:BB:CC',
    asn1Curve: 'prime256v1',
    bits: 256,
    pubkey: Buffer.alloc(0),
  });

  socket.getEphemeralKeyInfo = vi.fn().mockReturnValue({
    type: 'ECDH',
    name: 'X25519',
    size: 253,
  });

  return socket;
}

describe('scanHost', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('extracts TLS data from a successful connection', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });

    const result = await scanHost('example.com', 443, 10000);

    expect(result.host).toBe('example.com');
    expect(result.port).toBe(443);
    expect(result.protocol).toBe('TLSv1.3');
    expect(result.cipher).toBeTruthy();
    expect(result.cipher!.name).toBe('TLS_AES_256_GCM_SHA384');
    expect(result.ephemeralKeyInfo).toBeTruthy();
    expect(result.ephemeralKeyInfo!.name).toBe('X25519');
    expect(mockSocket.destroy).toHaveBeenCalled();
  });

  it('handles null ephemeralKeyInfo gracefully', async () => {
    const mockSocket = createMockSocket();
    mockSocket.getEphemeralKeyInfo.mockReturnValue(null);
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });

    const result = await scanHost('example.com', 443, 10000);

    expect(result.ephemeralKeyInfo).toBeNull();
  });

  it('rejects on connection error', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation(() => {
      process.nextTick(() => mockSocket.emit('error', new Error('ECONNREFUSED')));
      return mockSocket;
    });

    await expect(scanHost('bad.host', 443, 10000)).rejects.toThrow('ECONNREFUSED');
  });

  it('rejects on timeout', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation(() => {
      process.nextTick(() => mockSocket.emit('timeout'));
      return mockSocket;
    });

    await expect(scanHost('slow.host', 443, 100)).rejects.toThrow('timed out');
  });

  it('connects with rejectUnauthorized false', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });

    await scanHost('example.com', 443, 10000);

    expect(tls.connect).toHaveBeenCalledWith(
      expect.objectContaining({ rejectUnauthorized: false }),
      expect.any(Function),
    );
  });
});

describe('scanHost input validation', () => {
  it('rejects hostname with shell metacharacters', async () => {
    await expect(scanHost(';rm -rf /', 443, 5000)).rejects.toThrow(/invalid hostname/i);
  });

  it('rejects invalid port at scanner boundary', async () => {
    await expect(scanHost('example.com', 0, 5000)).rejects.toThrow(/invalid port/i);
  });
});

describe('scanHost OpenSSL warning', () => {
  beforeEach(() => {
    _resetOpensslWarning();
    vi.mocked(findOpenssl3).mockResolvedValue(null);
  });

  it('prints stderr warning when OpenSSL 3.5+ is not found', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    await scanHost('example.com', 443, 10000);

    const calls = stderrSpy.mock.calls.map((c) => String(c[0]));
    expect(calls.some((c) => c.includes('OpenSSL 3.5+ not found'))).toBe(true);
    stderrSpy.mockRestore();
  });

  it('does not print warning when OpenSSL is available', async () => {
    vi.mocked(findOpenssl3).mockResolvedValue('/usr/bin/openssl');
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    await scanHost('example.com', 443, 10000);

    const calls = stderrSpy.mock.calls.map((c) => String(c[0]));
    expect(calls.some((c) => c.includes('OpenSSL 3.5+ not found'))).toBe(false);
    stderrSpy.mockRestore();
  });
});

describe('scanHost OpenSSL warning deduplication', () => {
  beforeEach(() => {
    _resetOpensslWarning();
    vi.mocked(findOpenssl3).mockResolvedValue(null);
  });

  it('only prints the warning once across multiple scanHost calls', async () => {
    const mockSocket = createMockSocket();
    vi.mocked(tls.connect).mockImplementation((...args: any[]) => {
      const cb = args[args.length - 1];
      process.nextTick(() => cb());
      return mockSocket;
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

    await scanHost('example.com', 443, 10000);
    await scanHost('example.com', 443, 10000);

    const warningCalls = stderrSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((c) => c.includes('OpenSSL 3.5+ not found'));
    expect(warningCalls).toHaveLength(1);
    stderrSpy.mockRestore();
  });
});
