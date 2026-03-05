import tls from 'node:tls';
import type { TlsScanResult } from '../types/index.js';
import { probeWithOpenssl } from './openssl.js';

export async function scanHost(
  host: string,
  port: number,
  timeout: number,
): Promise<TlsScanResult> {
  const result = await connectTls(host, port, timeout);

  // Enrich with openssl probe for PQC detection
  // Node.js returns {} for getEphemeralKeyInfo() on TLS 1.3
  try {
    const probe = await probeWithOpenssl(host, port);

    if (probe.group) {
      const groupUpper = probe.group.toUpperCase();
      const isPqc =
        groupUpper.includes('KYBER') ||
        groupUpper.includes('MLKEM') ||
        groupUpper.includes('ML-KEM');

      if (isPqc) {
        result.ephemeralKeyInfo = {
          type: 'KEM',
          name: probe.group,
          size: 0,
        };
      } else if (!result.ephemeralKeyInfo) {
        // Classical group detected by openssl, Node.js had nothing
        result.ephemeralKeyInfo = {
          type: 'ECDH',
          name: probe.group,
          size: 0,
        };
      }
    } else if (!result.ephemeralKeyInfo && probe.peerTempKey) {
      // No negotiated group line but we got Peer Temp Key info
      result.ephemeralKeyInfo = {
        type: probe.peerTempKey.type,
        name: probe.peerTempKey.name,
        size: probe.peerTempKey.size,
      };
    }
  } catch {
    // openssl probe failed — keep Node.js data as-is
  }

  return result;
}

function connectTls(
  host: string,
  port: number,
  timeout: number,
): Promise<TlsScanResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout,
      },
      () => {
        try {
          const result = extractTlsData(socket, host, port);
          socket.destroy();
          resolve(result);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      },
    );

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Connection to ${host}:${port} timed out`));
    });
  });
}

function extractTlsData(
  socket: tls.TLSSocket,
  host: string,
  port: number,
): TlsScanResult {
  const cipher = socket.getCipher();
  const protocol = socket.getProtocol();
  const cert = socket.getPeerCertificate(true);

  let ephemeralKeyInfo: TlsScanResult['ephemeralKeyInfo'] = null;
  try {
    const eki = (socket as any).getEphemeralKeyInfo?.();
    if (eki && eki.type) {
      ephemeralKeyInfo = {
        type: eki.type,
        name: eki.name,
        size: eki.size,
      };
    }
  } catch {
    // getEphemeralKeyInfo not available — leave null
  }

  let certificate: TlsScanResult['certificate'] = null;
  if (cert && cert.subject) {
    const cn =
      typeof cert.subject === 'object'
        ? (cert.subject as any).CN ?? ''
        : String(cert.subject);

    const issuerCN =
      typeof cert.issuer === 'object'
        ? (cert.issuer as any).CN ?? (cert.issuer as any).O ?? ''
        : String(cert.issuer);

    let publicKeyAlgorithm = 'Unknown';
    const publicKeySize = (cert as any).bits ?? 0;
    const curve = (cert as any).asn1Curve;
    const modulus = (cert as any).modulus;
    const sigAlgorithm = (cert as any).sigalg ?? '';

    // Detect algorithm from cert properties (sigalg is not always available)
    if (modulus) {
      publicKeyAlgorithm = 'RSA';
    } else if (curve) {
      publicKeyAlgorithm = 'EC';
    } else if (sigAlgorithm.includes('RSA') || sigAlgorithm.includes('rsa')) {
      publicKeyAlgorithm = 'RSA';
    } else if (sigAlgorithm.includes('ecdsa') || sigAlgorithm.includes('ECDSA')) {
      publicKeyAlgorithm = 'EC';
    } else if (sigAlgorithm.includes('ed25519') || sigAlgorithm.includes('Ed25519')) {
      publicKeyAlgorithm = 'Ed25519';
    } else if (sigAlgorithm.includes('ed448') || sigAlgorithm.includes('Ed448')) {
      publicKeyAlgorithm = 'Ed448';
    } else if (sigAlgorithm.includes('dsa') || sigAlgorithm.includes('DSA')) {
      publicKeyAlgorithm = 'DSA';
    }

    certificate = {
      subject: cn,
      issuer: issuerCN,
      validFrom: cert.valid_from ?? '',
      validTo: cert.valid_to ?? '',
      serialNumber: cert.serialNumber ?? '',
      fingerprint256: cert.fingerprint256 ?? '',
      sigAlgorithm,
      publicKeyAlgorithm,
      publicKeySize,
      curve,
    };
  }

  return {
    host,
    port,
    protocol: protocol ?? null,
    cipher: cipher
      ? {
          name: cipher.name,
          standardName: (cipher as any).standardName ?? cipher.name,
          version: cipher.version,
          bits: (cipher as any).bits ?? parseCipherBits(cipher.name),
        }
      : null,
    certificate,
    ephemeralKeyInfo,
  };
}

function parseCipherBits(cipherName: string): number {
  const upper = cipherName.toUpperCase();
  if (upper.includes('256')) return 256;
  if (upper.includes('128')) return 128;
  if (upper.includes('CHACHA20')) return 256;
  return 0;
}
