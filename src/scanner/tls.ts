import tls from 'node:tls';
import type { TlsScanResult } from '../types/index.js';

export function scanHost(
  host: string,
  port: number,
  timeout: number,
): Promise<TlsScanResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
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
    if (eki) {
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

    const sigAlgorithm = (cert as any).sigalg ?? '';
    let publicKeyAlgorithm = 'Unknown';
    const publicKeySize = (cert as any).bits ?? 0;
    const curve = (cert as any).asn1Curve;

    if (sigAlgorithm.includes('RSA') || sigAlgorithm.includes('rsa')) {
      publicKeyAlgorithm = 'RSA';
    } else if (curve || sigAlgorithm.includes('ecdsa') || sigAlgorithm.includes('ECDSA')) {
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
          bits: (cipher as any).bits ?? 0,
        }
      : null,
    certificate,
    ephemeralKeyInfo,
  };
}
