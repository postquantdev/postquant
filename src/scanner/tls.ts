import tls from 'node:tls';
import chalk from 'chalk';
import type { TlsScanResult } from '../types/index.js';
import { probeWithOpenssl, findOpenssl3 } from './openssl.js';
import { validateHostname, validatePort } from '../utils/validate.js';

let opensslWarningShown = false;

/** @internal — for testing only */
export function _resetOpensslWarning(): void {
  opensslWarningShown = false;
}

export async function scanHost(
  host: string,
  port: number,
  timeout: number,
): Promise<TlsScanResult> {
  if (!validateHostname(host)) {
    throw new Error(`Invalid hostname: "${host}" contains prohibited characters`);
  }
  if (!validatePort(port)) {
    throw new Error(`Invalid port: ${port} must be an integer between 1 and 65535`);
  }

  const result = await connectTls(host, port, timeout);

  // Check OpenSSL availability and warn if missing
  let opensslAvailable = false;
  try {
    opensslAvailable = (await findOpenssl3()) !== null;
  } catch {
    // findOpenssl3 failed entirely
  }

  if (!opensslAvailable && !opensslWarningShown) {
    opensslWarningShown = true;
    process.stderr.write(
      chalk.yellow('Warning: OpenSSL 3.5+ not found — PQC key exchange detection unavailable\n'),
    );
  }

  // Enrich with openssl probe for PQC detection
  if (opensslAvailable) {
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
          result.ephemeralKeyInfo = {
            type: 'ECDH',
            name: probe.group,
            size: 0,
          };
        }
      } else if (!result.ephemeralKeyInfo && probe.peerTempKey) {
        result.ephemeralKeyInfo = {
          type: probe.peerTempKey.type,
          name: probe.peerTempKey.name,
          size: probe.peerTempKey.size,
        };
      }
    } catch {
      // openssl probe failed — keep Node.js data as-is
    }
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
