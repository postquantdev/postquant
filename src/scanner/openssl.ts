import { execFile } from 'node:child_process';
import { access, constants } from 'node:fs/promises';
import { validateHostname, validatePort } from '../utils/validate.js';

export interface OpensslProbeResult {
  /** Negotiated TLS 1.3 group (e.g., 'X25519MLKEM768') */
  group: string | null;
  /** Classical key exchange info from "Peer Temp Key" / "Server Temp Key" */
  peerTempKey: { type: string; name: string; size: number } | null;
}

const OPENSSL_CANDIDATES = [
  'openssl',
  '/opt/homebrew/opt/openssl@3/bin/openssl',
  '/usr/local/opt/openssl@3/bin/openssl',
];

const PROBE_TIMEOUT_MS = 5000;

/**
 * Find an OpenSSL 3.x binary (not LibreSSL).
 * Returns the path or null if none found.
 */
export async function findOpenssl3(): Promise<string | null> {
  for (const candidate of OPENSSL_CANDIDATES) {
    try {
      // For absolute paths, check file exists first
      if (candidate.startsWith('/')) {
        await access(candidate, constants.X_OK);
      }

      const version = await runCommand(candidate, ['version']);
      if (version.startsWith('OpenSSL 3.')) {
        return candidate;
      }
    } catch {
      // Not found or not usable — try next
    }
  }
  return null;
}

/**
 * Probe a host via `openssl s_client` to detect the negotiated TLS group.
 * Gracefully returns nulls on any failure.
 */
export async function probeWithOpenssl(
  host: string,
  port: number,
): Promise<OpensslProbeResult> {
  const nullResult: OpensslProbeResult = { group: null, peerTempKey: null };

  if (!validateHostname(host) || !validatePort(port)) {
    return nullResult;
  }

  let opensslBin: string | null;
  try {
    opensslBin = await findOpenssl3();
  } catch {
    return nullResult;
  }

  if (!opensslBin) {
    return nullResult;
  }

  let output: string;
  try {
    output = await runCommand(opensslBin, [
      's_client',
      '-connect',
      `${host}:${port}`,
      '-servername',
      host,
    ]);
  } catch {
    return nullResult;
  }

  return parseOpensslOutput(output);
}

/**
 * Parse openssl s_client output for TLS group and key exchange info.
 */
export function parseOpensslOutput(output: string): OpensslProbeResult {
  const result: OpensslProbeResult = { group: null, peerTempKey: null };

  // Match: "Negotiated TLS1.3 group: X25519MLKEM768"
  const groupMatch = output.match(
    /Negotiated TLS[\d.]+ group:\s*(\S+)/i,
  );
  if (groupMatch) {
    result.group = groupMatch[1];
  }

  // Match: "Peer Temp Key: ECDH, X25519, 253 bits"
  // or:    "Server Temp Key: ECDH, prime256v1, 256 bits"
  const tempKeyMatch = output.match(
    /(?:Peer|Server) Temp Key:\s*(\w+),\s*([^,]+),\s*(\d+)\s*bits/i,
  );
  if (tempKeyMatch) {
    result.peerTempKey = {
      type: tempKeyMatch[1],
      name: tempKeyMatch[2].trim(),
      size: parseInt(tempKeyMatch[3], 10),
    };
  }

  return result;
}

function runCommand(bin: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);

    const child = execFile(
      bin,
      args,
      {
        timeout: PROBE_TIMEOUT_MS,
        signal: controller.signal,
      },
      (error: Error | null, stdout: string | Buffer, stderr: string | Buffer) => {
        clearTimeout(timer);
        // openssl s_client writes useful info to both stdout and stderr
        // and may exit non-zero even on success (connection closed)
        const combined = String(stdout ?? '') + '\n' + String(stderr ?? '');
        if (combined.trim().length > 0) {
          resolve(combined);
        } else if (error) {
          reject(error);
        } else {
          resolve('');
        }
      },
    );

    // Close stdin immediately so openssl doesn't hang waiting for input
    try {
      child.stdin?.end();
    } catch {
      // ignore
    }
  });
}
