/**
 * Characters that must never appear in a hostname.
 * Covers shell metacharacters, whitespace, and null bytes.
 */
const HOSTNAME_DENY_RE = /[\s\0;`$|&<>(){}\[\]!#'"\\]/;
/** Same deny list but without brackets — used for IPv6 inner content. */
const IPV6_INNER_DENY_RE = /[\s\0;`$|&<>(){}!#'"\\]/;

/**
 * Validate a hostname for safety.
 * Not full DNS validation — rejects obviously malicious input.
 */
export function validateHostname(hostname: string): boolean {
  if (hostname.length === 0 || hostname.length > 253) return false;
  // Handle bracketed IPv6 before the general deny regex (which includes brackets)
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    const inner = hostname.slice(1, -1);
    if (inner.length === 0) return false;
    return !IPV6_INNER_DENY_RE.test(inner);
  }
  if (HOSTNAME_DENY_RE.test(hostname)) return false;
  return true;
}

/** Validate a port number. Must be an integer 1–65535. */
export function validatePort(port: number): boolean {
  if (!Number.isInteger(port)) return false;
  return port >= 1 && port <= 65535;
}

/** Validate a file path. Only rejects null bytes — fs errors handle the rest. */
export function validateFilePath(filePath: string): boolean {
  if (filePath.length === 0) return false;
  if (filePath.includes('\0')) return false;
  return true;
}
