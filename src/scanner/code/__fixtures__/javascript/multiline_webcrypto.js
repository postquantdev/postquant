/**
 * Fixture: WebCrypto calls split across multiple lines.
 * Regex can't match these because the pattern spans lines.
 */
const key = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt"]
);
