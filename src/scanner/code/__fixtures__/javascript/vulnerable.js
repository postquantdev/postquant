/**
 * Test fixture: JavaScript code with quantum-vulnerable cryptography.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// RSA key generation (CRITICAL)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// EC key generation (CRITICAL)
const ecKeys = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',
});

// Ed25519 (CRITICAL)
const edKeys = crypto.generateKeyPairSync('ed25519');

// X25519 key exchange (CRITICAL)
const x25519Keys = crypto.generateKeyPairSync('x25519');

// ECDH (CRITICAL)
const ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();

// DH (CRITICAL)
const dh = crypto.createDiffieHellman(2048);

// MD5 hash (CRITICAL)
const md5 = crypto.createHash('md5');

// SHA-1 hash (CRITICAL)
const sha1 = crypto.createHash('sha1');

// AES-128 cipher (MODERATE)
const cipher128 = crypto.createCipheriv('aes-128-gcm', key16, iv);

// JWT with RSA (CRITICAL)
const token = jwt.sign({ sub: '1234' }, privateKey, { algorithm: 'RS256' });

// JWT with ECDSA (CRITICAL)
const ecToken = jwt.sign({ sub: '1234' }, ecPrivateKey, { algorithm: 'ES256' });
