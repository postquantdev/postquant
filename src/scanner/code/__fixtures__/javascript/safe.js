/**
 * Test fixture: JavaScript code with quantum-safe cryptography.
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// AES-256 (SAFE)
const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv);

// SHA-256 (SAFE)
const hash = crypto.createHash('sha256');

// SHA-384 (SAFE)
const hash384 = crypto.createHash('sha384');

// HMAC-SHA256 (SAFE)
const hmac = crypto.createHmac('sha256', secret);

// JWT with HMAC (SAFE - symmetric)
const token = jwt.sign({ sub: '1234' }, 'shared-secret', { algorithm: 'HS256' });
