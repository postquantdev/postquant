/**
 * Test fixture: Crypto mentions only in comments — no real calls.
 * crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
 * crypto.createHash('md5')
 */

// crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
// crypto.createHash('md5')

const message = "Use crypto.generateKeyPairSync('rsa') for RSA keys";
const another = "crypto.createHash('md5') is insecure";

function noCrypto() {
  return "hello";
}
