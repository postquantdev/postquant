import type { ASTPattern } from './types.js';

/** Generic query matching obj.method(...) calls in JS/TS */
const METHOD_CALL_QUERY = `
  (call_expression
    function: (member_expression
      object: (identifier) @obj
      property: (property_identifier) @method)
    arguments: (arguments) @args)
`;

export const javascriptASTPatterns: ASTPattern[] = [
  {
    id: 'js-rsa-keygen',
    language: 'javascript',
    category: 'asymmetric-encryption',
    algorithm: 'RSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['generateKeyPairSync', 'generateKeyPair'],
    firstArgPattern: /['"]rsa['"]/i,
    description: "RSA key generation is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'js-ec-keygen',
    language: 'javascript',
    category: 'asymmetric-encryption',
    algorithm: 'ECDSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['generateKeyPairSync', 'generateKeyPair'],
    firstArgPattern: /['"]ec['"]/i,
    description: "EC key generation is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'js-dh-exchange',
    language: 'javascript',
    category: 'key-exchange',
    algorithm: 'DH',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['createDiffieHellman'],
    description: "Diffie-Hellman key exchange is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'js-ecdh-exchange',
    language: 'javascript',
    category: 'key-exchange',
    algorithm: 'ECDH',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['createECDH'],
    description: "ECDH key exchange is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'js-md5-hash',
    language: 'javascript',
    category: 'weak-hash',
    algorithm: 'MD5',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['createHash'],
    firstArgPattern: /['"]md5['"]/i,
    description: 'MD5 is cryptographically broken and unsuitable for any security use',
    migration: 'Migrate to SHA-256 or SHA-3 for hashing',
  },
  {
    id: 'js-sha1-hash',
    language: 'javascript',
    category: 'weak-hash',
    algorithm: 'SHA-1',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'crypto', allowAlias: true },
    ],
    methodNames: ['createHash'],
    firstArgPattern: /['"]sha-?1['"]/i,
    description: 'SHA-1 is cryptographically broken with practical collision attacks',
    migration: 'Migrate to SHA-256 or SHA-3 for hashing',
  },
  {
    id: 'js-jwt-sign',
    language: 'javascript',
    category: 'digital-signature',
    algorithm: 'RSA/ECDSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'jsonwebtoken', allowAlias: true },
    ],
    methodNames: ['sign'],
    description: 'JWT signing with RSA/ECDSA algorithms is vulnerable to quantum attacks',
    migration: 'Migrate to post-quantum JWT algorithms when standardized',
  },
];
