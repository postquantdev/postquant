import type { ASTPattern } from './types.js';

/** Generic query matching obj.method(...) calls */
const METHOD_CALL_QUERY = `
  (call
    function: (attribute
      object: (identifier) @obj
      attribute: (identifier) @method)
    arguments: (argument_list) @args)
`;

export const pythonASTPatterns: ASTPattern[] = [
  {
    id: 'python-rsa-keygen',
    language: 'python',
    category: 'asymmetric-encryption',
    algorithm: 'RSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric', symbol: 'rsa', allowAlias: true },
    ],
    methodNames: ['generate_private_key'],
    description: "RSA key generation is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for encryption or ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'python-rsa-sign',
    language: 'python',
    category: 'digital-signature',
    algorithm: 'RSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'Crypto.PublicKey', symbol: 'RSA', allowAlias: true },
    ],
    methodNames: ['generate'],
    description: "RSA key generation (PyCryptodome) is vulnerable to quantum attacks",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'python-ec-keygen',
    language: 'python',
    category: 'asymmetric-encryption',
    algorithm: 'ECDSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric', symbol: 'ec', allowAlias: true },
    ],
    methodNames: ['generate_private_key'],
    description: "Elliptic curve key generation is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'python-ecdsa-sign',
    language: 'python',
    category: 'digital-signature',
    algorithm: 'ECDSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'Crypto.PublicKey', symbol: 'ECC', allowAlias: true },
    ],
    methodNames: ['generate'],
    description: "ECC key generation (PyCryptodome) is vulnerable to quantum attacks",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'python-ed25519',
    language: 'python',
    category: 'digital-signature',
    algorithm: 'Ed25519',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric.ed25519', symbol: 'Ed25519PrivateKey', allowAlias: true },
    ],
    methodNames: ['generate'],
    description: "Ed25519 is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'python-x25519',
    language: 'python',
    category: 'key-exchange',
    algorithm: 'X25519',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric.x25519', symbol: 'X25519PrivateKey', allowAlias: true },
    ],
    methodNames: ['generate'],
    description: "X25519 key exchange is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'python-dsa-keygen',
    language: 'python',
    category: 'digital-signature',
    algorithm: 'DSA',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric', symbol: 'dsa', allowAlias: true },
    ],
    methodNames: ['generate_private_key'],
    description: "DSA key generation is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-DSA (FIPS 204) for signatures',
  },
  {
    id: 'python-dh-keygen',
    language: 'python',
    category: 'key-exchange',
    algorithm: 'DH',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'cryptography.hazmat.primitives.asymmetric', symbol: 'dh', allowAlias: true },
    ],
    methodNames: ['generate_parameters'],
    description: "Diffie-Hellman key exchange is vulnerable to quantum attacks via Shor's algorithm",
    migration: 'Migrate to ML-KEM (FIPS 203) for key exchange',
  },
  {
    id: 'python-md5',
    language: 'python',
    category: 'weak-hash',
    algorithm: 'MD5',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'hashlib', allowAlias: true },
    ],
    methodNames: ['md5'],
    description: 'MD5 is cryptographically broken and unsuitable for any security use',
    migration: 'Migrate to SHA-256 or SHA-3 for hashing',
  },
  {
    id: 'python-sha1',
    language: 'python',
    category: 'weak-hash',
    algorithm: 'SHA-1',
    risk: 'critical',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'hashlib', allowAlias: true },
    ],
    methodNames: ['sha1'],
    description: 'SHA-1 is cryptographically broken with practical collision attacks',
    migration: 'Migrate to SHA-256 or SHA-3 for hashing',
  },
  {
    id: 'python-sha256',
    language: 'python',
    category: 'safe-hash',
    algorithm: 'SHA-256',
    risk: 'moderate',
    query: METHOD_CALL_QUERY,
    requiredImports: [
      { module: 'hashlib', allowAlias: true },
    ],
    methodNames: ['sha256'],
    description: "SHA-256 has reduced security margin under Grover's algorithm (128-bit effective)",
    migration: 'Consider SHA-384 or SHA-512 for larger post-quantum security margin',
  },
];
