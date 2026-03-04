import type {
  TlsScanResult,
  ClassifiedFinding,
  ClassifiedResult,
} from '../types/index.js';

export function classify(scan: TlsScanResult): ClassifiedResult {
  return {
    host: scan.host,
    port: scan.port,
    findings: [
      classifyProtocol(scan),
      classifyCertificate(scan),
      classifyKeyExchange(scan),
      classifyCipher(scan),
      classifyHash(scan),
    ],
  };
}

function classifyProtocol(scan: TlsScanResult): ClassifiedFinding {
  const protocol = scan.protocol ?? '';

  if (protocol === 'TLSv1.3') {
    return {
      component: 'protocol',
      algorithm: 'TLS 1.3',
      risk: 'safe',
      reason: 'Current protocol version',
    };
  }

  if (protocol === 'TLSv1.2') {
    return {
      component: 'protocol',
      algorithm: 'TLS 1.2',
      risk: 'moderate',
      reason: 'Aging protocol, still functional',
      migration: 'Upgrade to TLS 1.3',
    };
  }

  const version = protocol || 'Unknown';
  return {
    component: 'protocol',
    algorithm: version,
    risk: 'critical',
    reason: 'Legacy protocol, already insecure',
    migration: 'Upgrade to TLS 1.3 immediately',
  };
}

function classifyCertificate(scan: TlsScanResult): ClassifiedFinding {
  if (!scan.certificate) {
    return {
      component: 'certificate',
      algorithm: 'Unknown',
      risk: 'critical',
      reason: 'Unknown algorithm — assumed vulnerable',
      migration: 'ML-DSA (FIPS 204)',
    };
  }

  const algo = scan.certificate.publicKeyAlgorithm.toUpperCase();
  const keySize = scan.certificate.publicKeySize;

  const pqcAlgos = ['ML-DSA', 'ML-KEM', 'SLH-DSA', 'HQC'];
  if (pqcAlgos.some((pqc) => algo.includes(pqc.toUpperCase()))) {
    return {
      component: 'certificate',
      algorithm: scan.certificate.publicKeyAlgorithm,
      keySize,
      risk: 'safe',
      reason: 'NIST post-quantum standard',
    };
  }

  const classicalAlgos = ['RSA', 'EC', 'ECDSA', 'ED25519', 'ED448', 'DSA', 'DH'];
  if (classicalAlgos.some((ca) => algo.includes(ca))) {
    return {
      component: 'certificate',
      algorithm: scan.certificate.publicKeyAlgorithm,
      keySize,
      curve: scan.certificate.curve,
      risk: 'critical',
      reason: "Vulnerable to Shor's algorithm",
      migration: 'ML-DSA (FIPS 204)',
    };
  }

  return {
    component: 'certificate',
    algorithm: scan.certificate.publicKeyAlgorithm,
    keySize,
    risk: 'critical',
    reason: 'Unknown algorithm — assumed vulnerable',
    migration: 'ML-DSA (FIPS 204)',
  };
}

function isPqcKeyExchange(scan: TlsScanResult): boolean {
  const ephName = scan.ephemeralKeyInfo?.name?.toUpperCase() ?? '';
  const cipherName = scan.cipher?.name?.toUpperCase() ?? '';

  const pqcPatterns = ['KYBER', 'MLKEM', 'ML-KEM', 'X25519MLKEM'];
  return pqcPatterns.some(
    (p) => ephName.includes(p) || cipherName.includes(p),
  );
}

function classifyKeyExchange(scan: TlsScanResult): ClassifiedFinding {
  if (isPqcKeyExchange(scan)) {
    const name = scan.ephemeralKeyInfo?.name ?? 'PQC hybrid';
    return {
      component: 'keyExchange',
      algorithm: name,
      risk: 'safe',
      reason: 'Post-quantum hybrid key exchange',
    };
  }

  if (!scan.ephemeralKeyInfo) {
    const cipherName = scan.cipher?.name?.toUpperCase() ?? '';

    // TLS 1.2 cipher names include key exchange (e.g., ECDHE-RSA-AES256-GCM-SHA384)
    if (cipherName.includes('ECDHE') || cipherName.includes('X25519')) {
      return {
        component: 'keyExchange',
        algorithm: 'ECDHE (inferred)',
        risk: 'critical',
        reason: "Vulnerable to Shor's algorithm",
        migration: 'ML-KEM (FIPS 203) hybrid key exchange',
      };
    }

    if (cipherName.includes('DHE')) {
      return {
        component: 'keyExchange',
        algorithm: 'DHE (inferred)',
        risk: 'critical',
        reason: "Vulnerable to Shor's algorithm",
        migration: 'ML-KEM (FIPS 203) hybrid key exchange',
      };
    }

    // TLS 1.3 always uses ephemeral key exchange (typically X25519 or ECDHE P-256)
    // but cipher names don't include it — infer from protocol
    if (scan.protocol === 'TLSv1.3') {
      return {
        component: 'keyExchange',
        algorithm: 'X25519 (inferred)',
        risk: 'critical',
        reason: "Vulnerable to Shor's algorithm (TLS 1.3 uses ephemeral ECDHE)",
        migration: 'ML-KEM (FIPS 203) hybrid key exchange',
      };
    }

    return {
      component: 'keyExchange',
      algorithm: 'Unknown',
      risk: 'critical',
      reason: 'Unknown key exchange — assumed vulnerable',
      migration: 'ML-KEM (FIPS 203) hybrid key exchange',
    };
  }

  const type = scan.ephemeralKeyInfo.type.toUpperCase();
  const name = scan.ephemeralKeyInfo.name ?? scan.ephemeralKeyInfo.type;

  if (type === 'ECDH' || type === 'DH') {
    return {
      component: 'keyExchange',
      algorithm: name,
      keySize: scan.ephemeralKeyInfo.size,
      risk: 'critical',
      reason: "Vulnerable to Shor's algorithm",
      migration: 'ML-KEM (FIPS 203) hybrid key exchange',
    };
  }

  return {
    component: 'keyExchange',
    algorithm: name,
    keySize: scan.ephemeralKeyInfo.size,
    risk: 'critical',
    reason: 'Unknown key exchange — assumed vulnerable',
    migration: 'ML-KEM (FIPS 203) hybrid key exchange',
  };
}

function classifyCipher(scan: TlsScanResult): ClassifiedFinding {
  if (!scan.cipher) {
    return {
      component: 'cipher',
      algorithm: 'Unknown',
      risk: 'critical',
      reason: 'Unknown cipher — assumed vulnerable',
      migration: 'Use AES-256-GCM or ChaCha20-Poly1305',
    };
  }

  const name = scan.cipher.name.toUpperCase();
  const bits = scan.cipher.bits;

  if (name.includes('CHACHA20')) {
    return {
      component: 'cipher',
      algorithm: 'ChaCha20-Poly1305',
      keySize: 256,
      risk: 'safe',
      reason: 'Quantum-resistant symmetric cipher',
    };
  }

  if (name.includes('AES')) {
    if (bits >= 256) {
      return {
        component: 'cipher',
        algorithm: `AES-${bits}`,
        keySize: bits,
        risk: 'safe',
        reason: 'Quantum-resistant at current key size',
      };
    }

    return {
      component: 'cipher',
      algorithm: `AES-${bits}`,
      keySize: bits,
      risk: 'moderate',
      reason: "Grover's algorithm reduces to 64-bit effective security",
      migration: 'Upgrade to AES-256',
    };
  }

  return {
    component: 'cipher',
    algorithm: scan.cipher.name,
    keySize: bits,
    risk: 'critical',
    reason: 'Unknown cipher — assumed vulnerable',
    migration: 'Use AES-256-GCM or ChaCha20-Poly1305',
  };
}

function extractHash(scan: TlsScanResult): string {
  const name = scan.cipher?.name?.toUpperCase() ?? '';
  const standardName = scan.cipher?.standardName?.toUpperCase() ?? '';

  // Check cipher name first (primary source)
  if (name.includes('SHA384') || name.includes('SHA_384')) return 'SHA-384';
  if (name.includes('SHA512') || name.includes('SHA_512')) return 'SHA-512';
  if (name.includes('SHA256') || name.includes('SHA_256')) return 'SHA-256';
  if (name.endsWith('-SHA') || name.endsWith('_SHA')) return 'SHA-1';
  if (name.includes('MD5')) return 'MD5';

  // Fallback to standardName
  if (standardName.includes('SHA384') || standardName.includes('SHA_384')) return 'SHA-384';
  if (standardName.includes('SHA512') || standardName.includes('SHA_512')) return 'SHA-512';
  if (standardName.includes('SHA256') || standardName.includes('SHA_256')) return 'SHA-256';
  if (standardName.endsWith('_SHA')) return 'SHA-1';
  if (standardName.includes('MD5')) return 'MD5';

  return 'Unknown';
}

function classifyHash(scan: TlsScanResult): ClassifiedFinding {
  const hash = extractHash(scan);

  if (hash === 'SHA-384' || hash === 'SHA-512') {
    return {
      component: 'hash',
      algorithm: hash,
      risk: 'safe',
      reason: 'Sufficient post-quantum security margin',
    };
  }

  if (hash === 'SHA-256') {
    return {
      component: 'hash',
      algorithm: hash,
      risk: 'moderate',
      reason: "Grover's reduces to 128-bit effective (still acceptable)",
      migration: 'Consider upgrading to SHA-384',
    };
  }

  if (hash === 'SHA-1') {
    return {
      component: 'hash',
      algorithm: hash,
      risk: 'critical',
      reason: 'Already broken — not quantum-specific',
      migration: 'Upgrade to SHA-256 or SHA-384 immediately',
    };
  }

  if (hash === 'MD5') {
    return {
      component: 'hash',
      algorithm: hash,
      risk: 'critical',
      reason: 'Already broken — not quantum-specific',
      migration: 'Upgrade to SHA-256 or SHA-384 immediately',
    };
  }

  return {
    component: 'hash',
    algorithm: hash,
    risk: 'critical',
    reason: 'Unknown hash — assumed vulnerable',
    migration: 'Use SHA-384 or SHA-512',
  };
}
