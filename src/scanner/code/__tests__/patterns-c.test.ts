import { describe, it, expect } from 'vitest';
import { cPatterns } from '../patterns/c.js';
import type { CryptoPattern } from '../../../types/index.js';

const byId = (id: string): CryptoPattern => {
  const p = cPatterns.find((pat) => pat.id === id);
  if (!p) throw new Error(`Pattern not found: ${id}`);
  return p;
};

const callMatches = (p: CryptoPattern, s: string): boolean =>
  p.callPatterns.some((r) => r.test(s));

const importMatches = (p: CryptoPattern, s: string): boolean =>
  (p.importPatterns ?? []).some((r) => r.test(s));

describe('C/C++ patterns', () => {
  it('exports 18 patterns', () => {
    expect(cPatterns).toHaveLength(18);
  });

  describe.each(cPatterns)('$id', (pattern) => {
    it('has valid structure', () => {
      expect(pattern.id).toMatch(/^c-/);
      expect(pattern.language).toBe('c');
      expect(pattern.callPatterns.length).toBeGreaterThan(0);
      expect(pattern.description).toBeTruthy();
      expect(pattern.migration).toBeTruthy();
      expect(['critical', 'moderate', 'safe']).toContain(pattern.risk);
    });
  });

  // --- Call pattern match tests ---
  const matchCases: [string, string][] = [
    // OpenSSL RSA
    ['c-rsa-keygen', 'RSA_generate_key_ex(rsa, 2048, e, NULL)'],
    ['c-rsa-keygen', 'RSA_generate_key(2048, RSA_F4, NULL, NULL)'],
    ['c-rsa-keygen', 'EVP_PKEY_keygen(ctx, &pkey)'],
    ['c-rsa-keygen', 'EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)'],
    ['c-rsa-sign', 'RSA_sign(NID_sha256, digest, dlen, sig, &slen, rsa)'],
    ['c-rsa-sign', 'RSA_verify(NID_sha256, digest, dlen, sig, slen, rsa)'],
    ['c-rsa-sign', 'EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey)'],
    ['c-rsa-sign', 'EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey)'],
    ['c-rsa-sign', 'EVP_SignFinal(ctx, sig, &slen, pkey)'],
    ['c-rsa-sign', 'EVP_VerifyFinal(ctx, sig, slen, pkey)'],
    ['c-rsa-encrypt', 'RSA_public_encrypt(len, from, to, rsa, padding)'],
    ['c-rsa-encrypt', 'RSA_private_decrypt(len, from, to, rsa, padding)'],
    ['c-rsa-encrypt', 'EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen)'],
    ['c-rsa-encrypt', 'EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen)'],
    // OpenSSL EC
    ['c-ec-keygen', 'EC_KEY_generate_key(eckey)'],
    ['c-ec-keygen', 'EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)'],
    ['c-ec-keygen', 'ECDSA_sign(0, digest, dlen, sig, &slen, eckey)'],
    ['c-ec-keygen', 'ECDSA_do_sign(digest, dlen, eckey)'],
    ['c-ec-keygen', 'ECDH_compute_key(secret, slen, point, eckey, NULL)'],
    ['c-ec-keygen', 'EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)'],
    // OpenSSL DH
    ['c-dh-keygen', 'DH_generate_key(dh)'],
    ['c-dh-keygen', 'DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL)'],
    ['c-dh-keygen', 'DH_compute_key(secret, peer_pub, dh)'],
    ['c-dh-keygen', 'EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL)'],
    // OpenSSL DSA
    ['c-dsa-keygen', 'DSA_generate_key(dsa)'],
    ['c-dsa-keygen', 'DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL)'],
    ['c-dsa-keygen', 'DSA_sign(0, digest, dlen, sig, &slen, dsa)'],
    ['c-dsa-keygen', 'EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL)'],
    // OpenSSL hashes
    ['c-md5', 'MD5_Init(&ctx)'],
    ['c-md5', 'MD5_Update(&ctx, data, len)'],
    ['c-md5', 'MD5_Final(digest, &ctx)'],
    ['c-md5', 'MD5(data, len, digest)'],
    ['c-md5', 'md = EVP_md5()'],
    ['c-sha1', 'SHA1_Init(&ctx)'],
    ['c-sha1', 'SHA1_Update(&ctx, data, len)'],
    ['c-sha1', 'SHA1_Final(digest, &ctx)'],
    ['c-sha1', 'SHA1(data, len, digest)'],
    ['c-sha1', 'md = EVP_sha1()'],
    ['c-sha256', 'SHA256_Init(&ctx)'],
    ['c-sha256', 'SHA256(data, len, digest)'],
    ['c-sha256', 'SHA384(data, len, digest)'],
    ['c-sha256', 'SHA512(data, len, digest)'],
    ['c-sha256', 'md = EVP_sha256()'],
    ['c-sha256', 'md = EVP_sha384()'],
    ['c-sha256', 'md = EVP_sha512()'],
    // OpenSSL AES
    ['c-aes', 'EVP_aes_256_gcm()'],
    ['c-aes', 'EVP_aes_128_cbc()'],
    ['c-aes', 'AES_set_encrypt_key(key, 256, &aeskey)'],
    ['c-aes', 'AES_set_decrypt_key(key, 256, &aeskey)'],
    ['c-aes', 'AES_encrypt(in, out, &aeskey)'],
    ['c-aes', 'AES_cbc_encrypt(in, out, len, &aeskey, iv, AES_ENCRYPT)'],
    // libsodium box
    ['c-libsodium-box', 'crypto_box_keypair(pk, sk)'],
    ['c-libsodium-box', 'crypto_box_easy(c, m, mlen, n, pk, sk)'],
    ['c-libsodium-box', 'crypto_box_open_easy(m, c, clen, n, pk, sk)'],
    ['c-libsodium-box', 'crypto_box_seal(c, m, mlen, pk)'],
    ['c-libsodium-box', 'crypto_box_seal_open(m, c, clen, pk, sk)'],
    ['c-libsodium-box', 'crypto_scalarmult(q, n, p)'],
    ['c-libsodium-box', 'crypto_scalarmult_base(q, n)'],
    ['c-libsodium-box', 'crypto_kx_keypair(pk, sk)'],
    ['c-libsodium-box', 'crypto_kx_client_session_keys(rx, tx, cpk, csk, spk)'],
    ['c-libsodium-box', 'crypto_kx_server_session_keys(rx, tx, spk, ssk, cpk)'],
    // libsodium sign
    ['c-libsodium-sign', 'crypto_sign_keypair(pk, sk)'],
    ['c-libsodium-sign', 'crypto_sign(sm, &smlen, m, mlen, sk)'],
    ['c-libsodium-sign', 'crypto_sign_open(m, &mlen, sm, smlen, pk)'],
    ['c-libsodium-sign', 'crypto_sign_detached(sig, &siglen, m, mlen, sk)'],
    ['c-libsodium-sign', 'crypto_sign_verify_detached(sig, m, mlen, pk)'],
    ['c-libsodium-sign', 'crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk)'],
    // libsodium AEAD
    ['c-libsodium-aead', 'crypto_aead_chacha20poly1305_ietf_encrypt(c, &clen, m, mlen, ad, adlen, NULL, n, k)'],
    ['c-libsodium-aead', 'crypto_aead_xchacha20poly1305_ietf_encrypt(c, &clen, m, mlen, ad, adlen, NULL, n, k)'],
    ['c-libsodium-aead', 'crypto_aead_chacha20poly1305_ietf_decrypt(m, &mlen, NULL, c, clen, ad, adlen, n, k)'],
    ['c-libsodium-aead', 'crypto_aead_xchacha20poly1305_ietf_decrypt(m, &mlen, NULL, c, clen, ad, adlen, n, k)'],
    ['c-libsodium-aead', 'crypto_secretbox_easy(c, m, mlen, n, k)'],
    ['c-libsodium-aead', 'crypto_secretbox_open_easy(m, c, clen, n, k)'],
    // wolfSSL
    ['c-wolfssl-rsa', 'wc_RsaKeyGen(rng, &key, 2048)'],
    ['c-wolfssl-rsa', 'wc_MakeRsaKey(&key, 2048, 65537, rng)'],
    ['c-wolfssl-rsa', 'wc_RsaPublicEncrypt(in, inLen, out, outLen, &key, rng)'],
    ['c-wolfssl-rsa', 'wc_RsaPrivateDecrypt(in, inLen, out, outLen, &key)'],
    ['c-wolfssl-rsa', 'wc_RsaSSL_Sign(in, inLen, out, outLen, &key, rng)'],
    ['c-wolfssl-rsa', 'wc_RsaSSL_Verify(in, inLen, out, outLen, &key)'],
    // mbedTLS RSA
    ['c-mbedtls-rsa', 'mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537)'],
    ['c-mbedtls-rsa', 'mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, ilen, input, output)'],
    ['c-mbedtls-rsa', 'mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &olen, input, output, output_max)'],
    ['c-mbedtls-rsa', 'mbedtls_rsa_pkcs1_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 0, hash, sig)'],
    ['c-mbedtls-rsa', 'mbedtls_rsa_pkcs1_verify(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0, hash, sig)'],
    // mbedTLS EC
    ['c-mbedtls-ec', 'mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg)'],
    ['c-mbedtls-ec', 'mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, hlen, sig, &slen, mbedtls_ctr_drbg_random, &ctr_drbg)'],
    ['c-mbedtls-ec', 'mbedtls_ecdsa_read_signature(&ctx, hash, hlen, sig, slen)'],
    ['c-mbedtls-ec', 'mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg)'],
    ['c-mbedtls-ec', 'mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &ctr_drbg)'],
  ];

  it.each(matchCases)('%s matches: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(true);
  });

  // --- Non-match tests ---
  const noMatchCases: [string, string][] = [
    ['c-rsa-keygen', 'printf("hello world")'],
    ['c-md5', 'SHA256_Init(&ctx)'],
    ['c-sha256', 'MD5_Init(&ctx)'],
    ['c-aes', 'RSA_generate_key_ex(rsa, 2048, e, NULL)'],
    ['c-libsodium-box', 'crypto_sign_keypair(pk, sk)'],
    ['c-libsodium-sign', 'crypto_box_keypair(pk, sk)'],
  ];

  it.each(noMatchCases)('%s does NOT match: %s', (id, code) => {
    expect(callMatches(byId(id), code)).toBe(false);
  });

  // --- Import pattern tests ---
  const importCases: [string, string][] = [
    ['c-rsa-keygen', '#include <openssl/rsa.h>'],
    ['c-rsa-keygen', '#include <openssl/evp.h>'],
    ['c-ec-keygen', '#include <openssl/ec.h>'],
    ['c-ec-keygen', '#include <openssl/ecdsa.h>'],
    ['c-dh-keygen', '#include <openssl/dh.h>'],
    ['c-dsa-keygen', '#include <openssl/dsa.h>'],
    ['c-md5', '#include <openssl/md5.h>'],
    ['c-sha1', '#include <openssl/sha.h>'],
    ['c-libsodium-box', '#include <sodium.h>'],
    ['c-libsodium-sign', '#include <sodium.h>'],
    ['c-libsodium-aead', '#include <sodium.h>'],
    ['c-wolfssl-rsa', '#include <wolfssl/wolfcrypt/rsa.h>'],
    ['c-mbedtls-rsa', '#include <mbedtls/rsa.h>'],
    ['c-mbedtls-ec', '#include <mbedtls/ecdsa.h>'],
    ['c-mbedtls-ec', '#include <mbedtls/ecp.h>'],
  ];

  it.each(importCases)('%s import matches: %s', (id, importLine) => {
    expect(importMatches(byId(id), importLine)).toBe(true);
  });

  // --- Risk level validation ---
  it('all asymmetric/signature/exchange patterns are critical', () => {
    const critical = cPatterns.filter(
      (p) =>
        p.category === 'asymmetric-encryption' ||
        p.category === 'digital-signature' ||
        p.category === 'key-exchange',
    );
    critical.forEach((p) => expect(p.risk).toBe('critical'));
  });

  it('sha256 is safe', () => {
    expect(byId('c-sha256').risk).toBe('safe');
  });

  it('aes default risk is moderate', () => {
    expect(byId('c-aes').risk).toBe('moderate');
  });

  it('all non-PQC patterns have medium confidence', () => {
    cPatterns
      .filter((p) => p.category !== 'pqc-algorithm')
      .forEach((p) => expect(p.confidence).toBe('medium'));
  });

  describe('c-aes key-size risk', () => {
    const aes = byId('c-aes');

    it('has a keySizeExtractor', () => {
      expect(aes.keySizeExtractor).toBeDefined();
    });

    it('has a keySizeRisk function', () => {
      expect(aes.keySizeRisk).toBeDefined();
    });

    it('extracts key size from EVP_aes_256_gcm()', () => {
      const match = aes.keySizeExtractor!.exec('EVP_aes_256_gcm()');
      expect(match).not.toBeNull();
      const size = parseInt(match![1], 10);
      expect(size).toBe(256);
    });

    it('extracts key size from EVP_aes_128_cbc()', () => {
      const match = aes.keySizeExtractor!.exec('EVP_aes_128_cbc()');
      expect(match).not.toBeNull();
      const size = parseInt(match![1], 10);
      expect(size).toBe(128);
    });

    it('classifies AES-256 as safe', () => {
      expect(aes.keySizeRisk!(256)).toBe('safe');
    });

    it('classifies AES-128 as moderate', () => {
      expect(aes.keySizeRisk!(128)).toBe('moderate');
    });

    it('classifies AES-192 as moderate', () => {
      expect(aes.keySizeRisk!(192)).toBe('moderate');
    });
  });

  describe('PQC patterns', () => {
    it('c-pqc-oqs-kem matches liboqs KEM calls', () => {
      const p = byId('c-pqc-oqs-kem');
      expect(callMatches(p, 'OQS_KEM_new("ML-KEM-768")')).toBe(true);
      expect(callMatches(p, 'OQS_KEM_keypair(kem, pk, sk)')).toBe(true);
      expect(callMatches(p, 'OQS_KEM_encaps(kem, ct, ss, pk)')).toBe(true);
      expect(callMatches(p, 'OQS_KEM_decaps(kem, ss, ct, sk)')).toBe(true);
    });

    it('c-pqc-oqs-kem import matches', () => {
      const p = byId('c-pqc-oqs-kem');
      expect(importMatches(p, '#include <oqs/oqs.h>')).toBe(true);
      expect(importMatches(p, '#include "oqs/oqs.h"')).toBe(true);
    });

    it('c-pqc-oqs-sig matches liboqs SIG calls', () => {
      const p = byId('c-pqc-oqs-sig');
      expect(callMatches(p, 'OQS_SIG_new("ML-DSA-65")')).toBe(true);
      expect(callMatches(p, 'OQS_SIG_sign(sig, signature, &sig_len, message, msg_len, sk)')).toBe(true);
      expect(callMatches(p, 'OQS_SIG_verify(sig, message, msg_len, signature, sig_len, pk)')).toBe(true);
    });

    it('c-pqc-oqs-sig import matches', () => {
      const p = byId('c-pqc-oqs-sig');
      expect(importMatches(p, '#include <oqs/oqs.h>')).toBe(true);
      expect(importMatches(p, '#include "oqs/oqs.h"')).toBe(true);
    });

    it('all PQC patterns are safe with high confidence', () => {
      const pqc = cPatterns.filter((p) => p.category === 'pqc-algorithm');
      expect(pqc).toHaveLength(2);
      pqc.forEach((p) => {
        expect(p.risk).toBe('safe');
        expect(p.confidence).toBe('high');
      });
    });
  });
});
