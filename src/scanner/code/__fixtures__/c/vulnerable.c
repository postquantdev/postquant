/* Test fixture: C code with multiple quantum-vulnerable crypto calls. */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sodium.h>

int main(void) {
    /* RSA key generation */
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);

    /* EC key generation */
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(eckey);

    /* DH key exchange */
    DH *dh = DH_new();
    DH_generate_key(dh);

    /* MD5 hashing */
    MD5_CTX ctx;
    MD5_Init(&ctx);

    /* SHA-1 hashing */
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);

    /* libsodium box (Curve25519) */
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    printf("Done\n");
    return 0;
}
