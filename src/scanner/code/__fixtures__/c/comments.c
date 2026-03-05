/* Test fixture: Crypto calls inside comments only — should produce 0 findings. */
#include <stdio.h>

// RSA_generate_key_ex(rsa, 2048, e, NULL)
// EC_KEY_generate_key(eckey);

/* DH_generate_key(dh); */

/*
 * MD5_Init(&ctx)
 * crypto_box_keypair(pk, sk);
 * SHA1_Init(&sha_ctx);
 */

// EVP_aes_256_gcm()
// SHA256_Init(&ctx)

int main(void) {
    /* crypto_aead_xchacha20poly1305_ietf_encrypt(...) */
    printf("No crypto here\n");
    return 0;
}
