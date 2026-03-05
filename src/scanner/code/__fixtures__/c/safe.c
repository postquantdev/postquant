/* Test fixture: C code with only quantum-safe crypto calls. */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sodium.h>

int main(void) {
    /* AES-256-GCM (safe symmetric) */
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();

    /* SHA-256 (safe hash) */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    /* libsodium AEAD ChaCha20-Poly1305 (safe symmetric) */
    unsigned char ciphertext[128];
    unsigned long long ciphertext_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
        NULL, 0, NULL, 0, NULL, NULL, NULL);

    printf("Done\n");
    return 0;
}
