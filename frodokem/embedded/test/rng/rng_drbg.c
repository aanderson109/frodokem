/*
 * NIST AES-256 CTR DRBG for KAT testing
 *
 * Uses OpenSSL AES-256 ECB
 */
#include "rng_drbg.h"
#include <openssl/aes.h>
#include <string.h>

static AES256_CTR_DRBG_struct DRBG_ctx;

static void AES256_ECB(unsigned char *key, unsigned char *in,
                       unsigned char *out) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);
    AES_ecb_encrypt(in, out, &aes_key, AES_ENCRYPT);
}

void AES256_CTR_DRBG_Update(unsigned char *provided_data, unsigned char *Key,
                            unsigned char *V) {
    unsigned char temp[48];
    int i, j;
    for (i = 0; i < 3; i++) {
        // increment V
        for (j = 15; j >= 0; j--) {
            if (V[j] == 0xff)
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }
        AES256_ECB(Key, V, temp + 16 * i);
    }
    if (provided_data != NULL) {
        for (i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }
    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);
}

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength) {
    unsigned char seed_material[48];
    int i;
    (void)security_strength;
    memcpy(seed_material, entropy_input, 48);
    if (personalization_string) {
        for (i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

void randombytes(unsigned char *x, size_t xlen) {
    unsigned char block[16];
    int i = 0;
    int j;
    while (xlen > 0) {
        // increment V
        for (j = 15; j >= 0; j--) {
            if (DRBG_ctx.V[j] == 0xff) {
                DRBG_ctx.V[j] = 0x00;
            } else {
                DRBG_ctx.V[j]++;
                break;
            }
        }
        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
        if (xlen > 15) {
            memcpy(x + i, block, 16);
            i += 16;
            xlen -= 16;
        } else {
            memcpy(x + i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;
}