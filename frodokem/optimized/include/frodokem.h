#ifndef FRODOKEM_H
#define FRODOKEM_H

#include <stddef.h>
#include <stdint.h>

/* FrodoKEM-1344-AES Parameter Sizes */
#define CRYPTO_PUBLICKEYBYTES  21520
#define CRYPTO_SECRETKEYBYTES  43088
#define CRYPTO_CIPHERTEXTBYTES 21632
#define CRYPTO_BYTES           32
#define CRYPTO_ALGNAME         "FrodoKEM-1344-AES"

/* Public API */
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int crypto_kem_encap(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int crypto_kem_decap(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif