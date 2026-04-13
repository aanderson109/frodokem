/**
 * @file frodokem.h
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Public API
 * @version 0.1
 * @date 2026-04-12
 *
 * Public-facing header for FrodoKEM-1344-AES.
 * 
 * @note This is the only header external consumers should include
 *       in their projects.
 * 
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#ifndef FRODOKEM_H
#define FRODOKEM_H

#include <stddef.h>
#include <stdint.h>

/* FrodoKEM-1344-AES Parameter Sizes */
#define CRYPTO_PUBLICKEYBYTES  21520
#define CRYPTO_SECRETKEYBYTES  43088
#define CRYPTO_CIPHERTEXTBYTES 21696
#define CRYPTO_BYTES           32
#define CRYPTO_ALGNAME         "FrodoKEM-1344-AES"

/* Public API */
/**
 * @brief Generates a FrodoKEM-1344-AES keypair.
 * 
 * @param[out] pk Output public key (CRYPTO_PUBLICKEYBYTES bytes)
 * @param[out] sk Output secret key (CRYPTO_SECRETKEYBYTES bytes)
 * @return        0 on success
 */
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate a shared secret using a public key.
 * 
 * @param[out] ct Output ciphertext (CRYPTO_CIPHERTEXTBYTES bytes)
 * @param[out] ss Output shared secret (CRYPTO_BYTES bytes)
 * @param[in]  pk Input public key (CRYPTO_PUBLICKEYBYTES bytes)
 * @return        0 on success
 */
int crypto_kem_encap(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate a ciphertext to recover the shared secret.
 * 
 * @param[out] ss Output shared secret (CRYPTO_BYTES bytes)
 * @param[in]  ct Input ciphertext (CRYPTO_CIPHERTEXTBYTES bytes)
 * @param[in]  sk Input secret key (CRYPTO_SECRETKEYBYTES bytes)
 * @return        0 on success
 */
int crypto_kem_decap(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif // FRODOKEM_H