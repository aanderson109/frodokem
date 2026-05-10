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
#define FRODO_PUBLICKEYBYTES  21520
#define FRODO_SECRETKEYBYTES  43088
#define FRODO_CIPHERTEXTBYTES 21696
#define FRODO_BYTES           32
#define FRODO_ALGNAME         "FrodoKEM-1344-AES"

/* Public API */
/**
 * @brief Generates a FrodoKEM-1344-AES keypair.
 * 
 * @param[out] pk Output public key
 * @param[out] sk Output secret key
 * @return        FRODO_SUCCESS (0) on success
 * 
 * @note Public key layout: seed_A || packed_B
 * @note Secret key layout: s || pk || encoded_ST || pkh
 * 
 * @see frodo_encaps
 * @see frodo_decaps
 */
int frodo_keygen(uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate a shared secret using a public key.
 * 
 * @param[out] ct Output ciphertext
 * @param[out] ss Output shared secret
 * @param[in]  pk Input public key
 * @return        0 on success
 */
int frodo_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate a ciphertext to recover the shared secret.
 * 
 * @param[out] ss Output shared secret
 * @param[in]  ct Input ciphertext
 * @param[in]  sk Input secret key
 * @return        0 on success
 */
int frodo_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif // FRODOKEM_H