/**
 * @file frodo_internal.h
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Internal Parameters & Function Declarations
 * @version 0.1
 * @date 2026-04-12
 *
 * Defines all parameters, derived size macros, and internal function
 * declarations for FrodoKEM-1344-AES.
 * 
 * @note This header should be included by all implementation files.
 * @note External consumers attempting to use the exposed API KEM
 *       functions should use frodokem.h instead, though.
 * @note Parameter values are taken from the FrodoKEM specification (2025).
 * 
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#ifndef FRODO_INTERNAL_H
#define FRODO_INTERNAL_H

#include "frodokem.h"
#include <stddef.h>
#include <stdint.h>

// FrodoKEM-1344-AES Parameters
#define FRODO_N           1344 // Matrix dimensions
#define FRODO_NBAR        8
#define FRODO_LOGQ        16
#define FRODO_Q           (1 << FRODO_LOGQ)
#define FRODO_B           4
#define FRODO_STRIPE_STEP 8
#define FRODO_D           16 // Equals log q

// Bit lengths from parameter set
#define FRODO_LENGTH_SEED_A 128
#define FRODO_LENGTH_SEC    256
#define FRODO_LENGTH_SE     512
#define FRODO_LENGTH_SALT   512
#define FRODO_L             (FRODO_B * FRODO_NBAR * FRODO_NBAR)
#define FRODO_L_BYTES       (FRODO_L / 8)

// Derived size macros
#define FRODO_SEED_A_BYTES   (FRODO_LENGTH_SEED_A / 8)     // 16 bytes
#define FRODO_SEC_BYTES      (FRODO_LENGTH_SEC / 8)        // 32 bytes
#define FRODO_SE_BYTES       (FRODO_LENGTH_SE / 8)         // 64 bytes
#define FRODO_SALT_BYTES     (FRODO_LENGTH_SALT / 8)       // 64 bytes
#define FRODO_PACKED_B_BYTES (FRODO_N * FRODO_NBAR * 2)    // 21504 bytes
#define FRODO_PACKED_C_BYTES (FRODO_NBAR * FRODO_NBAR * 2) // 128 bytes

// Public Key (pk <- Seed_A || b = 21520 bytes)
#define FRODO_PK_BYTES (FRODO_SEED_A_BYTES + FRODO_PACKED_B_BYTES)

// Secret Key (sk <- s || pk || S^T || pkh = 43088 bytes)
#define FRODO_SK_BYTES (FRODO_SEC_BYTES + FRODO_PK_BYTES + FRODO_PACKED_B_BYTES + FRODO_SEC_BYTES)

// Ciphertext (ct <- c1 || c2 || salt = 21696 bytes)
#define FRODO_CT_BYTES (FRODO_PACKED_B_BYTES + FRODO_PACKED_C_BYTES + FRODO_SALT_BYTES)

// Shared Secret (ss <- SHAKE(ct || kbar) = 32 bytes)
#define FRODO_SS_BYTES (FRODO_SEC_BYTES)

// Key Generation Randomness
#define FRODO_KEYGEN_RAND_BYTES (FRODO_SEC_BYTES + FRODO_SE_BYTES + FRODO_SEED_A_BYTES)

// Encaps Randomness
#define FRODO_ENCAP_RAND_BYTES (FRODO_SEC_BYTES + FRODO_SALT_BYTES)

// Error Distribuition
#define FRODO_D_PARAM 6 // entries in CDF table
extern const uint16_t FRODO1344_T_X[7];

// Matrix Size Aliases
#define FRODO_MATRIX_N_NBAR_SIZE    (FRODO_N * FRODO_NBAR)
#define FRODO_MATRIX_NBAR_NBAR_SIZE (FRODO_NBAR * FRODO_NBAR)

/* Internal Matrix Types */

// n x nbar matrix (S, E, B)
typedef struct {
    uint16_t data[FRODO_N * FRODO_NBAR];
} frodo_matrix_n_nbar_t;

// nbar x nbar matrix (V, C, M)
typedef struct {
    uint16_t data[FRODO_NBAR * FRODO_NBAR];
} frodo_matrix_nbar_nbar_t;

/* Function Declarations */

// matrix.c
void frodo_compute_b(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A);
void frodo_compute_out(uint16_t *out, const uint16_t *s, size_t r_rows, size_t s_cols,
                       const uint16_t *b, size_t b_cols, const uint16_t *e);
void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);
void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);
void frodo_mul_add_spa_plus_e(uint16_t *out, const uint16_t *sp, const uint16_t *e,
                              const uint8_t *seed_A);

// encode.c
void frodo_encode(uint16_t *out, const uint8_t *in);
void frodo_decode(uint8_t *out, const uint16_t *in);

// pack.c
void frodo_pack(uint8_t *out, size_t outlen, const uint16_t *in, size_t n);
void frodo_unpack(uint16_t *out, size_t n, const uint8_t *in, size_t inlen);

// sample.c
void frodo_sample_matrix(uint16_t *out, const uint16_t *r, size_t n);

// gen_A.c
void frodo_gen_A(uint16_t *out, const uint8_t *seed);
void frodo_gen_A_row(uint16_t *row, const uint8_t *seed, uint16_t i);

// util.c
void frodo_pack_le16(uint8_t *out, const uint16_t *in, size_t n);
void frodo_unpack_le16(uint16_t *out, const uint8_t *in, size_t n);
void randombytes(uint8_t *buf, size_t len);
int frodo_ct_verify(const uint8_t *a, const uint8_t *b, size_t len);
void frodo_ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len, int selector);

// hardware abstraction layer
void frodo_aes128_ecb(const uint8_t *key, const uint8_t *in, uint8_t *out);
void frodo_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

// kem.c
void frodo_keygen(uint8_t *pk, uint8_t *sk);
void frodo_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
void frodo_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif // FRODO_INTERNAL_H