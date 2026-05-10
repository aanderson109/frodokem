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
#include "hal.h"
#include <stddef.h>
#include <stdint.h>
#include "frodo_config.h"


//////////////////////////////////
//       PARAMETER MACROS       //
//////////////////////////////////
/**
 * @defgroup frodo1344_params FrodoKEM-1344-AES Parameters
 * @brief Core algorithm parameters from the FrodoKEM 2025 specification
 * @{
 */

/**
 * @def FRODO_N
 * @brief Matrix dimension (n = 1344)
 */
#define FRODO_N 1344

/**
 * @def FRODO_NBAR
 * @brief Matrix dimension (nbar = 8)
 */
#define FRODO_NBAR 8

/**
 * @def FRODO_D
 * @brief Bit width of matrix entries (D = 16 bits)
 */
#define FRODO_D 16

/**
 * @def FRODO_Q
 * @brief Modulus (q = 2^D = 2^16 = 65,536)
 */
#define FRODO_Q (1 << FRODO_D)

/**
 * @def FRODO_B
 * @brief Bits extracted per matrix entry during encode/decode
 */
#define FRODO_B 4

/**
 * @def FRODO_STRIPE_STEP
 * @brief Row stride used during streaming generation of public matrix
 */
#define FRODO_STRIPE_STEP 8

/** @} */ // end frodo1344_params


//////////////////////////////////
//      BIT LENGTH MACROS       //
//////////////////////////////////
/**
 * @defgroup frodo1344_bit_lengths FrodoKEM-1344-AES Bit Lengths
 * @brief Bit length constants for important values
 * @{
 */

/**
 * @def FRODO_LENGTH_SEED_A
 * @brief Bit length of seed_A (128 bits)
 */
#define FRODO_LENGTH_SEED_A 128

/**
 * @def FRODO_LENGTH_SEC
 * @brief Bit length of secret seed s (256 bits)
 */
#define FRODO_LENGTH_SEC 256

/**
 * @def FRODO_LENGTH_SE
 * @brief Bit length of seed_SE (512 bits)
 */
#define FRODO_LENGTH_SE 512

/**
 * @def FRODO_LENGTH_SALT
 * @brief Bit length of salt (512 bits)
 */
#define FRODO_LENGTH_SALT 512

/**
 * @def FRODO_L
 * @brief Bit length of encoded plaintext message
 * @par Derivation: B * nbar * nbar = 4 * 8 * 8 = 256 bits
 */
#define FRODO_L (FRODO_B * FRODO_NBAR * FRODO_NBAR)

/** @} */ // end frodo1344_bit_lengths


//////////////////////////////////
//    DERIVED SIZE MACROS       //
//////////////////////////////////
/**
 * @defgroup frodo1344_size_macros FrodoKEM-1344-AES Derived Size Macros
 * @brief Byte-length constants derived from core parameters
 * @{
 */

/**
 * @def FRODO_SEED_A_BYTES
 * @brief Byte length of seed_A
 * @par Derivation: FRODO_LENGTH_SEED_A / 8 = 16 bytes
 */
#define FRODO_SEED_A_BYTES (FRODO_LENGTH_SEED_A / 8)

/**
 * @def FRODO_SEC_BYTES
 * @brief Byte length of secret seed s
 * @par Derivation: FRODO_LENGTH_SEC / 8 = 32 bytes
 */
#define FRODO_SEC_BYTES (FRODO_LENGTH_SEC / 8)

/**
 * @def FRODO_SE_BYTES
 * @brief Byte length of seed_SE randomness
 * @par Derivation: FRODO_LENGTH_SE / 8 = 64 bytes
 */
#define FRODO_SE_BYTES (FRODO_LENGTH_SE / 8)

/**
 * @def FRODO_SALT_BYTES
 * @brief Byte length of salt
 * @par Derivation: FRODO_LENGTH_SALT / 8 = 64 bytes
 */
#define FRODO_SALT_BYTES (FRODO_LENGTH_SALT / 8)

/**
 * @def FRODO_PACKED_B_BYTES
 * @brief Byte length of packed matrix B
 * @par Derivation: n * nbar * 2 = 1344 * 8 * 2 = 21,504 bytes
 */
#define FRODO_PACKED_B_BYTES (FRODO_N * FRODO_NBAR * 2)

/**
 * @def FRODO_PACKED_C_BYTES
 * @brief Byte length of packed matrix C
 * @par Derivation: nbar * nbar * 2 = 8 * 8 * 2 = 128 bytes
 */
#define FRODO_PACKED_C_BYTES (FRODO_NBAR * FRODO_NBAR * 2)

/**
 * @def FRODO_L_BYTES
 * @brief Byte length of encoded plaintext message
 * @par Derivation: FRODO_L / 8 = 32 bytes
 */
#define FRODO_L_BYTES (FRODO_L / 8)

/**
 * @def FRODO_ENCODED_ST_BYTES
 * @brief Byte length of encoded S^T matrix
 * @par Derivation: nbar * n * 2 = 8 * 1344 * 2 = 21,504 bytes
 * 
 */
#define FRODO_ENCODED_ST_BYTES (FRODO_NBAR * FRODO_N * 2)

/**
 * @def FRODO_C1_BYTES
 * @brief Byte length of ciphertext component c1
 */
#define FRODO_C1_BYTES FRODO_PACKED_B_BYTES

/**
 * @def FRODO_C2_BYTES
 * @brief Byte length of ciphertext component c2
 */
#define FRODO_C2_BYTES FRODO_PACKED_C_BYTES

/**
 * @def FRODO_K_BYTES
 * @brief Byte length of intermediate value k
 */
#define FRODO_K_BYTES (FRODO_SE_BYTES + FRODO_SEC_BYTES)

/** @} */ // end frodo1344_size_macros


//////////////////////////////////
// KEY & CIPHERTEXT SIZE MACROS //
//////////////////////////////////
/**
 * @defgroup frodo1344_key_sizes FrodoKEM-1344-AES Key & Ciphertext Sizes
 * @brief Byte-length macros for public API types
 * @{
 */

 /**
  * @def FRODO_PKH_BYTES
  * @brief Public key hash size in bytes (32 bytes)
  */
#define FRODO_PKH_BYTES FRODO_SEC_BYTES

/**
 * @def FRODO_PK_BYTES
 * @brief Public key size in bytes (21,520 bytes)
 * 
 * Computed as: pk <- Seed_A || b
 */
#define FRODO_PK_BYTES (FRODO_SEED_A_BYTES + FRODO_PACKED_B_BYTES)

/**
 * @def FRODO_SK_BYTES
 * @brief Secret key size in bytes (43,088 bytes)
 * 
 * Computed as: sk <- seed s || pk || S^T || pkh
 */
#define FRODO_SK_BYTES (FRODO_SEC_BYTES + FRODO_PK_BYTES + FRODO_PACKED_B_BYTES + FRODO_SEC_BYTES)

/**
 * @def FRODO_SS_BYTES
 * @brief Shared secret size in bytes (32 bytes)
 * 
 * Computed as: ss <- SHAKE(ct || kbar)
 */
#define FRODO_SS_BYTES (FRODO_SEC_BYTES)

/**
 * @def FRODO_SS_PREIMAGE_BYTES
 * @brief Shared secret preimage size in bytes (43,072 bytes)
 * @note Preimage is the value before applying SHAKE to generate a hash
 */
#define FRODO_SS_PREIMAGE_BYTES (FRODO_C1_BYTES + FRODO_C2_BYTES + FRODO_SALT_BYTES)

/**
 * @def FRODO_CT_BYTES
 * @brief Ciphertext size in bytes (21,696 bytes)
 * 
 * ct <- c1 || c2 || salt
 * 
 * @note Ciphertext is the encapsulated secret value  
 */
#define FRODO_CT_BYTES (FRODO_PACKED_B_BYTES + FRODO_PACKED_C_BYTES + FRODO_SALT_BYTES)

/**
 * @def FRODO_KEYGEN_RAND_BYTES
 * @brief Size of randomly generated values for key generation
 */
#define FRODO_KEYGEN_RAND_BYTES (FRODO_SEC_BYTES + FRODO_SE_BYTES + FRODO_SEED_A_BYTES)

 /**
  * @def FRODO_ENCAP_RAND_BYTES
  * @brief Size of randomly generated values for key encapsulation
  */
#define FRODO_ENCAP_RAND_BYTES (FRODO_SEC_BYTES + FRODO_SALT_BYTES)

/** @} */ // end frodo1344_key_sizes


//////////////////////////////////
//      MATRIX SIZE MACROS      //
//////////////////////////////////
/**
 * @defgroup frodo1344_matrix_sizes FrodoKEM-1344-AES Matrix Size Macros
 * @brief Element counts for internal matrix types
 * @{
 */

/**
 * @def FRODO_MATRIX_N_NBAR_SIZE
 * @brief Size of an n-by-nbar matrix
 * @note n and nbar are defined by the parameter set
 */
#define FRODO_MATRIX_N_NBAR_SIZE    (FRODO_N * FRODO_NBAR)

/**
 * @def FRODO_MATRIX_NBAR_NBAR_SIZE
 * @brief Size of an nbar-by-nbar matrix
 * @note nbar is defined by the parameter set
 */
#define FRODO_MATRIX_NBAR_NBAR_SIZE (FRODO_NBAR * FRODO_NBAR)

/** @} */ // end frodo1344_matrix_sizes


//////////////////////////////////
//      ERROR DISTRIBUTION      //
//////////////////////////////////
/**
 * @defgroup frodo1344_error_dist FrodoKEM-1344-AES Error Distribution
 * @brief CDF table and length for discrete Gaussian sampling
 * @{
 */

/**
 * @def T_X_TABLE_LEN
 * @brief Number of entries in the Gaussian distribution table
 * @note Sampled to generate secret matrices
 * @note Defined by the parameter set
 */
#define T_X_TABLE_LEN 7

/**
 * @var FRODO1344_T_X
 * @brief CDF table for FrodoKEM-1344
 */
extern const uint16_t FRODO1344_T_X[7];

/** @} */ // end frodo1344_error_dist


//////////////////////////////////
//      FRODO RETURN VALUES     //
//////////////////////////////////
/**
 * @def FRODO_SUCCESS
 * @brief Return value indicating successful execution
 * @note Returned by KeyGen, Encaps, Decaps
 */
#define FRODO_SUCCESS 0


//////////////////////////////////
//       STRUCTURED TYPES       //
//////////////////////////////////
/**
 * @defgroup frodo1344_types FrodoKEM-1344-AES Structured Types
 * @brief Structured types for keys, ciphertext, and shared secret
 * @{
 */

/**
 * @brief Public key structure
 * @typedef frodo_pk_t
 */
typedef struct {
    uint8_t seed_A[FRODO_SEED_A_BYTES];     /**< Seed for Matrix A */
    uint8_t packed_B[FRODO_PACKED_B_BYTES]; /**< Packed Matrix B */
} frodo_pk_t;

/**
 * @brief Secret key structure
 * @typedef frodo_sk_t
 */
typedef struct {
    uint8_t seed_s[FRODO_SEC_BYTES];            /**< Secret seed s */
    uint8_t pk[FRODO_PK_BYTES];                 /**< Public key */
    uint8_t encoded_ST[FRODO_ENCODED_ST_BYTES]; /**< Encoded S^T matrix */
    uint8_t pkh[FRODO_PKH_BYTES];               /**< Hash of public key */
} frodo_sk_t;

/**
 * @brief Ciphertext structure
 * @typedef frodo_ct_t
 */
typedef struct {
    uint8_t c1[FRODO_C1_BYTES];     /**< Packed B' matrix */
    uint8_t c2[FRODO_C2_BYTES];     /**< Packed C matrix */
    uint8_t salt[FRODO_SALT_BYTES]; /**< Random salt value */
} frodo_ct_t;

/**
 * @brief Shared secret preimage structure
 * @typedef frodo_ss_preimage_t
 */
typedef struct {
    uint8_t ct[FRODO_CT_BYTES]; /**< Ciphertext: c1 || c2 || salt (21,696 bytes) */
    uint8_t k[FRODO_K_BYTES];   /**< Intermediate value (96 bytes) */
} frodo_ss_preimage_t;

/**
 * @brief Shared secret structure
 * @typedef frodo_ss_t
 */
typedef struct {
    uint8_t ss[FRODO_SS_BYTES]; /**< Shared secret */
} frodo_ss_t;

/** @} */ // end frodo1344_types


//////////////////////////////////
//      FRODO MATRIX TYPES      //
//////////////////////////////////
/**
 * @defgroup frodo1344_matrix_types FrodoKEM-1344-AES Internal Matrix Types
 * @brief Struct matrix types for commonly used matrices
 * @{
 */

/**
 * @brief n-by-nbar matrix type
 * @typedef frodo_matrix_n_nbar_t
 * @note Used for matrices S, E, B
 */
typedef struct {
    uint16_t data[FRODO_N * FRODO_NBAR];
} frodo_matrix_n_nbar_t;

/**
 * @brief nbar-by-nbar matrix type
 * @typedef frodo_matrix_nbar_nbar_t
 * @note Used for matrices V, C, M
 */
typedef struct {
    uint16_t data[FRODO_NBAR * FRODO_NBAR];
} frodo_matrix_nbar_nbar_t;

/**
 * @brief nbar-by-n matrix type
 * @typedef frodo_matrix_nbar_n_t
 * @note Used for matrix S^T
 */
typedef struct {
    uint16_t data[FRODO_NBAR * FRODO_N];
} frodo_matrix_nbar_n_t;

/** @} */ // end frodo1344_matrix_types


/**
 * matrix.c Function Prototypes
 */
void frodo_compute_b(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A);
void frodo_compute_out(uint16_t *out, const uint16_t *s, size_t r_rows, size_t s_cols,
                       const uint16_t *b, size_t b_cols, const uint16_t *e);
void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);
void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);
void frodo_mul_add_spa_plus_e(uint16_t *out, const uint16_t *sp, const uint16_t *e,
                              const uint8_t *seed_A);


/**
 * encode.c Function Prototypes 
 */
void frodo_encode(uint16_t *out, const uint8_t *in);
void frodo_decode(uint8_t *out, const uint16_t *in);


/**
 * pack.c Function Prototypes
 */
void frodo_pack(uint8_t *out, size_t outlen, const uint16_t *in, size_t n);
void frodo_unpack(uint16_t *out, size_t n, const uint8_t *in, size_t inlen);


/**
 * sample.c Function Prototypes
 */
void frodo_sample_matrix(uint16_t *out, const uint16_t *r, size_t n);

/**
 * gen_A.c Function Prototypes
 */
void frodo_gen_A(uint16_t *out, const uint8_t *seed);
void frodo_gen_A_row(uint16_t *row, const uint8_t *seed, uint16_t i);

/**
 * utils.c Function Prototypes
 */
void frodo_pack_le16(uint8_t *out, const uint16_t *in, size_t n);
void frodo_unpack_le16(uint16_t *out, const uint8_t *in, size_t n);
int frodo_ct_verify(const uint8_t *a, const uint8_t *b, size_t len);
void frodo_ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len, int selector);


/**
 * hal.c Function Prototypes
 */
// TODO


// kem.c --> declared in the Public API in frodokem.h

#endif // FRODO_INTERNAL_H