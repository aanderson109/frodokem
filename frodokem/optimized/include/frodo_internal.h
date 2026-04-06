#ifndef FRODO_INTERNAL_H
#define FRODO_INTERNAL_H

#include "frodokem.h"
#include <stddef.h>
#include <stdint.h>

// FrodoKEM-1344-AES Parameters
#define FRODO_N           1344
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

// Noise distro
#define FRODO_D_PARAM 6 // entries in CDF table
#define FRODO_LEN_CHI 16
extern const uint16_t FRODO1344_T_X[7];

// Key & ciphertext sizes in bytes
#define FRODO_PUBLIC_KEY_BYTES                                                 \
    ((FRODO_LENGTH_SEED_A + FRODO_D * FRODO_N * FRODO_NBAR) / 8)
#define FRODO_SECRET_KEY_BYTES                                                 \
    ((2 * FRODO_LENGTH_SEC + FRODO_LENGTH_SEED_A +                             \
      FRODO_D * FRODO_N * FRODO_NBAR) /                                        \
     8)
#define FRODO_CIPHERTEXT_BYTES                                                 \
    ((FRODO_D * FRODO_NBAR * FRODO_N + FRODO_D * FRODO_NBAR * FRODO_NBAR +     \
      FRODO_LENGTH_SALT) /                                                     \
     8)
#define FRODO_SHARED_SECRET_BYTES (FRODO_LENGTH_SEC / 8)

// Translating type aliases from Cryptol
#define FRODO_MATRIX_N_NBAR_SIZE    (FRODO_N * FRODO_NBAR)
#define FRODO_MATRIX_NBAR_NBAR_SIZE (FRODO_NBAR * FRODO_NBAR)

// CDF table for error sampling
extern const uint16_t CDF_TABLE[];
extern const size_t CDF_TABLE_LEN;

// Internal matrix type
typedef struct {
    uint16_t data[FRODO_N * FRODO_NBAR];
} frodo_matrix_n_nbar_t;

typedef struct {
    uint16_t data[FRODO_NBAR * FRODO_NBAR];
} frodo_matrix_nbar_nbar_t;

// matrix.c
void frodo_mul_add_as_plus_e(uint16_t *out, const uint16_t *s,
                             const uint16_t *e, const uint8_t *seed_A);
void frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b,
                             const uint16_t *s, const uint16_t *e);
void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);
void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len);

// encode.c
void frodo_key_encode(uint16_t *out, const uint8_t *in);
void frodo_key_decode(uint8_t *out, const uint16_t *in);

// pack.c
void frodo_pack(uint8_t *out, size_t outlen, const uint16_t *in, size_t inlen,
                uint8_t lsb);
void frodo_unpack(uint16_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                  uint8_t lsb);

// sample.c
void frodo_sample_n(uint16_t *out, size_t n, const uint8_t *seed, uint16_t ctr);

// gen_a.c
void frodo_gen_A(uint16_t *out, const uint8_t *seed);

// util.c
void randombytes(uint8_t *out, size_t len);
int frodo_ct_verify(const uint8_t *a, const uint8_t *b, size_t len);
void frodo_ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b,
                     size_t len, int selector);

#endif