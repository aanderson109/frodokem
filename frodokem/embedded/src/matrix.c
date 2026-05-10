/**
 * @file matrix.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Matrix Operations Over Z_q
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements matrix arithmetic and compound multiply-add operations
 * for FrodoKEM-1344-AES. All arithmetic is performed mod q, where
 * q = 65536.
 * 
 * @note The full N x N public matrix A is 3.6MB and never materialized
 *       in memory because of that.
 * @note frodo_compute_b and frodo_mul_add_spa_plus_e generate A one
 *       row at a time via frodo_gen_A_row to stay within the SRAM
 *       budget of the embedded platforms targeted for the project.
 *
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#include "../include/frodo_internal.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Element-wise matrix addition mod q.
 * 
 * Computes out = a + b coefficient-wise.
 * 
 * @param[out]  out Output array of len coeffs
 * @param[in]   a   First input array of len coeffs
 * @param[in]   b   Second input array of len coeffs
 * @param[in]   len Number of coeffs
 */
void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = a[i] + b[i];
    }
}

/**
 * @brief Element-wise matrix subtraction mod q.
 * 
 * Computes out = a - b coefficient-wise.
 * 
 * @param[out]  out Output array of len coeffs
 * @param[in]   a   First input array of len coeffs
 * @param[in]   b   Second input array of len coeffs
 * @param[in]   len Number of coeffs
 */
void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = a[i] - b[i];
    }
}

/**
 * @brief Compute B = A*S + E, where A is generated on-the-fly.
 * 
 * @note Used in Frodo.KeyGen to generate A one row at a time via
 *       frodo_gen_A_row to avoid materializing the full N x N matrix
 *       in SRAM.
 * @note Matrix dimensions:
 *          - A : N x N
 *          - S : N x NBAR
 *          - E : N x NBAR
 *          - out : N x NBAR
 * 
 * @param[out] out    Output B matrix 
 * @param[in]  s      Input S matrix
 * @param[in]  e      Input E matrix
 * @param[in]  seed_A 16-byte seed for AES-based generation of A
 */
void frodo_compute_b(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A) {
    uint16_t a_row[FRODO_N];
    size_t i, j, k;

    for (i = 0; i < FRODO_N; i++) {
        frodo_gen_A_row(a_row, seed_A, (uint16_t)i);
        for (j = 0; j < FRODO_NBAR; j++) {
            uint32_t acc = 0;
            for (k = 0; k < FRODO_N; k++) {
                acc += (uint32_t)a_row[k] * (uint32_t)s[k * FRODO_NBAR + j];
            }
            out[i * FRODO_NBAR + j] = (uint16_t)acc + e[i * FRODO_NBAR + j];
        }
    }
}

/**
 * @brief Compute out = S*B + E for general matrix dimensions.
 * 
 * @note Used in Frodo.Encaps and Frodo.Decaps for computing
 *       V = S' * B + E'' and W = B' * S.
 * @note Dimensions are passed explicitly to handle both
 *       NBAR x N and NBAR x NBAR output cases.
 * 
 * @param[out] out    Output matrix
 * @param[in]  s      Input S matrix
 * @param[in]  s_rows Number of rows in S
 * @param[in]  s_cols Number of columns in S
 * @param[in]  b      Input B matrix 
 * @param[in]  b_cols Number of columns in B
 * @param[in]  e      Input E matrix
 */
void frodo_compute_out(uint16_t *out, const uint16_t *s, size_t s_rows, size_t s_cols,
                       const uint16_t *b, size_t b_cols, const uint16_t *e) {
    size_t i, j, k;
    for (i = 0; i < s_rows; i++) {
        for (j = 0; j < b_cols; j++) {
            uint32_t acc = 0;
            for (k = 0; k < s_cols; k++) {
                acc += (uint32_t)s[i * s_cols + k] * (uint32_t)b[k * b_cols + j];
            }
            out[i * b_cols + j] = (uint16_t)acc + e[i * b_cols + j];
        }
    }
}

/**
 * @brief Compute out = S' * A + E, where A is generated on-the-fly.
 * 
 * @note Used in Frodo.Encaps and Frodo.Decaps to compute
 *       B' = S'*A + E'.
 * @note Generates A one row at a time to avoid materializing the full
 *       N x N matrix.
 * 
 * @param[out] out    Output matrix
 * @param[in]  sp     Input S' matrix
 * @param[in]  e      Input E' matrix
 * @param[in]  seed_A 16-byte seed for AES-based A generation
 */
void frodo_mul_add_spa_plus_e(uint16_t *out, const uint16_t *sp, const uint16_t *e,
                              const uint8_t *seed_A) {
    uint16_t a_row[FRODO_N];
    size_t i, j, k;

    /* Init out with E' */
    memcpy(out, e, FRODO_NBAR * FRODO_N * sizeof(uint16_t));

    /* Accumulate the product S'*A row by row*/
    for (i = 0; i < FRODO_N; i++) {
        frodo_gen_A_row(a_row, seed_A, (uint16_t)i);
        for (j = 0; j < FRODO_NBAR; j++) {
            for (k = 0; k < FRODO_N; k++) {
                out[j * FRODO_N + k] += sp[j * FRODO_N + i] * a_row[k];
            }
        }
    }
}