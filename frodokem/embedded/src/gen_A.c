/**
 * @file gen_A.c
 * @author Alex Anderson & Aemiliana Cruz
 * @brief FrodoKEM-1344-AES Public Matrix Generation
 * @version 0.1
 * @date 2026-05-11
 *
 * Implements Frodo.Gen for FrodoKEM-1344-AES using AES128 as a
 * pseudorandom random function.
 * 
 * @note Each AES128 call processes one 128-bit block and produces
 *       FRODO_STRIPE_STEP=8 uint16_t coeffs of A.
 * @note Full n x n matrix A is never fully realized in SRAM.
 * @note frodo_gen_A generates the full matrix and is provided
 *       for testing purposes.
 * @note frodo_aes128_ecb is provided by hal_aes_soft.c on host
 *       and will be provided by hal_aes.c via TivaWare on the
 *       TM4C target.
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
 * @brief Construct the 16-byte AES input block for row i, stripe j.
 * 
 * Encodes the row index i and stripe column index j as little-endian
 * 16-bit integers in the first four bytes of the block.
 * 
 * @param[out] block 16-byte AES input block
 * @param[in]  i     Row index (0 to n-1)
 * @param[in]  j     Stripe column index (0 to n-1 in steps of 8)
 */
static void build_aes_input(uint8_t *block, uint16_t i, uint16_t j) {
    block[0] = (uint8_t)i;
    block[1] = (uint8_t)(i >> 8);
    block[2] = (uint8_t)j;
    block[3] = (uint8_t)(j >> 8);
}

/**
 * @brief Generate one row of the public matrix A using AES128.
 * 
 * Implements one iteration of Frodo.Gen. Processes the row in
 * stripes of 8 coefficients per AES call.
 * 
 * @note Coeffs are extracted as little-endian uint16_t values.
 * 
 * @param[out] row  Output array of n uint16_t coefficients
 * @param[in]  seed 16-byte Seed_A (used as AES128 key)
 * @param[in]  i    Row index (0 to n-1)
 */
void frodo_gen_A_row(uint16_t *row, const uint8_t *seed, uint16_t i) {
    uint8_t block_in[16] = {0};
    uint8_t block_out[16];

    // set row index once
    block_in[0] = (uint8_t)i;
    block_in[1] = (uint8_t)(i >> 8);

    for (uint16_t j = 0; j < FRODO_N; j += FRODO_STRIPE_STEP) {

        // Only update the column index
        block_in[2] = (uint8_t)j;
        block_in[3] = (uint8_t)(j >> 8);

        frodo_aes128_ecb(seed, block_in, block_out);

        for (size_t k = 0; k < FRODO_STRIPE_STEP; k++) {
            row[j + k] = (uint16_t)block_out[2 * k] | ((uint16_t)block_out[2 * k + 1] << 8);
        }
    }
}

/**
 * @brief Generate the full n x n public matrix A using AES128.
 * 
 * Calls frodo_gen_A_row for each row to produce the complete matrix.
 * 
 * @param[out] out  Output array of n * n uint16_t coefficients
 * @param[in]  seed 16-byte Seed_A (used as AES128 key)
 * 
 * @warning Be careful when calling on embedded targets;
 *          ensure they have the memory to support the
 *          full 3.6MB matrix.
 */
void frodo_gen_A(uint16_t *out, const uint8_t *seed) {
    for (uint16_t i = 0; i < FRODO_N; i++) {
        frodo_gen_A_row(&out[(size_t)i * FRODO_N], seed, i);
    }
}