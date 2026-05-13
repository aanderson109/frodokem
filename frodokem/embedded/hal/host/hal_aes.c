/**
 * @file hal_aes.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief Software AES128 Hardware Abstraction Layer
 * @version 0.1
 * @date 2026-04-12
 * 
 * Implements frodo_aes128_ecb for host-side testing using the
 * tiny-AES library. Used by frodo_gen_A_row to generate the
 * public matrix A on-the-fly, row-by-row.
 * 
 * @note On the TM4C123G/TM4C1294 target platforms, this file
 *       is replaced by hal_aes.c.
 *
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#include "../../include/hal.h"
#include "../common/aes.h"
#include <stdint.h>
#include <string.h>

/**
 * @brief Encrypt one 16-byte block using AES128-ECB.
 * 
 * Implements the AES128 pseudorandom function used by
 * Frodo.Gen to generate the public matrix A.
 * 
 * @param[in]   key 16-byte (128-bit) AES128 key
 * @param[in]   in  16-byte plaintext input block
 * @param[out]  out 16-byte ciphertext output block
 */
void frodo_aes128_ecb(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    struct AES_ctx ctx;
    memcpy(out, in, 16);
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, out);
}
