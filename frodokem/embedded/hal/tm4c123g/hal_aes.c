/**
 * @file hal_aes.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief TM4C123GH6PM AES128 Hardware Abstraction Layer
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements frodo_aes128_ecb for the TM4C123GH6PM target using
 * the portable tiny-AES software library.
 *
 * @note The TM4C123GH6PM does not have hardware AES acceleration.
 *       This implementation uses the same tiny-AES software library
 *       as the host build. Hardware AES is available on the
 *       TM4C1294NCPDT via TivaWare -- that will be a separate
 *       hal_aes.c for the 1294 target.
 *
 * @note tiny-AES (aes.c/aes.h) must be included in the TM4C build.
 *       Add it to FRODO_SRCS in the target Makefile.
 *
 * @see hal_aes_soft.c for the equivalent host implementation
 * @see FrodoKEM Preliminary Standardization Proposal, Section 7.7.1
 *
 * @copyright Copyright (c) 2026
 */
#include "../../include/frodo_internal.h"
#include "../common/aes.h"
#include <stdint.h>
#include <string.h>

/**
 * @brief Encrypt one 16-byte block using AES128-ECB (software).
 *
 * Implements the AES128 PRF used by Frodo.Gen to generate the
 * public matrix A per Section 7.7.1 of the FrodoKEM spec.
 *
 * Identical to hal_aes_soft.c -- tiny-AES is portable C and
 * compiles for Cortex-M4F without modification.
 *
 * @param[in]  key 16-byte AES128 key (seed_A)
 * @param[in]  in  16-byte plaintext input block
 * @param[out] out 16-byte ciphertext output block
 *
 * @note tiny-AES encrypts in-place so out is initialized from in
 *       before calling AES_ECB_encrypt.
 * @note TODO: replace with TivaWare hardware AES on TM4C1294NCPDT.
 */
void frodo_aes128_ecb(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    struct AES_ctx ctx;
    memcpy(out, in, 16);
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, out);
}