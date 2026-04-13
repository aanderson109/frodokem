/**
 * @file hal_shake_soft.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief Software SHAKE256 Hardware Abstraction Layer
 * @version 0.1
 * @date 2026-04-12
 * 
 * Implements frodo_shake256 for host-side testing using the PQClean
 * fips202 library. Used throughout FrodoKEM for key derivation,
 * domain separation, and pseudorandom bit generation.
 * 
 * @note On the TM4C123G/TM4C1294 target platforms, this file
 *       is replaced by hal_shake.c.
 *
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#include "../include/frodo_internal.h"
#include "fips202.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compute SHAKE256 extendable output function (XOF).
 * 
 * Thin wrapper around PQClean fips202 shake256 implementation.
 * 
 * @param[out]  out     Output buffer
 * @param[in]   outlen  Number of output bytes required
 * @param[in]   in      Input buffer
 * @param[in]   inlen   Number of input bytes
 */
void frodo_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}