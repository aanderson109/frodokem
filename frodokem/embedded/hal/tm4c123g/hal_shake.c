/**
 * @file hal_shake.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief TM4C123GH6PM SHAKE256 Hardware Abstraction Layer
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements frodo_shake256 for the TM4C123GH6PM target using
 * the portable PQClean fips202 software library.
 *
 * @note Neither the TM4C123GH6PM nor the TM4C1294NCPDT has hardware
 *       Keccak or SHAKE acceleration. The TivaWare SHA/MD5 module
 *       (shamd5.c) supports SHA-1 and MD5 only -- not SHA-256 or
 *       SHAKE256. This software implementation is therefore used
 *       on both target boards.
 *
 * @note fips202.c/fips202.h must be included in the TM4C build.
 *       Add fips202.c to FRODO_SRCS in the target Makefile.
 *
 * @note SHAKE256 is the primary performance bottleneck on the TM4C.
 *       It is called in KeyGen, Encaps, and Decaps for key derivation
 *       and r stream generation. Optimizing this with an ARM
 *       Cortex-M4 assembly Keccak implementation would significantly
 *       reduce cycle counts.
 *
 * @see hal_shake_soft.c for the equivalent host implementation
 * @see FrodoKEM Preliminary Standardization Proposal, Section 6.2
 *
 * @copyright Copyright (c) 2026
 */
#include "../../include/hal.h"
#include "../common/fips202.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compute SHAKE256 extendable output function (software).
 *
 * Thin wrapper around the PQClean fips202 shake256 implementation.
 * Compiles for Cortex-M4F without modification -- fips202.c is
 * portable C with no platform dependencies.
 *
 * Used throughout FrodoKEM for:
 *   - Deriving seed_A from z (KeyGen step 2)
 *   - Generating r stream from seed_SE (KeyGen step 4)
 *   - Deriving seedSE and k from pkh || u || salt (Encaps step 3)
 *   - Computing pkh = SHAKE256(pk) (KeyGen step 9)
 *   - Computing shared secret ss (Encaps step 15, Decaps step 16)
 *
 * @param[out] out    Output buffer
 * @param[in]  outlen Number of output bytes requested
 * @param[in]  in     Input buffer
 * @param[in]  inlen  Number of input bytes
 *
 * @note This is identical to hal_shake_soft.c -- the same fips202
 *       implementation runs on both host and TM4C targets.
 * @note TODO: replace with optimized ARM Cortex-M4 Keccak assembly
 *       for improved performance on embedded targets.
 */
void frodo_shake256(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}