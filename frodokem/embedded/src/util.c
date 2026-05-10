/**
 * @file util.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Utility Functions
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements constant-time comparison and selection, little-endian
 * 16-bit packing helpers, and platform-specific random byte generation.
 * 
 * @note SHAKE256 is provided by the HAL (hal_shake_soft.c on host,
 *       hardware implementation on TM4C target, if supported)
 * @note randombytes uses /dev/urandom on host and is stubbed for
 *       TM4C (hardware RNG TODO if available)
 * @note When FRODO_KAT_TEST is defined, randombytes is omitted and
 *       provided by rng_drbg.c (NIST AES-256 CTR DRBG via OpenSSL)
 *
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#include "../include/frodo_internal.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Constant-time byte array comparison
 * 
 * Accumulates differences via OR so execution time is independent
 * of where differences occur.
 * 
 * @param[in] a    First byte array
 * @param[in] b    Second byte array
 * @param[in] len  Number of bytes to compare
 * @return 0       if a == b, non-zero otherwise
 * 
 * @warning Must not be replaced with memcmp; memcmp is not constant-time
 */
int frodo_ct_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)diff;
}

/**
 * @brief Constant-time selection between two byte arrays.
 * 
 * Used in Frodo.Decaps to select between k' and s without
 * leaking information about the secret key and comparison 
 * result.
 * 
 * @param[out]  out      Byte array of len bytes
 * @param[in]   a        Selected when selector != 0
 * @param[in]   b        Selected when selector == 0
 * @param[in]   len      Number of bytes
 * @param[in]   selector 0 selects b, non-zero selects a
 * 
 * @warning Must not be replaced with a conditional; branches leak timing
 *          information
 */
void frodo_ct_select(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len, int selector) {
    uint8_t norm = (uint8_t)(((unsigned int)!!selector) & 0xFF);
    uint8_t mask = (uint8_t)(0u - (unsigned int)norm);
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = (a[i] & mask) | (b[i] & ~mask);
    }
}

/**
 * @brief Pack n uint16_t coefficients into a byte array in
 *        little-endian order.
 * 
 * Used exclusively for encoding S^T into the secret key.
 * 
 * @param[out]  out Output byte array (2*n bytes)
 * @param[in]   in  Input array of n uint16_t coefficients
 * @param[in]   n   Number of coefficients
 * 
 * @note Mirrors the le16 and encode_ST functions from the Cryptol spec
 * @note Section 8.1 of FrodoKEM specification requires little-endian byte
 *       order, while it also requires Frodo.Pack to use big-endian bye order
 *       for its encoding. This function addresses potential issues resulting
 *       from this complex byte ordering schema.
 */
void frodo_pack_le16(uint8_t *out, const uint16_t *in, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        out[2 * i]     = (uint8_t)(in[i] & 0xFF);
        out[2 * i + 1] = (uint8_t)(in[i] >> 8);
    }
}

/**
 * @brief Unpack n little-endian byte pairs into uint16_t coefficients.
 * 
 * Inverse of frodo_pack_le16. Used in Frodo.Decaps to recover S^T from
 * the secret key.
 * 
 * @param[out]  out Output array of n uint16_t coefficients
 * @param[in]   in Input byte array (2*n bytes)
 * @param[in]   n Number of coefficients
 */
void frodo_unpack_le16(uint16_t *out, const uint8_t *in, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        out[i] = (uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8);
    }
}