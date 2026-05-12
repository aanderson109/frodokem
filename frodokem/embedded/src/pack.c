/**
 * @file pack.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Matrix Packing & Unpacking
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements Frodo.Pack and Frodo.Unpack for FrodoKEM-1344-AES.
 *
 * @note Specialized for D=16. Since D is the full uint16_t
 *          width, each coefficient maps to exactly 2 bytes.
 * @note Per Section 7.2, Frodo.Pack uses big endian byte ordering
 *       within each octet. This differs from the general
 *       little-endian octet encoding used throughout FrodoKEM.
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
 * @brief Pack n matrix coefficients into a byte array (big-endian order)
 * 
 * Implements Frodo.Pack; extracts D=16 least significant bits from each
 * coefficient and writes them most significant bit first per specification.
 * 
 * @param[out]  out     Output byte array (2*n bytes)
 * @param[in]   outlen  Size of out in bytes
 * @param[in]   in      Input array of n uint16_t coefficients
 * @param[in]   n       Number of coefficients to pack
 * 
 * @note Uses MSB-first byte order.
 * @note Use frodo_pack_le16 for little-endian packing of S^T
 */
void frodo_pack(uint8_t *out, size_t outlen, const uint16_t *in, size_t n) {
    size_t i;
    (void)outlen;
    for (i = 0; i < n; i++) {
        out[2 * i]     = (uint8_t)(in[i] >> 8);
        out[2 * i + 1] = (uint8_t)(in[i] & 0xFF);
    }
}

/**
 * @brief Unpack a byte array into n matrix coefficients (MSB-first).
 * 
 * Implements Frodo.Unpack; inverse of frodo_pack by reconstructing
 * uint16_t coefficients from MSB-first byte pairs.
 * 
 * @param[out]  out   Output array of n uint16_t coeffs
 * @param[in]   n     Number of coeffs to unpack
 * @param[in]   in    Input byte array
 * @param[in]   inlen Size of in in bytes
 * 
 * @note Uses MSB-first (big-endian) byte order.
 * @note Use frodo_unpack_le16 for little-endian unpacking of S^T.
 */
void frodo_unpack(uint16_t *out, size_t n, const uint8_t *in, size_t inlen) {
    size_t i;
    (void)inlen;
    for (i = 0; i < n; i++) {
        out[i] = ((uint16_t)in[2 * i] << 8) | (uint16_t)in[2 * i + 1];
    }
}