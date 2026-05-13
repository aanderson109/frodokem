/**
 * @file encode.c
 * @author Alex Anderson & Aemiliana Cruz
 * @brief FrodoKEM-1344-AES Message Encoding & Decoding
 * @version 0.1
 * @date 2026-05-11
 * 
 * Implements Frodo.Encode and Frodo.Decode for FrodoKEM-1344-AES.
 * 
 * @note Encode maps a FRODO_L_BYTES message into an nbar x nbar matrix
 *       of Z_q elements by packing B = 4 bits per coeff.
 * @note For FrodoKEM-1344:
 *          - B = 4
 *          - D = 16
 *          - q = 65536
 *          - nbar = 8
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
 * @brief Encode a message as an nbar x nbar matrix of Z_q elements.
 *
 * Implements Frodo.Encode.
 * 
 * @note Each input byte is split into two 4-bit nibbles, each scaled by
 *       2^(D-B) = 2^12 to produce a Z_q coefficient.
 *
 * @param[out] out Output matrix
 * @param[in]  in  Input message
 */
void frodo_encode(uint16_t *out, const uint8_t *in) {
    const unsigned shift = FRODO_D - FRODO_B;

    for (size_t i = 0; i < FRODO_L_BYTES; i++) {
        uint8_t byte   = in[i];
        out[2 * i]     = (uint16_t)(byte & 0x0F) << shift;
        out[2 * i + 1] = (uint16_t)(byte >> 4) << shift;
    }
}

/**
 * @brief Decode an nbar x nbar matrix of Z_q elements back to a message.
 *
 * Implements Frodo.Decode.
 * 
 * @note Each coefficient is rounded to the nearest B-bit value by adding
 *       2^(D-B-1) before shifting
 *
 * @param[out] out Output message
 * @param[in]  in  Input matrix
 */
void frodo_decode(uint8_t *out, const uint16_t *in) {
    const unsigned shift = FRODO_D - FRODO_B;
    uint16_t round_add   = (uint16_t)(1 << (shift - 1));

    for (size_t i = 0; i < FRODO_L_BYTES; i++) {
        uint16_t lo = (in[2 * i] + round_add) >> shift;
        uint16_t hi = (in[2 * i + 1] + round_add) >> shift;
        out[i]      = (uint8_t)((lo & 0x0F) | ((hi & 0x0F) << 4));
    }
}