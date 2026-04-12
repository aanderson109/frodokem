/*
 * Software AES128 Hardware Abstraction Layer (`hal_aes_soft.c`)
 *
 * Ussed for host-side testing of FrodoKEM algorithm
 *
 * Implements AES128 generation for Public Matrix A using
 * the Tiny-AES library
 *
 * On the TM4C microcontroller, this is replaced by the hardware
 * acceleration
 */

#include "../include/frodo_internal.h"
#include "aes.h"
#include <stdint.h>
#include <string.h>

/*
 * AES128 as PRF (`frodo_aes128_ecb`)
 *
 * Encrypts on 16-byte block using AES128-ECB
 *
 * Parameters:
 *     `key` : 16-byte AES key (`seed_A`)
 *     `in`  : 16-byte plaintext input block
 *     `out` : 16-byte ciphertext output block
 */
void frodo_aes128_ecb(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    struct AES_ctx ctx;
    memcpy(out, in, 16);
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, out);
}
