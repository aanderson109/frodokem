/*
 * Software SHAKE256 Hardware Abstraction Layer for host-side testing
 * `hal_shake_soft.c`
 * 
 * Implements `frodo_shake256` using `fips202` for host builds
 * On the TM4C, this is replaced by hardware
 */
#include "../include/frodo_internal.h"
#include "fips202.h"
#include <stddef.h>
#include <stdint.h>

void frodo_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}