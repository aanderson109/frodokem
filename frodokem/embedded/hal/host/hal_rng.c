/**
 * @file hal_rng.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief Host random byte generation
 * 
 * Implements randombytes() for the host platform using
 * /dev/urandom
 * 
 * @see frodo_config.h for build flag docs
 * 
 * @version 0.1
 * @date 2026-05-09
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include "../../include/hal.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


/**
 * @brief Fill a buffer with uniform random bytes.
 * 
 * Host implementation reads from /dev/urandom.
 * 
 * @param[out]  buf  Output buffer
 * @param[in]   len  Number of random bytes requested
 * 
 * @note When FRODO_KAT_TEST is defined, this function is omitted
 *       and replaced by the NIST AES-256 CTR DRBG in rng_drbg.c
 *       for deterministic KAT testing.
 */
void randombytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return;
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return;
    }
    fclose(f);
}
