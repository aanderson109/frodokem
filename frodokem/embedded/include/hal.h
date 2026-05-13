/**
 * @file hal.h
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Hardware Abstraction Layer
 * 
 * Declares the three platform primitives required by FrodoKEM. Each
 * target platform must provide implementations for all three functions.
 * The Makefile selects which hal/ subdirectory gets compiled based on
 * the TARGET variable.
 * 
 * @par HAL Implementations by Target (markdown table):
 *      | Target   | Directory     | AES      | SHAKE   | RNG                        |
 *      | -------- | ------------- | -------- | ------- | -------------------------- |
 *      | host     | hal/host/     | tiny-AES | fips202 | /dev/urandom               |
 *      | tm4c123g | hal/tm4c123g/ | tiny-AES | fips202 | fixed or ADC noise harvest |
 *      | tm4c1294 | hal/tm4c1294/ | HW AES   | HW SHA3 | HW TRNG (TBR)              |
 * 
 * @par Adding a New Target:
 *      1. Create a hal/[target]/ directory
 *      2. Implement hal_aes.c, hal_shake.c, and hal_rng.c
 *      3. Add TARGET case to target/Makefile
 *      4. Add -DFRODO_TARGET to that target's CFLAGS
 * 
 * @see frodo_config.h for build flag docs
 * @see target/Makefile for build system integration
 * 
 * @version 0.1
 * @date 2026-05-09
 * 
 * @copyright Copyright (c) 2026
 * 
 */

#ifndef HAL_H
#define HAL_H

#include <stddef.h>
#include <stdint.h>
#include "../hal/common/fips202.h"

/* AES-128 ECB */
void frodo_aes128_ecb(const uint8_t *key, const uint8_t *in, uint8_t *out);

/* SHAKE256 */
void frodo_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* Random Bytes */
void randombytes(uint8_t *buf, size_t len);

#endif /* HAL_H */