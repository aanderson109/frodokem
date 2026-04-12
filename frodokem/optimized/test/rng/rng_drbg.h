/*
 * NIST AES-256 CTR DRBG for KAT testing (`rng_drbg.h`)
 *
 * Used only for KAT verification, never production
 */
#ifndef RNG_DRBG_H
#define RNG_DRBG_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    unsigned char Key[32];
    unsigned char V[16];
    int reseed_counter;
} AES256_CTR_DRBG_struct;

void randombytes_init(unsigned char *entropy_input,
                      unsigned char *personalization_string,
                      int security_strength);
void randombytes(unsigned char *x, size_t xlen);
void AES256_CTR_DRBG_Update(unsigned char *provided_data, unsigned char *Key,
                            unsigned char *V);

#endif