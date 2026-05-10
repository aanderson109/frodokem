/**
 * @file main.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES host KEM runner
 * 
 * Exercises the full KeyGen -> Encaps -> Decaps flow on the
 * host platform using /dev/urandom for randomness. Serves as
 * a client-facing integration test and timing reference for
 * the host build.
 * 
 * @note Build with: make TARGET=host
 * @note Uses the public API frodokem.h only
 * 
 * @version 0.1
 * @date 2026-05-09
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include "../../include/frodokem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint8_t pk[FRODO_PUBLICKEYBYTES];
static uint8_t sk[FRODO_SECRETKEYBYTES];
static uint8_t ct[FRODO_CIPHERTEXTBYTES];
static uint8_t ss_enc[FRODO_BYTES];
static uint8_t ss_dec[FRODO_BYTES];

int main(void) {
    clock_t start, end;
    double elapsed;

    printf("FrodoKEM-1344-AES Host Runner\n");
    printf("=============================\n\n");

    start = clock();

    if (frodo_keygen(pk, sk) != 0) {
        printf("[FAIL] keygen\n");
        return 1;
    }
    printf("[PASS] keygen\n");

    if (frodo_encaps(ct, ss_enc, pk) != 0) {
        printf("[FAIL] encaps\n");
        return 1;
    }
    printf("[PASS] encaps\n");

    if (frodo_decaps(ss_dec, ct, sk) != 0) {
        printf("[FAIL] decaps\n");
        return 1;
    }
    printf("[PASS] decaps\n");

    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    if (memcmp(ss_enc, ss_dec, FRODO_BYTES) != 0) {
        printf("[FAIL] shared secrets do not match\n");
        return 1;
    }

    printf("\n[PASS] ss match\n");
    printf("Total time: %.3f seconds\n", elapsed);

    return 0;
}