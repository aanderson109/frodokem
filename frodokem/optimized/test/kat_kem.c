/**
 * @file kat_kem.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES NIST KAT Verification
 * @version 0.1
 * @date 2026-04-12
 * 
 * Runs all 100 entries from newer_PQCkemKAT_43088.rsp through
 * the FrodoKEM-1344-AES implementation.
 * 
 * @note Uses NIST AES-256 CTR DRBG for randomness and compares pk,
 * sk, ct, and ss against the known answer values.
 * @note Run with: make kat
 * @note Expected result: 100/100 passed
 * @note Requires newer_PQCkemKAT_43088.rsp in test/ directory
 * @note newer_PQCkemKAT_43088.rsp is the most recent KAT file from
 *       the official FrodoKEM repository, renamed to differentiate.
 *
 * @see kat_test.c for unit and functionality testing
 * @see rng/rng_drbg.c for the NIST DRBG implementation
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see FrodoKEM Official GitHub
 * 
 * @copyright Copyright (c) 2026
 */
#include "../include/frodo_internal.h"
#include "rng/rng_drbg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_MARKER_LEN 50

/**
 * @brief Scan a infile for a specific marker string.
 * 
 * Advances the file position until the marker is found or EOF is reached.
 * 
 * @param[in] infile File to scan 
 * @param[in] marker Marker string to search for
 * @return 1 if marker found, 0 if EOF reached
 */
static int FindMarker(FILE *infile, const char *marker) {
    char line[MAX_MARKER_LEN];
    int i, len, curr_line;

    len = (int)strlen(marker);
    if (len > MAX_MARKER_LEN - 1) len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++) {
        curr_line = fgetc(infile);
        line[i] = curr_line;
        if (curr_line == EOF) return 0;
    }
    line[len] = '\0';

    while (1) {
        if (!strncmp(line, marker, len)) return 1;
        for (i = 0; i < len - 1; i++) line[i] = line[i + 1];
        curr_line = fgetc(infile);
        line[len - 1] = curr_line;
        if (curr_line == EOF) return 0;
        line[len] = '\0';
    }
}

/**
 * @brief Read a hex-coded field from infile into a byte array.
 * 
 * Searches for str marker then reads Length hex-encoded bytes into A.
 * 
 * @param[in]   infile  File to read from
 * @param[out]  A       Output byte array
 * @param[in]   Length  Number of bytes to read
 * @param[in]   str     Field marker to search for
 * @return 1 on success, 0 on failure
 */
static int ReadHex(FILE *infile, unsigned char *A, int Length, char *str) {
    int i, ch, started;
    unsigned char ich;

    if (Length == 0) { 
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;

    if (FindMarker(infile, str)) {
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n') {
                        break;
                    } else {
                        continue;
                    }
                } else {
                    break;
                }
            }
            started = 1;
            if (ch >= '0' && ch <= '9') {
                ich = ch - '0';
            } else if (ch >= 'A' && ch <= 'F') {
                ich = ch - 'A' + 10;
            } else if (ch >= 'a' && ch <= 'f') {
                ich = ch - 'a' + 10;
            } else {
                ich = 0;
            }
            for (i = 0; i < Length - 1; i++) {
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            }
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    } else {
        return 0;
    }
    return 1;
}

/* Static buffers */
static unsigned char kat_pk[FRODO_PK_BYTES];
static unsigned char kat_sk[FRODO_SK_BYTES];
static unsigned char kat_ct[FRODO_CT_BYTES];
static unsigned char kat_ss_enc[FRODO_SS_BYTES];
static unsigned char kat_ss_dec[FRODO_SS_BYTES];
static unsigned char kat_pk_rsp[FRODO_PK_BYTES];
static unsigned char kat_sk_rsp[FRODO_SK_BYTES];
static unsigned char kat_ct_rsp[FRODO_CT_BYTES];
static unsigned char kat_ss_rsp[FRODO_SS_BYTES];

/**
 * @brief Run all 100 NIST KAT entries and report results.
 * 
 * @return 0 if all 100 entries pass, 1 otherwise
 */
int main(void) {
    FILE *fp;
    unsigned char seed[48];
    int count;
    int total = 0, passed = 0;
    clock_t start, end;     // used to time execution
    double elapsed;         // total time executed

    fp = fopen("newer_PQCkemKAT_43088.rsp", "r");
    if (fp == NULL) {
        printf("ERROR: could not open newer_PQCkemKAT_43088.rsp\n");
        return 1;
    }

    printf("FrodoKEM-1344-AES KAT Verification\n");
    printf("=====================================\n\n");

    // Start the clock
    start = clock();

    while (FindMarker(fp, "count = ")) {
        
        if (fscanf(fp, "%d", &count) != 1) {
            break;
        }

        if (!ReadHex(fp, seed, 48, "seed = ")) {
            break;
        }

        // Seed NIST AES-256 DRBG
        randombytes_init(seed, NULL, 256);

        // Run Frodo.KeyGen
        frodo_keygen(kat_pk, kat_sk);

        if (!ReadHex(fp, kat_pk_rsp, FRODO_PK_BYTES, "pk = ")) {
            break;
        }

        if (!ReadHex(fp, kat_sk_rsp, FRODO_SK_BYTES, "sk = ")) {
            break;
        }

        // Fail if pk values don't match
        if (memcmp(kat_pk, kat_pk_rsp, FRODO_PK_BYTES) != 0) {
            printf("[FAIL] count=%d pk mismatch\n", count);
            fclose(fp);
            return 1;
        }

        // Fail if sk values don't match
        if (memcmp(kat_sk, kat_sk_rsp, FRODO_SK_BYTES) != 0) {
            printf("[FAIL] count=%d sk mismatch\n", count);
            fclose(fp);
            return 1;
        }

        // Run Frodo.Encaps
        frodo_encaps(kat_ct, kat_ss_enc, kat_pk);

        if (!ReadHex(fp, kat_ct_rsp, FRODO_CT_BYTES, "ct = ")) {
            break;
        }

        if (!ReadHex(fp, kat_ss_rsp, FRODO_SS_BYTES, "ss = ")) {
            break;
        }

        // Fail if ct values are mismatched
        if (memcmp(kat_ct, kat_ct_rsp, FRODO_CT_BYTES) != 0) {
            printf("[FAIL] count=%d ct mismatch\n", count);
            fclose(fp);
            return 1;
        }

        // Fail if ss values are mismatched
        if (memcmp(kat_ss_enc, kat_ss_rsp, FRODO_SS_BYTES) != 0) {
            printf("[FAIL] count=%d ss mismatch\n", count);
            fclose(fp);
            return 1;
        }

        // Run Frodo.Decaps to verify ss matches output from Frodo.Encaps
        frodo_decaps(kat_ss_dec, kat_ct, kat_sk);
        if (memcmp(kat_ss_dec, kat_ss_enc, FRODO_SS_BYTES) != 0) {
            printf("[FAIL] count=%d decaps mismatch\n", count);
            fclose(fp);
            return 1;
        }

        // Print test results
        printf("[PASS] count=%d\n", count);
        passed++;
        total++;
    }

    // Stop the clock
    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    fclose(fp);

    // Report results
    printf("\n=====================================\n");
    printf("KAT: %d/%d passed\n", passed, total);
    printf("Total time: %.2f seconds\n", elapsed);
    printf("Average time per iteration: %.2f seconds \n", elapsed / total);
    
    return (passed == total && total == 100) ? 0 : 1;
}