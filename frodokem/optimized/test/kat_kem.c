/*
 * kat_kem.c -- FrodoKEM-1344-AES KAT Verification
 *
 * Runs count=0 from PQCkemKAT_43088.rsp through our implementation
 * using the NIST AES-256 CTR DRBG and compares pk, sk, ct, ss
 * against the known answer values.
 */
#include "../include/frodo_internal.h"
#include "rng/rng_drbg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_MARKER_LEN 50
#define KAT_COUNTS     1   /* only verify count=0 for now */

/* hex parsing helpers from NIST reference */
static int FindMarker(FILE *infile, const char *marker)
{
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

static int ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
    int i, ch, started;
    unsigned char ich;

    if (Length == 0) { A[0] = 0x00; return 1; }
    memset(A, 0x00, Length);
    started = 0;
    if (FindMarker(infile, str))
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) { if (ch == '\n') break; else continue; }
                else break;
            }
            started = 1;
            if      (ch >= '0' && ch <= '9') ich = ch - '0';
            else if (ch >= 'A' && ch <= 'F') ich = ch - 'A' + 10;
            else if (ch >= 'a' && ch <= 'f') ich = ch - 'a' + 10;
            else ich = 0;
            for (i = 0; i < Length - 1; i++)
                A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    else return 0;
    return 1;
}

/* static buffers to avoid stack overflow */
static unsigned char kat_pk[FRODO_PK_BYTES];
static unsigned char kat_sk[FRODO_SK_BYTES];
static unsigned char kat_ct[FRODO_CT_BYTES];
static unsigned char kat_ss_enc[FRODO_SS_BYTES];
static unsigned char kat_ss_dec[FRODO_SS_BYTES];
static unsigned char kat_pk_rsp[FRODO_PK_BYTES];
static unsigned char kat_sk_rsp[FRODO_SK_BYTES];
static unsigned char kat_ct_rsp[FRODO_CT_BYTES];
static unsigned char kat_ss_rsp[FRODO_SS_BYTES];

int main(void) {
    FILE *fp;
    unsigned char seed[48];
    int count;
    int total = 0, passed = 0;

    // Used to measure execution time
    clock_t start, end;
    double elapsed;

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
        if (fscanf(fp, "%d", &count) != 1) break;

        if (!ReadHex(fp, seed, 48, "seed = ")) break;

        randombytes_init(seed, NULL, 256);

        frodo_keygen(kat_pk, kat_sk);

        if (!ReadHex(fp, kat_pk_rsp, FRODO_PK_BYTES, "pk = ")) break;
        if (!ReadHex(fp, kat_sk_rsp, FRODO_SK_BYTES, "sk = ")) break;

        if (memcmp(kat_pk, kat_pk_rsp, FRODO_PK_BYTES) != 0) {
            printf("[FAIL] count=%d pk mismatch\n", count);
            fclose(fp);
            return 1;
        }
        if (memcmp(kat_sk, kat_sk_rsp, FRODO_SK_BYTES) != 0) {
            printf("[FAIL] count=%d sk mismatch\n", count);
            fclose(fp);
            return 1;
        }

        frodo_encaps(kat_ct, kat_ss_enc, kat_pk);

        if (!ReadHex(fp, kat_ct_rsp, FRODO_CT_BYTES, "ct = ")) break;
        if (!ReadHex(fp, kat_ss_rsp, FRODO_SS_BYTES, "ss = ")) break;

        if (memcmp(kat_ct, kat_ct_rsp, FRODO_CT_BYTES) != 0) {
            printf("[FAIL] count=%d ct mismatch\n", count);
            fclose(fp);
            return 1;
        }
        if (memcmp(kat_ss_enc, kat_ss_rsp, FRODO_SS_BYTES) != 0) {
            printf("[FAIL] count=%d ss mismatch\n", count);
            fclose(fp);
            return 1;
        }

        frodo_decaps(kat_ss_dec, kat_ct, kat_sk);
        if (memcmp(kat_ss_dec, kat_ss_enc, FRODO_SS_BYTES) != 0) {
            printf("[FAIL] count=%d decaps mismatch\n", count);
            fclose(fp);
            return 1;
        }

        printf("[PASS] count=%d\n", count);
        passed++;
        total++;
    }

    // Stop the clock
    end = clock();
    elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    fclose(fp);
    printf("\n=====================================\n");
    printf("KAT: %d/%d passed\n", passed, total);
    printf("Total time: %.2f seconds\n", elapsed);
    printf("Average time per iteration: %.2f seconds \n", elapsed / total);
    return (passed == total && total == 100) ? 0 : 1;
}