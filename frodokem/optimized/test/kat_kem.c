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

    fp = fopen("newer_PQCkemKAT_43088.rsp", "r");
    if (fp == NULL) {
        printf("ERROR: could not open newer_PQCkemKAT_43088.rsp\n");
        printf("       place the KAT file in the test/ directory\n");
        return 1;
    }

    printf("FrodoKEM-1344-AES KAT Verification\n");
    printf("=====================================\n\n");

    /* read count=0 only */
    if (!FindMarker(fp, "count = ")) {
        printf("ERROR: could not find count field\n");
        fclose(fp);
        return 1;
    }
    if (fscanf(fp, "%d", &count) != 1) {
        printf("ERROR: could not read count\n");
        fclose(fp);
        return 1;
    }
    printf("count = %d\n", count);

    /* read seed */
    if (!ReadHex(fp, seed, 48, "seed = ")) {
        printf("ERROR: could not read seed\n");
        fclose(fp);
        return 1;
    }

    /* seed the DRBG */
    randombytes_init(seed, NULL, 256);

    /* KeyGen */
    frodo_keygen(kat_pk, kat_sk);

    /* read expected pk, sk */
    if (!ReadHex(fp, kat_pk_rsp, FRODO_PK_BYTES, "pk = ")) {
        printf("ERROR: could not read pk\n");
        fclose(fp);
        return 1;
    }
    if (!ReadHex(fp, kat_sk_rsp, FRODO_SK_BYTES, "sk = ")) {
        printf("ERROR: could not read sk\n");
        fclose(fp);
        return 1;
    }

    /* compare pk */
    if (memcmp(kat_pk, kat_pk_rsp, FRODO_PK_BYTES) != 0) {
        printf("[FAIL] pk does not match KAT\n");
        
        // FIND FIRST BYTE THAT IS DIFFERENT
        for (int i = 0; i < FRODO_PK_BYTES; i++) {
            if (kat_pk[i] != kat_pk_rsp[i]) {
                printf("    first diff at byte %d\n", i);
                printf("    got:    ");
                for (int j = i; j < i + 16 && j < FRODO_PK_BYTES; j++) {
                    printf("%02X", kat_pk[j]);
                }
                printf("...\n");
                printf("    expected: ");
                for (int j = i; j < i + 16 && j < FRODO_PK_BYTES; j++) {
                    printf("%02X", kat_pk_rsp[j]);
                }
                printf("...\n");
                break;
            }
        }
        fclose(fp);
        return 1;
    }
    printf("[PASS] pk matches KAT\n");

    /* compare sk */
    if (memcmp(kat_sk, kat_sk_rsp, FRODO_SK_BYTES) != 0) {
        printf("[FAIL] sk does not match KAT\n");

        // PRINT FIRST BYTE THAT IS DIFFERENT
        for (int i = 0; i < FRODO_SK_BYTES; i++) {
            if (kat_sk[i] != kat_sk_rsp[i]) {
                printf("  first diff byte at %d\n", i);
                printf("  got:  ");
                for (int j = i; j < i + 16 && j < FRODO_SK_BYTES; j++) {
                    printf("%02X", kat_sk[j]);
                }
                printf("...\n");
                printf("  expected: ");
                for (int j = i; j < i + 16 && j < FRODO_SK_BYTES; j++) {
                    printf("%02X", kat_sk_rsp[j]);
                }
                printf("...\n");
                break;
            }
        }
        fclose(fp);
        return 1;
        /*
        printf("  got:      ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_sk[i]);
        printf("...\n");
        printf("  expected: ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_sk_rsp[i]);
        printf("...\n");
        fclose(fp);
        return 1; */
    }
    printf("[PASS] sk matches KAT\n");

    /* Encaps */
    frodo_encaps(kat_ct, kat_ss_enc, kat_pk);

    /* read expected ct, ss */
    if (!ReadHex(fp, kat_ct_rsp, FRODO_CT_BYTES, "ct = ")) {
        printf("ERROR: could not read ct\n");
        fclose(fp);
        return 1;
    }
    if (!ReadHex(fp, kat_ss_rsp, FRODO_SS_BYTES, "ss = ")) {
        printf("ERROR: could not read ss\n");
        fclose(fp);
        return 1;
    }

    /* compare ct */
    if (memcmp(kat_ct, kat_ct_rsp, FRODO_CT_BYTES) != 0) {
        printf("[FAIL] ct does not match KAT\n");
        printf("  got:      ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_ct[i]);
        printf("...\n");
        printf("  expected: ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_ct_rsp[i]);
        printf("...\n");
        fclose(fp);
        return 1;
    }
    printf("[PASS] ct matches KAT\n");

    /* compare ss */
    if (memcmp(kat_ss_enc, kat_ss_rsp, FRODO_SS_BYTES) != 0) {
        printf("[FAIL] ss does not match KAT\n");
        printf("  got:      ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_ss_enc[i]);
        printf("...\n");
        printf("  expected: ");
        for (int i = 0; i < 16; i++) printf("%02X", kat_ss_rsp[i]);
        printf("...\n");
        fclose(fp);
        return 1;
    }
    printf("[PASS] ss matches KAT\n");

    /* Decaps */
    frodo_decaps(kat_ss_dec, kat_ct, kat_sk);
    if (memcmp(kat_ss_dec, kat_ss_enc, FRODO_SS_BYTES) != 0) {
        printf("[FAIL] decaps ss does not match encaps ss\n");
        fclose(fp);
        return 1;
    }
    printf("[PASS] decaps ss matches encaps ss\n");

    printf("\n=====================================\n");
    printf("KAT PASSED -- count=0 verified\n");

    fclose(fp);
    return 0;
}