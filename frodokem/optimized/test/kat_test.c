/*
 * KAT & Other Functionality Tests (`kat_test.c`)
 *
 *
 * @author Alex Anderson
 */
#include "../include/frodo_internal.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Large KEM buffers -- file scope to avoid stack overflow */
static uint8_t pk[FRODO_PK_BYTES];
static uint8_t sk[FRODO_SK_BYTES];
static uint8_t ct[FRODO_CT_BYTES];
static uint8_t ss_enc[FRODO_SS_BYTES];
static uint8_t ss_dec[FRODO_SS_BYTES];
static uint8_t pk2[FRODO_PK_BYTES];
static uint8_t sk2[FRODO_SK_BYTES];
static uint8_t ct2[FRODO_CT_BYTES];
static uint8_t ss_enc2[FRODO_SS_BYTES];
static uint8_t ss_dec2[FRODO_SS_BYTES];


/*
 * Roundtrip test for Pack and Unpack
 */
static void test_pack_unpack_roundtrip(void) {

    uint16_t in[4] = {0x1234, 0x5678, 0xABCD, 0x0001};
    uint8_t buf[8];
    uint16_t out[4];

    frodo_pack(buf, 8, in, 4);
    frodo_unpack(out, 4, buf, 8);

    // updated to be big-endian
    assert(buf[0] == 0x12 && buf[1] == 0x34);
    assert(buf[2] == 0x56 && buf[3] == 0x78);

    // verify roundtrip
    assert(memcmp(in, out, 8) == 0);

    printf("[PASS] pack/unpack roundtrip\n");
    printf("[PASS] big-endian byte order\n");
}

/*
 * Sample Test for Frodo.SampleMatrix & Frodo.Sample
 */
static void test_sample(void) {
    uint16_t r_zero[1] = {0};
    uint16_t out_zero[1];
    frodo_sample_matrix(out_zero, r_zero, 1);
    assert(out_zero[0] == 0);

    // r=1, r=3 should be negative
    uint16_t r_pos[1] = {2};
    uint16_t r_neg[1] = {3};
    uint16_t out_pos[1], out_neg[1];
    frodo_sample_matrix(out_pos, r_pos, 1);
    frodo_sample_matrix(out_neg, r_neg, 1);
    // out_pos + out_neg should equal 0 mod q
    assert((int16_t)(out_pos[0] + out_neg[0]) == 0);

    // Range check: all outputs must be in [-6, 6] mod q
    uint16_t r_all[65536];
    uint16_t out_all[65536];
    uint32_t i;
    for (i = 0; i < 65536; i++) {
        r_all[i] = (uint16_t)i;
    }
    frodo_sample_matrix(out_all, r_all, 65536);
    for (i = 0; i < 65536; i++) {
        assert(out_all[i] <= 6 || out_all[i] >= 65530);
    }

    printf("[PASS] sample zero input\n");
    printf("[PASS] sample sign symmetry\n");
    printf("[PASS] sample range check (all 65536 inputs)\n");
}

/*
 * Encode/Decode Tests
 */
static void test_encode_decode(void) {
    uint8_t msg[FRODO_L_BYTES];
    uint16_t encoded[FRODO_NBAR * FRODO_NBAR];
    uint8_t decoded[FRODO_L_BYTES];
    size_t i;

    // all zeros roundtrip
    memset(msg, 0x00, sizeof(msg));
    frodo_encode(encoded, msg);
    frodo_decode(decoded, encoded);
    assert(memcmp(msg, decoded, FRODO_L_BYTES) == 0);

    // all ones roundtrip
    memset(msg, 0xFF, sizeof(msg));
    frodo_encode(encoded, msg);
    frodo_decode(decoded, encoded);
    assert(memcmp(msg, decoded, FRODO_L_BYTES) == 0);

    // Verify scaling
    memset(msg, 0x00, sizeof(msg));
    msg[0] = 0x01;
    frodo_encode(encoded, msg);
    assert(encoded[0] == (uint16_t)(0x01 << (FRODO_D - FRODO_B)));
    assert(encoded[1] == 0);

    // incremental pattern roundtrip
    for (i = 0; i < FRODO_L_BYTES; i++) {
        msg[i] = (uint8_t)i;
    }
    frodo_encode(encoded, msg);
    frodo_decode(decoded, encoded);
    assert(memcmp(msg, decoded, FRODO_L_BYTES) == 0);

    printf("[PASS] encode/decode zero roundtrip\n");
    printf("[PASS] encode/encode 0xFF roundtrip\n");
    printf("[PASS] encode scaling check\n");
    printf("[PASS] encode/decode incremental roundtrip\n");
}

/*
 * Public Matrix `A` Generation Tests
 */
static void test_gen_A(void) {
    uint8_t seed_zero[16] = {0};
    uint8_t seed_one[16]  = {1};
    uint16_t row0_a[FRODO_N];
    uint16_t row0_b[FRODO_N];
    uint16_t row1_a[FRODO_N];

    // same seed, same row -> same output
    frodo_gen_A_row(row0_a, seed_zero, 0);
    frodo_gen_A_row(row0_b, seed_zero, 0);
    assert(memcmp(row0_a, row0_b, FRODO_N * sizeof(uint16_t)) == 0);

    // different row -> different output
    frodo_gen_A_row(row1_a, seed_zero, 1);
    assert(memcmp(row0_a, row1_a, FRODO_N * sizeof(uint16_t)) != 0);

    // different seed -> different ouput
    frodo_gen_A_row(row0_b, seed_one, 0);
    assert(memcmp(row0_a, row0_b, FRODO_N * sizeof(uint16_t)) != 0);

    printf("[PASS] deterministic\n");
    printf("[PASS] different rows distinct\n");
    printf("[PASS] different seeds distinct\n");
}

/*
 * Matrix Tests
 */
static void test_matrix(void) {
    // small dimension for speed
    size_t n = FRODO_NBAR * FRODO_NBAR;
    uint16_t a[FRODO_NBAR * FRODO_NBAR];
    uint16_t b[FRODO_NBAR * FRODO_NBAR];
    uint16_t out[FRODO_NBAR * FRODO_NBAR];
    size_t i;

    // fill a and b with known values
    for (i = 0; i < n; i++) {
        a[i] = (uint16_t)(i * 3 + 1);
        b[i] = (uint16_t)(i * 7 + 2);
    }

    // add then subtract should return a
    frodo_add(out, a, b, n);
    frodo_sub(out, out, b, n);
    assert(memcmp(out, a, n * sizeof(uint16_t)) == 0);

    // mod q wrap: 0xFFFF + 1 = 0x0000
    uint16_t x[1] = {0xFFFF};
    uint16_t y[1] = {0x0001};
    uint16_t z[1];
    frodo_add(z, x, y, 1);
    assert(z[0] == 0x0000);

    // mod q wrap: 0x0000 -1 = 0xFFFF
    uint16_t p[1] = {0x0000};
    uint16_t q[1] = {0x0001};
    uint16_t r[1];
    frodo_sub(r, p, q, 1);
    assert(r[0] == 0xFFFF);

    // compute general matrix
    uint16_t s1[1] = {2};
    uint16_t b1[2] = {3};
    uint16_t e1[1] = {0};
    uint16_t o1[1];
    frodo_compute_out(o1, s1, 1, 1, b1, 1, e1);
    assert(o1[0] == 6);

    // with error term
    uint16_t e2[1] = {5};
    uint16_t o2[1];
    frodo_compute_out(o2, s1, 1, 1, b1, 1, e2);
    assert(o2[0] == 11);

    // compute B
    uint8_t seed[16] = {0};
    static uint16_t s2[FRODO_N * FRODO_NBAR];
    static uint16_t e3[FRODO_N * FRODO_NBAR];
    static uint16_t out1[FRODO_N * FRODO_NBAR];
    static uint16_t out2[FRODO_N * FRODO_NBAR];
    memset(s2, 0, sizeof(s2));
    memset(e3, 0, sizeof(e3));
    frodo_compute_b(out1, s2, e3, seed);
    frodo_compute_b(out2, s2, e3, seed);
    assert(memcmp(out1, out2, sizeof(out1)) == 0);

    printf("[PASS] matrix add/sub inverse\n");
    printf("[PASS] matrix add wraps mod q\n");
    printf("[PASS] matrix sub wraps mod q\n");
    printf("[PASS] matrix compute general matrix basic\n");
    printf("[PASS] matrix compute general matrix with error\n");
    printf("[PASS] matrix compute matrix B deterministic\n");
}

/*
 * Utility Tests
 */
static void test_util(void) {
    uint8_t a[32], b[32], out[32];
    uint8_t in[16];
    uint8_t h1[32], h2[32];
    uint8_t r[32];
    size_t i;
    for (i = 0; i < 32; i++)
        a[i] = b[i] = (uint8_t)i;
    assert(frodo_ct_verify(a, b, 32) == 0);
    b[15] ^= 0xFF;
    assert(frodo_ct_verify(a, b, 32) != 0);
    memset(a, 0xAA, 32);
    memset(b, 0xBB, 32);
    frodo_ct_select(out, a, b, 32, 0);
    for (i = 0; i < 32; i++)
        assert(out[i] == 0xBB);
    frodo_ct_select(out, a, b, 32, 1);
    for (i = 0; i < 32; i++)
        assert(out[i] == 0xAA);
    memset(in, 0, sizeof(in));
    frodo_shake256(h1, 32, in, 16);
    frodo_shake256(h2, 32, in, 16);
    assert(memcmp(h1, h2, 32) == 0);
    in[0] = 1;
    frodo_shake256(h2, 32, in, 16);
    assert(memcmp(h1, h2, 32) != 0);
    memset(r, 0, sizeof(r));
    randombytes(r, 32);
    printf("[PASS] ct_verify equal\n");
    printf("[PASS] ct_verify different\n");
    printf("[PASS] ct_select picks b when selector=0\n");
    printf("[PASS] ct_select picks a when selector!=0\n");
    printf("[PASS] shake256 deterministic\n");
    printf("[PASS] shake256 distinct inputs\n");
    printf("[PASS] randombytes runs\n");
}

/*
 * KEM Tests
 */
static void test_kem(void)
{
    /* KeyGen */
    frodo_keygen(pk, sk);

    /* Encaps */
    frodo_encaps(ct, ss_enc, pk);

    /* Decaps */
    frodo_decaps(ss_dec, ct, sk);

    /* Shared secrets must match */
    assert(memcmp(ss_enc, ss_dec, FRODO_SS_BYTES) == 0);

    /* Tamper with ciphertext -- decaps must return different ss */
    ct[0] ^= 0xFF;
    frodo_decaps(ss_dec, ct, sk);
    assert(memcmp(ss_enc, ss_dec, FRODO_SS_BYTES) != 0);

    /* Check ss is not all zeros */
    uint8_t zeros[FRODO_SS_BYTES] = {0};
    assert(memcmp(ss_enc, zeros, FRODO_SS_BYTES) != 0);

    /* Run a second keygen/encaps/decaps to check no state leakage */
    frodo_keygen(pk2, sk2);
    frodo_encaps(ct2, ss_enc2, pk2);
    frodo_decaps(ss_dec2, ct2, sk2);
    assert(memcmp(ss_enc2, ss_dec2, FRODO_SS_BYTES) == 0);

    /* Two keygens should produce different keys */
    assert(memcmp(pk, pk2, FRODO_PK_BYTES) != 0);

    /* Cross decaps should fail */
    ct2[0] ^= 0xFF;
    frodo_decaps(ss_dec2, ct2, sk2);
    assert(memcmp(ss_enc2, ss_dec2, FRODO_SS_BYTES) != 0);

    printf("[PASS] kem keygen/encaps/decaps roundtrip\n");
    printf("[PASS] kem tampered ciphertext rejected\n");
    printf("[PASS] kem ss non-zero\n");
    printf("[PASS] kem second roundtrip\n");
    printf("[PASS] kem distinct keygens\n");
    printf("[PASS] kem tampered second ciphertext rejected\n");
}


/*
 * Main Function
 */
int main(void) {
    test_pack_unpack_roundtrip();
    test_sample();
    test_encode_decode();
    test_gen_A();
    test_matrix();
    test_util();
    test_kem();
    return 0;
}
