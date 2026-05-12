/**
 * @file sample.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Error Distribution Sampling
 * @version 0.1
 * @date 2026-04-12
 *
 * Implements Frodo.Sample and Frodo.SampleMatrix for FrodoKEM-1344-AES.
 *
 * @warning CDF comparison loop must execute in constant time. A timing
 *          side channel here leaks information about the error distribution
 *          and hurts the security of the algorithm.
 *
 * @see FrodoKEM Preliminary Standardization Proposal
 * @see https://frodokem.org
 *
 * @copyright Copyright (c) 2026
 */
#include "../include/frodo_internal.h"
#include <stddef.h>
#include <stdint.h>

/* CDF table (T_x) for FrodoKEM-1344 */
const uint16_t FRODO1344_T_X[7] = {9142, 23462, 30338, 32361, 32725, 32765, 32767};

/**
 * @brief Sample one error value from the discrete Gaussian distribution.
 *  
 * @param[in] r         16-bit random input string 
 * @return    uint16_t  Sampled coefficient in Z_q.
 * 
 * @note Negative values are represented as the two's complement mod q.
 * 
 * @warning Must execute in constant time.
 */
static uint16_t frodo_sample(uint16_t r) {
    uint16_t t  = r >> 1;
    uint16_t r0 = r & 1;
    uint16_t e  = 0;
    uint32_t mask;
    size_t i;

    /* Constant-time CDF inversion */
    for (i = 0; i < T_X_TABLE_LEN - 1; i++) {
        mask = (uint32_t)(((int32_t)FRODO1344_T_X[i] - (int32_t)t) >> 31);
        e += (uint16_t)(mask & 1);
    }

    /* Apply Sign: if r0 == 1 -> negate e mod q */
    uint16_t neg_mask = (uint16_t)(-(uint16_t)r0);
    uint16_t neg_e    = (uint16_t)(0 - e);

    return (e & ~neg_mask) | (neg_e & neg_mask);
}

/**
 * @brief Sample an error matrix by applying Frodo.Sample to each element.
 * 
 * @param[out]  out Output array of n sampled uint16_t coefficients
 * @param[in]   r   Input array of n 16-bit random values
 * @param[in]   n   Number of coefficients to sample 
 * 
 * @note The caller is responsible for generating the r values from
 *       the appropriate seed via SHAKE256.
 */
void frodo_sample_matrix(uint16_t *out, const uint16_t *r, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        out[i] = frodo_sample(r[i]);
    }
}