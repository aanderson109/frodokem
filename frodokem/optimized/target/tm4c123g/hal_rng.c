/**
 * @file hal_rng.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief TM4C123GH6PM Random Byte Generation
 * @version 0.1
 * @date 2026-04-13
 * 
 * Provides randombytes() for the TM4C123GH6PM target platform.
 * 
 * Two implementations are provided:
 *      1. FRODO_RNG_ADC: ADC noise harvesting; reads thermal noise from a floating ADC
 *         pin and whitens with SHAKE256. Suitable for demonstration purposes only. Not
 *         a NIST-validated entropy source.
 * 
 *      2. FRODO_RNG_FIXED: Fixed seed; deterministic output for build verification and
 *         size characterization only. Never use in a real production environment.
 * 
 * Select at compile time:
 *      -DFRODO_RNG_ADC     use ADC noise harvesting
 *      -DFRODO_RNG_FIXED   use fixed seed (default if neither defined)
 * 
 * @warning Neither implementation is a production-grade entropy source.
 * 
 * @note On TM4C1294NCPDT, the same file applies.
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include "../../include/frodo_internal.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define PART_TM4C123GH6PM
#include "../tivaware/driverlib/adc.h"
#include "../tivaware/driverlib/sysctl.h"
#include "../tivaware/inc/hw_memmap.h"

/* Option A: ADC Noise Harvesting */
#ifdef FRODO_RNG_ADC

/* Number of raw ADC samples to collect before whitening */
#define ADC_SAMPLE_COUNT 512

/**
 * @brief Initialize ADC0 sequencer 3 for noise sampling.
 * 
 * Configure ADC0 channel 0 for processor-triggered single-sample
 * mode. The pin should be left floating; do not connect it
 * to any signal or voltage reference.
 * 
 * @warning PE3 must be unconnected for noise harvesting. Connecting it
 *          will bias the output.
 */
static void adc_noise_init(void) {
    SysCtlPeripheralEnable(SYSCTL_PERIPH_ADC0);
    while(!SysCtlPeripheralReady(SYSCTL_PERIPH_ADC0)) {}

    /* Sequencer 3: single sample, processor trigger, highest priority */
    ADCSequenceConfigure(ADC0_BASE, 3, ADC_TRIGGER_PROCESSOR, 0);
    ADCSequenceStepConfigure(ADC0_BASE, 3, 0, ADC_CTL_CHO | ADC_CTL_IE | ADC_CTL_END);
    ADCSequenceEnable(ADC0_BASE, 3);
    ADCIntClear(ADC0_BASE, 3);
}

/**
 * @brief Take one 12-bit ADC sample and return the raw value.
 * 
 * @return Raw 12-bit ADC reading (0-4095)
 * 
 */
static uint32_t adc_sample(void) {
    uint32_t val;
    ADCProcessorTrigger(ADC0_BASE, 3);
    while (!ADCIntStatus(ADC0_BASE, 3, false)) {}
    ADCIntClear(ADC0_BASE, 3);
    ADCSequenceDataGet(ADC0_BASE, 3, &val);
    return val;
}

/**
 * @brief Fill buffer with random bytes derived from ADC noise
 * 
 * Collects ADC_SAMPLE_COUNT raw 12-bit samples from a floating ADC pin,
 * packs theminto a byte array, whitens with SHAKE256 to produce the
 * requested number of output bytes.
 * 
 * @param[out]  buf Output buffer
 * @param[in]   len Number of random bytes requested
 * 
 * @note First call inits the ADC peripheral; subsequent calls reuse that configuration.
 * @warning Not a secure source of entropy.
 */
void randombytes(uint8_t *buf, size_t len) {
    static uint8_t initialized = 0;
    if (!initalized) {
        adc_noise_init();
        initialized = 1;
    }

    // collect raw noise samples
    uint8_t raw[ADC_SAMPLE_COUNT * 2];
    for (size_t i = 0; i < ADC_SAMPLE_COUNT; i++) {
        uint32_t sample = adc_sample();
        raw[2 * i] = (uint8_t)(sample & 0xFF);
        raw[2 * i + 1] = (uint8_t)((sample >> 8) & 0x0F);
    }

    // whiten though SHAKE256
    frodo_shake256(buf, len, raw, sizeof(raw));
}

/* Option B: Fixed Seed */
#else   // FRODO_RNG_FIXED

/**
 * @brief Fill buffer with deterministic bytes derived from a fixed seed.
 * 
 * Uses a fixed 32-byte seed.
 * 
 * @param[out]  buf Output buffer
 * @param[in]   len Number of bytes requested
 * 
 * @warning very insecure!
 * 
 */
void randombytes(uint8_t *buf, size_t len) {
    static const uint8_t seed[32] = {
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
    };
    static uint32_t counter = 0;

    uint8_t input[36];
    memcpy(input, seed, 32);
    input[32] = (uint8_t)(counter >> 24);
    input[33] = (uint8_t)(counter >> 16);
    input[34] = (uint8_t)(counter >> 8);
    input[35] = (uint8_t)(counter);
    counter++;

    frodo_shake256(buf, len, input, sizeof(input));
}

#endif // FRODO_RNG_ADC