/**
 * @file frodo_config.h
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES Build Configuration
 * 
 * Centralizes compile-time build flags. Flags are passed via
 * the Makefile in optimized/test/ and target/, respectively.
 * Flags are validated here during preprocessing and provide
 * error messages if a misconfiguration exists.
 * 
 * @attention Flags are not directly defined in this file. Use
 * the aforementioned makefiles to define them.
 * 
 * @version 0.1
 * @date 2026-05-09
 * 
 * @copyright Copyright (c) 2026
 */
#ifndef FRODO_CONFIG_H
#define FRODO_CONFIG_H

/**
 * @defgroup frodo_config Build Configuration Flags
 * @brief Build configuration flags
 * @{
 */

 /**
  * @def FRODO_TARGET
  * @brief Defined in embedded target builds.
  * Excludes host-only code (e.g., /dev/urandom in util.c).
  * Set via -DFRODO_TARGET in target/Makefile in CFLAGS_TM4C123GH6PM
  */

/**
 * @def FRODO_RNG_FIXED
 * @brief Selects fixed-seed RNG in hal_rng.c.
 * Set via -DFRODO_RNG_FIXED in target/Makefile for hal_rng.o build rule.
 * @warning Not a production entropy source; only use for testing!
 */

/**
 * @def FRODO_RNG_ADC
 * @brief Selects floating ADC pin noise harvesting as RNG in hal_rng.c.
 * Set via -DFRODO_RNG_ADC on hal_rng.o build rule only.
 * @warning Not a production entropy source; only use for advanced on-board testing or research!
 */

/**
 * DEPRECATED --> NO LONGER USED
 * @def FRODO_KAT_TEST
 * @brief Excludes util.c randombytes for KAT testing builds.
 * randombytes() is provided by rng_drbg.c instead, which is pulled
 * from the official reference FrodoKEM source code.
 * 
 * Set via -DFRODO_KAT_TEST on util.c compile rule in test/Makefile
 */

 /** @} */ // end frodo_config

/* Validate: embedded build must have an RNG selected */
#ifdef FRODO_TARGET
#if !defined(FRODO_RNG_FIXED) && !defined(FRODO_RNG_ADC)
#error "Embedded (target) build requires -DFRODO_RNG_FIXED or -DFRODO_RNG_ADC"
#endif
#endif /* FRODO_TARGET */

/* Validate: only one RNG method may be selected at a time */
#if defined(FRODO_RNG_FIXED) && defined(FRODO_RNG_ADC)
#error "Select only one RNG method"
#endif

/* Diagnostics */
#ifdef FRODO_PRINT_CONFIG
    #ifdef FRODO_TARGET
    #pragma message("FRODO: Embedded target build")
    #else
    #pragma message("FRODO: Host build")
    #endif

    #ifdef FRODO_RNG_FIXED
    #pragma message("FRODO: RNG = fixed seed")
    #elif defined(FRODO_RNG_ADC)
    #pragma message("FRODO: RNG = ADC floating pin noise harvest")
    #else
    #pragma message("FRODO: RNG = /dev/urandom (host)")
    #endif

#endif /* FRODO_PRINT_CONFIG */

#endif /* FRODO_CONFIG_H */