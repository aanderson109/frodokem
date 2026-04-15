/**
 * @file main.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief FrodoKEM-1344-AES for TM4C123GH6PM
 * @version 0.1
 * @date 2026-04-13
 * 
 * Runs Frodo.KeyGen, Frodo.Encaps, and Frodo.Decaps on the TM4C123GH6PM
 * and reports results and timing over UART0.
 * 
 * Timing uses SysTick at 80 MHz
 * 
 * @note randombytes is provided by hal_rng.c
 * 
 * @warning if build with FRODO_RNG_FIXED the output is deterministic and
 *          not cryptographically secure.
 * 
 * @copyright Copyright (c) 2026
 * 
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define PART_TM4C123GH6PM

#include "../../include/frodo_internal.h"
#include "../../target/tivaware/driverlib/gpio.h"
#include "../../target/tivaware/driverlib/pin_map.h"
#include "../../target/tivaware/driverlib/sysctl.h"
#include "../../target/tivaware/driverlib/systick.h"
#include "../../target/tivaware/driverlib/uart.h"
#include "../../target/tivaware/inc/hw_memmap.h"
#include "../../target/tivaware/inc/hw_types.h"
#include "../../target/tivaware/inc/tm4c123gh6pm.h"

/* Pin & Peripheral Constants */
#define LED_PERIPH SYSCTL_PERIPH_GPIOF
#define LED_BASE GPIO_PORTF_BASE
#define LED_GREEN GPIO_PIN_3
#define LED_RED GPIO_PIN_1 

#define UART_PERIPH SYSCTL_PERIPH_UART0
#define UART_GPIO_PERIPH SYSCTL_PERIPH_GPIOA
#define UART_BASE UART0_BASE
#define UART_GPIO_BASE GPIO_PORTA_BASE
#define UART_RX_PIN GPIO_PIN_0
#define UART_TX_PIN GPIO_PIN_1

#define SYSCLK_HZ 80000000UL
#define BAUD_RATE 115200UL

/* KEM Buffers */
static uint8_t pk[FRODO_PK_BYTES];
static uint8_t sk[FRODO_SK_BYTES];
static uint8_t ct[FRODO_CT_BYTES];
static uint8_t ss_enc[FRODO_SS_BYTES];
static uint8_t ss_dec[FRODO_SS_BYTES];

/* Function Prototypes */
static void clock_init(void);
static void uart_init(void);
static void gpio_init(void);
static void uart_print(const char *str);
static void uart_print_hex(const uint8_t *buf, size_t len);
static void uart_print_dec(uint32_t val);
static void uart_print_cycles(uint32_t cycles);
static uint32_t systick_elapsed(uint32_t start, uint32_t end);

/* SysTick Timing Helper Functions */
/**
 * @brief Read current SysTick counter value
 * @return Current counter value
 * 
 */
static inline uint32_t systick_now(void) {
    return SysTickValueGet();
}

/**
 * @brief Compute elapsed cycles between two SysTick readings
 * 
 */
static uint32_t systick_elapsed(uint32_t start, uint32_t end) {
    if (start >= end) {
        return start - end;
    }
    return (SYSCLK_HZ - 1 - end) + start;
}

/**
 * @brief FrodoKEM-1344-AES
 * 
 * Initializes hardware, runs KeyGen/Encaps/Decaps, reports timing
 * and correctness over UART0
 * 
 */
int main(void) {
    uint32_t t0, t1;
    uint32_t cycles_keygen, cycles_encaps, cycles_decaps;
    bool ss_match;

    clock_init();
    uart_init();
    gpio_init();

    SysTickPeriodSet(SYSCLK_HZ - 1);
    SysTickEnable();

    uart_print("\r\n");
    uart_print("=================================\r\n");
    uart_print("    FrodoKEM-1344-AES on T4MC123GH6PM\r\n");
    uart_print("=================================\r\n\r\n");

/* Print build config */
#ifdef FRODO_RNG_ADC
    uart_print("[RNG] ADC Noise Harvesting (PE3 floating)\r\n");
#else
    uart_print("[RNG] Fixed seed...\r\n");
#endif
    uart_print("[CLK] 80 MHz \r\n");
    uart_print("[UART] 115200 8N1 via ICDI\r\n\r\n");
    /* Print key sizes */
    uart_print("[SIZE] pk  = ");
    uart_print_dec(FRODO_PK_BYTES);
    uart_print(" bytes\r\n");
    uart_print("[SIZE] sk  = ");
    uart_print_dec(FRODO_SK_BYTES);
    uart_print(" bytes\r\n");
    uart_print("[SIZE] ct  = ");
    uart_print_dec(FRODO_CT_BYTES);
    uart_print(" bytes\r\n");
    uart_print("[SIZE] ss  = ");
    uart_print_dec(FRODO_SS_BYTES);
    uart_print(" bytes\r\n\r\n");

    /* ── Frodo.KeyGen ── */
    uart_print("[KEM]  Running Frodo.KeyGen...\r\n");
    GPIOPinWrite(LED_BASE, LED_GREEN, LED_GREEN); /* green on */
    t0 = systick_now();
    frodo_keygen(pk, sk);
    t1 = systick_now();
    GPIOPinWrite(LED_BASE, LED_GREEN, 0);
    cycles_keygen = systick_elapsed(t0, t1);

    uart_print("[KEM]  KeyGen complete\r\n");
    uart_print("[KEM]  pk[0..7]: ");
    uart_print_hex(pk, 8);
    uart_print("\r\n");
    uart_print("[TIME] KeyGen: ");
    uart_print_cycles(cycles_keygen);
    uart_print("\r\n\r\n");

    /* ── Frodo.Encaps ── */
    uart_print("[KEM]  Running Frodo.Encaps...\r\n");
    GPIOPinWrite(LED_BASE, LED_GREEN, LED_GREEN);
    t0 = systick_now();
    frodo_encaps(ct, ss_enc, pk);
    t1 = systick_now();
    GPIOPinWrite(LED_BASE, LED_GREEN, 0);
    cycles_encaps = systick_elapsed(t0, t1);

    uart_print("[KEM]  Encaps complete\r\n");
    uart_print("[KEM]  ss_enc[0..7]: ");
    uart_print_hex(ss_enc, 8);
    uart_print("\r\n");
    uart_print("[TIME] Encaps: ");
    uart_print_cycles(cycles_encaps);
    uart_print("\r\n\r\n");

    /* ── Frodo.Decaps ── */
    uart_print("[KEM]  Running Frodo.Decaps...\r\n");
    GPIOPinWrite(LED_BASE, LED_GREEN, LED_GREEN);
    t0 = systick_now();
    frodo_decaps(ss_dec, ct, sk);
    t1 = systick_now();
    GPIOPinWrite(LED_BASE, LED_GREEN, 0);
    cycles_decaps = systick_elapsed(t0, t1);

    uart_print("[KEM]  Decaps complete\r\n");
    uart_print("[KEM]  ss_dec[0..7]: ");
    uart_print_hex(ss_dec, 8);
    uart_print("\r\n");
    uart_print("[TIME] Decaps: ");
    uart_print_cycles(cycles_decaps);
    uart_print("\r\n\r\n");

    /* ── Verify shared secrets match ── */
    ss_match = (memcmp(ss_enc, ss_dec, FRODO_SS_BYTES) == 0);

    uart_print("========================================\r\n");
    uart_print("[RESULT] Shared secret match: ");
    uart_print(ss_match ? "PASS\r\n" : "FAIL\r\n");
    uart_print("[RESULT] Total cycles: ");
    uart_print_dec(cycles_keygen + cycles_encaps + cycles_decaps);
    uart_print("\r\n");
    uart_print("========================================\r\n");

    /* ── Set LED based on result ── */
    if (ss_match) {
        GPIOPinWrite(LED_BASE, LED_GREEN | LED_RED, LED_GREEN);
    } else {
        GPIOPinWrite(LED_BASE, LED_GREEN | LED_RED, LED_RED);
    }

    while (1) {}
    return 0;
}

/**
 * @brief Configure system clock to 80 MHz via PLL.
 */
static void clock_init(void) {
    SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL |
                   SYSCTL_OSC_MAIN   | SYSCTL_XTAL_16MHZ);
}

/**
 * @brief Initialize UART0 at 115200 8N1 on PA0/PA1.
 */
static void uart_init(void) {
    SysCtlPeripheralEnable(UART_GPIO_PERIPH);
    SysCtlPeripheralEnable(UART_PERIPH);
    while (!SysCtlPeripheralReady(UART_GPIO_PERIPH)) {}
    while (!SysCtlPeripheralReady(UART_PERIPH)) {}

    GPIOPinConfigure(GPIO_PA0_U0RX);
    GPIOPinConfigure(GPIO_PA1_U0TX);
    GPIOPinTypeUART(UART_GPIO_BASE, UART_RX_PIN | UART_TX_PIN);

    UARTConfigSetExpClk(UART_BASE, SysCtlClockGet(), BAUD_RATE,
                        UART_CONFIG_WLEN_8  |
                        UART_CONFIG_STOP_ONE |
                        UART_CONFIG_PAR_NONE);
    UARTEnable(UART_BASE);
}

/**
 * @brief Initialize PF1 (red) and PF3 (green) LEDs as outputs.
 */
static void gpio_init(void) {
    SysCtlPeripheralEnable(LED_PERIPH);
    while (!SysCtlPeripheralReady(LED_PERIPH)) {}
    GPIOPinTypeGPIOOutput(LED_BASE, LED_GREEN | LED_RED);
    GPIOPinWrite(LED_BASE, LED_GREEN | LED_RED, 0);
}

/* -------------------------------------------------------------------------
 * UART Output Utilities
 * ------------------------------------------------------------------------- */

/**
 * @brief Transmit a null-terminated string over UART0.
 * @param[in] str Null-terminated string
 */
static void uart_print(const char *str) {
    while (*str) {
        UARTCharPut(UART_BASE, (unsigned char)*str++);
    }
}

/**
 * @brief Print len bytes of buf as uppercase hex over UART0.
 * @param[in] buf Byte array to print
 * @param[in] len Number of bytes to print
 */
static void uart_print_hex(const uint8_t *buf, size_t len) {
    const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        UARTCharPut(UART_BASE, hex[(buf[i] >> 4) & 0xF]);
        UARTCharPut(UART_BASE, hex[buf[i] & 0xF]);
    }
}

/**
 * @brief Print a uint32_t as unsigned decimal over UART0.
 * @param[in] val Value to print
 */
static void uart_print_dec(uint32_t val) {
    char buf[11];
    int i = 10;
    buf[10] = '\0';
    if (val == 0) { uart_print("0"); return; }
    while (val > 0 && i > 0) {
        buf[--i] = '0' + (val % 10);
        val /= 10;
    }
    uart_print(&buf[i]);
}

/**
 * @brief Print cycle count with millisecond conversion at 80 MHz.
 *
 * Prints as "N cycles (M.mm ms)" for easy reading in the report.
 *
 * @param[in] cycles Elapsed clock cycles at 80 MHz
 */
static void uart_print_cycles(uint32_t cycles) {
    /* cycles / 80000 = milliseconds, keep 2 decimal places */
    uint32_t ms_whole = cycles / 80000;
    uint32_t ms_frac  = (cycles % 80000) / 800;

    uart_print_dec(cycles);
    uart_print(" cycles (");
    uart_print_dec(ms_whole);
    uart_print(".");
    if (ms_frac < 10) uart_print("0");
    uart_print_dec(ms_frac);
    uart_print(" ms)");
}