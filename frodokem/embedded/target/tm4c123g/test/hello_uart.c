/**
 * @file hello_uart.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief Build System Test for TM4C123GH6PM
 * @version 0.1
 * @date 2026-04-12
 * 
 * Verifies the full toolchain and board interface before attempting
 * to flash FrodoKEM.
 * 
 * @note Capture UART output on host with:
 *       tio -b 115200 /dev/tty.usbmodem* --log --log-file build/hello.txt
 * 
 * @note Flash with: make flash_tm4c123gh6pm-hello
 *
 * @copyright Copyright (c) 2026
 */
#include <stdbool.h>
#include <stdint.h>

#define PART_TM4C123GH6PM

#include "../../tivaware/driverlib/gpio.h"
#include "../../tivaware/driverlib/pin_map.h"
#include "../../tivaware/driverlib/sysctl.h"
#include "../../tivaware/driverlib/uart.h"
#include "../../tivaware/inc/hw_memmap.h"
#include "../../tivaware/inc/hw_types.h"
#include "../../tivaware/inc/tm4c123gh6pm.h"

/* Pin & Peripheral Constants */
#define LED_PERIPH SYSCTL_PERIPH_GPIOF       // GPIO Port F Peripheral
#define LED_BASE   GPIO_PORTF_BASE           // GPIO Port F Base Address
#define LED_PIN    GPIO_PIN_2                // PF2 = Onboard Blue LED

#define UART_PERIPH      SYSCTL_PERIPH_UART0 // UART0 Peripheral
#define UART_GPIO_PERIPH SYSCTL_PERIPH_GPIOA // GPIO Port A Peripheral
#define UART_BASE        UART0_BASE          // UART0 Base Address
#define UART_GPIO_BASE   GPIO_PORTA_BASE     // GPIO Port A Base Address
#define UART_RX_PIN      GPIO_PIN_0          // PA0 = U0RX
#define UART_TX_PIN      GPIO_PIN_1          // PA1 = U0TX

/* Clock & UART Configuration */
#define SYSCLK_HZ 80000000UL // 80 MHz
#define BAUD_RATE 115200UL   // UART baud rate

/* Memory Verification Constants */
#define EXPECTED_FLASH_KB 256U // TM4C123GH6PM flash size in KiB
#define EXPECTED_SRAM_KB  32U  // TM4C123GH6PM SRAM size in KiB

/* Startup Verification Global Identifiers */

// Startup copies to SRAM
static uint32_t g_data_test = 0xDEADBEEF;

// Startup must zero this
static uint32_t g_bss_test;

/* Function Prototypes */
static void clock_init(void);
static void uart_init(void);
static void gpio_init(void);
static void uart_print(const char *str);
static void uart_print_hex(uint32_t val);
static void uart_print_dec(uint32_t val);
static void delay(uint32_t count);
static void verify_memory(void);

/**
 * @brief Board initialization + startup entry point
 * 
 * Initializes clock, UART, and GPIO then runs startup verification
 * program; checks before entering the LED blink loop.
 * 
 * @return int 
 */
int main(void) {
    // Initialize peripherals + system clock
    clock_init();
    uart_init();
    gpio_init();

    // Print out over UART
    uart_print("\r\n");
    uart_print("========================================\r\n");
    uart_print("  Build OK\r\n");
    uart_print("  TM4C123GH6PM Test\r\n");
    uart_print("========================================\r\n");

    // Verify .data section
    uart_print("\r\n[.data] g_data_test = 0x");
    uart_print_hex(g_data_test);
    if (g_data_test == 0xDEADBEEF) {
        uart_print(" [+] PASS\r\n");
    } else {
        uart_print(" [!] FAIL (startup .data copy broken)\r\n");
    }

    // Verify .bss section
    uart_print("[.bss]  g_bss_test  = 0x");
    uart_print_hex(g_bss_test);
    if (g_bss_test == 0U) {
        uart_print(" [*] PASS\r\n");
    } else {
        uart_print(" [!] FAIL (startup .bss zero broken)\r\n");
    }

    // Verify memory sizes via SYSCTL_DC0 access
    verify_memory();

    uart_print("\r\n[LOOP] Blinking LED and echoing heartbeat...\r\n");
    uart_print("----------------------------------------\r\n");

    uint32_t count = 0;
    while (1) {
        // Toggle Blue LED
        GPIOPinWrite(LED_BASE, LED_PIN, GPIOPinRead(LED_BASE, LED_PIN) ^ LED_PIN);

        // Print heartbeat
        uart_print("[");
        uart_print_dec(count++);
        uart_print("] Build OK\r\n");

        delay(4000000UL); // approx. 0.5s at 80 MHz
    }
}

/**
 * @brief Configure system clock to 80 MHz.
 * 
 * Uses the 16 MHz onboard crystal as the reference.
 * 
 * @note SYSCTL_SYSDIV_2_5 divides the 200 MHz output by 2.5 -> 80 MHz
 */
static void clock_init(void) {
    SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_OSC_MAIN | SYSCTL_XTAL_16MHZ);
}

/**
 * @brief Initialize UART0 at 115200 8N1 on PA0/PA1
 * 
 * @note PA0 = U0RX
 * @note PA1 = U0TX
 * @note Routed to the host via the ICDI USB virtual COM port
 */
static void uart_init(void) {
    SysCtlPeripheralEnable(UART_GPIO_PERIPH);
    SysCtlPeripheralEnable(UART_PERIPH);

    // Wait for peripherals to be ready
    while (!SysCtlPeripheralReady(UART_GPIO_PERIPH)) {
    }
    while (!SysCtlPeripheralReady(UART_PERIPH)) {
    }

    GPIOPinConfigure(GPIO_PA0_U0RX);
    GPIOPinConfigure(GPIO_PA1_U0TX);
    GPIOPinTypeUART(UART_GPIO_BASE, UART_RX_PIN | UART_TX_PIN);

    UARTConfigSetExpClk(UART_BASE, SysCtlClockGet(), BAUD_RATE,
                        UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE | UART_CONFIG_PAR_NONE);

    UARTEnable(UART_BASE);
}

/**
 * @brief Initialize PF2 as GPIO output for the onboard blue LED.
 */
static void gpio_init(void) {
    SysCtlPeripheralEnable(LED_PERIPH);
    while (!SysCtlPeripheralReady(LED_PERIPH)) {
    }

    GPIOPinTypeGPIOOutput(LED_BASE, LED_PIN);
    // LED off initially
    GPIOPinWrite(LED_BASE, LED_PIN, 0);
}

/**
 * @brief Transmit a null-terminated string over UART0
 * 
 * @param[in] str Null-terminated string
 */
static void uart_print(const char *str) {
    while (*str) {
        UARTCharPut(UART_BASE, (unsigned char)*str++);
    }
}

/**
 * @brief Transmit a 32-bit value as an 8-digit uppercase hex string.
 * 
 * @param[in] val Value to print
 */
static void uart_print_hex(uint32_t val) {
    const char hex[] = "0123456789ABCDEF";
    char buf[9];
    int i;

    for (i = 7; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    buf[8] = '\0';
    uart_print(buf);
}

/**
 * @brief Transmit a 32-bit value as an unsigned decimal string.
 * 
 * @param[in] val Value to print
 */
static void uart_print_dec(uint32_t val) {
    char buf[11];
    int i = 10;

    buf[10] = '\0';
    if (val == 0) {
        uart_print("0");
        return;
    }
    while (val > 0 && i > 0) {
        buf[--i] = '0' + (val % 10);
        val /= 10;
    }
    uart_print(&buf[i]);
}

/**
 * @brief Busy-wait delay loop
 * 
 * @param[in] count Number of NOP iterations.
 * 
 * @note At 80 MHz, approx. 4000000 counts = 0.50 seconds
 */
static void delay(uint32_t count) {
    while (count--) {
        __asm volatile("nop");
    }
}

/**
 * @brief Verify the flash and SRAM sizes via SYSCTL_DC0 register.
 * 
 * Reads the Device Capabilities 0 register and compares the
 * reported flash and SRAM sizes against the values assumed
 * by the linker script.
 * 
 * @warning Mismatch indicates the wrong linker script or wrong chip.
 */
static void verify_memory(void) {
    uint32_t dc0         = HWREG(SYSCTL_BASE + 0x008); // SYSCTL_DC0 offset = 0x008
    uint32_t sram_field  = (dc0 & SYSCTL_DC0_SRAMSZ_M) >> 16;
    uint32_t flash_field = (dc0 & SYSCTL_DC0_FLASHSZ_M);

    // Compare values
    bool sram_ok = (sram_field == ((SYSCTL_DC0_SRAMSZ_32KB & SYSCTL_DC0_SRAMSZ_M) >> 16));
    ;
    bool flash_ok = (flash_field == ((SYSCTL_DC0_FLASHSZ_256K & SYSCTL_DC0_FLASHSZ_M)));

    // Print to UART
    uart_print("\r\n[MEM]  SYSCTL_DC0 = 0x");
    uart_print_hex(dc0);
    uart_print("\r\n");

    uart_print("[MEM]  SRAM  ");
    uart_print_dec(EXPECTED_SRAM_KB);
    uart_print(" KiB -- ");
    uart_print(sram_ok ? "PASS\r\n" : "FAIL (mismatch)\r\n");

    uart_print("[MEM]  Flash ");
    uart_print_dec(EXPECTED_FLASH_KB);
    uart_print(" KiB -- ");
    uart_print(flash_ok ? "PASS\r\n" : "FAIL (mismatch)\r\n");
}