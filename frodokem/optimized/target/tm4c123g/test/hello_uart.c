/*
 * hello_uart.c -> Build system bring-up test for TM4C123GH6PM
 *
 * Verifies:
 *   - Linker script places code correctly in Flash
 *   - Startup file runs, copies .data, zeros .bss, reaches main()
 *   - System clock configures to 80 MHz
 *   - UART0 transmits over PA0/PA1 (exposed via ICDI USB connection)
 *   - GPIO toggles onboard LED (PF2, blue)
 *   - SYSCTL_DC0 register matches linker script memory assumptions
 *
 * Host capture:
 *   tio -b 115200 /dev/tty.usbmodem* --log -log-file tm4c123g/build/hello.txt
 *
 * @author Alex Anderson
 * @course ECE 5580
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

/* 
 * Constants
 */
#define LED_PERIPH SYSCTL_PERIPH_GPIOF
#define LED_BASE   GPIO_PORTF_BASE
#define LED_PIN    GPIO_PIN_2 // PF2 = Blue LED

#define UART_PERIPH      SYSCTL_PERIPH_UART0
#define UART_GPIO_PERIPH SYSCTL_PERIPH_GPIOA
#define UART_BASE        UART0_BASE
#define UART_GPIO_BASE   GPIO_PORTA_BASE
#define UART_RX_PIN      GPIO_PIN_0 // PA0 = U0RX
#define UART_TX_PIN      GPIO_PIN_1 // PA1 = U0TX

#define SYSCLK_HZ 80000000UL // 80 MHz
#define BAUD_RATE 115200UL

/* 
 * Expected memory sizes from linker script
 */
#define EXPECTED_FLASH_KB 256U
#define EXPECTED_SRAM_KB  32U

/* 
 * Static initialized variable
 * Tests .data copy in startup file
 */
static uint32_t g_data_test = 0xDEADBEEF;

/* 
 * Static zero-initialized variable
 * Tests .bss zero in startup file
 */
static uint32_t g_bss_test;

/*
 * Local function prototypes 
 */
static void clock_init(void);
static void uart_init(void);
static void gpio_init(void);
static void uart_print(const char *str);
static void uart_print_hex(uint32_t val);
static void uart_print_dec(uint32_t val);
static void delay(uint32_t count);
static void verify_memory(void);

/* 
 * main function
 */
int main(void) {
    clock_init();
    uart_init();
    gpio_init();

    uart_print("\r\n");
    uart_print("========================================\r\n");
    uart_print("  Build OK\r\n");
    uart_print("  TM4C123GH6PM Test\r\n");
    uart_print("========================================\r\n");

    // Verify .data section -- startup file should have copied this
    uart_print("\r\n[.data] g_data_test = 0x");
    uart_print_hex(g_data_test);
    if (g_data_test == 0xDEADBEEF) {
        uart_print(" [+] PASS\r\n");
    } else {
        uart_print(" [!] FAIL (startup .data copy broken)\r\n");
    }

    // Verify .bss section -- startup file should have zeroed this
    uart_print("[.bss]  g_bss_test  = 0x");
    uart_print_hex(g_bss_test);
    if (g_bss_test == 0U) {
        uart_print(" [*] PASS\r\n");
    } else {
        uart_print(" [!] FAIL (startup .bss zero broken)\r\n");
    }

    // Read SYSCTL_DC0 and verify memory sizes match linker script
    verify_memory();

    uart_print("\r\n[LOOP] Blinking LED and echoing heartbeat...\r\n");
    uart_print("----------------------------------------\r\n");

    uint32_t count = 0;
    while (1) {
        // Toggle LED
        GPIOPinWrite(LED_BASE, LED_PIN,
                     GPIOPinRead(LED_BASE, LED_PIN) ^ LED_PIN);

        // Print heartbeat
        uart_print("[");
        uart_print_dec(count++);
        uart_print("] Build OK\r\n");

        delay(4000000UL); // approx. 0.5s at 80 MHz
    }
}

/* 
 * Clock initialization
 * Configure PLL for 80 MHz from 16 MHz crystal
 */
static void clock_init(void) {
    SysCtlClockSet(SYSCTL_SYSDIV_2_5 | SYSCTL_USE_PLL | SYSCTL_OSC_MAIN |
                   SYSCTL_XTAL_16MHZ);
}

/* 
 * UART0 initialization
 * PA0 = RX, PA1 = TX, 115200 8N1
 * Routed back to host via ICDI USB virtual COM port
 */
static void uart_init(void) {
    SysCtlPeripheralEnable(UART_GPIO_PERIPH);
    SysCtlPeripheralEnable(UART_PERIPH);

    // Wait for peripherals to be ready
    while (!SysCtlPeripheralReady(UART_GPIO_PERIPH))
        ;
    while (!SysCtlPeripheralReady(UART_PERIPH))
        ;

    GPIOPinConfigure(GPIO_PA0_U0RX);
    GPIOPinConfigure(GPIO_PA1_U0TX);
    GPIOPinTypeUART(UART_GPIO_BASE, UART_RX_PIN | UART_TX_PIN);

    UARTConfigSetExpClk(UART_BASE, SysCtlClockGet(), BAUD_RATE,
                        UART_CONFIG_WLEN_8 | UART_CONFIG_STOP_ONE |
                            UART_CONFIG_PAR_NONE);

    UARTEnable(UART_BASE);
}

/* 
 * GPIO initialization
 * PF2 = Blue LED, output
 */
static void gpio_init(void) {
    SysCtlPeripheralEnable(LED_PERIPH);
    while (!SysCtlPeripheralReady(LED_PERIPH))
        ;

    GPIOPinTypeGPIOOutput(LED_BASE, LED_PIN);
    GPIOPinWrite(LED_BASE, LED_PIN, 0); /* LED off initially */
}

/* 
 * UART string transmit
 */
static void uart_print(const char *str) {
    while (*str) {
        UARTCharPut(UART_BASE, (unsigned char)*str++);
    }
}

/*
 * UART hex print -- prints 8-digit hex value
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

/*
 * UART decimal print
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

/*
 * Busy-wait delay
 */
static void delay(uint32_t count) {
    while (count--) {
        __asm volatile("nop");
    }
}

/* 
 * Memory verification
 * Reads SYSCTL_DC0 register and compares against linker script
 */
static void verify_memory(void) {
    uint32_t dc0;
    uint32_t sram_field;
    uint32_t flash_field;
    bool sram_ok;
    bool flash_ok;

    dc0 = HWREG(SYSCTL_BASE + 0x008); /* SYSCTL_DC0 offset = 0x008 */

    sram_field  = (dc0 & SYSCTL_DC0_SRAMSZ_M) >> 16;
    flash_field = (dc0 & SYSCTL_DC0_FLASHSZ_M);

    sram_ok =
        (sram_field == ((SYSCTL_DC0_SRAMSZ_32KB & SYSCTL_DC0_SRAMSZ_M) >> 16));
    flash_ok =
        (flash_field == ((SYSCTL_DC0_FLASHSZ_256K & SYSCTL_DC0_FLASHSZ_M)));

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