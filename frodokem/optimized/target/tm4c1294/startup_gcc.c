/*
 * `startup_gcc.c` -> Reset Handler and Vector Table for TM4C1294NCPDT
 *
 *  Sources:
 *      - TM4C1294NCPDT Datasheet Figure 2-6
 *      - ARM Cortex-M4 TRM
 *      - `hw_memmap.h` from TivaWare Peripheral Library (`driverlib`)
 */

/*  Standard headers  */
#include <stddef.h>
#include <stdint.h>

/*  Linker script symbols  */
extern uint32_t _data_load;
extern uint32_t _data_start;
extern uint32_t _data_end;
extern uint32_t _bss_start;
extern uint32_t _bss_end;
extern uint32_t _stack_top;

/*  Prototypes  */
void Reset_Handler(void);
void Default_Handler(void);
int main(void);

/*  Exception handlers, weak aliased to `Default_Handler`
 *      - Override any of them by defining the function in the user program
 */
void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

/*
 * Vector Table
 * Placed in `.isr_vector` by the linker script (first in flash)
 * Cortex-M4F reads:
 *      [0]  -> initial stack pointer
 *      [1]  -> reset handler
 *      [2]+ -> exception/interrupt handlers
 */
__attribute__((used, section(".isr_vector"))) const uintptr_t vector_table[] = {
    (uintptr_t)&_stack_top,        // 0x0000.0000 Initial Stack Pointer
    (uintptr_t)Reset_Handler,      // 0x0000.0004 Reset
    (uintptr_t)NMI_Handler,        // 0x0000.0008 NMI
    (uintptr_t)HardFault_Handler,  // 0x0000.000C Hard Fault
    (uintptr_t)MemManage_Handler,  // 0x0000.0010 Memory Management Fault
    (uintptr_t)BusFault_Handler,   // 0x0000.0014 Bus Fault
    (uintptr_t)UsageFault_Handler, // 0x0000.0018 Usage Fault
    0,                             // 0x0000.001C Reserved
    0,                             // 0x0000.0020 Reserved
    0,                             // 0x0000.0024 Reserved
    0,                             // 0x0000.0028 Reserved
    (uintptr_t)SVC_Handler,        // 0x0000.002C SVCall
    0,                             // 0x0000.0030 Reserved (Debug)
    0,                             // 0x0000.0034 Reserved
    (uintptr_t)PendSV_Handler,     // 0x0000.0038 PendSV
    (uintptr_t)SysTick_Handler,    // 0x0000.003C SysTick

    // 0x0000.0040+ TM4C123GH6PM peripheral interrupt/exception handlers, as
    // needed
};

/*
 * Reset Handler
 *
 * First code executed following boot/reset. Prepares SRAM then calls `main()`
 * from user program
 */
void Reset_Handler(void) {
    uint32_t *src, *dst;

    // Copy initialized data from flash to SRAM
    src = &_data_load;
    dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    // Zero `bss`
    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0;
    }

    // TODO: Enable FPU before calling code that uses floating point

    // Call `main()`
    (void)main();

    // If `main()` returns, hang
    while (1) {
    }
}

/*
 * Default Handler
 *
 * Catches any unhandled interrupt or fault. Hangs so debugger can identify the
 * problem
 */
void Default_Handler(void) {
    while (1) {
    }
}