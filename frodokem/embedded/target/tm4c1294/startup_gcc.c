/**
 * @file startup_gcc.c
 * @author Alex Anderson (aandrs@vt.edu)
 * @brief TM4C1294 Startup File with Reset Handler + Interrupt Vector Table
 * @version 0.1
 * @date 2026-04-12
 * 
 * Defines the ARM Cortex-M4F interrupt vector table and Reset Handler
 * for the TM4C1294NCPDT.
 * 
 * @note Exception handlers are weakly aliased to Default_Handler.
 *       Override any handler by defining the function elsewhere in
 *       the project.
 * 
 * @note The Floating Point Unit (FPU) is not enabled in Reset Handler.
 *
 * @copyright Copyright (c) 2026
 */
#include <stddef.h>
#include <stdint.h>

/*  Linker Script Symbols  */
extern uint32_t _data_load;  // start of .data section in flash
extern uint32_t _data_start; // start of .data in SRAM
extern uint32_t _data_end;   // end of .data in SRAM
extern uint32_t _bss_start;  // start of .bss in SRAM
extern uint32_t _bss_end;    // end of .bss in SRAM
extern uint32_t _stack_top;  // initial stack pointer

/*  Forward Declarations/Prototypes  */
void Reset_Handler(void);
void Default_Handler(void);
int main(void);

/* Exception Handlers */
void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

/**
 * @brief Interrupt Vector Table
 * 
 * Placed in .isr_vector by the linker script so it can be found
 * at the start of flash (offset 0x0000.0000).
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

    // 0x0000.0040+ TM4C1294 peripheral interrupt/exception handlers, as
    // needed
};

/**
  * @brief First code executed after boot or reset.
  * 
  * Performs the minimum C runtime setup required before calling main()
  * 
  * @note Sequence is:
  * @note   1. Copy init data from flash to SRAM
  * @note   2. Zeros uninit data section
  * @note   3. Calls main()
  * @note   4. Hangs if main() returns
  */
void Reset_Handler(void) {
    uint32_t *src, *dst;

    /* Copy .data from flash to SRAM */
    src = &_data_load;
    dst = &_data_start;
    while (dst < &_data_end) {
        *dst++ = *src++;
    }

    /* Zero data in .bss */
    dst = &_bss_start;
    while (dst < &_bss_end) {
        *dst++ = 0;
    }

    /* Call user program */
    (void)main();

    /* Hang if main() returns */

    while (1) {
    }
}

/**
 * @brief Catch-all handler for unhandled interrupts and faults.
 * 
 * Spins indefinitely so a debugger can half execution and identify
 * which vector triggered the unhandled exception via the IPSR register.
 */
void Default_Handler(void) {
    while (1) {
    }
}