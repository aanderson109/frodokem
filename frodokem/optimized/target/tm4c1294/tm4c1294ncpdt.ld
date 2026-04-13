/*************************************************************
 * tm4c1294ncpdt.ld  |   Linker Script for TM4C1294NCPDT
 *
 * Memory Layout:
 *      Flash -> 1024K @ 0x0000.0000 (code, rodata, .data load image)
 *      SRAM  -> 256K  @ 0x2000.0000 (stack, .data, .bss, heap)
 *
 * Section Layout:
 *      .data   ->  initialized global identifiers
 *      .bss    ->  zero-initialized global identifiers
 *      heap    ->  grows upward from _heap_start
 *      stack   ->  grows downward from _stack_top
 *
 * Symbols exported to startup_gcc.c:
 *      _data_load    ->  load address of .data in flash
 *      _data_start   ->  start of .data section in SRAM
 *      _data_end     ->  end of .data in SRAM
 *      _bss_start    ->  start of .bss in SRAM
 *      _bss_end      ->  end of .bss in SRAM
 *      _stack_top    ->  initial stack pointer
 *
 *************************************************************/

/* MEMORY REGIONS */
MEMORY {
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 32K
}

/* STACK CONFIGURATION */
_stack_size = 0x1000;   /* 16 KB */
_estack = ORIGIN(SRAM) + LENGTH(SRAM);

/* SECTIONS */
SECTIONS {

    /* .text section -> code and read-only data */
    .text : {
        KEEP(*(.isr_vector))    /* Interrupt Vector Table */
        *(.text*)               /* All user code */
        *(.rodata*)             /* Read-only data */
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    /* .data section -> initialized global identifiers */
    _data_load = LOADADDR(.data);   /* flash address of .data load image */

    .data : {
        . = ALIGN(4);
        _data_start = .;            /* SRAM start of .data (copy dest) */
        *(.data*)
        . = ALIGN(4);
        _data_end = .;              /* SRAM end of .data */
    } > SRAM AT > FLASH

    /* .bss section -> zero-initialized global identifiers */
    .bss : {
        . = ALIGN(4);
        _bss_start = .;             /* SRAM start of .bss */
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;               /* SRAM end of .bss */
    } > SRAM

    /* Heap + Stack */
    . = ALIGN(8);
    _heap_start = .;                        /* Heap starts after .bss */
    _stack_top = _estack;                   /* Initial stack pointer */
    _stack_limit = _estack - _stack_size;   /* Lowest valid stack address */
    _heap_end = _stack_limit;               /* Heap bounded by stack reserve */

    /* Catch SRAM overflow at link time */
    ASSERT(_heap_start <= _heap_end,
           "ERROR: SRAM overflow -> reduce stack size or reduce .data")
}