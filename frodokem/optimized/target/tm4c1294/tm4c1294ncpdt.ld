MEMORY {
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 1024K     /* Flash Size */
    SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 256K      /* SRAM Size */
}

_stack_size = 0x4000;   /* 16 KB */
_estack = ORIGIN(SRAM) + LENGTH(SRAM);

SECTIONS {
    /* Vector Table + User Code --> Flash */
    .text : {
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    /* Init data lives in flash, runs in SRAM */
    /* _data_load --> where init data sits in flash */
    _data_load = LOADADDR(.data);

    .data : {
        . = ALIGN(4);
        _data_start = .;
        *(.data*)
        . = ALIGN(4);
        _data_end = .;
    } > SRAM AT > FLASH

    /* Zero-init data --> no flash storage needed */
    .bss : {
        . = ALIGN(4);
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;
    } > SRAM

    /* Heap begins after SRAM allocations */
    . = ALIGN(8);
    _heap_start = .;

    /* Stack occupies top of SRAM */
    _stack_top = _estack;
    _stack_limit = _estack - _stack_size;

    /* Heap may use everything below reserved stack area */
    _heap_end = _stack_limit;

    ASSERT(_heap_start <= _heap_end, "ERROR: RAM overflow, no room for heap/stack")
}