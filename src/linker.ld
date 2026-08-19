/*
 * Image load: contiguous .text/.rodata/.data from 0x80000.
 * Must stay below UART_RXBUF (0xF8000) / TIB (0xFF000) / FORTH (0x100000).
 *
 * .bss lives at BSS_BASE (0x08000000) — not adjacent to the image — so
 * growth cannot land on the Forth dictionary (see memory.h).
 */
SECTIONS {
    __core0_stack_base = 0x00040000;
    __core0_stack_top = 0x00080000;
    . = 0x80000;
    .text.boot : { *(.text.boot) }
    .text       : { *(.text) }
    .rodata     : { *(.rodata*) }
    .data       : { *(.data*) }

    . = 0x08000000;                 /* BSS_BASE — see memory.h */
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss)
        *(COMMON)
        __bss_end = .;
    }
    ASSERT(__bss_end <= 0x09800000,
           ".bss exceeds admitted 75% of the 32 MiB window")
    ASSERT(__bss_end <= 0x0A000000,
           ".bss exceeds reserved 32 MiB window")
}
