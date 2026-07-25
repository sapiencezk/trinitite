/*
 * Image load: contiguous .text/.rodata/.data from 0x80000.
 * Must stay below UART_RXBUF (0xF8000) / TIB (0xFF000) / FORTH (0x100000).
 *
 * .bss lives at BSS_BASE (0x08000000) — not adjacent to the image — so
 * growth cannot land on the Forth dictionary (see memory.h).
 */
SECTIONS {
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
}
