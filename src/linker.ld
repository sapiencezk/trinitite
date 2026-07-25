/*
 * Image load: code/rodata/data from 0x80000 (below Forth dictionary).
 *
 * .bss must NOT follow .data into 0x8f000–0x490000.  That range is the
 * Forth region (TIB at 0x8f000, dictionary from FORTH_BASE 0x90000,
 * stacks at the top).  Historical bug: .bss after a growing .text landed
 * on top of the dictionary; jam's g_jcache / g_jambuf then corrupted
 * LATEST and FIND broke after the first JAM.  Keep .bss in a high RAM
 * window documented in memory.h (BSS_BASE).
 */
SECTIONS {
    . = 0x80000;
    .text.boot : { *(.text.boot) }
    .text       : { *(.text) }
    .rodata     : { *(.rodata) }
    .data       : { *(.data) }

    . = 0x08000000;                 /* BSS_BASE — see memory.h */
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss)
        *(COMMON)
        __bss_end = .;
    }
}
