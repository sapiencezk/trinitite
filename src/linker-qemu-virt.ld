/* QEMU virt AArch64 RAM begins at 0x40000000.  The image is loaded at the
 * conventional 0x40080000 kernel address; the rest of the layout preserves
 * the existing relative offsets without changing Nock or IEC semantics. */
ENTRY(_start)
SECTIONS {
    __core0_stack_base = 0x40040000;
    __core0_stack_top = 0x40080000;
    . = 0x40080000;
    __text_start = .;
    .text.boot : { *(.text.boot) }
    .text       : { *(.text) }
    __text_end = .;
    __rodata_start = .;
    .rodata     : { *(.rodata*) }
    __rodata_end = .;
    .data       : { *(.data*) }

    . = 0x48000000;
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss)
        *(COMMON)
        __bss_end = .;
    }
    ASSERT(__bss_end <= 0x49800000,
           ".bss exceeds admitted 75% of the qemu-virt 32 MiB window")
    ASSERT(__bss_end <= 0x4A000000,
           ".bss exceeds reserved qemu-virt 32 MiB window")
}
