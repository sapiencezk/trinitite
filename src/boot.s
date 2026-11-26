.section ".text.boot"
.global _start

// Core 0 stack (must match memory.h). qemu-virt starts RAM at 0x40000000;
// the Pi firmware sends only core 0 here and keeps cores 1-3 parked in its
// spin table, which this image never releases.
#if defined(TRINITITE_PLATFORM_QEMU_VIRT)
.set CORE0_STACK_BASE, 0x40040000
.set CORE0_STACK_TOP,  0x40080000
#else
.set CORE0_STACK_BASE, 0x00040000
.set CORE0_STACK_TOP,  0x00080000
#endif

// ── Core 0 entry (firmware sends only CPU0 here at 0x80000) ───────────────
_start:
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF
    cbnz    x0, .Lpark              // should not happen; park if it does

    // Fill the fixed core-0 C stack with a known pattern before using it.
    ldr     x0, =CORE0_STACK_BASE
    ldr     x1, =CORE0_STACK_TOP
    ldr     x2, =0xA55AC33CA55AC33C
.Lfill_core0_stack:
    cmp     x0, x1
    b.ge    .Lcore0_stack_ready
    str     x2, [x0], #8
    b       .Lfill_core0_stack
.Lcore0_stack_ready:
    mov     sp, x1

    // Zero BSS
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
.Lzero_bss:
    cmp     x0, x1
    b.ge    .Lbss_done
    str     xzr, [x0], #8
    b       .Lzero_bss
.Lbss_done:

    bl      main
    b       .Lpark

.Lpark:
    wfe
    b       .Lpark
