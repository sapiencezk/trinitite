.section ".text.boot"
.global _start
.global secondary_entry

// Stack tops for secondaries (must match memory.h)
.set CORE1_STACK_TOP, 0x07004000
.set CORE2_STACK_TOP, 0x07008000
.set CORE3_STACK_TOP, 0x0700C000
.set CORE0_STACK_BASE, 0x00040000
.set CORE0_STACK_TOP,  0x00080000

// cores_ready lives in .data so it is image-loaded as 0 (not wiped mid-race).
    .section .data
    .global cores_ready
    .balign 8
cores_ready:
    .quad   0

    .section ".text.boot"

// ── Core 0 entry (firmware sends only CPU0 here at 0x80000) ───────────────
_start:
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF
    cbnz    x0, .Lpark              // should not happen; park if it does

    // Fill the fixed core-0 C stack before using it. The base word is the
    // hard guard; the remaining pattern is scanned by QEMU evidence.
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

    // Mark runtime ready (secondaries use this after spin-table release)
    ldr     x0, =cores_ready
    mov     x1, #1
    str     x1, [x0]
    dsb     sy
    sev

    bl      main
    b       .Lpark

// ── Secondary landing pad (address written into firmware spin table) ──────
// Firmware parks cores 1–3 watching 0xe0 / 0xe8 / 0xf0.  When we store
// &secondary_entry there and SEV, the core jumps here at EL2 with no stack.
secondary_entry:
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF           // core id (1..3)

    cmp     x0, #1
    b.eq    .Lse1
    cmp     x0, #2
    b.eq    .Lse2
    cmp     x0, #3
    b.eq    .Lse3
    b       .Lpark

.Lse1:
    ldr     x1, =CORE1_STACK_TOP
    mov     sp, x1
    b       .Lse_go
.Lse2:
    ldr     x1, =CORE2_STACK_TOP
    mov     sp, x1
    b       .Lse_go
.Lse3:
    ldr     x1, =CORE3_STACK_TOP
    mov     sp, x1
.Lse_go:
    bl      core_secondary_main     // x0 = core id; never returns
    b       .Lpark

.Lpark:
    wfe
    b       .Lpark
