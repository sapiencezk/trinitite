#pragma once

/*
 * I3 production admission for the lite-node NockApp host (I3_HOST).
 * M12's i2_admission_envelope.h is unchanged so `make` default stays m12.
 * Sized from L0.1 mini cue (cells 276545 / cache 553091 / work 8636577 /
 * depth 625) plus kernel.jam (287450 cells / 294685 unique) with headroom.
 * Per-slam numbers are the jetted R1 golden with headroom; I3_HOST enforces
 * them via nock_budget_set_limits / nock_eval_stack_set_limit.
 */
/* Decision 77. The plan blob is at PILL_BASE + 0x01000000 (i3_host.h).
 * The pill header is 16 bytes, so a jam of this length ends on the last
 * byte before the plan. The other ceilings stay: each sizes a fixed buffer
 * or the C stack. */
#define I3_CUE_MAX_INPUT_BYTES (0x01000000u - 16u)
#define I3_CUE_MAX_ATOM_BYTES 262144u
#define I3_CUE_MAX_TOTAL_ATOM_BYTES 2097152u
#define I3_CUE_CACHE_ENTRIES 1048576u
#define I3_CUE_CACHE_ADMITTED 1048576u
#define I3_CUE_MAX_WORK 20000000ULL
#define I3_CUE_MAX_BACKREFS 600000u
#define I3_CUE_MAX_DEPTH 1024u
#define I3_CUE_MAX_NODES 1200000u
#define I3_CUE_MAX_CELLS 600000u

/* 1499kernel row 385 (Guillaume, 2026-11-25: "Not hard: raise it"). A
 * management START runs the rows it releases in its own poke, up to the 16
 * rows a resource queue holds. The heaviest measured (QEMU, row 385's
 * kernel.jam with row 386, traced): a device START over 16 kept rows of
 * lite_probe's monolithic two-leaf-transfer, 2,396,612 ops / 806,652
 * cells / stack 92; 16 kept boundary rows of pipeline-local-processing,
 * 2,316,212 / 770,821 / 164. The caps are about 1.5x that: 4,000,000 ops
 * (1.67x) and 1,200,000 cells (1.49x). Memory: 1,200,000 x 24 bytes =
 * 27.5 MiB, plus an admitted input (65,536 cells, 1.5 MiB) decoded into
 * the same scratch = 29.0 MiB of its 32 MiB (memory.h, 1,398,101 cells),
 * 3.0 MiB to spare. The stack peak is 164 of 1,024; it stays. */
#define I3_SLAM_MAX_OPS 4000000ULL
#define I3_SLAM_MAX_CELLS 1200000ULL
#define I3_SLAM_MAX_STACK 1024ULL
#if defined(I3_UNJETTED)
/*
 * Diagnostic image only (I3_UNJETTED requires I3_L1_PROBE=1). Production
 * numbers above stay as they are. 16x ops and cells is the diagnostic
 * budget; the cells part is past what the 64 MiB unjetted scratch in
 * memory.h holds (2.796M cells), so an unjetted slam that large stops
 * with `scratch exhausted` before the cell cap. Stack 1024 already covers
 * the unjetted peak. Kernel pokes still abort at this cap — recorded,
 * not raised further.
 */
#undef I3_SLAM_MAX_OPS
#undef I3_SLAM_MAX_CELLS
#define I3_SLAM_MAX_OPS (4000000ULL * 16)
#define I3_SLAM_MAX_CELLS (1200000ULL * 16)
#endif
