#pragma once

/*
 * I3 production admission for the lite-node NockApp host (I3_HOST).
 * M12's i2_admission_envelope.h is unchanged so `make` default stays m12.
 * Sized from L0.1 mini cue (cells 276545 / cache 553091 / work 8636577 /
 * depth 625) plus kernel.jam (287450 cells / 294685 unique) with headroom.
 * Per-slam numbers are the jetted R1 golden with headroom; I3_HOST enforces
 * them via nock_budget_set_limits / nock_eval_stack_set_limit.
 */
#define I3_CUE_MAX_INPUT_BYTES 1048576u
#define I3_CUE_MAX_ATOM_BYTES 262144u
#define I3_CUE_MAX_TOTAL_ATOM_BYTES 2097152u
#define I3_CUE_CACHE_ENTRIES 1048576u
#define I3_CUE_CACHE_ADMITTED 1048576u
#define I3_CUE_MAX_WORK 20000000ULL
#define I3_CUE_MAX_BACKREFS 600000u
#define I3_CUE_MAX_DEPTH 1024u
#define I3_CUE_MAX_NODES 1200000u
#define I3_CUE_MAX_CELLS 600000u

#define I3_SLAM_MAX_OPS 2000000ULL
#define I3_SLAM_MAX_CELLS 128000ULL
#define I3_SLAM_MAX_STACK 1024ULL
#if defined(I3_UNJETTED)
/*
 * Diagnostic image only (I3_UNJETTED requires I3_L1_PROBE=1). Production
 * numbers above stay 2e6 / 128000 / 1024. 16× cells (2.048M) and ops
 * (32M) is the diagnostic budget; scratch is sized to match in memory.h.
 * Stack 1024 already covers the unjetted peak. Kernel pokes still abort
 * at this cap — recorded, not raised further.
 */
#undef I3_SLAM_MAX_OPS
#undef I3_SLAM_MAX_CELLS
#define I3_SLAM_MAX_OPS (2000000ULL * 16)
#define I3_SLAM_MAX_CELLS (128000ULL * 16)
#endif
