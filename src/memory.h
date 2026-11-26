#pragma once

#include "platform.h"

/*
 * Trinitite physical memory map
 * RPi 3: 1GB RAM (0x00000000 - 0x3FFFFFFF)
 * MMIO:  0x3F000000 - 0x3FFFFFFF (reserved, do not use)
 *
 * All addresses are absolute physical. Store absolute pointers
 * in noun cells — never region-relative offsets.
 */

/*
 * C .bss (linker.ld): absolute window, NOT adjacent to the image.
 * Must not overlap the cue high-RAM table. 32 MB is reserved; linker.ld
 * rejects every build whose .bss crosses BSS_TOP.
 */
#define BSS_BASE            PLATFORM_BSS_BASE
#define BSS_SIZE            0x02000000  /* 32 MB reserve */
#define BSS_TOP             (BSS_BASE + BSS_SIZE)

/* Core 0 C stack. The boot path (boot.s) fills this fixed region with a
 * known pattern before entering C. */
#define CORE0_STACK_BASE    PLATFORM_CORE0_STACK_BASE
#define CORE0_STACK_TOP     PLATFORM_CORE0_STACK_TOP

/*
 * Noun cell heap (split bump):
 *   PERSIST  HEAP_BASE .. HEAP_PERSIST_TOP  — live gate, event queue, tokens
 *   SCRATCH  HEAP_SCRATCH_BASE .. HEAP_TOP  — per-slam Nock product; reset
 *                                            after each event (host ArenaHost)
 * Production: HEAP_TOP ≤ ATOM_INDEX_BASE (silent overrun stomped atom index).
 * LITE_UNJETTED relocates scratch to high qemu RAM; persist still precedes
 * the atom index.
 */
#define HEAP_BASE           PLATFORM_HEAP_BASE
#define HEAP_SIZE           0x04000000  /* 64MB total */
#define HEAP_TOP            (HEAP_BASE + HEAP_SIZE)
/*
 * Persist is dual-space compacted each promote (from/to halves).
 * Scratch holds one slam product; reset after event.
 */
#define HEAP_PERSIST_SIZE   0x02000000  /* 32MB total (2×16MB semispace) */
#define HEAP_PERSIST_TOP    (HEAP_BASE + HEAP_PERSIST_SIZE)
#define HEAP_PERSIST_HALF   (HEAP_PERSIST_SIZE / 2)
#define HEAP_SCRATCH_BASE   HEAP_PERSIST_TOP
#define HEAP_SCRATCH_SIZE   (HEAP_TOP - HEAP_SCRATCH_BASE)  /* 32MB */
#if defined(LITE_UNJETTED)
#if !defined(TRINITITE_PLATFORM_QEMU_VIRT)
#error LITE_UNJETTED requires PLATFORM=qemu-virt
#endif
/*
 * Diagnostic image only (LITE_UNJETTED requires qemu-virt). Production
 * persist stays put; scratch moves to high RAM past pill (0x50000000)
 * and the plan blob (0x51000000). In-place 32MB scratch holds only
 * 1.398M 24-byte cells and crashed (`scratch exhausted`) before the
 * 2.048M diagnostic budget of the time (16x the 128,000-cell production
 * cap before 1499kernel row 385). 64MB holds 2.796M cells.
 */
#undef HEAP_SCRATCH_BASE
#undef HEAP_SCRATCH_SIZE
#undef HEAP_TOP
#define HEAP_SCRATCH_BASE (PLATFORM_DRAM_BASE + 0x20000000ULL)
#define HEAP_SCRATCH_SIZE 0x04000000ULL
#define HEAP_TOP (HEAP_SCRATCH_BASE + HEAP_SCRATCH_SIZE)
#endif

/*
 * Atom store: content-addressed (type-10) atom cache.
 * Index: hash table mapping 62-bit BLAKE3 prefix -> atom struct pointer.
 * Data:  atom structs for interned content atoms.
 * Phase 6 adds SD card cold store behind this hot cache.
 */
#define ATOM_INDEX_BASE     PLATFORM_ATOM_INDEX_BASE
#define ATOM_INDEX_SIZE     0x00100000  /* 1MB — hash table */
#define ATOM_DATA_BASE      PLATFORM_ATOM_DATA_BASE
#define ATOM_DATA_SIZE      0x00400000  /* 4MB — atom struct storage */
#define ATOM_DATA_TOP       (ATOM_DATA_BASE + ATOM_DATA_SIZE)

/* Layout: heap → atom index → atom data → … → MMIO. No silent overlap.
 * LITE_UNJETTED relocates scratch to high qemu RAM; persist still ends at
 * HEAP_PERSIST_TOP, which stays ≤ ATOM_INDEX_BASE. */
#if !defined(LITE_UNJETTED)
#if HEAP_TOP > ATOM_INDEX_BASE
#error "noun heap overlaps atom index (HEAP_TOP > ATOM_INDEX_BASE)"
#endif
#else
#if HEAP_PERSIST_TOP > ATOM_INDEX_BASE
#error "persist heap overlaps atom index"
#endif
#if HEAP_SCRATCH_BASE < (PLATFORM_PILL_BASE + 0x02000000ULL)
#error "unjetted scratch overlaps pill/plan"
#endif
#endif
#if (ATOM_INDEX_BASE + ATOM_INDEX_SIZE) > ATOM_DATA_BASE
#error "atom index overlaps atom data"
#endif
#if ATOM_DATA_TOP > (PLATFORM_DRAM_BASE + 0x3F000000ULL)
#error "Atom store region overlaps MMIO"
#endif

/*
 * Row 212 (running log and ring): the recorder ring's RAM window (src/lite_ring.c), only with
 * LITE_CHECKPOINT_EVERY > 0 and LITE_LOG. It starts at DRAM + 0x30000000,
 * above every region below it (heap incl. the LITE_UNJETTED scratch, atom
 * store, cold window, pill scratch, and the pill, plan and app slots, which
 * end by PILL_BASE + 0x10000000), and must end below MMIO.
 */
#if defined(LITE_CHECKPOINT_EVERY) && LITE_CHECKPOINT_EVERY > 0 && defined(LITE_LOG)
#ifndef LITE_RING_BYTES
#define LITE_RING_BYTES 67108864ULL
#endif
#define LITE_RING_WINDOW_BASE (PLATFORM_DRAM_BASE + 0x30000000ULL)
#define LITE_RING_WINDOW_TOP  (LITE_RING_WINDOW_BASE + (LITE_RING_BYTES))
#if HEAP_TOP > LITE_RING_WINDOW_BASE
#error "noun heap overlaps the ring window"
#endif
#if ATOM_DATA_TOP > LITE_RING_WINDOW_BASE
#error "atom store overlaps the ring window"
#endif
#if (PLATFORM_COLD_BASE + 0x00800000ULL) > LITE_RING_WINDOW_BASE
#error "cold window overlaps the ring window"
#endif
#if (PLATFORM_PILL_BASE + 0x10000000ULL) > LITE_RING_WINDOW_BASE
#error "pill, plan and app slots overlap the ring window"
#endif
#if LITE_RING_WINDOW_TOP > (PLATFORM_DRAM_BASE + 0x3F000000ULL)
#error "ring window overlaps MMIO"
#endif
#endif

/*
 * Row 221 (row 212 (c)): the code region. Only with LITE_CHECKPOINT_EVERY > 0
 * and LITE_LOG (the row 212 flags, off by default). At boot the host cues
 * the pill's kernel and runs the kick into this fixed region once, with the
 * poke and peek formulas. Nothing writes to it after that, and no persist
 * flip or reset touches it. If the build overflows it, boot halts with
 * `LITEH terminal=code-region`; it never spills into a persist half.
 */
#if defined(LITE_CHECKPOINT_EVERY) && LITE_CHECKPOINT_EVERY > 0 && defined(LITE_LOG)
#define LITE_COMPACT 1
#define LITE_CODE_BASE (PLATFORM_DRAM_BASE + 0x0D000000ULL)
#define LITE_CODE_SIZE 0x00C00000ULL /* 12 MiB */
#define LITE_CODE_TOP  (LITE_CODE_BASE + LITE_CODE_SIZE)
#if LITE_CODE_BASE < (PLATFORM_CUE_CACHE_BASE + 0x01800000ULL)
#error "code region overlaps the cue cache"
#endif
#if LITE_CODE_BASE < BSS_TOP
#error "code region overlaps .bss"
#endif
#if LITE_CODE_TOP > PLATFORM_PILL_BASE
#error "code region overlaps the pill, plan and app slots"
#endif
#if LITE_CODE_TOP > LITE_RING_WINDOW_BASE
#error "code region overlaps the ring window"
#endif
#if LITE_CODE_TOP > (PLATFORM_DRAM_BASE + 0x3F000000ULL)
#error "code region overlaps MMIO"
#endif
#if LITE_CODE_TOP > 0x100000000ULL
#error "code region must sit below 4 GiB (32-bit cell pointers)"
#endif
#endif

/*
 * Row 317 (3), question 7, sized in row 317 round 3 (question 11 (B), ckpt_jam.h): the checkpoint
 * region. With LITE_CHECKPOINT_EVERY > 0 only. Between the code region (or
 * .bss and the cue scratch) and the pill:
 *   +0x0000000  ckpt jam backref cache, 2^19 entries      12 MiB
 *   +0x0C00000  ckpt jam mug memo, 2^18 entries             4 MiB
 *   +0x1000000  ckpt jam buffer (CKPT_JAM_MAX_BYTES + cur)  5 MiB slot
 *   +0x1500000  cold.c object scratch (jam_scratch)         4 MiB
 *   +0x1900000  cold.c append scratch                       4 MiB
 * Not zeroed at boot: lite_host_boot calls ckpt_jam_reset before first use;
 * the buffer and the scratches are written before they are read.
 */
#if defined(LITE_CHECKPOINT_EVERY) && LITE_CHECKPOINT_EVERY > 0
#define LITE_CKPT_JAM_BASE (PLATFORM_DRAM_BASE + 0x0E000000ULL)
#define LITE_CKPT_JAM_SIZE 0x01D00000ULL /* 29 MiB */
#define LITE_CKPT_JAM_TOP  (LITE_CKPT_JAM_BASE + LITE_CKPT_JAM_SIZE)
#define LITE_CKPT_JAM_MEMO_OFF 0x00C00000ULL
#define LITE_CKPT_JAM_BUF_OFF  0x01000000ULL
#define LITE_CKPT_JAM_COLD_OFF 0x01500000ULL
#define LITE_CKPT_JAM_APPEND_OFF 0x01900000ULL
#define LITE_CKPT_COLD_SCRATCH_BYTES 0x00400000ULL
#if LITE_CKPT_JAM_APPEND_OFF + LITE_CKPT_COLD_SCRATCH_BYTES > LITE_CKPT_JAM_SIZE
#error "checkpoint region slots exceed the region"
#endif
#if LITE_CKPT_JAM_COLD_OFF + LITE_CKPT_COLD_SCRATCH_BYTES > LITE_CKPT_JAM_APPEND_OFF
#error "cold object scratch overlaps the append scratch"
#endif
#if LITE_CKPT_JAM_BASE < BSS_TOP
#error "checkpoint jam region overlaps .bss"
#endif
#if LITE_CKPT_JAM_BASE < (PLATFORM_CUE_CACHE_BASE + 0x01800000ULL)
#error "checkpoint jam region overlaps the cue cache"
#endif
#if defined(LITE_CODE_TOP) && LITE_CKPT_JAM_BASE < LITE_CODE_TOP
#error "checkpoint jam region overlaps the code region"
#endif
#if LITE_CKPT_JAM_TOP > PLATFORM_PILL_BASE
#error "checkpoint jam region overlaps the pill, plan and app slots"
#endif
#if LITE_CKPT_JAM_TOP > 0x100000000ULL
#error "checkpoint jam region must sit below 4 GiB"
#endif
#if defined(LITE_RING_WINDOW_BASE) && LITE_CKPT_JAM_TOP > LITE_RING_WINDOW_BASE && LITE_CKPT_JAM_BASE < LITE_RING_WINDOW_TOP
#error "checkpoint jam region overlaps the ring window"
#endif
#if LITE_CKPT_JAM_TOP > (PLATFORM_DRAM_BASE + 0x3F000000ULL)
#error "checkpoint jam region overlaps MMIO"
#endif
#endif

/*
 * 1499kernel row 328 (d): the Tip5 walk's tables (nock.c, the
 * hash-hashable-noun jet): a memo of 2^19 slots (key, generation and pool
 * index) over a pool of 2^18 digests, and the walk's task and result
 * stacks. LITE_HOST only; other builds keep small tables in .bss. Not zeroed
 * at boot: the slot table is cleared before its first use.
 *   +0x0000000  memo keys, 2^19 x 8                          4 MiB
 *   +0x0400000  memo tags, 2^19 x 8                          4 MiB
 *   +0x0800000  digest pool, 2^18 x 40                      10 MiB
 *   +0x1200000  task stack, 2^16 x 8 (+ 2^16 kinds)        576 KiB
 *   +0x1300000  result stack, 2^16 x 4                     256 KiB
 */
#define LITE_TIP5_BASE (PLATFORM_DRAM_BASE + 0x28000000ULL)
#define LITE_TIP5_SIZE 0x01400000ULL /* 20 MiB */
#define LITE_TIP5_TOP  (LITE_TIP5_BASE + LITE_TIP5_SIZE)
#if LITE_TIP5_BASE < HEAP_TOP
#error "tip5 region overlaps the noun heap"
#endif
#if LITE_TIP5_BASE < (PLATFORM_PILL_BASE + 0x10000000ULL)
#error "tip5 region overlaps the pill, plan and app slots"
#endif
#if defined(LITE_RING_WINDOW_BASE) && LITE_TIP5_TOP > LITE_RING_WINDOW_BASE && LITE_TIP5_BASE < LITE_RING_WINDOW_TOP
#error "tip5 region overlaps the ring window"
#endif
#if LITE_TIP5_TOP > (PLATFORM_DRAM_BASE + 0x3F000000ULL)
#error "tip5 region overlaps MMIO"
#endif

/*
 * PILL_BASE carries the pill: u64 jam length, shape byte (2 = NockApp),
 * 7 bytes, then the kernel jam at +16 (lite_host.c, read_pill). The plan and
 * the application bundle follow it (lite_host.h).
 *
 * 256 MB: safely above all allocators and below MMIO (0x3F000000).
 */
#define PILL_BASE  PLATFORM_PILL_BASE

/*
 * Phase 5 — cold store (content-addressed jam blobs) at fixed PA.
 * Working copy is always this RAM window. NV = semihost flush to host
 * "cold.img", reloaded on next QEMU boot via:
 *   -device loader,file=cold.img,addr=0x07100000,force-raw=on
 * SDHCI can replace flush later without moving the window.
 */
#define COLD_BASE           PLATFORM_COLD_BASE
#define COLD_SIZE           0x00800000  /* 8 MB */
#define COLD_TOP            (COLD_BASE + COLD_SIZE)
