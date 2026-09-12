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
 * Must not overlap Forth or the legacy cue high-RAM table. 32 MB is
 * reserved; linker.ld rejects every build whose .bss crosses BSS_TOP.
 */
#define BSS_BASE            PLATFORM_BSS_BASE
#define BSS_SIZE            0x02000000  /* 32 MB reserve */
#define BSS_TOP             (BSS_BASE + BSS_SIZE)

/* Core 0 C stack. The boot path fills this fixed region before entering C;
 * QEMU evidence scans it and the scheduler checks the base guard. */
#define CORE0_STACK_BASE    PLATFORM_CORE0_STACK_BASE
#define CORE0_STACK_TOP     PLATFORM_CORE0_STACK_TOP
#define CORE0_STACK_SIZE    (CORE0_STACK_TOP - CORE0_STACK_BASE)
#define CORE0_STACK_PATTERN 0xA55AC33CA55AC33CULL

/*
 * Forth region: dictionary grows up, stacks grow down.
 * Starts at 1 MB so the kernel image (loaded at 0x80000) can grow past
 * the old 0x90000 boundary without stomping the dictionary / TIB.
 * Ends at ARENA_BASE (0x490000).
 */
#define FORTH_BASE          PLATFORM_FORTH_BASE
#define FORTH_SIZE          0x00390000  /* → 0x00490000 = ARENA_BASE */
#define FORTH_TOP           (FORTH_BASE + FORTH_SIZE)

#if BSS_BASE < FORTH_TOP
#error "BSS_BASE overlaps Forth region"
#endif
#if CORE0_STACK_TOP > FORTH_BASE
#error "core 0 stack overlaps kernel image"
#endif
#if FORTH_TOP > PLATFORM_ARENA_BASE
#error "Forth region overlaps ARENA_BASE"
#endif

/* Forth stacks at top of region, growing down */
#define RSTACK_TOP          (FORTH_TOP)
#define RSTACK_SIZE         0x00010000  /* 64KB return stack */
#define DSTACK_TOP          (RSTACK_TOP - RSTACK_SIZE)
#define DSTACK_SIZE         0x00010000  /* 64KB data stack */
#define DSTACK_GUARD        (DSTACK_TOP - DSTACK_SIZE)

/* Dictionary grows up from FORTH_BASE */
#define DICT_BASE           FORTH_BASE
#define DICT_TOP            DSTACK_GUARD  /* must not cross this */

/* Noun event arena: bump allocator, reset after each +poke */
#define ARENA_BASE          PLATFORM_ARENA_BASE
#define ARENA_SIZE          0x02000000  /* 32MB */
#define ARENA_TOP           (ARENA_BASE + ARENA_SIZE)

/*
 * Noun cell heap (split bump):
 *   PERSIST  HEAP_BASE .. HEAP_PERSIST_TOP  — live gate, event queue, tokens
 *   SCRATCH  HEAP_SCRATCH_BASE .. HEAP_TOP  — per-slam Nock product; reset
 *                                            after each event (host ArenaHost)
 * Production: HEAP_TOP ≤ ATOM_INDEX_BASE (silent overrun stomped atom index).
 * I3_UNJETTED relocates scratch to high qemu RAM; persist still precedes
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
#if defined(I3_UNJETTED)
#if !defined(TRINITITE_PLATFORM_QEMU_VIRT)
#error I3_UNJETTED requires PLATFORM=qemu-virt
#endif
/*
 * Diagnostic image only (I3_UNJETTED requires qemu-virt). Production
 * persist stays put; scratch moves to high RAM past pill (0x50000000)
 * and the I3 plan blob (0x51000000). In-place 32MB scratch holds only
 * 1.398M 24-byte cells and crashed (`scratch exhausted`) before the
 * 2.048M diagnostic budget. 64MB holds 2.796M cells.
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

/*
 * Stack canary value — written to DSTACK_GUARD on boot.
 * Checked in error handler. If overwritten, stack has overflowed
 * into the dictionary.
 */
#define STACK_CANARY        0xDEADF0C4

/* Layout: heap → atom index → atom data → … → MMIO. No silent overlap.
 * I3_UNJETTED relocates scratch to high qemu RAM; persist still ends at
 * HEAP_PERSIST_TOP, which stays ≤ ATOM_INDEX_BASE. */
#if !defined(I3_UNJETTED)
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
 * PILL_BASE carries either:
 *   - isolated legacy I1 PILL v2: u64 len, shape, version/pad, jam at +16; or
 *   - I2 PILL2: 256-byte integrity/RuntimeIdentity header, then bounded jam.
 * Exact I2 layout: 1499kernel/docs/I2-M2-CONTRACT.md.
 *
 * 256 MB: safely above all allocators and below MMIO (0x3F000000).
 */
#define PILL_BASE  PLATFORM_PILL_BASE

/*
 * Scratch for pill_load jam limbs. MUST NOT live in .bss under FORTH_BASE
 * (a 1MB static array there overlays the dictionary/stacks and brick the VM
 * if anything touches past the first few KB).  Place between cold store and
 * PILL_BASE.
 */
#define PILL_SCRATCH_BASE  PLATFORM_PILL_SCRATCH_BASE
#define PILL_SCRATCH_SIZE  0x00100000   /* 1 MB */
#if (PILL_SCRATCH_BASE + PILL_SCRATCH_SIZE) > PILL_BASE
#error "pill scratch overlaps PILL_BASE"
#endif

/*
 * UART receive buffer: below TIB (0xFF000). I2 uses it only after a strict
 * 56-byte incremental frame header admits an exact payload length. I1 keeps
 * the isolated legacy uart_recv_noun path.
 */
#define UART_RXBUF_BASE  PLATFORM_UART_RXBUF_BASE
#define UART_RXBUF_SIZE  0x00007000
#if (UART_RXBUF_BASE + UART_RXBUF_SIZE) > (PLATFORM_DRAM_BASE + 0x000FF000ULL)
#error "UART_RXBUF overlaps TIB"
#endif

/*
 * Phase 4 — secondary core C stacks (between atom store and PILL).
 * Grow down from TOP. Core 0 keeps the boot stack below 0x80000.
 */
#define NCORES              PLATFORM_NCORES
#define CORE_STACK_SIZE     0x4000      /* 16 KB each */
#define CORE1_STACK_TOP     PLATFORM_CORE1_STACK_TOP
#define CORE2_STACK_TOP     PLATFORM_CORE2_STACK_TOP
#define CORE3_STACK_TOP     PLATFORM_CORE3_STACK_TOP

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
