#pragma once

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
 * Must not overlap Forth or arenas. ~0.7 MB used; 16 MB reserved.
 */
#define BSS_BASE            0x08000000
#define BSS_SIZE            0x01000000  /* 16 MB reserve */
#define BSS_TOP             (BSS_BASE + BSS_SIZE)

/*
 * Forth region: dictionary grows up, stacks grow down.
 * Starts at 1 MB so the kernel image (loaded at 0x80000) can grow past
 * the old 0x90000 boundary without stomping the dictionary / TIB.
 * Ends at ARENA_BASE (0x490000).
 */
#define FORTH_BASE          0x00100000
#define FORTH_SIZE          0x00390000  /* → 0x00490000 = ARENA_BASE */
#define FORTH_TOP           (FORTH_BASE + FORTH_SIZE)

#if BSS_BASE < FORTH_TOP
#error "BSS_BASE overlaps Forth region"
#endif
#if FORTH_TOP > 0x00490000
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
#define ARENA_BASE          0x00490000
#define ARENA_SIZE          0x02000000  /* 32MB */
#define ARENA_TOP           (ARENA_BASE + ARENA_SIZE)

/* Noun persistent heap: refcounted cells and indirect atoms */
#define HEAP_BASE           0x02490000
#define HEAP_SIZE           0x04000000  /* 64MB */
#define HEAP_TOP            (HEAP_BASE + HEAP_SIZE)

/*
 * Atom store: content-addressed (type-11) atom cache.
 * Index: hash table mapping 62-bit BLAKE3 prefix -> atom struct pointer.
 * Data:  atom structs for interned content atoms.
 * Phase 6 adds SD card cold store behind this hot cache.
 */
#define ATOM_INDEX_BASE     0x06490000
#define ATOM_INDEX_SIZE     0x00100000  /* 1MB — hash table */
#define ATOM_DATA_BASE      0x06590000
#define ATOM_DATA_SIZE      0x00400000  /* 4MB — atom struct storage */
#define ATOM_DATA_TOP       (ATOM_DATA_BASE + ATOM_DATA_SIZE)

/*
 * Stack canary value — written to DSTACK_GUARD on boot.
 * Checked in error handler. If overwritten, stack has overflowed
 * into the dictionary.
 */
#define STACK_CANARY        0xDEADF0C4

/* Sanity check: atom store must not reach MMIO */
#if ATOM_DATA_TOP > 0x3F000000
#error "Atom store region overlaps MMIO"
#endif

/*
 * PILL format v2 (written by tools/mkpill.py):
 *   bytes  0-7:   uint64_t (LE) = byte count of jam data
 *   byte   8:     kernel shape  (0 = Arvo, 1 = Shrine)
 *   bytes  9-15:  reserved/padding (zeros)
 *   bytes  16+:   raw jam bytes (16-byte aligned)
 *
 * 256 MB: safely above all allocators (~107 MB top) and below MMIO (0x3F000000).
 */
#define PILL_BASE  0x10000000

/*
 * Scratch for pill_load jam limbs. MUST NOT live in .bss under FORTH_BASE
 * (a 1MB static array there overlays the dictionary/stacks and brick the VM
 * if anything touches past the first few KB).  Place between cold store and
 * PILL_BASE.
 */
#define PILL_SCRATCH_BASE  0x07900000
#define PILL_SCRATCH_SIZE  0x00100000   /* 1 MB */
#if (PILL_SCRATCH_BASE + PILL_SCRATCH_SIZE) > PILL_BASE
#error "pill scratch overlaps PILL_BASE"
#endif

/*
 * UART receive buffer: below TIB (0xFF000). Used by uart_recv_noun.
 * ~28 KB — enough for Phase 6 test events / modest jam payloads.
 */
#define UART_RXBUF_BASE  0x000F8000
#define UART_RXBUF_SIZE  0x00007000
#if (UART_RXBUF_BASE + UART_RXBUF_SIZE) > 0x000FF000
#error "UART_RXBUF overlaps TIB"
#endif

/*
 * Phase 4 — secondary core C stacks (between atom store and PILL).
 * Grow down from TOP. Core 0 keeps the boot stack below 0x80000.
 */
#define NCORES              4
#define CORE_STACK_SIZE     0x4000      /* 16 KB each */
#define CORE1_STACK_TOP     0x07004000
#define CORE2_STACK_TOP     0x07008000
#define CORE3_STACK_TOP     0x0700C000

/*
 * Phase 5 — RAM-backed cold store (content-addressed jam blobs).
 * Between core stacks and PILL.  SD backend can replace cold_read/write later.
 */
#define COLD_BASE           0x07100000
#define COLD_SIZE           0x00800000  /* 8 MB */
#define COLD_TOP            (COLD_BASE + COLD_SIZE)
