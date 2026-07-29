#pragma once
#include <stdint.h>
#include <stddef.h>
#include "memory.h"

/*
 * Noun representation — every noun is a 64-bit word.
 *
 * Bits 63:62  tag
 *   0x  direct atom    bit 63 = 0; value = noun word (bits 62:0), range 0..2^63-1
 *   10  indirect atom  bits 63:62 = 10; bits 61:0 = 62-bit BLAKE3 hash of limb data
 *   11  cell           bits 63:62 = 11; bits 31:0 = 32-bit heap pointer to {head,tail}
 *
 * Direct atoms: the noun word IS the value.  direct(42) == 42.
 * Indirect atoms: content-addressed; identity is the 62-bit BLAKE3 hash.
 *   Limb data lives in the atom store (ATOM_INDEX_BASE / ATOM_DATA_BASE).
 * Cells: heap pointer to cell_t; allocated from HEAP_BASE.
 */

typedef uint64_t noun;

#define TAG_INDIRECT    (2ULL << 62)   /* bits 63:62 = 10 */
#define TAG_CELL        (3ULL << 62)   /* bits 63:62 = 11 */

/* ── Tag tests ─────────────────────────────────────────────────────────────── */

static inline int noun_is_direct(noun n)   { return !(n >> 63); }
static inline int noun_is_indirect(noun n) { return (n >> 62) == 2; }
static inline int noun_is_cell(noun n)     { return (n >> 62) == 3; }
static inline int noun_is_atom(noun n)     { return (n >> 62) != 3; }

/* ── Direct atom pack/unpack ────────────────────────────────────────────────── */

/* direct(v): v must have bit 63 = 0 (values 0..2^63-1). */
static inline noun     direct(uint64_t val)   { return val & 0x7FFFFFFFFFFFFFFFULL; }
static inline uint64_t direct_val(noun n)     { return n & 0x7FFFFFFFFFFFFFFFULL; }

/* ── Cell pack/unpack ───────────────────────────────────────────────────────── */

static inline noun     cell_noun(uint32_t ptr) { return TAG_CELL | (noun)ptr; }
static inline uint32_t cell_ptr(noun n)        { return (uint32_t)(n & 0xFFFFFFFF); }

/* ── Indirect atom pack/unpack ──────────────────────────────────────────────── */

/* Indirect noun: bits 61:0 hold the 62-bit BLAKE3 hash (identity of the atom). */
static inline noun     indirect(uint64_t hash62)  { return TAG_INDIRECT | (hash62 & 0x3FFFFFFFFFFFFFFFULL); }
static inline uint64_t indirect_hash(noun n)       { return n & 0x3FFFFFFFFFFFFFFFULL; }

/* ── Heap struct for indirect (type-10) atoms ───────────────────────────────── */

typedef struct atom {
    uint64_t  size;      /* number of 64-bit limbs                        */
    uint32_t  blake3[8]; /* full 256-bit BLAKE3 hash                      */
    uint64_t  limbs[];   /* little-endian limb data (size elements)        */
} atom_t;

/* ── Heap struct for cells ──────────────────────────────────────────────────── */

typedef struct cell {
    uint32_t  refcount;
    uint32_t  _pad;
    noun      head;
    noun      tail;
} cell_t;

/* ── Well-known atoms ───────────────────────────────────────────────────────── */

#define NOUN_ZERO   direct(0)   /* = 0 */
#define NOUN_ONE    direct(1)   /* = 1 */
#define NOUN_YES    direct(0)   /* Nock yes = 0 */
#define NOUN_NO     direct(1)   /* Nock no  = 1 */

/* ── Allocator interface (implemented in noun.c) ────────────────────────────── */

void  noun_heap_init(void);

/* Heap mode: PERSIST = long-lived (gate/queue); SCRATCH = per-event Nock. */
#define HEAP_MODE_PERSIST  0
#define HEAP_MODE_SCRATCH  1
void  heap_set_mode(int mode);     /* PERSIST or SCRATCH */
int   heap_get_mode(void);
void  heap_scratch_reset(void);    /* bump scratch ptr to HEAP_SCRATCH_BASE */
void  heap_persist_reset(void);    /* bump current persist semispace to its base */
void  heap_persist_flip(void);     /* switch to other semispace (empty); for compact */
/* Transactional candidate semispace.  A failed pre-promotion copy restores
 * both selector and bump pointer, leaving live roots readable. */
void  heap_persist_begin_tx(void);
void  heap_persist_commit_tx(void);
void  heap_persist_abort_tx(void);
/* Activation guard: I2 publish enables this around the final effect pass.
 * Any accidental heap allocation is a deterministic host-integrity failure. */
void  heap_noalloc_begin(void);
void  heap_noalloc_end(void);

/* Loader/decode transaction. Only one is active on the single scheduler
 * core. Abort restores the selected cell bump pointer and all atom-store
 * insertions made since begin. */
int   noun_tx_begin(int mode);
void  noun_tx_commit(void);
void  noun_tx_abort(void);
int   noun_tx_active(void);
uint64_t heap_cells_used(int mode);
uint64_t atom_store_bytes_used(void);

noun  alloc_cell(noun head, noun tail);
int   alloc_cell_checked(noun head, noun tail, noun *out);
void  cell_inc(noun n);   /* increment refcount */
void  cell_dec(noun n);   /* decrement; frees cell (and recursively children) when 0 */

/* Deep-copy cells into the *current* heap mode (atoms shared via store). */
noun  noun_copy(noun n);
int   noun_copy_checked(noun n, noun *out);
/* Deterministic test hook: fail a checked deep copy after N new cells.
 * Negative disables injection. */
void  noun_test_copy_fail_after(int64_t cells);
/* Copy into PERSIST region (saves/restores mode). */
noun  noun_persist(noun n);

/* Nock equality: structural, O(1) for atoms via word compare */
int   noun_eq(noun a, noun b);

/*
 * make_atom: given limb array limbs[0..size-1], produce a canonical noun.
 * Strips trailing zero limbs, promotes to direct if value < 2^63,
 * otherwise hashes with BLAKE3 and inserts into the atom store.
 * Returns a properly tagged noun (direct or indirect).
 */
noun  make_atom(const uint64_t *limbs, uint64_t size);
int   make_atom_checked(const uint64_t *limbs, uint64_t size, noun *out);
/* Read a canonical atom value into exactly len little-endian bytes, zero
 * extending as needed. Returns 0 if n is a cell or has significant bytes
 * beyond len. */
int   noun_atom_read_fixed(noun n, uint8_t *out, size_t len);

/* cord_from_bytes: create a cord (atom) from a C byte string */
noun  cord_from_bytes(const char *str, size_t len);

/* cord_to_cstr: decode a cord atom to a null-terminated C string.
 * Returns the string length; writes at most bufsz-1 bytes into buf. */
size_t cord_to_cstr(noun n, char *buf, size_t bufsz);

/*
 * atom_store_get: look up a 62-bit BLAKE3 hash in the atom store.
 * Returns a pointer to the atom_t, or NULL if not found.
 */
atom_t *atom_store_get(uint64_t hash62);

/* Load a jammed atom from PILL_BASE (placed by QEMU's -device loader).
   Reads PILL format v2 header: sets noun_pill_shape (0=Arvo, 1=Shrine).
   Returns 0 (C null) if no pill is present; otherwise a valid tagged noun.
   CUE the result to decode. */
extern int noun_pill_shape;
extern uint32_t noun_pill_version;  /* PILL v2 bytes 9-12 LE; 0 if unversioned */
noun  pill_load(void);
