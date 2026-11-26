#include <stdint.h>
#include "jam.h"
#include "bignum.h"
#include "nock.h"    /* nock_crash */
#include "i2_admission_envelope.h"
#include "platform.h"

/* ── Bitstream writer ─────────────────────────────────────────────────────── */

/* I2 hybrid gates jam ~10KB; headroom for live state + tarms (~1 Mbit). */
#ifndef JAM_MAX_LIMBS          /* ckpt_jam.c builds this file again, larger */
#define JAM_MAX_LIMBS 16384   /* 1 Mbit max jam output */
#endif

typedef struct {
    uint64_t buf[JAM_MAX_LIMBS];
    uint64_t cur;               /* next bit position to write */
} jambuf_t;

static int jam_charge(uint64_t amount);
static jam_admission_budget_t *g_jam_budget;

static void jb_init(jambuf_t *b) {
    for (int i = 0; i < JAM_MAX_LIMBS; i++) b->buf[i] = 0;
    b->cur = 0;
}

static void jb_write(jambuf_t *b, int bit) {
    if (!jam_charge(1))
        return;
    if (b->cur >= (uint64_t)(JAM_MAX_LIMBS * 64)) {
        if (g_jam_budget) {
            g_jam_budget->exhausted = 1;
            return;
        }
        nock_crash("jam: output too large");
    }
    uint64_t w = b->cur >> 6, o = b->cur & 63;
    if (bit) b->buf[w] |= 1ULL << o;
    b->cur++;
}

static void jb_write_n(jambuf_t *b, uint64_t val, uint64_t n) {
    for (uint64_t i = 0; i < n; i++)
        jb_write(b, (val >> i) & 1);
}

/* Write n bits of atom a, starting from bit 0 (LSB first). */
static void jb_write_atom(jambuf_t *b, noun a, uint64_t n) {
    if (noun_is_direct(a)) {
        jb_write_n(b, direct_val(a), n);
        return;
    }
    atom_t *at = atom_store_get(indirect_hash(a));
    for (uint64_t i = 0; i < n; i++) {
        uint64_t limb = i >> 6, off = i & 63;
        int bit = (limb < at->size) ? (int)((at->limbs[limb] >> off) & 1) : 0;
        jb_write(b, bit);
    }
}

/* ── mat: self-describing integer encoding ────────────────────────────────── */

/* Bit length of a raw uint64_t (0 → 0, 1 → 1, 2–3 → 2, …). */
static uint64_t u64_bits(uint64_t v) {
    uint64_t c = 0;
    while (v) { c++; v >>= 1; }
    return c;
}

/* Length in bits that mat(k) will emit. */
static uint64_t mat_len(noun k) {
    uint64_t a = bn_met(k);
    if (a == 0) return 1;           /* k == 0: single 1 bit */
    uint64_t b = u64_bits(a);
    return 2 * b + a;
}

/* Emit mat(k) into the bitstream. */
static void do_mat(jambuf_t *jb, noun k) {
    uint64_t a = bn_met(k);
    if (a == 0) { jb_write(jb, 1); return; }
    uint64_t b = u64_bits(a);
    /* b zeros */
    for (uint64_t i = 0; i < b; i++) jb_write(jb, 0);
    /* 1 delimiter */
    jb_write(jb, 1);
    /* b-1 low bits of a */
    jb_write_n(jb, a, b - 1);
    /* a bits of k */
    jb_write_atom(jb, k, a);
}

/* ── jam cache: noun → bit position ──────────────────────────────────────── */

/* Large hybrid gates need many backrefs (7k+ cells). */
#define JAM_CACHE_SZ I2_JAM_CACHE_ENTRIES

typedef struct { noun key; uint64_t pos; int used; } jcent_t;

#ifndef JAM_TABLE    /* ckpt_jam.c places its tables in the I3_CKPT_JAM region */
#define JAM_TABLE(type, name, n) static type name[n]
#endif
#ifndef JAM_MUG_GEN_INIT
#define JAM_MUG_GEN_INIT
#endif
JAM_TABLE(jcent_t, g_jcache, JAM_CACHE_SZ);
/* 0: structural noun_eq (M8 trampoline battery digest).
 * 1: pointer identity (host Python jam of ResourceProgram). */
static int g_jam_identity_keys;
/* ++jam's own rule (hoon.hoon, and the full node's nockvm jam): a repeated
 * atom is written again when (met 0 a) <= (met 0 cursor), else backref. */
static int g_jam_hoon_rule;
static uint32_t g_jcache_used;
static uint32_t g_jam_depth;

static int jam_charge(uint64_t amount)
{
    if (!g_jam_budget)
        return 1;
    if (amount > g_jam_budget->max_work
        || g_jam_budget->work > g_jam_budget->max_work - amount) {
        g_jam_budget->exhausted = 1;
        return 0;
    }
    g_jam_budget->work += amount;
    return 1;
}

static int jam_charge_atom(noun n)
{
    uint64_t bits = bn_met(n);
    return jam_charge(bits == 0 ? 1 : bits);
}

static void jcache_init(void) {
    if (g_jam_budget && !jam_charge(JAM_CACHE_SZ))
        return;
    for (uint32_t i = 0; i < JAM_CACHE_SZ; i++) g_jcache[i].used = 0;
    g_jcache_used = 0;
}

static uint32_t jcache_ptr_hash(noun n) {
    return (uint32_t)((n ^ (n >> 23)) * 2654435761ULL) & (JAM_CACHE_SZ - 1);
}

/* ++jam's rule keys its map by noun value, so under g_jam_hoon_rule the cache
 * hashes by structure: equal subtrees at different addresses must land in the
 * same probe chain, or the structural compare never sees them and no backref
 * is written. An atom's noun word is already its value (direct) or its content
 * hash (indirect). A cell's hash mixes its children's; a per-jam memo keyed by
 * address only saves recomputing it, it never decides equality. */
#ifndef JAM_MUG_MEMO
#define JAM_MUG_MEMO 65536u      /* 16 B an entry: 1 MiB static */
#endif
#ifndef JAM_HOON_DEPTH
#define JAM_HOON_DEPTH 1024u     /* deepest noun the jet takes; else Nock */
#endif
typedef struct { noun key; uint32_t mug; uint32_t gen; } jmug_t;
JAM_TABLE(jmug_t, g_jmug, JAM_MUG_MEMO);
static uint32_t g_jmug_gen JAM_MUG_GEN_INIT;
static int g_jam_cache_full;

static uint64_t jam_mix(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    return x ^ (x >> 33);
}

static jmug_t *jmug_find(noun n) {
    uint32_t h = (uint32_t)jam_mix(n) & (JAM_MUG_MEMO - 1);
    for (uint32_t i = 0; i < 8; i++) {
        jmug_t *e = &g_jmug[(h + i) & (JAM_MUG_MEMO - 1)];
        if (e->gen == g_jmug_gen && e->key == n)
            return e;
    }
    return 0;
}

static void jmug_put(noun n, uint32_t m) {
    uint32_t h = (uint32_t)jam_mix(n) & (JAM_MUG_MEMO - 1);
    for (uint32_t i = 0; i < 8; i++) {
        jmug_t *e = &g_jmug[(h + i) & (JAM_MUG_MEMO - 1)];
        if (e->gen != g_jmug_gen) {
            e->key = n; e->mug = m; e->gen = g_jmug_gen;
            return;
        }
    }
}

/* Iterative post-order with an explicit stack, so a deep noun cannot overflow
 * the C stack. A noun deeper than JAM_HOON_DEPTH marks the cache full, and the
 * jet then runs the arm as Nock. */
typedef struct { noun n; uint32_t head; uint8_t state; } jmug_frame_t;
static jmug_frame_t g_jmug_stack[JAM_HOON_DEPTH];

static uint32_t jam_mug(noun n) {
    uint32_t sp = 0, ret = 0;
    if (!noun_is_cell(n))
        return (uint32_t)jam_mix(n);
    g_jmug_stack[sp].n = n; g_jmug_stack[sp].state = 0; sp++;
    while (sp) {
        jmug_frame_t *f = &g_jmug_stack[sp - 1];
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(f->n);
        noun child;
        if (f->state == 0) {
            jmug_t *e = jmug_find(f->n);
            if (e) { ret = e->mug; sp--; continue; }
            f->state = 1; child = c->head;
        } else if (f->state == 1) {
            f->head = ret; f->state = 2; child = c->tail;
        } else {
            uint32_t m = (uint32_t)jam_mix((uint64_t)f->head * 31u
                + jam_mix((uint64_t)ret ^ 0x9e3779b97f4a7c15ULL));
            jmug_put(f->n, m);
            ret = m; sp--; continue;
        }
        if (!noun_is_cell(child)) { ret = (uint32_t)jam_mix(child); continue; }
        if (sp == JAM_HOON_DEPTH) { g_jam_cache_full = 1; return 0; }
        g_jmug_stack[sp].n = child; g_jmug_stack[sp].state = 0; sp++;
    }
    return ret;
}

static uint32_t jcache_hash(noun n) {
    if (g_jam_hoon_rule)
        return (uint32_t)jam_mug(n) & (JAM_CACHE_SZ - 1);
    return jcache_ptr_hash(n);
}

static int jcache_get(noun n, uint64_t *pos) {
    uint32_t h = jcache_hash(n);
    for (uint32_t i = 0; i < JAM_CACHE_SZ; i++) {
        if (!jam_charge(1))
            return 0;
        uint32_t idx = (h + i) & (JAM_CACHE_SZ - 1);
        if (!g_jcache[idx].used) return 0;
        if (g_jam_identity_keys ? g_jcache[idx].key == n
                                : noun_eq(g_jcache[idx].key, n)) {
            *pos = g_jcache[idx].pos;
            return 1;
        }
    }
    return 0;
}

static int jcache_put(noun n, uint64_t pos) {
    uint32_t h = jcache_hash(n);
    for (uint32_t i = 0; i < JAM_CACHE_SZ; i++) {
        if (!jam_charge(1))
            return 0;
        uint32_t idx = (h + i) & (JAM_CACHE_SZ - 1);
        if (!g_jcache[idx].used) {
            if (g_jcache_used >= I2_JAM_CACHE_ADMITTED) {
                /* A skipped entry loses a backref; under ++jam's rule that
                 * is wrong bits, so the caller falls back to Nock. */
                g_jam_cache_full = 1;
                return 1;
            }
            g_jcache[idx].key = n; g_jcache[idx].pos = pos; g_jcache[idx].used = 1;
            g_jcache_used++;
            return 1;
        }
        if (g_jam_identity_keys ? g_jcache[idx].key == n
                                : noun_eq(g_jcache[idx].key, n)) {
            g_jcache[idx].pos = pos;
            return 1;
        }
    }
    /* cache full — skip (correctness preserved; dedup opportunity lost) */
    g_jam_cache_full = 1;
    return 1;
}

/* ── jam recursive core ───────────────────────────────────────────────────── */

#ifndef JAM_BUF_DECL         /* ckpt_jam.c places its buffer in the I3_CKPT_JAM region */
#define JAM_BUF_DECL static jambuf_t g_jambuf
#endif
JAM_BUF_DECL;

static void do_jam(noun n) {
    if (g_jam_budget && g_jam_budget->exhausted)
        return;
    if (!jam_charge(1))
        return;
    if (g_jam_budget && ++g_jam_depth > 256u) {
        g_jam_budget->exhausted = 1;
        g_jam_depth--;
        return;
    }
    if (!noun_is_cell(n) && !jam_charge_atom(n))
        goto done;
    uint64_t cached_pos;
    int found = jcache_get(n, &cached_pos);
    if (g_jam_budget && g_jam_budget->exhausted)
        goto done;

    if (noun_is_cell(n)) {
        if (found) {
            /* back-reference to this cell */
            jb_write(&g_jambuf, 1); jb_write(&g_jambuf, 1);
            do_mat(&g_jambuf, direct(cached_pos));
        } else {
            if (!jcache_put(n, g_jambuf.cur))
                goto done;
            jb_write(&g_jambuf, 1); jb_write(&g_jambuf, 0);  /* tag 01 */
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
            do_jam(c->head);
            do_jam(c->tail);
        }
    } else {
        /* atom */
        if (!found) {
            if (!jcache_put(n, g_jambuf.cur))
                goto done;
            jb_write(&g_jambuf, 0);     /* atom tag */
            do_mat(&g_jambuf, n);
        } else if (g_jam_hoon_rule) {
            if (bn_met(n) <= u64_bits(cached_pos)) {
                jb_write(&g_jambuf, 0);
                do_mat(&g_jambuf, n);
            } else {
                jb_write(&g_jambuf, 1); jb_write(&g_jambuf, 1);
                do_mat(&g_jambuf, direct(cached_pos));
            }
        } else if (g_jam_identity_keys) {
            /* Host jam.py: re-emit the atom when value.bit_length()
             * is strictly less than the cached bit-position. */
            if (bn_met(n) < u64_bits(cached_pos)) {
                if (!jcache_put(n, g_jambuf.cur))
                    goto done;
                jb_write(&g_jambuf, 0);
                do_mat(&g_jambuf, n);
            } else {
                jb_write(&g_jambuf, 1); jb_write(&g_jambuf, 1);
                do_mat(&g_jambuf, direct(cached_pos));
            }
        } else {
            /* choose shorter: direct atom encoding vs back-reference */
            uint64_t atom_bits = 1 + mat_len(n);
            uint64_t ref_bits  = 2 + mat_len(direct(cached_pos));
            if (atom_bits <= ref_bits) {
                jb_write(&g_jambuf, 0);
                do_mat(&g_jambuf, n);
            } else {
                jb_write(&g_jambuf, 1); jb_write(&g_jambuf, 1);
                do_mat(&g_jambuf, direct(cached_pos));
            }
        }
    }
done:
    if (g_jam_budget)
        g_jam_depth--;
}

/* Length-only companion to do_jam().  Keep this deliberately adjacent to the
 * encoder: a deployment/checkpoint bound is only useful if it follows the
 * exact back-reference and atom-shortening decisions of jam(). */
static uint64_t g_jam_len;
static uint64_t g_jam_max_bits;
static int g_jam_len_ok;
static uint32_t g_jam_len_depth;

static void jam_len_add(uint64_t bits)
{
    if (!g_jam_len_ok || bits > g_jam_max_bits - g_jam_len) {
        g_jam_len_ok = 0;
        return;
    }
    if (!jam_charge(bits)) {
        g_jam_len_ok = 0;
        return;
    }
    g_jam_len += bits;
}

static void do_jam_len(noun n)
{
    if (!g_jam_len_ok)
        return;
    if (g_jam_hoon_rule && g_jam_cache_full) {
        g_jam_len_ok = 0;
        return;
    }
    int bounded = g_jam_budget != 0;
    if (!jam_charge(1)) {
        g_jam_len_ok = 0;
        return;
    }
    if (bounded && ++g_jam_len_depth > 256u) {
        g_jam_budget->exhausted = 1;
        g_jam_len_ok = 0;
        g_jam_len_depth--;
        return;
    }
    if (!noun_is_cell(n) && !jam_charge_atom(n)) {
        g_jam_len_ok = 0;
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    uint64_t cached_pos;
    int found = jcache_get(n, &cached_pos);
    if (g_jam_budget && g_jam_budget->exhausted) {
        g_jam_len_ok = 0;
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    if (noun_is_cell(n)) {
        if (found) {
            jam_len_add(2 + mat_len(direct(cached_pos)));
        } else {
            if (!jcache_put(n, g_jam_len)) {
                g_jam_len_ok = 0;
                return;
            }
            jam_len_add(2);
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
            do_jam_len(c->head);
            do_jam_len(c->tail);
        }
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    if (!found) {
        if (!jcache_put(n, g_jam_len)) {
            g_jam_len_ok = 0;
            if (bounded)
                g_jam_len_depth--;
            return;
        }
        jam_len_add(1 + mat_len(n));
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    if (g_jam_hoon_rule) {
        jam_len_add(bn_met(n) <= u64_bits(cached_pos) ? 1 + mat_len(n)
                                                      : 2 + mat_len(direct(cached_pos)));
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    if (g_jam_identity_keys) {
        if (bn_met(n) < u64_bits(cached_pos)) {
            if (!jcache_put(n, g_jam_len)) {
                g_jam_len_ok = 0;
                if (bounded)
                    g_jam_len_depth--;
                return;
            }
            jam_len_add(1 + mat_len(n));
        } else {
            jam_len_add(2 + mat_len(direct(cached_pos)));
        }
        if (bounded)
            g_jam_len_depth--;
        return;
    }
    uint64_t atom_bits = 1 + mat_len(n);
    uint64_t ref_bits = 2 + mat_len(direct(cached_pos));
    jam_len_add(atom_bits <= ref_bits ? atom_bits : ref_bits);
    if (bounded)
        g_jam_len_depth--;
}

static int jam_size_in(noun n, uint64_t max_bytes, uint64_t *out_bytes)
{
    if (!out_bytes || max_bytes == 0
        || max_bytes > UINT64_MAX / 8)
        return -1;
    g_jam_len = 0;
    g_jam_max_bits = max_bytes * 8;
    g_jam_len_ok = 1;
    g_jam_len_depth = 0;
    jcache_init();
    do_jam_len(n);
    if (!g_jam_len_ok || (g_jam_budget && g_jam_budget->exhausted))
        return -1;
    *out_bytes = (g_jam_len + 7) / 8;
    if (*out_bytes == 0)
        *out_bytes = 1;
    return *out_bytes <= max_bytes ? 0 : -1;
}

/* Selftest only: abort mid-jam under ++jam's rule, as a Nock abort would. */
static int g_jam_test_abort;

static uint64_t jam_encode(noun n) {
    if (g_jam_hoon_rule && g_jam_test_abort)
        longjmp(nock_abort, NOCK_ABORT_CRASH);
    jb_init(&g_jambuf);
    jcache_init();
    do_jam(n);
    return g_jambuf.cur;
}

static noun jam_in(noun n) {
    uint64_t bits = jam_encode(n);
    uint64_t limbs = (bits + 63) / 64;
    if (limbs == 0) limbs = 1;
    return bn_normalize(g_jambuf.buf, limbs);
}

/* The public entries clear g_jam_hoon_rule first: a Nock or budget abort can
 * longjmp out of jam_hoon_checked with the rule still set, and the cold store
 * and admission must never inherit it. */
int jam_size_checked(noun n, uint64_t max_bytes, uint64_t *out_bytes)
{
    g_jam_hoon_rule = 0;
    return jam_size_in(n, max_bytes, out_bytes);
}



int jam_encode_bytes_checked(noun n, const uint8_t **out,
                             uint64_t *out_bytes)
{
    uint64_t checked_bytes;
    if (!out || !out_bytes)
        return -1;
    *out = 0;
    *out_bytes = 0;
    if (jam_size_checked(n, JAM_MAX_BYTES, &checked_bytes) != 0)
        return -1;
    uint64_t bits = jam_encode(n);
    uint64_t bytes = (bits + 7) / 8;
    if (bytes == 0)
        bytes = 1;
    if (bytes != checked_bytes || bytes > JAM_MAX_BYTES)
        return -1;
    *out = (const uint8_t *)(const void *)g_jambuf.buf;
    *out_bytes = bytes;
    return 0;
}

int jam_hoon_checked(noun n, noun *out)
{
    uint64_t bytes;
    int rc = -1;
    g_jam_hoon_rule = 1;
    g_jam_cache_full = 0;
    if (++g_jmug_gen == 0) {
        for (uint32_t i = 0; i < JAM_MUG_MEMO; i++) g_jmug[i].gen = 0;
        g_jmug_gen = 1;
    }
    if (jam_size_in(n, JAM_MAX_BYTES, &bytes) == 0 && !g_jam_cache_full) {
        *out = jam_in(n);
        rc = g_jam_cache_full ? -1 : 0;
    }
    g_jam_hoon_rule = 0;
    return rc;
}
