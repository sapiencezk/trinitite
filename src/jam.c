#include <stdint.h>
#include "jam.h"
#include "bignum.h"
#include "nock.h"    /* nock_crash */
#include "i2_admission_envelope.h"
#include "i2_admission_metrics.h"
#include "platform.h"

/* ── Bitstream writer ─────────────────────────────────────────────────────── */

/* I2 hybrid gates jam ~10KB; headroom for live state + tarms (~1 Mbit). */
#define JAM_MAX_LIMBS 16384   /* 1 Mbit max jam output */

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

static jcent_t g_jcache[JAM_CACHE_SZ];
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
    g_i2_admission_metrics.jam_passes++;
    g_i2_admission_metrics.jam_clear_count++;
    g_i2_admission_metrics.jam_clear_bytes += sizeof g_jcache;
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
#define JAM_MUG_MEMO 65536u      /* 16 B an entry: 1 MiB static */
#define JAM_HOON_DEPTH 1024u     /* deepest noun the jet takes; else Nock */
typedef struct { noun key; uint32_t mug; uint32_t gen; } jmug_t;
static jmug_t g_jmug[JAM_MUG_MEMO];
static uint32_t g_jmug_gen;
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
        i2_admission_metrics_max(
            &g_i2_admission_metrics.jam_probe_hwm, (uint64_t)i + 1u);
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
        i2_admission_metrics_max(
            &g_i2_admission_metrics.jam_probe_hwm, (uint64_t)i + 1u);
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
            i2_admission_metrics_max(
                &g_i2_admission_metrics.jam_cache_entries_hwm,
                g_jcache_used);
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

static jambuf_t g_jambuf;

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

noun jam(noun n) {
    g_jam_hoon_rule = 0;
    return jam_in(n);
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

int jam_encode_bytes_identity(noun n, const uint8_t **out, uint64_t *out_bytes)
{
    g_jam_identity_keys = 1;
    int rc = jam_encode_bytes_checked(n, out, out_bytes);
    g_jam_identity_keys = 0;
    return rc;
}

void jam_admission_budget_init(jam_admission_budget_t *budget,
                               uint64_t max_work)
{
    if (!budget)
        return;
    budget->work = 0;
    budget->max_work = max_work;
    budget->exhausted = 0;
}

int jam_encode_bytes_identity_bounded(noun n, const uint8_t **out,
                                      uint64_t *out_bytes,
                                      jam_admission_budget_t *budget)
{
    if (!out || !out_bytes || !budget)
        return -1;
    jam_admission_budget_t *prior_budget = g_jam_budget;
    int prior_identity = g_jam_identity_keys;
    uint32_t prior_depth = g_jam_depth;
    g_jam_budget = budget;
    g_jam_identity_keys = 1;
    g_jam_depth = 0;
    *out = 0;
    *out_bytes = 0;
    uint64_t checked_bytes = 0;
    int rc = jam_size_checked(n, JAM_MAX_BYTES, &checked_bytes);
    if (rc == 0 && !budget->exhausted) {
        uint64_t bits = jam_encode(n);
        uint64_t bytes = (bits + 7) / 8;
        if (bytes == 0)
            bytes = 1;
        if (!budget->exhausted && bytes == checked_bytes
            && bytes <= JAM_MAX_BYTES) {
            *out = (const uint8_t *)(const void *)g_jambuf.buf;
            *out_bytes = bytes;
        } else {
            rc = -1;
        }
    } else {
        rc = -1;
    }
    g_jam_depth = prior_depth;
    g_jam_identity_keys = prior_identity;
    g_jam_budget = prior_budget;
    return rc == 0 && *out ? 0 : -1;
}

static int jam_byte_view_matches(noun n)
{
    uint8_t direct_bytes[8] = {0};
    const uint8_t *legacy_bytes = direct_bytes;
    uint64_t legacy_len = 0;
    noun encoded = jam(n);
    if (noun_is_direct(encoded)) {
        uint64_t value = direct_val(encoded);
        for (unsigned i = 0; i < sizeof direct_bytes; i++) {
            direct_bytes[i] = (uint8_t)(value & 0xffu);
            if (direct_bytes[i])
                legacy_len = (uint64_t)i + 1u;
            value >>= 8;
        }
        if (legacy_len == 0)
            legacy_len = 1;
    } else if (noun_is_indirect(encoded)) {
        atom_t *atom = atom_store_get(indirect_hash(encoded));
        if (!atom)
            return 0;
        legacy_bytes = (const uint8_t *)atom->limbs;
        legacy_len = atom->size * sizeof(uint64_t);
        while (legacy_len > 1 && legacy_bytes[legacy_len - 1] == 0)
            legacy_len--;
    } else {
        return 0;
    }

    const uint8_t *view;
    uint64_t view_len;
    if (jam_encode_bytes_checked(n, &view, &view_len) != 0
        || view_len != legacy_len)
        return 0;
    for (uint64_t i = 0; i < view_len; i++)
        if (view[i] != legacy_bytes[i])
            return 0;
    return 1;
}

uint64_t jam_encode_bytes_selftest(void)
{
    uint64_t failures = 0;
    noun atom63 = direct(0x4000000000000000ULL);
    uint64_t limb64[1] = {0x8000000000000000ULL};
    uint64_t limb65[2] = {0, 1};
    noun atom64, atom65, shared, nested, near;
    if (!make_atom_checked(limb64, 1, &atom64)
        || !make_atom_checked(limb65, 2, &atom65)
        || !alloc_cell_checked(atom64, atom65, &shared)
        || !alloc_cell_checked(shared, shared, &nested))
        return 1;
    noun cases[] = {NOUN_ZERO, direct(1), atom63, atom64, atom65, nested};
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++)
        if (!jam_byte_view_matches(cases[i]))
            failures++;

    const uint64_t near_limbs = JAM_MAX_BYTES / sizeof(uint64_t) - 512u;
    for (uint64_t i = 0; i < near_limbs; i++)
        g_jambuf.buf[i] = 0x8000000000000000ULL ^ (i * 0x9e3779b97f4a7c15ULL);
    if (!make_atom_checked(g_jambuf.buf, near_limbs, &near)
        || !jam_byte_view_matches(near))
        failures++;

    /* An abort inside the %jam jet must not leave ++jam's rule on for the
     * cold store: [7 7] jams differently under the two rules. */
    {
        noun pair, hoon, before, after;
        jmp_buf saved;
        if (!alloc_cell_checked(direct(7), direct(7), &pair))
            return failures + 1;
        before = jam(pair);
        if (jam_hoon_checked(pair, &hoon) != 0 || hoon == jam(pair))
            failures++;
        __builtin_memcpy(saved, nock_abort, sizeof saved);
        if (setjmp(nock_abort) == 0) {
            g_jam_test_abort = 1;
            (void)jam_hoon_checked(pair, &hoon);
        }
        g_jam_test_abort = 0;
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        after = jam(pair);   /* the cold store's rule, not ++jam's */
        if (before != after || after == hoon)
            failures++;
    }

    /* A deep list (100,000 cells) must not overflow the C stack: the jet
     * declines it (Nock runs the arm). A 500-deep list still takes the jet. */
    {
        noun list = NOUN_ZERO, out;
        for (uint32_t i = 0; i < 100000u; i++)
            if (!alloc_cell_checked(NOUN_ZERO, list, &list))
                return failures + 1;
        if (jam_hoon_checked(list, &out) != -1)
            failures++;
        list = NOUN_ZERO;
        for (uint32_t i = 0; i < 500u; i++)
            if (!alloc_cell_checked(NOUN_ZERO, list, &list))
                return failures + 1;
        if (jam_hoon_checked(list, &out) != 0)
            failures++;
    }
    return failures;
}

/* ── cue: atom → noun ─────────────────────────────────────────────────────── */

/* Read a single bit from atom a at bit position pos. */
static int atom_bit_at(noun a, uint64_t pos) {
    if (noun_is_direct(a)) {
        if (pos >= 63) return 0;   /* direct atoms use bits 62:0 */
        return (int)((direct_val(a) >> pos) & 1);
    }
    atom_t *at = atom_store_get(indirect_hash(a));
    uint64_t limb = pos >> 6, off = pos & 63;
    if (limb >= at->size) return 0;
    return (int)((at->limbs[limb] >> off) & 1);
}

/* rub: decode a mat-encoded atom from atom a starting at *cur; advance *cur. */
static noun do_rub(noun a, uint64_t *cur) {
    /* count leading zero bits */
    uint64_t z = 0;
    while (atom_bit_at(a, *cur) == 0) {
        z++; (*cur)++;
        if (z > 64) nock_crash("cue: malformed mat encoding");
    }
    (*cur)++;  /* skip the 1 delimiter */

    if (z == 0) return NOUN_ZERO;

    uint64_t below = z - 1;
    /* read below bits: low bits of the encoded length */
    uint64_t lbits = 0;
    for (uint64_t i = 0; i < below; i++)
        lbits |= (uint64_t)atom_bit_at(a, (*cur)++) << i;

    uint64_t len = (1ULL << below) | lbits;

    /* read len bits as the atom value */
    uint64_t limb_count = (len + 63) / 64;
    /*
     * Embedded atoms in large hoonc jams can exceed BN_MAX_LIMBS (stack
     * bignum limit).  Use high-RAM scratch for cue only (not .bss).
     */
#define CUE_RUB_MAX_LIMBS  16384u   /* 128 KiB limbs */
#define CUE_RUB_SCRATCH    PLATFORM_CUE_RUB_SCRATCH
    if (limb_count == 0) return NOUN_ZERO;
    if (limb_count > CUE_RUB_MAX_LIMBS) nock_crash("cue: atom too large");
    uint64_t *scratch;
    uint64_t stack_sc[BN_MAX_LIMBS];
    if (limb_count <= (uint64_t)BN_MAX_LIMBS)
        scratch = stack_sc;
    else
        scratch = (uint64_t *)(uintptr_t)CUE_RUB_SCRATCH;
    for (uint64_t i = 0; i < limb_count; i++) scratch[i] = 0;
    for (uint64_t i = 0; i < len; i++)
        scratch[i >> 6] |= (uint64_t)atom_bit_at(a, (*cur)++) << (i & 63);

    return bn_normalize(scratch, limb_count);
}

/* ── cue cache: bit position → noun ──────────────────────────────────────── */
/*
 * Large hoonc jams (100k+ cells) need a big backref table.  A multi-MB static
 * .bss array would overlay FORTH_BASE (~0x90000); keep the table in high RAM.
 */
#define CUE_CACHE_SZ   1048576u      /* 1M slots — hoonc jams are dense */
#define CUE_CACHE_BASE PLATFORM_CUE_CACHE_BASE

typedef struct { uint64_t pos; noun val; int used; } ccent_t;

static ccent_t *g_ccache = (ccent_t *)(uintptr_t)CUE_CACHE_BASE;

static void ccache_init(void) {
    for (uint32_t i = 0; i < CUE_CACHE_SZ; i++)
        g_ccache[i].used = 0;
}

static void ccache_put(uint64_t pos, noun val) {
    uint32_t h = (uint32_t)(pos * 2654435761ULL) & (CUE_CACHE_SZ - 1);
    for (uint32_t i = 0; i < CUE_CACHE_SZ; i++) {
        uint32_t idx = (h + i) & (CUE_CACHE_SZ - 1);
        if (!g_ccache[idx].used || g_ccache[idx].pos == pos) {
            g_ccache[idx].pos = pos;
            g_ccache[idx].val = val;
            g_ccache[idx].used = 1;
            return;
        }
    }
    nock_crash("cue: backref cache full");
}

static noun ccache_get(uint64_t pos) {
    uint32_t h = (uint32_t)(pos * 2654435761ULL) & (CUE_CACHE_SZ - 1);
    for (uint32_t i = 0; i < CUE_CACHE_SZ; i++) {
        uint32_t idx = (h + i) & (CUE_CACHE_SZ - 1);
        if (!g_ccache[idx].used) break;
        if (g_ccache[idx].pos == pos) return g_ccache[idx].val;
    }
    nock_crash("cue: invalid back-reference");
    return NOUN_ZERO;  /* unreachable */
}

/* ── cue recursive core ───────────────────────────────────────────────────── */

static noun do_cue(noun a, uint64_t *cur) {
    uint64_t start = *cur;
    noun result;

    int tag0 = atom_bit_at(a, (*cur)++);
    if (tag0 == 0) {
        /* atom */
        result = do_rub(a, cur);
    } else {
        int tag1 = atom_bit_at(a, (*cur)++);
        if (tag1 == 0) {
            /* cell: decode head then tail */
            noun head = do_cue(a, cur);
            noun tail = do_cue(a, cur);
            result = alloc_cell(head, tail);
        } else {
            /* back-reference: decode position then look up */
            noun ref_pos = do_rub(a, cur);
            if (!noun_is_direct(ref_pos))
                nock_crash("cue: back-ref position too large");
            result = ccache_get(direct_val(ref_pos));
        }
    }

    ccache_put(start, result);
    return result;
}

noun cue(noun a) {
    if (!noun_is_atom(a)) nock_crash("cue: expected atom");
    ccache_init();
    uint64_t cur = 0;
    return do_cue(a, &cur);
}
