#include <stddef.h>
#include <stdint.h>
#include "bounded_cue.h"

#ifdef I2_M11
/* M11 BFB gates occupy ~70k unique jam backref slots. The 64k table
 * linear-probes until charge() reports WORK before CACHE. */
#define BOUNDED_CACHE_MAX       131072u
#else
#define BOUNDED_CACHE_MAX       65536u
#endif
#define BOUNDED_ATOM_LIMBS_MAX  32768u /* 256 KiB */

typedef struct {
    uint64_t pos;
    noun val;
    uint8_t used;
} bounded_cache_entry_t;

typedef struct {
    const uint8_t *bytes;
    uint64_t bits;
    uint64_t cur;
    const cue_bounded_limits_t *lim;
    cue_bounded_status_t status;
    uint64_t work;
    uint64_t total_atom_bytes;
    uint32_t nodes;
    uint32_t cells;
    uint32_t backrefs;
    uint32_t cache_entries;
} cue_reader_t;

static bounded_cache_entry_t g_bounded_cache[BOUNDED_CACHE_MAX];
static uint64_t g_bounded_atom_limbs[BOUNDED_ATOM_LIMBS_MAX];

const cue_bounded_limits_t cue_i2_limits = {
    .max_input_bytes = 1024u * 1024u,
    .max_depth = 256,
    .max_nodes = 131072,
    .max_cells = 65536,
    .max_backrefs = 65536,
#ifdef I2_M11
    .max_cache_entries = 131072,
#else
    .max_cache_entries = 65536,
#endif
    .max_atom_bytes = 256u * 1024u,
    .max_total_atom_bytes = 1024u * 1024u,
    .max_work = 2000000
};

static int charge(cue_reader_t *r, uint64_t n)
{
    if (r->status != CUE_BOUNDED_OK)
        return 0;
    if (n > r->lim->max_work || r->work > r->lim->max_work - n) {
        r->status = CUE_BOUNDED_WORK;
        return 0;
    }
    r->work += n;
    return 1;
}

static int read_bit(cue_reader_t *r, int *out)
{
    if (!charge(r, 1))
        return 0;
    if (r->cur >= r->bits) {
        r->status = CUE_BOUNDED_TRUNCATED;
        return 0;
    }
    *out = (r->bytes[r->cur >> 3] >> (r->cur & 7)) & 1;
    r->cur++;
    return 1;
}

static uint32_t cache_hash(uint64_t pos)
{
    return (uint32_t)(pos * 2654435761ULL) & (BOUNDED_CACHE_MAX - 1u);
}

static int cache_put(cue_reader_t *r, uint64_t pos, noun value)
{
    uint32_t h = cache_hash(pos);
    uint32_t cap = r->lim->max_cache_entries;
    if (cap == 0 || cap > BOUNDED_CACHE_MAX)
        cap = BOUNDED_CACHE_MAX;
    for (uint32_t i = 0; i < cap; i++) {
        if (!charge(r, 1))
            return 0;
        uint32_t slot = (h + i) & (BOUNDED_CACHE_MAX - 1u);
        if (!g_bounded_cache[slot].used) {
            if (r->cache_entries >= r->lim->max_cache_entries) {
                r->status = CUE_BOUNDED_CACHE;
                return 0;
            }
            g_bounded_cache[slot].used = 1;
            g_bounded_cache[slot].pos = pos;
            g_bounded_cache[slot].val = value;
            r->cache_entries++;
            return 1;
        }
        if (g_bounded_cache[slot].pos == pos) {
            g_bounded_cache[slot].val = value;
            return 1;
        }
    }
    r->status = CUE_BOUNDED_CACHE;
    return 0;
}

static int cache_get(cue_reader_t *r, uint64_t pos, noun *out)
{
    uint32_t h = cache_hash(pos);
    uint32_t cap = r->lim->max_cache_entries;
    if (cap == 0 || cap > BOUNDED_CACHE_MAX)
        cap = BOUNDED_CACHE_MAX;
    for (uint32_t i = 0; i < cap; i++) {
        if (!charge(r, 1))
            return 0;
        uint32_t slot = (h + i) & (BOUNDED_CACHE_MAX - 1u);
        if (!g_bounded_cache[slot].used)
            break;
        if (g_bounded_cache[slot].pos == pos) {
            *out = g_bounded_cache[slot].val;
            return 1;
        }
    }
    r->status = CUE_BOUNDED_BACKREF;
    return 0;
}

static int decode_mat(cue_reader_t *r, noun *out)
{
    uint64_t zeros = 0;
    int bit;
    for (;;) {
        if (!read_bit(r, &bit))
            return 0;
        if (bit)
            break;
        zeros++;
        if (zeros > 63) {
            r->status = CUE_BOUNDED_ATOM;
            return 0;
        }
    }
    if (zeros == 0) {
        *out = NOUN_ZERO;
        return 1;
    }
    uint64_t below = zeros - 1;
    uint64_t len_bits = 0;
    for (uint64_t i = 0; i < below; i++) {
        if (!read_bit(r, &bit))
            return 0;
        len_bits |= (uint64_t)bit << i;
    }
    uint64_t atom_bits = (1ULL << below) | len_bits;
    uint64_t atom_bytes = (atom_bits + 7) / 8;
    if (atom_bytes == 0 || atom_bytes > r->lim->max_atom_bytes
        || atom_bytes > (uint64_t)BOUNDED_ATOM_LIMBS_MAX * 8) {
        r->status = CUE_BOUNDED_ATOM;
        return 0;
    }
    if (atom_bytes > r->lim->max_total_atom_bytes
        || r->total_atom_bytes > r->lim->max_total_atom_bytes - atom_bytes) {
        r->status = CUE_BOUNDED_ATOM;
        return 0;
    }
    r->total_atom_bytes += atom_bytes;
    if (!charge(r, atom_bytes))
        return 0;

    uint64_t limbs = (atom_bits + 63) / 64;
    for (uint64_t i = 0; i < limbs; i++)
        g_bounded_atom_limbs[i] = 0;
    for (uint64_t i = 0; i < atom_bits; i++) {
        if (!read_bit(r, &bit))
            return 0;
        if (bit)
            g_bounded_atom_limbs[i >> 6] |= 1ULL << (i & 63);
    }
    if (!make_atom_checked(g_bounded_atom_limbs, limbs, out)) {
        r->status = CUE_BOUNDED_ALLOC;
        return 0;
    }
    return 1;
}

static int decode_noun(cue_reader_t *r, uint32_t depth, noun *out)
{
    if (depth > r->lim->max_depth) {
        r->status = CUE_BOUNDED_DEPTH;
        return 0;
    }
    if (++r->nodes > r->lim->max_nodes) {
        r->status = CUE_BOUNDED_NODES;
        return 0;
    }
    if (!charge(r, 1))
        return 0;

    uint64_t start = r->cur;
    int tag0, tag1;
    noun result;
    if (!read_bit(r, &tag0))
        return 0;
    if (tag0 == 0) {
        if (!decode_mat(r, &result))
            return 0;
    } else {
        if (!read_bit(r, &tag1))
            return 0;
        if (tag1 == 0) {
            noun head, tail;
            if (++r->cells > r->lim->max_cells) {
                r->status = CUE_BOUNDED_CELLS;
                return 0;
            }
            /* Refuse the recursive edge in the current frame so even the
             * rejecting path cannot place a 257th decode frame on C stack. */
            if (depth >= r->lim->max_depth) {
                r->status = CUE_BOUNDED_DEPTH;
                return 0;
            }
            if (!decode_noun(r, depth + 1, &head)
                || !decode_noun(r, depth + 1, &tail))
                return 0;
            if (!alloc_cell_checked(head, tail, &result)) {
                r->status = CUE_BOUNDED_ALLOC;
                return 0;
            }
        } else {
            noun ref;
            if (++r->backrefs > r->lim->max_backrefs) {
                r->status = CUE_BOUNDED_BACKREF;
                return 0;
            }
            if (!decode_mat(r, &ref) || !noun_is_direct(ref)) {
                if (r->status == CUE_BOUNDED_OK)
                    r->status = CUE_BOUNDED_BACKREF;
                return 0;
            }
            uint64_t pos = direct_val(ref);
            if (pos >= start || !cache_get(r, pos, &result)) {
                if (r->status == CUE_BOUNDED_OK)
                    r->status = CUE_BOUNDED_BACKREF;
                return 0;
            }
        }
    }
    if (!cache_put(r, start, result))
        return 0;
    *out = result;
    return 1;
}

cue_bounded_status_t cue_bounded_bytes(const uint8_t *bytes, uint64_t len,
                                       const cue_bounded_limits_t *limits,
                                       int heap_mode, noun *out)
{
    if (!bytes || !out || !limits || len == 0
        || len > limits->max_input_bytes
        || limits->max_cache_entries == 0
        || limits->max_cache_entries > BOUNDED_CACHE_MAX)
        return CUE_BOUNDED_INPUT;
    if (!noun_tx_begin(heap_mode))
        return CUE_BOUNDED_ALLOC;

    for (uint32_t i = 0; i < BOUNDED_CACHE_MAX; i++)
        g_bounded_cache[i].used = 0;
    cue_reader_t r = {
        .bytes = bytes,
        .bits = len * 8,
        .cur = 0,
        .lim = limits,
        .status = CUE_BOUNDED_OK
    };
    noun decoded = NOUN_ZERO;
    if (!decode_noun(&r, 1, &decoded)) {
        noun_tx_abort();
        return r.status;
    }
    uint64_t trailing = r.bits - r.cur;
    if (trailing > 7) {
        noun_tx_abort();
        return CUE_BOUNDED_TRAILING;
    }
    while (r.cur < r.bits) {
        int bit;
        if (!read_bit(&r, &bit) || bit != 0) {
            noun_tx_abort();
            return r.status == CUE_BOUNDED_OK
                ? CUE_BOUNDED_TRAILING : r.status;
        }
    }
    *out = decoded;
    return CUE_BOUNDED_OK;
}

const char *cue_bounded_status_name(cue_bounded_status_t status)
{
    static const char *names[] = {
        "ok", "input", "truncated", "depth", "work", "nodes", "cells",
        "backref", "cache", "atom", "alloc", "trailing"
    };
    if ((unsigned)status >= sizeof(names) / sizeof(names[0]))
        return "unknown";
    return names[status];
}
