/* Row 317 (3), Q7 (row 212 (4)): the lite checkpoint writer's own jam.
 *
 * jam.c compiled a second time, with every public name prefixed ckpt_, a
 * CKPT_JAM_MAX_BYTES (4 MiB, Round 3 Q11) output buffer and a
 * CKPT_JAM_CACHE_ENTRIES backref cache (sizes: ckpt_jam.h). Its statics are this file's own, so the %jam jet, the log
 * writer and every other jam.c caller keep their 128 KiB buffer and
 * 98,304-entry cache, and a flag-off image does not link this file at all
 * (Makefile CKPT_OBJS). The encoding rules are jam.c's: the default writer
 * stores the checkpoint state blob, ++jam's rule gives the bytes D hashes.
 * A larger cache changes only where an entry is probed, never which
 * backrefs ++jam's rule writes (it keys by value). */
#if defined(LITE_CHECKPOINT_EVERY) && LITE_CHECKPOINT_EVERY > 0
#define jam ckpt_jam
#define cue ckpt_cue
#define jam_size_checked ckpt_jam_size_checked
#define jam_encode_bytes_checked ckpt_jam_encode_bytes_checked
#define jam_encode_bytes_identity ckpt_jam_encode_bytes_identity
#define jam_hoon_checked ckpt_jam_hoon_checked
#define jam_encode_bytes_selftest ckpt_jam_encode_bytes_selftest
#define jam_admission_budget_init ckpt_jam_admission_budget_init
#define jam_encode_bytes_identity_bounded ckpt_jam_encode_bytes_identity_bounded
#include "jam.h"
#include "admission_envelope.h"
#include "ckpt_jam.h"
#include "lite_admission.h"
/* Q8: ++jam of a checkpoint state as deep as live admission allows. */
#define JAM_HOON_DEPTH (LITE_CUE_MAX_DEPTH + CKPT_DEPTH_MARGIN)
#undef JAM_MAX_BYTES
#define JAM_MAX_BYTES CKPT_JAM_MAX_BYTES
#define JAM_MAX_LIMBS (CKPT_JAM_MAX_BYTES / 8u)
#undef ENVELOPE_JAM_CACHE_ENTRIES
#define ENVELOPE_JAM_CACHE_ENTRIES CKPT_JAM_CACHE_ENTRIES
#undef ENVELOPE_JAM_CACHE_ADMITTED
#define ENVELOPE_JAM_CACHE_ADMITTED CKPT_JAM_CACHE_ADMITTED
/* The backref cache (12 MiB), the mug memo (4 MiB) and the 4 MiB buffer
 * live in the fixed LITE_CKPT_JAM region (memory.h), not in .bss: with them
 * .bss would pass its 24 MiB bound. Region memory
 * is not zeroed at boot: ckpt_jam_reset clears the cache and the memo once
 * before first use; besides, jam.c clears the cache's used flags and the
 * buffer on every jam, and the memo's generation starts at its last value
 * so a first jam without the reset would wrap it and clear the memo. */
#include "memory.h"
#define JAM_TABLE(type, name, n) \
    static type (*const name##_at)[n] = (type (*)[n])(uintptr_t)(LITE_CKPT_JAM_##name)
#define LITE_CKPT_JAM_g_jcache LITE_CKPT_JAM_BASE
#define LITE_CKPT_JAM_g_jmug (LITE_CKPT_JAM_BASE + LITE_CKPT_JAM_MEMO_OFF)
#define g_jcache (*g_jcache_at)
#define g_jmug (*g_jmug_at)
#define JAM_MUG_GEN_INIT = 0xFFFFFFFFu
#define JAM_MUG_MEMO CKPT_JAM_MUG_MEMO
#define JAM_BUF_DECL \
    static jambuf_t *const g_jambuf_at = (jambuf_t *)(uintptr_t)(LITE_CKPT_JAM_BASE + LITE_CKPT_JAM_BUF_OFF)
#define g_jambuf (*g_jambuf_at)
#include "jam.c"

_Static_assert(sizeof g_jambuf <= LITE_CKPT_JAM_COLD_OFF - LITE_CKPT_JAM_BUF_OFF, "ckpt jam buffer fits its slot");
_Static_assert(CKPT_JAM_CACHE_ADMITTED >= 2u * CKPT_CUE_MAX_CELLS + 1u, "a cache entry for every distinct noun");
_Static_assert(CKPT_JAM_MUG_MEMO >= 2u * CKPT_CUE_MAX_CELLS, "mug memo at most half full");
_Static_assert((2ull * CKPT_CUE_MAX_CELLS + (CKPT_CUE_MAX_CELLS + 1ull) * CKPT_JAM_LEAF_BITS
                + 8ull * LITE_CUE_MAX_TOTAL_ATOM_BYTES + 7ull) / 8ull <= CKPT_JAM_MAX_BYTES,
               "the jam of any state the checkpoint cue admits fits the buffer");

_Static_assert(sizeof g_jcache <= LITE_CKPT_JAM_MEMO_OFF, "ckpt jam cache fits under the memo");
_Static_assert(LITE_CKPT_JAM_MEMO_OFF + sizeof g_jmug <= LITE_CKPT_JAM_BUF_OFF, "ckpt jam memo fits under the buffer");

void ckpt_jam_reset(void)
{
#if defined(LITE_CKPT_TEST_DIRTY)
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)LITE_CKPT_JAM_BASE;
    for (uint64_t i = 0; i < LITE_CKPT_JAM_SIZE / 8u; i++)
        p[i] = 0xA5A5A5A5A5A5A5A5ULL;
#endif
    for (uint32_t i = 0; i < JAM_CACHE_SZ; i++) {
        g_jcache[i].key = 0;
        g_jcache[i].pos = 0;
        g_jcache[i].used = 0;
    }
    for (uint32_t i = 0; i < JAM_MUG_MEMO; i++) {
        g_jmug[i].key = 0;
        g_jmug[i].mug = 0;
        g_jmug[i].gen = 0;
    }
    g_jmug_gen = 0;
}

_Static_assert(JAM_MAX_LIMBS * 8u == CKPT_JAM_MAX_BYTES, "ckpt jam buffer is the capacity");
_Static_assert(CKPT_JAM_CACHE_ADMITTED * 4u == CKPT_JAM_CACHE_ENTRIES * 3u, "ckpt cache 75% admitted");

int ckpt_jam_hoon_bytes(noun n, const uint8_t **out, uint64_t *out_bytes)
{
    const uint8_t *b = (const uint8_t *)(const void *)g_jambuf.buf;
    uint64_t bytes;
    int rc = -1;
    if (!out || !out_bytes)
        return -1;
    g_jam_hoon_rule = 1;
    g_jam_cache_full = 0;
    if (++g_jmug_gen == 0) {
        for (uint32_t i = 0; i < JAM_MUG_MEMO; i++) g_jmug[i].gen = 0;
        g_jmug_gen = 1;
    }
    if (jam_size_in(n, JAM_MAX_BYTES, &bytes) == 0 && !g_jam_cache_full) {
        bytes = (jam_encode(n) + 7) / 8;
        while (bytes > 1 && b[bytes - 1] == 0)
            bytes--;
        if (!g_jam_cache_full && bytes > 0 && b[bytes - 1] != 0) {
            *out = b;
            *out_bytes = bytes;
            rc = 0;
        }
    }
    g_jam_hoon_rule = 0;
    return rc;
}
#endif
