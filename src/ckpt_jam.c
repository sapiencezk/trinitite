/* Row 317 (3), Q7 (row 212 (4)): the lite checkpoint writer's own jam.
 *
 * jam.c compiled a second time, with every public name prefixed ckpt_, a
 * CKPT_JAM_MAX_BYTES (256 KiB) output buffer and a CKPT_JAM_CACHE_ENTRIES
 * backref cache. Its statics are this file's own, so the %jam jet, the log
 * writer and every other jam.c caller keep their 128 KiB buffer and
 * 98,304-entry cache, and a flag-off image does not link this file at all
 * (Makefile CKPT_OBJS). The encoding rules are jam.c's: the default writer
 * stores the checkpoint state blob, ++jam's rule gives the bytes D hashes.
 * A larger cache changes only where an entry is probed, never which
 * backrefs ++jam's rule writes (it keys by value). */
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
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
#include "i2_admission_envelope.h"
#include "ckpt_jam.h"
#undef JAM_MAX_BYTES
#define JAM_MAX_BYTES CKPT_JAM_MAX_BYTES
#define JAM_MAX_LIMBS (CKPT_JAM_MAX_BYTES / 8u)
#undef I2_JAM_CACHE_ENTRIES
#define I2_JAM_CACHE_ENTRIES CKPT_JAM_CACHE_ENTRIES
#undef I2_JAM_CACHE_ADMITTED
#define I2_JAM_CACHE_ADMITTED CKPT_JAM_CACHE_ADMITTED
#include "jam.c"

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
