#pragma once
#include <stdint.h>
#include "noun.h"

/* Row 317 (3), Q7: the lite checkpoint writer's own jam (ckpt_jam.c), built
 * only with I3_CHECKPOINT_EVERY. Its output buffer is the checkpoint object
 * capacity, which is also the input bound of the checkpoint cue (row 212 (4):
 * "fits the 128k-cell cue bound"). jam.c's 128 KiB writer (the %jam jet, the
 * log, cold_store) is unchanged.
 *
 * Round 3, Q11 B: every capacity is sized from that bound, so a state the
 * checkpoint cue admits is never skipped for a full table or buffer:
 * - CKPT_CUE_MAX_CELLS cells, so at most CKPT_CUE_MAX_CELLS + 1 leaves and
 *   2 * CKPT_CUE_MAX_CELLS + 1 distinct nouns, each at most one backref
 *   cache entry: 2^19 entries, 393,216 admitted (75%), 12 MiB;
 * - the mug memo keys cells only: 2^18 entries, at most half full, 4 MiB;
 * - the jam: 2 bits a cell, at most CKPT_JAM_LEAF_BITS a leaf (tag, mat
 *   header, a direct atom or a backref), and the cue's total atom bytes
 *   (I3_CUE_MAX_TOTAL_ATOM_BYTES) once more for indirect atoms' bits:
 *   4,001,167 bytes, so a 4 MiB buffer (asserted in ckpt_jam.c).
 * The tables, the buffer and the cold store's two object scratches (which
 * hold a checkpoint object too) live in the I3_CKPT_JAM region (memory.h). */
#define CKPT_CUE_MAX_CELLS 128000u
#define CKPT_JAM_MAX_BYTES (4u * 1024u * 1024u)
#define CKPT_JAM_CACHE_ENTRIES 524288u
#define CKPT_JAM_CACHE_ADMITTED 393216u
#define CKPT_JAM_MUG_MEMO 262144u
#define CKPT_JAM_LEAF_BITS 117u /* 1 tag + 2*25+1 mat header + 64 value; a backref is less */

/* jam_size_checked and jam_encode_bytes_checked (the default writer) at
 * CKPT_JAM_MAX_BYTES. */
int ckpt_jam_size_checked(noun n, uint64_t max_bytes, uint64_t *out_bytes);
int ckpt_jam_encode_bytes_checked(noun n, const uint8_t **out, uint64_t *out_bytes);
/* ++jam's bytes, as jam_hoon_checked makes them (the atom's (met 3) little-
 * endian bytes), left in the writer's buffer: no atom is built. -1 past
 * CKPT_JAM_MAX_BYTES or when the backref cache fills. Valid until the next
 * ckpt_jam call. */
int ckpt_jam_hoon_bytes(noun n, const uint8_t **out, uint64_t *out_bytes);
/* Region memory is not zeroed at boot: clear the cache and the mug memo
 * (and with I3_CKPT_TEST=dirty, first fill the whole region with 0xA5, as
 * stale RAM). Called once by i3_host_boot before any checkpoint jam. */
void ckpt_jam_reset(void);

/* Row 317 Round 3, Q8 (rows 212 (3), 213 (4), decision 131): what live
 * admission accepts must replay, from zero and from a checkpoint. Live
 * admission cues a job or an application at depth I3_CUE_MAX_DEPTH; the
 * log entry (the event number and the cause around it) and the checkpoint
 * state (the kernel's state around the application) are deeper than what
 * was admitted by a few wrapper cells. Log decode, the checkpoint cue and
 * the checkpoint writer's ++jam take that depth plus CKPT_DEPTH_MARGIN.
 * Each cue level is one C frame of bounded_cue.c's decoder (<= 128 B), so
 * the margin costs at most 8 KiB of the 256 KiB core stack. */
#define CKPT_DEPTH_MARGIN 64u
