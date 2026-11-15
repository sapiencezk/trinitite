#pragma once
#include <stdint.h>
#include "noun.h"

/* Row 317 (3), Q7: the lite checkpoint writer's own jam (ckpt_jam.c), built
 * only with I3_CHECKPOINT_EVERY. Its output buffer is the checkpoint object
 * capacity, which is also the input bound of the checkpoint cue (row 212 (4):
 * "fits the 128k-cell cue bound"); its ++jam backref cache admits 196,608
 * entries. jam.c's 128 KiB writer (the %jam jet, the log, cold_store) is
 * unchanged. */
#define CKPT_JAM_MAX_BYTES (256u * 1024u)
#define CKPT_JAM_CACHE_ENTRIES 262144u
#define CKPT_JAM_CACHE_ADMITTED 196608u

/* jam_size_checked and jam_encode_bytes_checked (the default writer) at
 * CKPT_JAM_MAX_BYTES. */
int ckpt_jam_size_checked(noun n, uint64_t max_bytes, uint64_t *out_bytes);
int ckpt_jam_encode_bytes_checked(noun n, const uint8_t **out, uint64_t *out_bytes);
/* ++jam's bytes, as jam_hoon_checked makes them (the atom's (met 3) little-
 * endian bytes), left in the writer's buffer: no atom is built. -1 past
 * CKPT_JAM_MAX_BYTES or when the backref cache fills. Valid until the next
 * ckpt_jam call. */
int ckpt_jam_hoon_bytes(noun n, const uint8_t **out, uint64_t *out_bytes);

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
