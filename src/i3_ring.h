/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdint.h>
#include "cold.h"

/*
 * Row 212 (2) as amended (1499kernel #263): the lite node's fixed-size
 * recorder ring on SD (PR 1c). Compiled only with COLD_LITE_LOG
 * (I3_CHECKPOINT_EVERY > 0 and I3_LITE_LOG), so other images are unchanged.
 *
 * The ring is I3_RING_BYTES bytes (build-time, default 64 MiB, a multiple of
 * 512). It keeps periodic checkpoints (every I3_RING_EVERY events, default
 * 2,000, a multiple of I3_CHECKPOINT_EVERY) and every input between them, for
 * exact replay off the device; when full, the oldest checkpoint and its
 * inputs are overwritten. It is separate from the running log in the cold
 * store, and the node never reads it except to find its own head at boot.
 *
 * Layout (little-endian; tools/ring_image.py reads it):
 *   [0, 512) and [512, 1024): two header slots (the higher valid gen wins),
 *     128 bytes each: magic "I3RING1\0", version 1, header_len 128,
 *     ring_bytes, gen, head, tail, tail_seq, next_seq, wraps, evicted,
 *     last_n, 0, then BLAKE3 of the first 96 bytes.
 *   [1024, ring_bytes): records, 8-byte aligned, never straddling the end:
 *     64-byte header (magic "I3RR", kind, seq, n, len, BLAKE3 of payload)
 *     then the payload. Kinds: 1 genesis (n 0, payload kernel-blake3: replay
 *     from the boot kernel), 2 checkpoint (n N, payload sha256 D || kernel-
 *     blake3 || ++jam of the state, so sha256 of the jam is D and /state-hash
 *     at N), 3 input (n the event number, payload the log entry's jam bytes,
 *     as in the cold log), 4 wrap (the next record is at 1024; implied when
 *     fewer than 64 bytes are left). The live records run from tail to head
 *     with consecutive seq; a segment is a genesis or checkpoint record and
 *     the inputs after it.
 */
#if defined(COLD_LITE_LOG)
#ifndef I3_RING_BYTES
#define I3_RING_BYTES 67108864ULL
#endif
#ifndef I3_RING_EVERY
#define I3_RING_EVERY 2000
#endif

void i3_ring_boot(uint64_t log_len, const uint8_t kernel_blake3[32]);
void i3_ring_input(uint64_t n, const uint8_t *bytes, uint64_t len);
void i3_ring_checkpoint(uint64_t n, const uint8_t d[32],
                        const uint8_t *jam, uint64_t len);
void i3_ring_flush(void);
#endif
