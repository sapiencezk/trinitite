#pragma once

#include <stdint.h>
#include "noun.h"

typedef enum {
    CUE_BOUNDED_OK = 0,
    CUE_BOUNDED_INPUT,
    CUE_BOUNDED_TRUNCATED,
    CUE_BOUNDED_DEPTH,
    CUE_BOUNDED_WORK,
    CUE_BOUNDED_NODES,
    CUE_BOUNDED_CELLS,
    CUE_BOUNDED_BACKREF,
    CUE_BOUNDED_CACHE,
    CUE_BOUNDED_ATOM,
    CUE_BOUNDED_ALLOC,
    CUE_BOUNDED_TRAILING
} cue_bounded_status_t;

typedef struct {
    uint64_t max_input_bytes;
    uint32_t max_depth;
    uint32_t max_nodes;
    uint32_t max_cells;
    uint32_t max_backrefs;
    uint32_t max_cache_entries;
    uint32_t max_atom_bytes;
    uint64_t max_total_atom_bytes;
    uint64_t max_work;
} cue_bounded_limits_t;

extern const cue_bounded_limits_t cue_i2_limits;

/*
 * Decode one canonical jam byte string into the selected cell heap.
 *
 * Success deliberately leaves a noun transaction active. The caller commits
 * it only after the enclosing ingress/pill/restore transaction is accepted,
 * or calls noun_tx_abort() on any later rejection. Failure rolls it back.
 */
cue_bounded_status_t cue_bounded_bytes(const uint8_t *bytes, uint64_t len,
                                       const cue_bounded_limits_t *limits,
                                       int heap_mode, noun *out);
const char *cue_bounded_status_name(cue_bounded_status_t status);
