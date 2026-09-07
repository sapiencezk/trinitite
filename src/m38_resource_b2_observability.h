#pragma once

#include <stdint.h>

#include "m38_resource_runtime.h"

/*
 * Test-only scalar projection for M38-D8 Wave B B2.  The projection is
 * compiled into the image only for the explicitly named B2 qualification
 * build.  It contains no host-dereferenceable pointers; guest root-slot
 * addresses are opaque uint64_t observations, and it never crosses the public
 * ResourceABI boundary.
 */
#define M38_B2_SESSION_COUNT 2u
#define M38_B2_CATALOG_COUNT 2u
#define M38_B2_HANDLE_COUNT 8u

typedef struct M38B2SessionSnapshot {
    uint64_t state;
    uint64_t in_flight;
    uint64_t registry_index;
    uint64_t capability;
    uint64_t primary_root;
    uint64_t refusal_root;
    uint64_t primary_view_root_slot;
    uint64_t refusal_view_root_slot;
    uint64_t primary_view_generation;
    uint64_t refusal_view_generation;
    uint64_t primary_view_wire;
    uint64_t refusal_view_wire;
    uint64_t primary_view_owner;
    uint64_t refusal_view_owner;
    uint64_t parse_count;
    uint64_t catalog_valid_mask;
    uint64_t cache_valid_mask;
    uint64_t catalog_roots[M38_B2_CATALOG_COUNT];
    uint64_t cache_roots[M38_B2_CATALOG_COUNT];
    uint64_t cache_formula_roots[M38_B2_CATALOG_COUNT];
    uint64_t cache_payload_roots[M38_B2_CATALOG_COUNT];
    uint64_t slot_used_mask;
    uint64_t slot_catalog[M38_B2_HANDLE_COUNT];
    uint64_t slot_generation[M38_B2_HANDLE_COUNT];
    uint64_t slot_snapshot_nonce[M38_B2_HANDLE_COUNT];
    uint64_t slot_handle_roots[M38_B2_HANDLE_COUNT];
    uint64_t slot_state_roots[M38_B2_HANDLE_COUNT];
    uint64_t slot_snapshot_roots[M38_B2_HANDLE_COUNT];
} M38B2SessionSnapshot;

typedef struct M38B2Snapshot {
    uint64_t runtime_state;
    uint64_t broker_owner;
    uint64_t session_count;
    uint64_t next_capability;
    uint64_t broker_transaction_id;
    uint64_t promoted_root_count;
    uint64_t next_fault;
    uint64_t persist_selector;
    uint64_t persistent_cells;
    uint64_t scratch_cells;
    uint64_t atom_bytes;
    uint64_t atom_index_occupancy;
    uint64_t atom_index_probe_depth;
    uint64_t live_roots;
    uint64_t scratch_mark;
    uint64_t noun_transaction_active;
    uint64_t evaluator_ops;
    uint64_t evaluator_cells;
    uint64_t evaluator_peak_depth;
    uint64_t evaluator_abort_reason;
    M38B2SessionSnapshot sessions[M38_B2_SESSION_COUNT];
} M38B2Snapshot;

void m38_resource_b2_snapshot(M38B2Snapshot *out);
