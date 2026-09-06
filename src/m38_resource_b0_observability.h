#pragma once

#include <stdint.h>

/* Private, test-only scalar seam.  No diagnostic type crosses ResourceABI. */
#define M38_B0_SCHEMA_VERSION 1u
#define M38_B0_RECORD_CAPACITY 1u
#define M38_B0_IMAGE_ID UINT64_C(0x4d3338d842423031)
#define M38_B0_CONTRACT_ID UINT64_C(0x4d3338d842434f31)

typedef enum M38B0Operation {
    M38_B0_OP_NONE = 0,
    M38_B0_OP_LOAD = 1,
    M38_B0_OP_POKE = 2,
    M38_B0_OP_PEEK = 3,
    M38_B0_OP_SNAPSHOT = 4,
    M38_B0_OP_RESTORE = 5,
} M38B0Operation;

typedef enum M38B0CopyDomain {
    M38_B0_COPY_NONE = 0,
    M38_B0_COPY_SESSION_A = 1,
    M38_B0_COPY_SESSION_B = 2,
    M38_B0_COPY_STAGED = 3,
} M38B0CopyDomain;

typedef struct M38B0MemoryPoint {
    uint64_t persistent_cells;
    uint64_t persistent_bytes;
    uint64_t scratch_cells;
    uint64_t scratch_bytes;
    uint64_t atom_bytes;
    uint64_t atom_index_occupancy;
    uint64_t atom_index_probe_depth;
} M38B0MemoryPoint;

typedef struct M38B0Record {
    uint32_t schema_version;
    uint32_t sequence;
    uint64_t image_identity;
    uint64_t contract_identity;
    uint8_t session_id;
    uint8_t operation;
    uint16_t reserved0;
    uint32_t final_status;
    uint32_t wire_status;
    uint8_t view_published;
    uint8_t semantic_roots_preserved;
    uint16_t reserved_view;
    uint64_t evaluator_ops;
    uint64_t evaluator_cells;
    uint64_t evaluator_peak_depth;
    uint8_t evaluator_aborted;
    uint8_t scratch_rewound;
    uint8_t reserved1[6];
    M38B0MemoryPoint before;
    M38B0MemoryPoint peak;
    M38B0MemoryPoint after;
    uint64_t scratch_entry_mark;
    uint64_t scratch_final_mark;
    uint8_t semispace_before;
    uint8_t semispace_after;
    uint16_t reserved2;
    uint64_t registered_sessions_before;
    uint64_t registered_sessions_after;
    uint64_t live_roots_before;
    uint64_t live_roots_after;
    uint64_t promotion_delta;
    uint64_t copied_session_a_cells;
    uint64_t copied_session_b_cells;
    uint64_t copied_staged_cells;
    uint64_t copy_map_passes;
    uint64_t copy_map_clear_bytes;
    uint64_t copy_map_peak_entries;
    uint64_t copy_map_peak_probe_depth;
    uint64_t resource_core_parse_count_before;
    uint64_t resource_core_parse_count_after;
    uint64_t request_safety_traversal_count;
    uint64_t request_decode_count;
    uint64_t primary_generation_a_before;
    uint64_t primary_generation_a_after;
    uint64_t refusal_generation_a_before;
    uint64_t refusal_generation_a_after;
    uint64_t primary_generation_b_before;
    uint64_t primary_generation_b_after;
    uint64_t refusal_generation_b_before;
    uint64_t refusal_generation_b_after;
} M38B0Record;

_Static_assert(sizeof(M38B0Record) <= 512u, "B0 record must remain bounded");

void m38_resource_b0_reset(void);
int m38_resource_b0_read(M38B0Record *out);

/* Instrumentation hooks used only by the runtime, noun, and Nock objects. */
void noun_b0_copy_metrics_reset(void);
void noun_b0_copy_domain_set(M38B0CopyDomain domain);
uint64_t noun_b0_copy_cells(M38B0CopyDomain domain);
uint64_t noun_b0_copy_passes(void);
uint64_t noun_b0_copy_clear_bytes(void);
uint64_t noun_b0_copy_peak_entries(void);
uint64_t noun_b0_copy_peak_probe_depth(void);
void nock_b0_metrics_reset(void);
