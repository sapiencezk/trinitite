#pragma once

#include <stdint.h>

typedef enum M38B3CopyDomain {
    M38_B3_COPY_NONE = 0,
    M38_B3_COPY_SESSION_A = 1,
    M38_B3_COPY_SESSION_B = 2,
    M38_B3_COPY_STAGED = 3,
} M38B3CopyDomain;

typedef struct M38B3Metrics {
    uint64_t persistent_cells_current;
    uint64_t scratch_cells_current;
    uint64_t persistent_cells_hwm;
    uint64_t scratch_cells_hwm;
    uint64_t atom_bytes_current;
    uint64_t atom_bytes_hwm;
    uint64_t atom_index_occupancy_current;
    uint64_t atom_index_occupancy_hwm;
    uint64_t atom_index_probe_depth_hwm;
    uint64_t copied_session_a_cells;
    uint64_t copied_session_b_cells;
    uint64_t copied_staged_cells;
    uint64_t copy_map_passes;
    uint64_t copy_map_clear_bytes;
    uint64_t copy_map_peak_entries;
    uint64_t copy_map_peak_probe_depth;
} M38B3Metrics;

void noun_b3_metrics_reset(void);
void noun_b3_metrics_begin_row(void);
void noun_b3_copy_domain_set(M38B3CopyDomain domain);
void noun_b3_metrics_read(M38B3Metrics *out);
