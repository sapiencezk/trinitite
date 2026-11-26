#pragma once

#include <stdint.h>

/*
 * High-water marks of the bounded cue since boot, printed on the host's
 * `LITEH cue` line after the kernel cue (lite_host.c, print_cue).
 */
typedef struct {
    uint64_t cue_work_hwm;
    uint64_t cue_depth_hwm;
    uint64_t cue_nodes_hwm;
    uint64_t cue_cells_hwm;
    uint64_t cue_backrefs_hwm;
    uint64_t cue_atom_bytes_hwm;
    uint64_t cue_cache_entries_hwm;
} admission_metrics_t;

extern admission_metrics_t g_admission_metrics;

void admission_metrics_max(uint64_t *field, uint64_t value);
