#pragma once

#include <stdint.h>

/*
 * High-water marks of the bounded cue since boot, printed on the host's
 * `I3H cue` line after the kernel cue (i3_host.c, print_cue).
 */
typedef struct {
    uint64_t cue_work_hwm;
    uint64_t cue_depth_hwm;
    uint64_t cue_nodes_hwm;
    uint64_t cue_cells_hwm;
    uint64_t cue_backrefs_hwm;
    uint64_t cue_atom_bytes_hwm;
    uint64_t cue_cache_entries_hwm;
} i2_admission_metrics_t;

extern i2_admission_metrics_t g_i2_admission_metrics;

void i2_admission_metrics_max(uint64_t *field, uint64_t value);
