#pragma once

#include <stdint.h>

/*
 * Fixed, allocation-free measurements for the sole I2 admission envelope.
 * These counters are diagnostic evidence, not an admission authority and not
 * part of the operator wire contract.  QEMU evidence reads the structure via
 * the GDB stub from the exact runtime image under test.
 */
#define I2_ADMISSION_METRICS_SCHEMA 1u

typedef struct {
    uint64_t schema;
    uint64_t bss_used_bytes;
    uint64_t bss_reserved_bytes;
    uint64_t bss_admitted_bytes;

    /* Framing is outside admission authority.  These diagnostic counters
     * identify the target-side path that refused a hostile framed noun. */
    uint64_t ingress_rejects;
    uint64_t ingress_version_rejects;
    uint64_t ingress_header_rejects;
    uint64_t ingress_length_rejects;
    uint64_t ingress_digest_rejects;
    uint64_t ingress_cue_rejects;
    uint64_t ingress_timeout_rejects;

    uint64_t cue_calls;
    uint64_t cue_rejects;
    uint64_t cue_input_bytes_hwm;
    uint64_t cue_work_hwm;
    uint64_t cue_depth_hwm;
    uint64_t cue_nodes_hwm;
    uint64_t cue_cells_hwm;
    uint64_t cue_backrefs_hwm;
    uint64_t cue_atom_bytes_hwm;
    uint64_t cue_cache_entries_hwm;
    uint64_t cue_probe_hwm;
    uint64_t cue_clear_count;
    uint64_t cue_clear_bytes;

    uint64_t jam_passes;
    uint64_t jam_cache_entries_hwm;
    uint64_t jam_probe_hwm;
    uint64_t jam_clear_count;
    uint64_t jam_clear_bytes;

    uint64_t formula_passes;
    uint64_t formula_nodes_hwm;
    uint64_t formula_cache_entries_hwm;
    uint64_t formula_probe_hwm;
    uint64_t formula_clear_count;
    uint64_t formula_clear_bytes;

    uint64_t copy_passes;
    uint64_t copy_cache_entries_hwm;
    uint64_t copy_probe_hwm;
    uint64_t copy_clear_count;
    uint64_t copy_clear_bytes;
} i2_admission_metrics_t;

extern i2_admission_metrics_t g_i2_admission_metrics;

void i2_admission_metrics_init(void);
void i2_admission_metrics_max(uint64_t *field, uint64_t value);
