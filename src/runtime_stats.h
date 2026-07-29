#pragma once

#include <stdint.h>

/*
 * I2 Hybrid v1 Milestone 3 measurement block.
 *
 * The block is fixed-size, allocation-free, single-owner (scheduler core 0),
 * and resettable between runs.  Histograms use log2(CNTVCT ticks) buckets:
 * bucket 0 is 0..1 tick, bucket n is 2^(n-1)+1..2^n ticks.
 */
#define RUNTIME_STATS_SCHEMA 1u
#define RUNTIME_STATS_HIST_BUCKETS 64u

typedef enum {
    RT_PHASE_INGRESS_COMPLETE_TO_ADMIT = 0,
    RT_PHASE_QUEUE_RESIDENCE,
    RT_PHASE_NOCK_SLAM,
    RT_PHASE_VALIDATE_RESERVE_PROMOTE,
    RT_PHASE_ACTIVATE,
    RT_PHASE_ADMIT_TO_ACTIVATE,
    RT_PHASE_TIMER_DUE_TO_ENQUEUE,
    RT_PHASE_TIMER_ENQUEUE_TO_SLAM,
    RT_PHASE_CHECKPOINT_CAPTURE,
    RT_PHASE_CHECKPOINT_JAM,
    RT_PHASE_CHECKPOINT_COLD_APPEND,
    RT_PHASE_CHECKPOINT_MEDIA_FLUSH,
    RT_PHASE_MEDIA_READ,
    RT_PHASE_MEDIA_WRITE,
    RT_PHASE_MEDIA_BARRIER,
    RT_PHASE_BOOT_LOAD,
    RT_PHASE_COUNT
} runtime_phase_t;

typedef enum {
    RT_COUNT_EVENTS_ADMITTED = 0,
    RT_COUNT_COMMITS,
    RT_COUNT_ABORTS,
    RT_COUNT_PREFLIGHT_REJECTS,
    RT_COUNT_PROMOTE_COPY_FAULTS,
    RT_COUNT_BUDGET_FAULTS,
    RT_COUNT_DEADLINE_FAULTS,
    RT_COUNT_QUEUE_HWM,
    RT_COUNT_QUEUE_OVERFLOWS,
    RT_COUNT_TIMER_ARMS,
    RT_COUNT_TIMER_FIRES,
    RT_COUNT_TIMER_CANCELS,
    RT_COUNT_TIMER_LATENESS_MAX,
    RT_COUNT_SERVICE_SUCCESS,
    RT_COUNT_SERVICE_FAILURE,
    RT_COUNT_PERSIST_CELLS_CURRENT,
    RT_COUNT_PERSIST_CELLS_START,
    RT_COUNT_PERSIST_CELLS_HWM,
    RT_COUNT_SCRATCH_CELLS_CURRENT,
    RT_COUNT_SCRATCH_CELLS_START,
    RT_COUNT_SCRATCH_CELLS_HWM,
    RT_COUNT_ATOM_BYTES_CURRENT,
    RT_COUNT_ATOM_BYTES_START,
    RT_COUNT_ATOM_BYTES_HWM,
    RT_COUNT_ATOM_INDEX_OCCUPANCY,
    RT_COUNT_ATOM_INDEX_START,
    RT_COUNT_ATOM_PROBE_HWM,
    RT_COUNT_CHECKPOINTS,
    RT_COUNT_CHECKPOINT_FAILURES,
    RT_COUNT_CHECKPOINT_BYTES,
    RT_COUNT_CHECKPOINT_GENERATION,
    RT_COUNT_COLD_DATA_HEAD,
    RT_COUNT_MEDIA_PHASE,
    RT_COUNT_MEDIA_STATUS,
    RT_COUNT_MEDIA_BYTES_READ,
    RT_COUNT_MEDIA_BYTES_WRITTEN,
    RT_COUNT_WDT_FAILURES,
    RT_COUNT_CANARY_FAILURES,
    RT_COUNT_INGRESS_VERSION,
    RT_COUNT_INGRESS_HEADER,
    RT_COUNT_INGRESS_LENGTH,
    RT_COUNT_INGRESS_DIGEST,
    RT_COUNT_INGRESS_CUE,
    RT_COUNT_INGRESS_TIMEOUT,
    RT_COUNT_EXPECTED_PRESSURE_REJECTS,
    RT_COUNT_UNEXPECTED_DELIVERY_LOSS,
    RT_COUNT_RESTARTS,
    RT_COUNT_RUN_TICKS,
    RT_COUNT_PRESSURE_PERCENT,
    RT_COUNT_PRESSURE_DEPTH,
    RT_COUNT_NOVEL_SAMPLES,
    RT_COUNT_NOVEL_BYTES_DELTA,
    RT_COUNT_NOVEL_INDEX_DELTA,
    RT_COUNT_NOVEL_EXHAUSTION_AT,
    RT_COUNT_COUNT
} runtime_counter_t;

typedef struct {
    uint64_t count;
    uint64_t ticks_sum;
    uint64_t ticks_min;
    uint64_t ticks_max;
    uint64_t bucket[RUNTIME_STATS_HIST_BUCKETS];
} runtime_histogram_t;

typedef struct {
    uint64_t schema;
    uint64_t enabled;
    uint64_t cntfrq;
    uint64_t reset_tick;
    uint64_t counter[RT_COUNT_COUNT];
    runtime_histogram_t phase[RT_PHASE_COUNT];
} runtime_stats_t;

uint64_t runtime_counter_now(void);
uint64_t runtime_counter_freq(void);

void runtime_stats_enable(int enabled);
int runtime_stats_enabled(void);
void runtime_stats_reset(void);
const runtime_stats_t *runtime_stats_get(void);

void runtime_stats_count(runtime_counter_t counter, uint64_t amount);
void runtime_stats_set(runtime_counter_t counter, uint64_t value);
void runtime_stats_max(runtime_counter_t counter, uint64_t value);
void runtime_stats_record(runtime_phase_t phase, uint64_t ticks);
void runtime_stats_note_memory(void);
void runtime_stats_note_ingress_reject(unsigned reason);
/* Post-run control path: retained even when instrumentation was disabled. */
void runtime_stats_finish_run(uint64_t ticks);

/* One bounded, post-run UART record.  Never called on a timed event path. */
void runtime_stats_emit(void);

/* Focused bounded/reset/64-bit histogram probe; zero means pass. */
uint64_t runtime_stats_selftest(void);
/* Separate bounded characterization; refuses an impossible sample count. */
int runtime_stats_characterize_novel(uint64_t samples);
