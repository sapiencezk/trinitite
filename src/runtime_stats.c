#include <stdint.h>
#include "runtime_stats.h"
#include "noun.h"
#include "uart.h"

static runtime_stats_t g_stats;

static const char *const g_counter_name[RT_COUNT_COUNT] = {
    "events_admitted",
    "commits",
    "aborts",
    "preflight_rejects",
    "promote_copy_faults",
    "budget_faults",
    "deadline_faults",
    "queue_hwm",
    "queue_overflows",
    "timer_arms",
    "timer_fires",
    "timer_cancels",
    "timer_lateness_max",
    "service_success",
    "service_failure",
    "persist_cells_current",
    "persist_cells_start",
    "persist_cells_hwm",
    "scratch_cells_current",
    "scratch_cells_start",
    "scratch_cells_hwm",
    "atom_bytes_current",
    "atom_bytes_start",
    "atom_bytes_hwm",
    "atom_index_occupancy",
    "atom_index_start",
    "atom_probe_hwm",
    "checkpoints",
    "checkpoint_failures",
    "checkpoint_bytes",
    "checkpoint_generation",
    "cold_data_head",
    "media_phase",
    "media_status",
    "media_bytes_read",
    "media_bytes_written",
    "wdt_failures",
    "canary_failures",
    "ingress_version",
    "ingress_header",
    "ingress_length",
    "ingress_digest",
    "ingress_cue",
    "ingress_timeout",
    "expected_pressure_rejects",
    "unexpected_delivery_loss",
    "restarts",
    "run_ticks",
    "pressure_percent",
    "pressure_depth",
    "novel_samples",
    "novel_bytes_delta",
    "novel_index_delta",
    "novel_exhaustion_at",
};

static const char *const g_phase_name[RT_PHASE_COUNT] = {
    "ingress_complete_to_admit",
    "queue_residence",
    "nock_slam",
    "validate_reserve_promote",
    "activate",
    "admit_to_activate",
    "timer_due_to_enqueue",
    "timer_enqueue_to_slam",
    "checkpoint_capture",
    "checkpoint_jam",
    "checkpoint_cold_append",
    "checkpoint_media_flush",
    "media_read",
    "media_write",
    "media_barrier",
    "boot_load",
};

uint64_t runtime_counter_now(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

uint64_t runtime_counter_freq(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value ? value : 54000000ULL;
}

static uint64_t sat_add(uint64_t a, uint64_t b)
{
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static unsigned log2_bucket(uint64_t ticks)
{
    if (ticks <= 1)
        return 0;
    unsigned bucket = 0;
    while (ticks > 1 && bucket + 1 < RUNTIME_STATS_HIST_BUCKETS) {
        ticks >>= 1;
        bucket++;
    }
    return bucket;
}

void runtime_stats_enable(int enabled)
{
    g_stats.enabled = enabled ? 1 : 0;
}

int runtime_stats_enabled(void)
{
    return g_stats.enabled != 0;
}

void runtime_stats_reset(void)
{
    uint64_t enabled = g_stats.enabled;
    uint64_t *words = (uint64_t *)(void *)&g_stats;
    for (uint64_t i = 0; i < sizeof g_stats / sizeof *words; i++)
        words[i] = 0;
    g_stats.schema = RUNTIME_STATS_SCHEMA;
    g_stats.enabled = enabled;
    g_stats.cntfrq = runtime_counter_freq();
    g_stats.reset_tick = runtime_counter_now();
    uint64_t persist = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t scratch = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms = atom_store_bytes_used();
    uint64_t index = atom_store_index_occupancy();
    g_stats.counter[RT_COUNT_PERSIST_CELLS_CURRENT] = persist;
    g_stats.counter[RT_COUNT_PERSIST_CELLS_START] = persist;
    g_stats.counter[RT_COUNT_PERSIST_CELLS_HWM] = persist;
    g_stats.counter[RT_COUNT_SCRATCH_CELLS_CURRENT] = scratch;
    g_stats.counter[RT_COUNT_SCRATCH_CELLS_START] = scratch;
    g_stats.counter[RT_COUNT_SCRATCH_CELLS_HWM] = scratch;
    g_stats.counter[RT_COUNT_ATOM_BYTES_CURRENT] = atoms;
    g_stats.counter[RT_COUNT_ATOM_BYTES_START] = atoms;
    g_stats.counter[RT_COUNT_ATOM_BYTES_HWM] = atoms;
    g_stats.counter[RT_COUNT_ATOM_INDEX_OCCUPANCY] = index;
    g_stats.counter[RT_COUNT_ATOM_INDEX_START] = index;
}

const runtime_stats_t *runtime_stats_get(void)
{
    return &g_stats;
}

void runtime_stats_count(runtime_counter_t counter, uint64_t amount)
{
    if (!g_stats.enabled || (unsigned)counter >= RT_COUNT_COUNT)
        return;
    g_stats.counter[counter] = sat_add(g_stats.counter[counter], amount);
}

void runtime_stats_set(runtime_counter_t counter, uint64_t value)
{
    if (!g_stats.enabled || (unsigned)counter >= RT_COUNT_COUNT)
        return;
    g_stats.counter[counter] = value;
}

void runtime_stats_max(runtime_counter_t counter, uint64_t value)
{
    if (!g_stats.enabled || (unsigned)counter >= RT_COUNT_COUNT)
        return;
    if (value > g_stats.counter[counter])
        g_stats.counter[counter] = value;
}

void runtime_stats_record(runtime_phase_t phase, uint64_t ticks)
{
    if (!g_stats.enabled || (unsigned)phase >= RT_PHASE_COUNT)
        return;
    runtime_histogram_t *hist = &g_stats.phase[phase];
    hist->count = sat_add(hist->count, 1);
    hist->ticks_sum = sat_add(hist->ticks_sum, ticks);
    if (hist->count == 1 || ticks < hist->ticks_min)
        hist->ticks_min = ticks;
    if (ticks > hist->ticks_max)
        hist->ticks_max = ticks;
    unsigned bucket = log2_bucket(ticks);
    hist->bucket[bucket] = sat_add(hist->bucket[bucket], 1);
}

void runtime_stats_note_memory(void)
{
    if (!g_stats.enabled)
        return;
    uint64_t persist = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t scratch = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms = atom_store_bytes_used();
    runtime_stats_set(RT_COUNT_PERSIST_CELLS_CURRENT, persist);
    runtime_stats_max(RT_COUNT_PERSIST_CELLS_HWM, persist);
    runtime_stats_set(RT_COUNT_SCRATCH_CELLS_CURRENT, scratch);
    runtime_stats_max(RT_COUNT_SCRATCH_CELLS_HWM, scratch);
    runtime_stats_set(RT_COUNT_ATOM_BYTES_CURRENT, atoms);
    runtime_stats_max(RT_COUNT_ATOM_BYTES_HWM, atoms);
    runtime_stats_set(
        RT_COUNT_ATOM_INDEX_OCCUPANCY, atom_store_index_occupancy());
    runtime_stats_max(RT_COUNT_ATOM_PROBE_HWM, atom_store_probe_hwm());
}

void runtime_stats_note_ingress_reject(unsigned reason)
{
    if (reason >= 1 && reason <= 6)
        runtime_stats_count(
            (runtime_counter_t)(RT_COUNT_INGRESS_VERSION + reason - 1), 1);
}

void runtime_stats_finish_run(uint64_t ticks)
{
    g_stats.counter[RT_COUNT_RUN_TICKS] = ticks;
}

static void uart_hex64(uint64_t value)
{
    static const char hex[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4)
        uart_putc(hex[(value >> shift) & 0xf]);
}

void runtime_stats_emit(void)
{
    uart_puts("M3STAT1 schema=");
    uart_hex64(g_stats.schema);
    uart_puts(" enabled=");
    uart_hex64(g_stats.enabled);
    uart_puts(" cntfrq=");
    uart_hex64(g_stats.cntfrq);
    uart_puts(" reset_tick=");
    uart_hex64(g_stats.reset_tick);
    uart_puts("\r\n");
    for (unsigned i = 0; i < RT_COUNT_COUNT; i++) {
        uart_puts("M3C ");
        uart_puts(g_counter_name[i]);
        uart_putc('=');
        uart_hex64(g_stats.counter[i]);
        uart_puts("\r\n");
    }
    for (unsigned p = 0; p < RT_PHASE_COUNT; p++) {
        const runtime_histogram_t *hist = &g_stats.phase[p];
        uart_puts("M3H ");
        uart_puts(g_phase_name[p]);
        uart_puts(" count=");
        uart_hex64(hist->count);
        uart_puts(" sum=");
        uart_hex64(hist->ticks_sum);
        uart_puts(" min=");
        uart_hex64(hist->ticks_min);
        uart_puts(" max=");
        uart_hex64(hist->ticks_max);
        uart_puts(" bins=");
        for (unsigned b = 0; b < RUNTIME_STATS_HIST_BUCKETS; b++) {
            if (b)
                uart_putc(',');
            uart_hex64(hist->bucket[b]);
        }
        uart_puts("\r\n");
    }
    uart_puts("M3STAT1 END\r\n");
}

uint64_t runtime_stats_selftest(void)
{
    uint64_t failures = 0;
    int prior = runtime_stats_enabled();
    runtime_stats_enable(1);
    runtime_stats_reset();
    runtime_stats_count(RT_COUNT_COMMITS, UINT64_MAX - 1);
    runtime_stats_count(RT_COUNT_COMMITS, 2);
    runtime_stats_record(RT_PHASE_NOCK_SLAM, 0);
    runtime_stats_record(RT_PHASE_NOCK_SLAM, 2);
    runtime_stats_record(RT_PHASE_NOCK_SLAM, 1ULL << 63);
    const runtime_stats_t *s = runtime_stats_get();
    if (s->counter[RT_COUNT_COMMITS] != UINT64_MAX)
        failures++;
    if (s->phase[RT_PHASE_NOCK_SLAM].count != 3
        || s->phase[RT_PHASE_NOCK_SLAM].ticks_min != 0
        || s->phase[RT_PHASE_NOCK_SLAM].ticks_max != (1ULL << 63)
        || s->phase[RT_PHASE_NOCK_SLAM].bucket[0] != 1
        || s->phase[RT_PHASE_NOCK_SLAM].bucket[1] != 1
        || s->phase[RT_PHASE_NOCK_SLAM].bucket[63] != 1)
        failures++;
    runtime_stats_enable(prior);
    runtime_stats_reset();
    return failures;
}

int runtime_stats_characterize_novel(uint64_t samples)
{
    const uint64_t limbs_per_atom = 2;
    const uint64_t bytes_per_atom =
        sizeof(atom_t) + limbs_per_atom * sizeof(uint64_t);
    uint64_t bytes_before = atom_store_bytes_used();
    uint64_t index_before = atom_store_index_occupancy();
    uint64_t byte_room =
        (atom_store_capacity_bytes() - bytes_before) / bytes_per_atom;
    uint64_t index_room =
        atom_store_index_capacity() - index_before;
    uint64_t safe = byte_room < index_room ? byte_room : index_room;
    runtime_stats_set(RT_COUNT_NOVEL_EXHAUSTION_AT, safe + 1);
    if (samples == 0 || samples > safe)
        return -1; /* preflight: no partial characterization */

    for (uint64_t i = 0; i < samples; i++) {
        uint64_t limbs[2] = {
            0x6d332d6e6f76656cULL ^ i,
            0x8000000000000000ULL | i
        };
        noun out;
        if (!make_atom_checked(limbs, 2, &out) || !noun_is_indirect(out))
            return -1;
    }
    uint64_t bytes_after = atom_store_bytes_used();
    uint64_t index_after = atom_store_index_occupancy();
    runtime_stats_set(RT_COUNT_NOVEL_SAMPLES, samples);
    runtime_stats_set(
        RT_COUNT_NOVEL_BYTES_DELTA, bytes_after - bytes_before);
    runtime_stats_set(
        RT_COUNT_NOVEL_INDEX_DELTA, index_after - index_before);
    runtime_stats_note_memory();
    return index_after - index_before == samples ? 0 : -1;
}
