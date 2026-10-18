#include <stddef.h>
#include <stdint.h>

#include "bignum.h"
#include "blake3.h"
#include "bounded_cue.h"
#include "cold.h"
#include "i2_admission_envelope.h"
#include "i2_admission_metrics.h"
#include "i3_admission.h"
#include "i3_host.h"
#if defined(COLD_LITE_LOG)
#include "i3_ring.h"
#endif
#if defined(I3_CKPT_TEST_REBASEFAULT)
#include "cold_media_fake_test.h"
#endif
#if defined(I3_L1_PROBE)
#include "i3_l1_probe.h"
#endif
#include "jam.h"
#include "nock.h"
#include "setjmp.h"
#include "sha256.h"
#include "uart.h"

#define KICK_FORMULA_TEXT "[9 2 0 1]"

static noun g_kernel;
static noun g_poke_fol;
static noun g_peek_fol;
static uint64_t g_event_num = 1;
static int g_ready;
static uint64_t g_jam_len;
/* Decision L2 (rows 141, 198): once set, the application is stopped and
 * every later poke is refused until the next boot. */
static const char *g_stop;
static const char STOP_PERSIST[] = "persist";
/* Row 200 persist stop (share): a live step must leave this many persist cells
 * free, 1/16 of what was free when replay began (i3_host_boot). Replaying
 * a step keeps a few more cells than the live step did (its job was
 * decoded from the log, not shared with input already in persist), so the
 * reserve is what lets the next boot replay every entry the live boot
 * appended before it stopped. */
static uint64_t g_persist_reserve;
/* The 1/16 share alone is not enough (row 200 amendment): a replayed step
 * decodes its job into scratch, so its persist copy pays for every kept
 * cell of that job, while the live step may share cells already in persist
 * (the application, about 2,760 cells in the R4 set). Persist is a bump
 * heap for the whole boot, so each replayed copy stays: the excess is a
 * SUM over jobs. The host cannot tell which cells of a job the kernel state
 * keeps, so it reserves the upper bound: the sum of the distinct cells of
 * every job this boot has seen (replayed or live, the step's own included).
 * This grows with every step, including inputs the state does not keep. */
#define JOB_UNBOUNDED (UINT64_MAX / 4)
static uint64_t g_job_sum;
static int g_replaying;
static uint8_t g_jam_blake3[32];

static uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static void put_u64(uint64_t n)
{
    char buf[20];
    uint32_t used = 0;
    do {
        buf[used++] = (char)('0' + (n % 10));
        n /= 10;
    } while (n);
    while (used)
        uart_putc(buf[--used]);
}

static void put_hex(const uint8_t *p, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        uart_putc("0123456789abcdef"[p[i] >> 4]);
        uart_putc("0123456789abcdef"[p[i] & 0xF]);
    }
}

const char *i3_host_abort_name(int jumped, uint64_t reason)
{
    if (jumped == 0)
        return "none";
    if (jumped == NOCK_ABORT_CRASH)
        return "crash";
    switch (reason) {
    case 1: return "ops";
    case 2: return "wall";
    case 3: return "cells";
    case 4: return "stack";
    default: return jumped == NOCK_ABORT_BUDGET ? "ops" : "crash";
    }
}

static int nest(noun head, noun tail, noun *out)
{
    return alloc_cell_checked(head, tail, out);
}

static int tuple(const noun *xs, uint32_t n, noun *out)
{
    if (!xs || !out || n == 0)
        return 0;
    if (n == 1) {
        *out = xs[0];
        return 1;
    }
    noun rest;
    if (!tuple(xs + 1, n - 1, &rest))
        return 0;
    return nest(xs[0], rest, out);
}

static noun tas(const char *s)
{
    size_t n = 0;
    while (s && s[n])
        n++;
    return cord_from_bytes(s, n);
}

static int slam_formula(noun *out)
{
    noun pul_xs[4] = {direct(9), direct(23), direct(0), direct(2)};
    noun sam_xs[3] = {direct(6), direct(0), direct(7)};
    noun pul, sam, fol_xs[8];
    if (!tuple(pul_xs, 4, &pul) || !tuple(sam_xs, 3, &sam))
        return 0;
    fol_xs[0] = direct(8);
    fol_xs[1] = pul;
    fol_xs[2] = direct(9);
    fol_xs[3] = direct(2);
    fol_xs[4] = direct(10);
    fol_xs[5] = sam;
    fol_xs[6] = direct(0);
    fol_xs[7] = direct(2);
    return tuple(fol_xs, 8, out);
}

static int peek_formula(noun *out)
{
    noun pul_xs[4] = {direct(9), direct(22), direct(0), direct(2)};
    noun sam_xs[3] = {direct(6), direct(0), direct(7)};
    noun pul, sam, fol_xs[8];
    if (!tuple(pul_xs, 4, &pul) || !tuple(sam_xs, 3, &sam))
        return 0;
    fol_xs[0] = direct(8);
    fol_xs[1] = pul;
    fol_xs[2] = direct(9);
    fol_xs[3] = direct(2);
    fol_xs[4] = direct(10);
    fol_xs[5] = sam;
    fol_xs[6] = direct(0);
    fol_xs[7] = direct(2);
    return tuple(fol_xs, 8, out);
}

static int kick_formula(noun *out)
{
    noun xs[4] = {direct(9), direct(2), direct(0), direct(1)};
    return tuple(xs, 4, out);
}

static int system_wire(noun *out)
{
    /* [%poke %sys 1 ~] — NockApp SystemWire. The kernel only matches the
     * %poke head; the source label is no longer L0. */
    noun rest;
    if (!nest(direct(1), NOUN_ZERO, &rest))
        return 0;
    if (!nest(tas("sys"), rest, &rest))
        return 0;
    return nest(tas("poke"), rest, out);
}

static int ovum_job(uint64_t num, noun cause, noun *out)
{
    noun wire, input_xs[4], input, ovum;
    if (!system_wire(&wire))
        return 0;
    input_xs[0] = direct(0);
    input_xs[1] = direct(0);
    input_xs[2] = direct(0);
    input_xs[3] = cause;
    if (!tuple(input_xs, 4, &input))
        return 0;
    if (!nest(wire, input, &ovum))
        return 0;
    return nest(direct(num), ovum, out);
}

static uint64_t effect_list_len(noun effects)
{
    uint64_t n = 0;
    while (noun_is_cell(effects)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(effects);
        effects = c->tail;
        n++;
        if (n > 1000000ULL)
            break;
    }
    return n;
}

static cue_bounded_limits_t i3_limits(void)
{
    cue_bounded_limits_t limits;
    limits.max_input_bytes = I3_CUE_MAX_INPUT_BYTES;
    limits.max_atom_bytes = I3_CUE_MAX_ATOM_BYTES;
    limits.max_total_atom_bytes = I3_CUE_MAX_TOTAL_ATOM_BYTES;
    limits.max_cache_entries = I3_CUE_CACHE_ADMITTED;
    limits.max_work = I3_CUE_MAX_WORK;
    limits.max_backrefs = I3_CUE_MAX_BACKREFS;
    limits.max_depth = I3_CUE_MAX_DEPTH;
    limits.max_nodes = I3_CUE_MAX_NODES;
    limits.max_cells = I3_CUE_MAX_CELLS;
    return limits;
}

static void host_budget(void)
{
    nock_budget_set_limits(I3_SLAM_MAX_OPS, I3_SLAM_MAX_CELLS);
    nock_eval_stack_set_limit(I3_SLAM_MAX_STACK);
}

static int host_nock(noun subject, noun formula, noun *product)
{
    jmp_buf saved;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    nock_trace_set(NOUN_ZERO);
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return jumped;
    }
    *product = nock(subject, formula);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    return 0;
}

static void clear_result(i3_host_result_t *out)
{
    if (!out)
        return;
    out->parse = 0;
    out->jumped = 0;
    out->ops = 0;
    out->cells = 0;
    out->stack = 0;
    out->ticks = 0;
    out->effect_len = 0;
    out->abort_reason = 0;
    out->effects = NOUN_ZERO;
    out->product = NOUN_ZERO;
    out->persist_ok = 0;
    out->persist_ticks = 0;
    out->persist_copy_map_hwm = 0;
    out->persist_copy_map_capacity = noun_copy_map_capacity();
}

static void fill_eval(i3_host_result_t *out, int jumped, uint64_t ticks)
{
    if (!out)
        return;
    out->jumped = jumped;
    out->ops = nock_ops_used();
    out->cells = nock_cells_used();
    out->stack = nock_eval_stack_peak();
    out->ticks = ticks;
    out->abort_reason = nock_budget_abort_reason();
}

/* Decision L2: the input log on the cold-store media. One entry per accepted
 * step, appended only after the step succeeded: the jam of the job the step
 * ran, `[event_num ovum]`, or for a crash the `%crud` ovo carrying the real
 * goof, as the full node's `event-log.sqlite3` and the web node's log
 * (decision 197). Entries are written to the cold-store media; on
 * semihost/RAM this is volatile logical acceptance, and rpi4-sd per-step
 * appends are unmeasured; no durability claim. */
static void nv_flush(void)
{
    if (cold_nv_enabled())
        (void)cold_nv_flush();
#if defined(COLD_LITE_LOG)
    i3_ring_flush();
#endif
}

#if defined(COLD_LITE_LOG)
/* Row 212 PR 1c: every accepted entry also goes to the recorder ring, as the
 * same jam bytes the cold log holds (src/i3_ring.c). A ring that cannot take
 * it skips inputs until its next checkpoint; the step is not affected. */
static void ring_input(uint64_t num, noun job)
{
    const uint8_t *bytes;
    uint64_t len;
    if (jam_encode_bytes_checked(job, &bytes, &len) == 0)
        i3_ring_input(num, bytes, len);
}
#endif

static int trip_noun(uint64_t num, noun *out)
{
    return nest(tas("i3-trip"), direct(num), out);
}

/* Row 200 persist stop: its own record, so it is never confused with a row
 * 141 trip. */
static int persist_trip_noun(uint64_t num, noun *out)
{
    return nest(tas("i3-trip-persist"), direct(num), out);
}

/* Row 141 stop: no entry is appended for the failed step. The trip is
 * recorded so the next boot, after replay, applies a journaled %manage STOP
 * before any input. The record names the event that tripped, so once that
 * STOP is logged the event number moves on and a later boot is not stopped
 * again: one trip stops one boot. A persist stop (row 200) writes a persist
 * trip instead: no STOP is ever logged for it, so the event number never
 * moves and every later boot finds it and refuses input (stop_after_trip). */
static void host_stop(const char *reason)
{
    noun trip;
    if (g_stop)
        return;
    g_stop = reason;
    uart_puts("I3H stop reason=");
    uart_puts(reason);
    uart_puts(" event=");
    put_u64(g_event_num);
    uart_puts("\r\n");
    if (!g_replaying && (reason == STOP_PERSIST
                         ? persist_trip_noun(g_event_num, &trip)
                         : trip_noun(g_event_num, &trip))) {
        (void)cold_store(trip);
        nv_flush();
    }
}

/* Append before the step is committed: on failure g_kernel and g_event_num
 * are unchanged, the step is refused with no effects, and the trip is keyed
 * at this event so the next boot replays N entries and then STOPs. */
static int log_append(noun job)
{
    if (g_replaying)
        return 1;
    if (cold_log(job) != 0) {
        host_stop("log");
        return 0;
    }
#if defined(COLD_LITE_LOG)
    ring_input(g_event_num, job);
#endif
    nv_flush();
    return 1;
}

static int install_sample(noun template, noun sample, noun *out)
{
    if (!noun_is_cell(template))
        return 0;
    cell_t *core = (cell_t *)(uintptr_t)cell_ptr(template);
    noun battery = core->head;
    if (!noun_is_cell(core->tail))
        return 0;
    cell_t *payload = (cell_t *)(uintptr_t)cell_ptr(core->tail);
    noun context = payload->tail;
    noun new_payload;
    if (!nest(sample, context, &new_payload))
        return 0;
    return nest(battery, new_payload, out);
}

/* Copy the kept part of `kernel` into the persist heap and build the
 * installed core there; nothing is committed. A live step calls this before
 * log_append (row 200 persist stop): if it fails, the step appends nothing
 * and g_kernel / g_event_num never move, so state never points into
 * scratch. The cells of a prepared copy whose append then fails are left
 * unreferenced in persist. The heap mode is restored for the caller. */
static int persist_prepare(noun kernel, i3_host_result_t *out, noun *installed_out);

/* Distinct cells in `job`, as a decode from the log builds them: every
 * cell counts once, whichever heap it sits in now (a live job may share
 * cells already in persist; its replay will not). Iterative, with a fixed
 * visited set. The limit is the log decoder's own: replay cues each entry
 * under cue_i2_limits (cold.c decode_object), whose max_cells is
 * I2_CUE_MAX_CELLS, and a decode builds at least one cell per distinct
 * cell. A job above it could never replay, so it counts as unbounded and
 * the step takes the row 200 persist stop instead of being accepted. The
 * set is twice the limit, so it is at most half full. */
#define JOB_CELLS_MAX ((uint32_t)I2_CUE_MAX_CELLS)
#define JOB_SET_BITS 17u
#define JOB_SET_SIZE (1u << JOB_SET_BITS)
#define JOB_STACK_MAX (2u * JOB_CELLS_MAX)
_Static_assert(JOB_SET_SIZE >= 2u * JOB_CELLS_MAX, "job set at most half full");
static uint32_t g_job_set[JOB_SET_SIZE];
static uint32_t g_job_stack[JOB_STACK_MAX];

static uint64_t job_cells(noun job)
{
    uint32_t sp = 0, cells = 0, i;
    for (i = 0; i < JOB_SET_SIZE; i++)
        g_job_set[i] = 0;
    if (!noun_is_cell(job))
        return 0;
    g_job_stack[sp++] = cell_ptr(job);
    while (sp) {
        uint32_t op = g_job_stack[--sp], k, h;
        int seen = 0;
        h = (op * 2654435761u) >> (32u - JOB_SET_BITS);
        for (k = 0; k < JOB_SET_SIZE; k++) {
            uint32_t slot_i = (h + k) & (JOB_SET_SIZE - 1u);
            if (g_job_set[slot_i] == op) {
                seen = 1;
                break;
            }
            if (g_job_set[slot_i] == 0) {
                g_job_set[slot_i] = op;
                break;
            }
        }
        if (seen)
            continue;
        if (++cells > JOB_CELLS_MAX)
            return JOB_UNBOUNDED;
        cell_t *c = (cell_t *)(uintptr_t)op;
        if (noun_is_cell(c->head)) {
            if (sp >= JOB_STACK_MAX)
                return JOB_UNBOUNDED;
            g_job_stack[sp++] = cell_ptr(c->head);
        }
        if (noun_is_cell(c->tail)) {
            if (sp >= JOB_STACK_MAX)
                return JOB_UNBOUNDED;
            g_job_stack[sp++] = cell_ptr(c->tail);
        }
    }
    return cells;
}

static uint64_t add_sat(uint64_t a, uint64_t b)
{
    return (a >= JOB_UNBOUNDED || b >= JOB_UNBOUNDED || a + b >= JOB_UNBOUNDED)
        ? JOB_UNBOUNDED : a + b;
}

static void job_seen(uint64_t cells)
{
    g_job_sum = add_sat(g_job_sum, cells);
}

/* Reserve a live step must leave, counting `cells` for its own job. */
static uint64_t live_reserve(uint64_t cells)
{
    uint64_t kept = add_sat(g_job_sum, cells);
    return kept > g_persist_reserve ? kept : g_persist_reserve;
}

/* Live step: prepare the persist copy and keep the reserve, or refuse. */
static int persist_prepare_live(noun kernel, noun job, i3_host_result_t *out,
                                noun *installed_out)
{
    uint64_t cells = job_cells(job);
    if (!persist_prepare(kernel, out, installed_out))
        return 0;
    if (heap_persist_free_cells() < live_reserve(cells)) {
        uart_puts("I3H persist reserve=");
        put_u64(live_reserve(cells));
        uart_puts(" share=");
        put_u64(g_persist_reserve);
        uart_puts(" free=");
        put_u64(heap_persist_free_cells());
        uart_puts("\r\n");
        if (out)
            out->persist_ok = 0;
        return 0;
    }
    job_seen(cells);
    return 1;
}

static int persist_prepare(noun kernel, i3_host_result_t *out, noun *installed_out)
{
    noun sample, copy, installed;
    uint64_t t0, t1;
    int ok, mode = heap_get_mode();
    if (out) {
        out->persist_ok = 0;
        out->persist_ticks = 0;
        out->persist_copy_map_hwm = 0;
        out->persist_copy_map_capacity = noun_copy_map_capacity();
    }
    if (!g_ready || !noun_is_cell(kernel))
        return 0;
    sample = slot(direct(6), kernel);
    heap_set_mode(HEAP_MODE_PERSIST);
    noun_copy_map_hwm_reset();
    t0 = cntvct();
    ok = noun_copy_checked(sample, &copy);
    t1 = cntvct();
    if (ok && install_sample(kernel, copy, &installed))
        *installed_out = installed;
    else
        ok = 0;
    heap_set_mode(mode);
    if (out) {
        out->persist_ok = ok;
        out->persist_ticks = t1 - t0;
        out->persist_copy_map_hwm = noun_copy_map_hwm();
        out->persist_copy_map_capacity = noun_copy_map_capacity();
    }
    return ok;
}

int i3_host_persist(i3_host_result_t *out)
{
    noun installed;
    if (!persist_prepare(g_kernel, out, &installed))
        return 0;
    g_kernel = installed;
    return 1;
}

static void print_cue(cue_bounded_status_t status, uint64_t ticks)
{
    uint64_t cells = g_i2_admission_metrics.cue_cells_hwm;
    uint64_t nodes = g_i2_admission_metrics.cue_nodes_hwm;
    uint64_t atoms = nodes > cells ? nodes - cells : 0;
    uart_puts("I3H cue status=");
    uart_puts(cue_bounded_status_name(status));
    uart_puts(" cells=");
    put_u64(cells);
    uart_puts(" cells_bound=");
    put_u64(I3_CUE_MAX_CELLS);
    uart_puts(" atoms=");
    put_u64(atoms);
    uart_puts(" ticks=");
    put_u64(ticks);
    uart_puts(" first_bound=");
    uart_puts(status == CUE_BOUNDED_OK ? "none" : cue_bounded_status_name(status));
    uart_puts(" work=");
    put_u64(g_i2_admission_metrics.cue_work_hwm);
    uart_puts(" work_bound=");
    put_u64(I3_CUE_MAX_WORK);
    uart_puts(" nodes=");
    put_u64(nodes);
    uart_puts(" nodes_bound=");
    put_u64(I3_CUE_MAX_NODES);
    uart_puts(" backrefs=");
    put_u64(g_i2_admission_metrics.cue_backrefs_hwm);
    uart_puts(" backrefs_bound=");
    put_u64(I3_CUE_MAX_BACKREFS);
    uart_puts(" cache=");
    put_u64(g_i2_admission_metrics.cue_cache_entries_hwm);
    uart_puts(" cache_bound=");
    put_u64(I3_CUE_CACHE_ADMITTED);
    uart_puts(" depth=");
    put_u64(g_i2_admission_metrics.cue_depth_hwm);
    uart_puts(" depth_bound=");
    put_u64(I3_CUE_MAX_DEPTH);
    uart_puts(" atom_bytes=");
    put_u64(g_i2_admission_metrics.cue_atom_bytes_hwm);
    uart_puts("\r\n");
}

int i3_host_ready(void)
{
    return g_ready;
}

int i3_host_cue_bytes(const uint8_t *bytes, uint64_t len, noun *out)
{
    cue_bounded_limits_t limits = i3_limits();
    cue_bounded_status_t status;
    if (!bytes || !out || len == 0 || len > I3_CUE_MAX_INPUT_BYTES)
        return 0;
    while (len > 1 && bytes[len - 1] == 0)
        len--;
    status = cue_bounded_bytes(bytes, len, &limits, HEAP_MODE_PERSIST, out);
    if (status != CUE_BOUNDED_OK)
        return 0;
    noun_tx_commit();
    return 1;
}

#if defined(I3_COMPACT)
/* Row 221 tests: the L1 plan is cued into scratch (see i3_l1_probe.c). */
int i3_host_cue_bytes_scratch(const uint8_t *bytes, uint64_t len, noun *out)
{
    cue_bounded_limits_t limits = i3_limits();
    cue_bounded_status_t status;
    if (!bytes || !out || len == 0 || len > I3_CUE_MAX_INPUT_BYTES)
        return 0;
    while (len > 1 && bytes[len - 1] == 0)
        len--;
    status = cue_bounded_bytes(bytes, len, &limits, HEAP_MODE_SCRATCH, out);
    if (status != CUE_BOUNDED_OK)
        return 0;
    noun_tx_commit();
    return 1;
}
#endif

static int hex_nibble(char c, uint8_t *nib)
{
    if (c >= '0' && c <= '9') { *nib = (uint8_t)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *nib = (uint8_t)(c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *nib = (uint8_t)(c - 'A' + 10); return 1; }
    return 0;
}

/* Parse a 64-char ASCII hex digest (case-insensitive). Returns 0 on a
 * malformed char. Sets *is_zero when every byte is zero (the "no gate" mark). */
static int parse_sha256_hex(const char *hex, uint8_t out[32], int *is_zero)
{
    uint32_t i;
    *is_zero = 1;
    if (!hex)
        return 0;
    for (i = 0; i < 32; i++) {
        uint8_t hi, lo;
        if (!hex_nibble(hex[2 * i], &hi) || !hex_nibble(hex[2 * i + 1], &lo))
            return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
        if (out[i] != 0)
            *is_zero = 0;
    }
    return 1;
}

/* Decision 151/152 admission gate (lite-node mirror of full-node
 * `--app-sha256`): hash the jammed bundle natively, refuse before cue/poke on
 * mismatch, lowercase-hex digest with the same `sha256 {actual} != expected
 * {expected}` naming. An all-zero expected digest is the "no gate" sentinel. */
int i3_host_load_app(const uint8_t *jam, uint64_t jam_len,
                     const char *expected_sha256, i3_host_result_t *out)
{
    uint8_t digest[32], want[32];
    int is_zero = 0, gated, match = 0;
    uint32_t i;
    noun app_noun, cause;

    clear_result(out);
    if (!jam || jam_len == 0 || jam_len > I3_CUE_MAX_INPUT_BYTES)
        return 0;

    sha256_hash(jam, jam_len, digest);
    gated = expected_sha256 != 0
        && parse_sha256_hex(expected_sha256, want, &is_zero)
        && !is_zero;
    if (gated) {
        match = 1;
        for (i = 0; i < 32; i++) {
            if (digest[i] != want[i]) {
                match = 0;
                break;
            }
        }
    }

    if (gated && !match) {
        uart_puts("I3H app-sha256 sha256 ");
        put_hex(digest, 32);
        uart_puts(" != expected ");
        for (i = 0; i < I3_APP_SHA256_HEX_LEN; i++)
            uart_putc(expected_sha256[i]);
        uart_puts("\r\n");
        return 0;
    }
    uart_puts("I3H app-sha256 sha256 ");
    put_hex(digest, 32);
    uart_puts(gated ? " match=yes\r\n" : " gate=no\r\n");

    if (!i3_host_cue_bytes(jam, jam_len, &app_noun))
        return 0;
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!nest(tas("load-bundle"), app_noun, &cause))
        return 0;
    return i3_host_poke(cause, out);
}

/* KP2 crash re-entry: the de-moled fast path lets a bail escape to the
 * host as NOCK_ABORT_CRASH. Reproduce the NockApp serf's `poke_swap` re-poke
 * (form.rs): run the same event again through the wire ~[/arvo] carrying the
 * bail's goof, so the outer keep core's %crud branch (wrapper.hoon) handles it.
 *
 *   wire      = [0 %arvo 0]                 (path ~[/arvo])
 *   goof      = [mote tang]                 (form.rs goof: mote, +mook trace)
 *   job_input = [eny our now cause] = [0 0 0 cause]   (as ovum_job builds)
 *   ovo       = [event_num [wire [goof job_input]]]
 *
 * The mote is %exit, or %meme when the heap ran out; the tang is the
 * crash-time trace of %hand/%hunk/%lose/%mean/%spot hints rendered by
 * nock_mook. A budget failure is NOCK_ABORT_BUDGET and never reaches here. */
static int mook_goof(uint64_t mote, noun trace, noun *goof)
{
    jmp_buf saved;
    volatile noun tang = NOUN_ZERO;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    if (setjmp(nock_abort) == 0)
        tang = nock_mook(trace);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    return nest(direct(mote), tang, goof);
}

/* Evidence line: the goof as a hex jam, so a host can compare it with the
 * full node's logged %crud ovum. Long goofs report only their size. */
static void put_goof(noun goof)
{
    const uint8_t *bytes;
    uint64_t n;
    if (jam_encode_bytes_checked(goof, &bytes, &n) != 0) {
        uart_puts("I3H crud goof=unjammable\r\n");
        return;
    }
    if (n > 4096) {
        uart_puts("I3H crud goof-bytes=");
        put_u64(n);
        uart_puts("\r\n");
        return;
    }
    uart_puts("I3H crud goof=");
    put_hex(bytes, (uint32_t)n);
    uart_puts("\r\n");
}

#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
/* Row 212 PR 1a: lite checkpoint writer, flag-gated (I3_CHECKPOINT_EVERY=K,
 * default off; with the flag off none of this is compiled). After every K
 * accepted live steps the host writes the kernel state (internal.outer,
 * axis 27; see ckpt_maybe_write) to cold media, then a header record
 *   [%i3-ckpt N state-id sha256(jam state) kernel-blake3]
 * and verifies both by reading back and re-hashing. kernel-blake3 is
 * g_jam_blake3: BLAKE3-256 of the pill's kernel jam bytes exactly as read
 * at boot (all jam_len bytes, trailing zero bytes included), not of a
 * re-jam of the cued kernel. N is the last event the state follows. PR 1b
 * adds the boot side (ckpt_boot, below); nothing is rotated or dropped
 * (rotation stays suspended until PR 1c).
 * A checkpoint that cannot be written or verified is skipped and logged;
 * the step itself is already committed and is not affected. The host
 * hashes and stores bytes; apart from the wrapper shape check below it
 * interprets nothing (decision 164). */
#define I3_CKPT_STATE_AXIS 27

/* Bounds. Defaults are the production rule; the I3_CKPT_TEST_* knobs
 * (Makefile I3_CKPT_TEST=cells|jam|stack|wrapper, test builds only) shrink
 * one bound so a QEMU run reaches that skip leg with a real state. */
#if defined(I3_CKPT_TEST_CELLS)
#define I3_CKPT_CELLS_MAX 8u
#else
#define I3_CKPT_CELLS_MAX JOB_CELLS_MAX
#endif
#if defined(I3_CKPT_TEST_JAM)
#define I3_CKPT_JAM_MAX 8u
#else
#define I3_CKPT_JAM_MAX JAM_MAX_BYTES
#endif
#if defined(I3_CKPT_TEST_STACK)
#define I3_CKPT_STACK_MAX 2u
#else
#define I3_CKPT_STACK_MAX JOB_STACK_MAX
#endif
#if defined(I3_CKPT_TEST_WRAPPER)
#define I3_CKPT_WRAPPER_TAG 1u
#else
#define I3_CKPT_WRAPPER_TAG 0u
#endif
/* Boot-side test knobs (row 212 PR 1b, tests/checkpoint_boot.py): the
 * writer stores a deliberately bad header for every N >= I3_CKPT_TEST_FROM
 * (default 1, i.e. all), so a flag-on boot of that log must reject it and
 * fall back (row 212 (3)). hdrshape drops the kernel-blake3 field, hdrsid
 * names a state id that is not in the store, hdrd flips one bit of D. The
 * state blob itself is written and verified as usual. */
#if defined(I3_CKPT_TEST_HDRSHAPE) || defined(I3_CKPT_TEST_HDRSID) || defined(I3_CKPT_TEST_HDRD) \
    || defined(I3_CKPT_TEST_CRASH)
#if !defined(I3_CKPT_TEST_FROM)
#define I3_CKPT_TEST_FROM 1
#endif
#define I3_CKPT_BAD_HDR(n) ((n) >= (uint64_t)I3_CKPT_TEST_FROM)
#endif
_Static_assert(I3_CKPT_STACK_MAX <= JOB_STACK_MAX, "ckpt stack fits");
_Static_assert(I3_CKPT_CELLS_MAX <= JOB_CELLS_MAX, "ckpt cells fit");
_Static_assert(I3_CKPT_JAM_MAX <= JAM_MAX_BYTES, "ckpt jam fits");

/* sha256 of ++jam's bytes (jam_hoon_checked, the %jam jet's writer), as
 * the kernel's (shax (jam state)): the atom's (met 3) little-endian bytes.
 * The default writer's backref choice differs from ++jam (row 211 (6)). */
static uint8_t g_ckpt_buf[JAM_MAX_BYTES];
static int ckpt_digest(noun state, uint8_t out[32], uint64_t *bytes)
{
    noun a;
    uint64_t n;
    if (jam_hoon_checked(state, &a) != 0 || !noun_is_atom(a))
        return 0;
    n = (bn_met(a) + 7) / 8;
    if (n == 0 || n > sizeof g_ckpt_buf
        || !noun_atom_read_fixed(a, g_ckpt_buf, (size_t)n))
        return 0;
    sha256_hash(g_ckpt_buf, n, out);
    if (bytes)
        *bytes = n;
    return 1;
}

static int digest_eq(const uint8_t a[32], const uint8_t b[32])
{
    uint32_t i;
    uint8_t d = 0;
    for (i = 0; i < 32; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static int bytes_atom(const uint8_t b[32], noun *out)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    uint32_t i;
    for (i = 0; i < 32; i++)
        limbs[i / 8] |= (uint64_t)b[i] << (8 * (i % 8));
    return make_atom_checked(limbs, 4, out);
}

static void ckpt_skip(uint64_t n, const char *why)
{
    uart_puts("I3H ckpt skip event=");
    put_u64(n);
    uart_puts(" reason=");
    uart_puts(why);
    uart_puts("\r\n");
}

/* Axis `a` of `n` without crashing: 0 when the path meets an atom. */
static int ckpt_axis(noun n, uint64_t a, noun *out)
{
    int depth = 0, i;
    uint64_t t = a;
    if (a == 0)
        return 0;
    while (t > 1) {
        t >>= 1;
        depth++;
    }
    for (i = depth - 1; i >= 0; i--) {
        cell_t *c;
        if (!noun_is_cell(n))
            return 0;
        c = (cell_t *)(uintptr_t)cell_ptr(n);
        n = ((a >> i) & 1) ? c->tail : c->head;
    }
    *out = n;
    return 1;
}

/* The state axis holds only while the core's sample (axis 6) is the NockApp
 * wrapper's outer-state [%0 desk-hash internal]: axis 12 the atom 0 and
 * axis 13 a cell, so axes 26 (desk-hash) and 27 (internal) exist. */
static int ckpt_wrapper_ok(noun core, noun *state)
{
    noun tag, rest;
    if (!ckpt_axis(core, 12, &tag) || !noun_is_direct(tag)
        || direct_val(tag) != I3_CKPT_WRAPPER_TAG)
        return 0;
    if (!ckpt_axis(core, 13, &rest) || !noun_is_cell(rest))
        return 0;
    return ckpt_axis(core, I3_CKPT_STATE_AXIS, state);
}

/* Distinct cells in `state` (job_cells' walk and its visited set, kept
 * separate so the flag-off image is unchanged). Returns 0 when at most
 * I3_CKPT_CELLS_MAX (65,536) cells, else the skip reason: "cells" past the
 * limit (skip only when > 65,536), "stack" if the walk stack would
 * overflow. With the default bounds "stack" cannot happen (each cell
 * popped pushes at most two, so depth <= cells + 1 <= 65,537 < 131,072);
 * it is a separate reason so it is never reported as a cell count. */
static const char *ckpt_cells(noun state)
{
    uint32_t sp = 0, cells = 0, i;
    for (i = 0; i < JOB_SET_SIZE; i++)
        g_job_set[i] = 0;
    if (!noun_is_cell(state))
        return 0;
    g_job_stack[sp++] = cell_ptr(state);
    while (sp) {
        uint32_t op = g_job_stack[--sp], k, h;
        int seen = 0;
        cell_t *c;
        h = (op * 2654435761u) >> (32u - JOB_SET_BITS);
        for (k = 0; k < JOB_SET_SIZE; k++) {
            uint32_t slot_i = (h + k) & (JOB_SET_SIZE - 1u);
            if (g_job_set[slot_i] == op) {
                seen = 1;
                break;
            }
            if (g_job_set[slot_i] == 0) {
                g_job_set[slot_i] = op;
                break;
            }
        }
        if (seen)
            continue;
        if (++cells > I3_CKPT_CELLS_MAX)
            return "cells";
        c = (cell_t *)(uintptr_t)op;
        if (noun_is_cell(c->head)) {
            if (sp >= I3_CKPT_STACK_MAX)
                return "stack";
            g_job_stack[sp++] = cell_ptr(c->head);
        }
        if (noun_is_cell(c->tail)) {
            if (sp >= I3_CKPT_STACK_MAX)
                return "stack";
            g_job_stack[sp++] = cell_ptr(c->tail);
        }
    }
    return 0;
}

#if defined(I3_CKPT_TEST_CRASH)
/* Test knob (row 212 PR 1c, tests/recorder_ring.py crash leg): for every
 * N >= I3_CKPT_TEST_FROM the state blob and a header with one bit of D
 * flipped (a damaged write) are stored and flushed, then the node stops dead
 * before the header is verified, as a power cut between writing and
 * verifying a checkpoint would. Never returns for such N. */
static void halt(void);
static int ckpt_test_crash(uint64_t n)
{
    if (!I3_CKPT_BAD_HDR(n))
        return 0;
    nv_flush();
    uart_puts("I3H ckpt test crash event=");
    put_u64(n);
    uart_puts("\r\nI3H terminal=test-crash\r\n");
    halt();
    return 1;
}
#endif

#if defined(COLD_LITE_LOG)
/* Row 212 (2) as amended (1499kernel #263, 5091bb19), running log, PR 1c:
 * "The node keeps the last verified checkpoint plus every entry after it,
 * and the previous checkpoint until the next one verifies. Entries before
 * the kept checkpoint are dropped." When the checkpoint at N verifies, the
 * previous verified one (P) becomes the oldest kept: the log base moves to P
 * (entries 1..P dropped, one superblock write), so P stays a boot fallback
 * until the checkpoint after N verifies. Row 221 (7) (amends row 213 (2),
 * (5), (6)): the row 213 job sum counts from the log base. When the base
 * moves from B to P the jobs of entries B+1..P leave the sum, and the new
 * base record holds the jobs of entries P+1..N (audit only: boot does not
 * load it, it counts from the base). g_base is the base this boot has;
 * g_last_ck_n the newest verified checkpoint (written live, or the one this
 * boot booted from) and g_last_ck_sum the jobs after the base up to it. */
static cold_log_base_t g_base;
static uint64_t g_last_ck_n, g_last_ck_sum;
static int g_rotated;
static const char STOP_ROTATED[] = "rotated";

/* ── Row 221 (row 212 (c)): compaction after a verified checkpoint ──────
 * (2) Only a running node compacts, right after checkpoint N verifies and
 * after the host has handed off that step's effects (i3_host_handoff, which
 * the driver calls once it has consumed the effects and reset scratch), so
 * the effects are not a root. Replay, a stopped node and a skipped
 * checkpoint never compact; no input is taken until it ends.
 * (4) Only the core's sample (axis 6) is copied; the new core is
 * [battery [new-sample context]], with battery and context still in the code
 * region; axis 27 of the new core must hash to D before the commit.
 * (5) The copy runs in a transaction on the other persist half; the commit
 * stores the core root and the half selector; any failure aborts and logs
 * `I3H compact skip event=N reason=...`, and the node runs on the old half.
 * (6) After the commit the atom store keeps the boot prefix and every atom
 * reachable from the state and the host roots (the poke and peek formulas,
 * the fast-hint registry, the crash trace); the walk stops at code-region
 * cells (their atoms are in the prefix). Work tables sit in scratch above its
 * bump mark. (8) Nothing is written to media and no state hash changes. */
static int g_cmp_pending;
static uint64_t g_cmp_n;
static uint8_t g_cmp_d[32];

static void compact_arm(uint64_t n, const uint8_t d[32])
{
    uint32_t i;
    for (i = 0; i < 32; i++)
        g_cmp_d[i] = d[i];
    g_cmp_n = n;
    g_cmp_pending = 1;
}

#if defined(I3_CKPT_TEST_CMPBEFORE) || defined(I3_CKPT_TEST_CMPCOPY) || defined(I3_CKPT_TEST_CMPAFTER) \
    || defined(I3_CKPT_TEST_CMPFLIP) || defined(I3_CKPT_TEST_CMPREBUILD) || defined(I3_CKPT_TEST_CMPSKIP)
#if !defined(I3_CKPT_TEST_FROM)
#define I3_CKPT_TEST_FROM 1
#endif
#define I3_CMP_TEST 1
/* Test knobs (tests/compaction.py): the first compaction at N >= FROM stops
 * dead at one crash point (before the copy, mid-copy, after the copy, after
 * the flip, mid-rebuild), as a power cut there would; cmpskip makes that
 * copy fail instead, so the transaction aborts and the node keeps running. */
static int g_cmp_test_done;
static void halt(void);
static void cmp_test_stop(const char *at)
{
    uart_puts("I3H compact test crash event=");
    put_u64(g_cmp_n);
    uart_puts(" at=");
    uart_puts(at);
    uart_puts("\r\nI3H terminal=test-crash\r\n");
    halt();
}
static int cmp_test_now(void)
{
    return !g_cmp_test_done && g_cmp_n >= (uint64_t)I3_CKPT_TEST_FROM;
}
static void cmp_test_mid(void) { cmp_test_stop("rebuild"); }
#endif

#define CMP_VIS_BITS 17u
#define CMP_VIS_N (1u << CMP_VIS_BITS)
#define CMP_ASET_BITS 17u
#define CMP_ASET_N (1u << CMP_ASET_BITS)
#define CMP_CELLS_MAX 65536u
#define CMP_STK_N (2u * CMP_CELLS_MAX + 2u)
#define CMP_ROOM ((uint64_t)CMP_VIS_N * 4u + (uint64_t)CMP_ASET_N * 8u + (uint64_t)CMP_STK_N * 8u)

typedef struct {
    uint32_t *vis;
    uint64_t *aset;
    noun *stk;
    uint64_t cells, atoms, stk_hwm, wild, overflow, missing;
} cmp_walk_t;
static cmp_walk_t g_cw;

static int cmp_vis_add(uint32_t p)
{
    uint32_t h = (p * 2654435761u) >> (32u - CMP_VIS_BITS), k;
    for (k = 0; k < CMP_VIS_N; k++) {
        uint32_t i = (h + k) & (CMP_VIS_N - 1u);
        if (g_cw.vis[i] == p)
            return 0;
        if (g_cw.vis[i] == 0) {
            g_cw.vis[i] = p;
            return 1;
        }
    }
    g_cw.overflow++;
    return 0;
}

static int cmp_aset_add(uint64_t h62)
{
    uint32_t h = (uint32_t)((h62 * 0x9E3779B97F4A7C15ULL) >> (64u - CMP_ASET_BITS)), k;
    for (k = 0; k < CMP_ASET_N; k++) {
        uint32_t i = (h + k) & (CMP_ASET_N - 1u);
        if (g_cw.aset[i] == h62)
            return 0;
        if (g_cw.aset[i] == 0) {
            g_cw.aset[i] = h62;
            return 1;
        }
    }
    g_cw.overflow++;
    return 0;
}

static int cmp_live(uint64_t h62)
{
    uint32_t h = (uint32_t)((h62 * 0x9E3779B97F4A7C15ULL) >> (64u - CMP_ASET_BITS)), k;
    for (k = 0; k < CMP_ASET_N; k++) {
        uint32_t i = (h + k) & (CMP_ASET_N - 1u);
        if (g_cw.aset[i] == h62)
            return 1;
        if (g_cw.aset[i] == 0)
            return 0;
    }
    return 0;
}

#if defined(I3_L1_PROBE)
/* Test harness root (the L1 plan, cued into the bottom of scratch). */
static noun g_cmp_harness;
static uint64_t g_cmp_harness_top;
void i3_host_harness_root(noun plan)
{
    g_cmp_harness = plan;
    g_cmp_harness_top = HEAP_SCRATCH_BASE + heap_scratch_mark();
}
#endif

/* Iterative walk: atoms into the atom set; cells in the live persist half
 * are followed; code-region cells are not (their atoms are in the boot
 * prefix); any other cell is wild (the rebuild is then skipped).
 * verify: also re-hash every atom reached. */
static void cmp_walk(noun root, int allow_scratch, int verify)
{
    uint64_t sp = 0;
    g_cw.stk[sp++] = root;
    while (sp) {
        noun n = g_cw.stk[--sp];
        if (noun_is_cell(n)) {
            uint32_t p = cell_ptr(n);
            cell_t *c;
            if (heap_in_code(p))
                continue;
            if (!heap_in_live_persist(p)) {
#if defined(I3_L1_PROBE)
                if (!(allow_scratch && (uint64_t)p >= HEAP_SCRATCH_BASE
                      && (uint64_t)p < g_cmp_harness_top)) {
                    g_cw.wild++;
                    continue;
                }
#else
                (void)allow_scratch;
                g_cw.wild++;
                continue;
#endif
            }
            if (!cmp_vis_add(p))
                continue;
            if (!allow_scratch && ++g_cw.cells > CMP_CELLS_MAX) {
                g_cw.overflow++;
                return;
            }
            c = (cell_t *)(uintptr_t)p;
            if (sp + 2 > CMP_STK_N) {
                g_cw.overflow++;
                return;
            }
            if (!noun_is_direct(c->tail))
                g_cw.stk[sp++] = c->tail;
            if (!noun_is_direct(c->head))
                g_cw.stk[sp++] = c->head;
            if (sp > g_cw.stk_hwm)
                g_cw.stk_hwm = sp;
        } else if (noun_is_indirect(n)) {
            if (!cmp_aset_add(indirect_hash(n)))
                continue;
            g_cw.atoms++;
            if (verify && !atom_store_rehash_ok(indirect_hash(n)))
                g_cw.missing++;
        }
    }
}

/* kind 1 (L1-only diagnostic tables, test harness): cells outside the code
 * region are not followed. */
static int g_cmp_verify;
static void cmp_root_cb(noun n, int kind)
{
    if (kind != 0 && noun_is_cell(n) && !heap_in_code(cell_ptr(n)))
        return;
    cmp_walk(n, 0, g_cmp_verify);
}

/* Every host root's cell must sit in the code region (or be an atom): a
 * cell in a persist half would be left behind by the flip. */
static uint64_t g_cmp_bad_roots;
static void cmp_check_root(noun n, int kind)
{
    if (kind == 0 && noun_is_cell(n) && !heap_in_code(cell_ptr(n)))
        g_cmp_bad_roots++;
}

static void cmp_clear(void)
{
    uint32_t i;
    for (i = 0; i < CMP_VIS_N; i++)
        g_cw.vis[i] = 0;
    for (i = 0; i < CMP_ASET_N; i++)
        g_cw.aset[i] = 0;
    g_cw.cells = g_cw.atoms = g_cw.stk_hwm = g_cw.wild = g_cw.overflow = g_cw.missing = 0;
}

/* Mark every atom reachable from the state and the host roots. */
static void cmp_mark(int verify)
{
    g_cmp_verify = verify;
    cmp_clear();
    cmp_walk(g_kernel, 0, verify);
    cmp_walk(g_poke_fol, 0, verify);
    cmp_walk(g_peek_fol, 0, verify);
    nock_host_roots(cmp_root_cb);
#if defined(I3_L1_PROBE)
    /* Test harness root: the L1 plan. */
    cmp_walk(g_cmp_harness, 1, verify);
#endif
}

static void compact_skip(uint64_t n, const char *why)
{
    uart_puts("I3H compact skip event=");
    put_u64(n);
    uart_puts(" reason=");
    uart_puts(why);
    uart_puts("\r\n");
}

static void compact_run(void)
{
    uint64_t n = g_cmp_n, mark, base, t0, t1, t2, t3, t4, before_cells, sel0;
    noun sample, copy, core, state;
    uint8_t dig[32];
    int mode = heap_get_mode();
    atom_compact_t st;
    cell_t *kc, *pc;
    g_cmp_pending = 0;
    if (!g_ready || g_stop || g_replaying)
        return;
#if defined(I3_CMP_TEST) && defined(I3_CKPT_TEST_CMPBEFORE)
    if (cmp_test_now())
        cmp_test_stop("before");
#endif
    /* The core is [battery [sample context]] with battery and context in
     * the code region, and every host root cell sits there too. */
    if (!noun_is_cell(g_kernel)) {
        compact_skip(n, "core");
        return;
    }
    kc = (cell_t *)(uintptr_t)cell_ptr(g_kernel);
    if (!noun_is_cell(kc->tail) || (noun_is_cell(kc->head) && !heap_in_code(cell_ptr(kc->head)))) {
        compact_skip(n, "code");
        return;
    }
    pc = (cell_t *)(uintptr_t)cell_ptr(kc->tail);
    if (noun_is_cell(pc->tail) && !heap_in_code(cell_ptr(pc->tail))) {
        compact_skip(n, "code");
        return;
    }
    g_cmp_bad_roots = 0;
    if (noun_is_cell(g_poke_fol) && !heap_in_code(cell_ptr(g_poke_fol)))
        g_cmp_bad_roots++;
    if (noun_is_cell(g_peek_fol) && !heap_in_code(cell_ptr(g_peek_fol)))
        g_cmp_bad_roots++;
    nock_host_roots(cmp_check_root);
    if (g_cmp_bad_roots) {
        compact_skip(n, "root");
        return;
    }
    before_cells = heap_cells_used(HEAP_MODE_PERSIST);
    sel0 = heap_persist_selector();
    sample = pc->head;
    /* (5) transaction on the other half */
    t0 = cntvct();
    heap_compact_begin();
    heap_set_mode(HEAP_MODE_PERSIST);
#if defined(I3_CMP_TEST) && (defined(I3_CKPT_TEST_CMPCOPY) || defined(I3_CKPT_TEST_CMPSKIP))
    if (cmp_test_now())
        noun_test_copy_fail_after(32);
#endif
    if (!noun_copy_checked(sample, &copy)) {
#if defined(I3_CMP_TEST) && (defined(I3_CKPT_TEST_CMPCOPY) || defined(I3_CKPT_TEST_CMPSKIP))
        noun_test_copy_fail_after(-1);
#if defined(I3_CKPT_TEST_CMPCOPY)
        if (cmp_test_now())
            cmp_test_stop("copy");
#else
        g_cmp_test_done = 1;
#endif
#endif
        heap_compact_abort();
        heap_set_mode(mode);
        compact_skip(n, "copy");
        return;
    }
    if (!install_sample(g_kernel, copy, &core)) {
        heap_compact_abort();
        heap_set_mode(mode);
        compact_skip(n, "alloc");
        return;
    }
    t1 = cntvct();
#if defined(I3_CMP_TEST) && defined(I3_CKPT_TEST_CMPAFTER)
    if (cmp_test_now())
        cmp_test_stop("after-copy");
#endif
    /* (4) axis 27 of the new core must hash to D */
    mark = heap_scratch_mark();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!ckpt_wrapper_ok(core, &state) || !ckpt_digest(state, dig, 0) || !digest_eq(dig, g_cmp_d)) {
        (void)heap_scratch_rewind(mark);
        heap_compact_abort();
        heap_set_mode(mode);
        compact_skip(n, "hash");
        return;
    }
    (void)heap_scratch_rewind(mark);
    /* commit: the core root and the half selector */
    g_kernel = core;
    heap_compact_commit();
    t2 = cntvct();
#if defined(I3_CMP_TEST) && defined(I3_CKPT_TEST_CMPFLIP)
    if (cmp_test_now())
        cmp_test_stop("after-flip");
#endif
    /* (6) atom store rebuild, work tables in scratch above its bump mark */
    mark = heap_scratch_mark();
    base = (HEAP_SCRATCH_BASE + mark + 0xFFFFu) & ~(uint64_t)0xFFFFu;
    if (base + CMP_ROOM > (uint64_t)HEAP_TOP) {
        heap_set_mode(mode);
        compact_skip(n, "rebuild-room");
        return;
    }
    g_cw.vis = (uint32_t *)(uintptr_t)base;
    g_cw.aset = (uint64_t *)(uintptr_t)(base + (uint64_t)CMP_VIS_N * 4u);
    g_cw.stk = (noun *)(uintptr_t)(base + (uint64_t)CMP_VIS_N * 4u + (uint64_t)CMP_ASET_N * 8u);
    (void)heap_scratch_rewind(base + CMP_ROOM - HEAP_SCRATCH_BASE);
    cmp_mark(0);
    t3 = cntvct();
    uart_puts("I3H compact walk event=");
    put_u64(n);
    uart_puts(" cells=");
    put_u64(g_cw.cells);
    uart_puts(" atoms=");
    put_u64(g_cw.atoms);
    uart_puts(" stack_hwm=");
    put_u64(g_cw.stk_hwm);
    uart_puts(" wild=");
    put_u64(g_cw.wild);
    uart_puts(" overflow=");
    put_u64(g_cw.overflow);
    uart_puts(" ticks=");
    put_u64(t3 - t2);
    uart_puts("\r\n");
    if (g_cw.wild || g_cw.overflow) {
        (void)heap_scratch_rewind(mark);
        heap_set_mode(mode);
        compact_skip(n, "rebuild-walk");
        return;
    }
#if defined(I3_CMP_TEST) && defined(I3_CKPT_TEST_CMPREBUILD)
    if (!atom_store_compact(cmp_live, cmp_test_now() ? cmp_test_mid : 0, &st)) {
#else
    if (!atom_store_compact(cmp_live, 0, &st)) {
#endif
        (void)heap_scratch_rewind(mark);
        heap_set_mode(mode);
        compact_skip(n, "rebuild-index");
        return;
    }
    /* Re-walk and re-hash every live atom (missing must be 0). */
    cmp_mark(1);
    t4 = cntvct();
    (void)heap_scratch_rewind(mark);
    heap_set_mode(mode);
#if defined(I3_CMP_TEST)
    if (cmp_test_now())
        g_cmp_test_done = 1;
#endif
    uart_puts("I3H compact ok event=");
    put_u64(n);
    uart_puts(" half=");
    put_u64(sel0);
    uart_puts("->");
    put_u64(heap_persist_selector());
    uart_puts(" persist_cells=");
    put_u64(before_cells);
    uart_puts("->");
    put_u64(heap_cells_used(HEAP_MODE_PERSIST));
    uart_puts(" free=");
    put_u64(heap_persist_free_cells());
    uart_puts(" atom_bytes=");
    put_u64(st.bytes_before);
    uart_puts("->");
    put_u64(st.bytes_after);
    uart_puts(" atom_idx=");
    put_u64(st.idx_before);
    uart_puts("->");
    put_u64(st.idx_after);
    uart_puts(" kept=");
    put_u64(st.kept);
    uart_puts(" dropped=");
    put_u64(st.dropped);
    uart_puts(" pin_bytes=");
    put_u64(atom_store_pin_bytes());
    uart_puts(" kept_digest=");
    put_hex((const uint8_t *)&st.kept_digest, 8);
    uart_puts(" after_digest=");
    put_hex((const uint8_t *)&st.after_digest, 8);
    uart_puts(" verify_atoms=");
    put_u64(g_cw.atoms);
    uart_puts(" missing=");
    put_u64(g_cw.missing);
    uart_puts(" job_sum=");
    put_u64(g_job_sum);
    uart_puts(" copy_ticks=");
    put_u64(t1 - t0);
    uart_puts(" flip_ticks=");
    put_u64(t2 - t0);
    uart_puts(" slide_ticks=");
    put_u64(st.slide_ticks);
    uart_puts(" index_ticks=");
    put_u64(st.index_ticks);
    uart_puts(" total_ticks=");
    put_u64(t4 - t0);
    uart_puts("\r\n");
}

/* The driver calls this once it has handed off the effects of the step it
 * just ran and reset scratch. */
void i3_host_handoff(void)
{
    if (g_cmp_pending)
        compact_run();
}

static void ckpt_verified(uint64_t n, noun state)
{
    noun marker, xs[3];
    uint8_t dig[32];
    uint64_t bytes = 0;
    int mode = heap_get_mode();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (g_last_ck_n > g_base.index) {
        cold_log_base_t now;
        /* Jobs of entries P+1..N, after the new base P = g_last_ck_n. */
        uint64_t after = g_job_sum >= JOB_UNBOUNDED ? JOB_UNBOUNDED
                         : g_job_sum - g_last_ck_sum;
        xs[0] = tas("i3-base");
        xs[1] = direct(g_last_ck_n);
        xs[2] = direct(n);
#if defined(I3_CKPT_TEST_REBASEFAULT)
        /* Test knob (tests/recorder_ring.py rebase-fault leg, COLD_MEDIA=fake):
         * the first base move meets a cold media timeout at its first
         * transfer, before any sector is submitted, so the move fails and
         * nothing is dropped. */
        static int rebase_fault_armed;
        if (!rebase_fault_armed) {
            rebase_fault_armed = 1;
            uart_puts("I3H ckpt test rebase-fault event=");
            put_u64(n);
            uart_puts("\r\n");
            cold_media_fake_fault_arm(COLD_MEDIA_FAKE_TIMEOUT, 1);
        }
#endif
        if (tuple(xs, 3, &marker)
            && cold_log_rebase(g_last_ck_n, after, marker) == 0
            && cold_log_base(&now) == 0) {
            g_base = now;
            /* Row 221 (7) Live: entries B+1..P leave the sum. */
            g_job_sum = after;
            uart_puts("I3H log base event=");
            put_u64(now.index);
            uart_puts(" ckpt=");
            put_u64(n);
            uart_puts(" kept_entries=");
            put_u64(now.len - now.index);
            uart_puts(" kept_bytes=");
            put_u64(cold_data_head() - now.off);
            uart_puts(" chain_bytes=");
            put_u64(cold_data_head());
            uart_puts("\r\n");
        } else {
            /* Nothing is dropped; the next verified checkpoint tries again. */
            uart_puts("I3H log base fail event=");
            put_u64(g_last_ck_n);
            uart_puts(" ckpt=");
            put_u64(n);
            uart_puts("\r\n");
        }
    }
    g_last_ck_n = n;
    g_last_ck_sum = g_job_sum;
    if (n % (uint64_t)I3_RING_EVERY == 0 && ckpt_digest(state, dig, &bytes))
        i3_ring_checkpoint(n, dig, g_job_sum, g_ckpt_buf, bytes);
    nv_flush();
    heap_set_mode(mode);
}
#endif

static void ckpt_maybe_write(void)
{
    noun state, loaded, hdr, xs[5];
    uint8_t dig[32], dig2[32], hd[32], hd2[32];
    uint64_t n = g_event_num - 1, bytes = 0, sid, hid;
    int mode = heap_get_mode();
    const char *why = 0;
    /* Never during replay and never once stopped: only a committed live
     * step reaches here, and the guard makes it explicit. */
    if (g_replaying || g_stop || n == 0 || n % (uint64_t)I3_CHECKPOINT_EVERY)
        return;
    /* The application state is internal.outer: the core's sample (axis 6) is
     * the NockApp wrapper's outer-state [%0 desk-hash internal], so the
     * kernel's own state (what /state-hash jams, row 199) is axis 27. Axis 6
     * would also hash the wrapper tag and build hash and never equal the
     * full node's /state-hash. Any other wrapper shape: skip. */
    if (!ckpt_wrapper_ok(g_kernel, &state)) {
        ckpt_skip(n, "wrapper");
        return;
    }
    /* Conservative stand-in for the 128k-cell cue bound: skip when the
     * state has more than I2_CUE_MAX_CELLS (65,536) distinct cells. */
    if ((why = ckpt_cells(state)) != 0) {
        ckpt_skip(n, why);
        return;
    }
    if (jam_size_checked(state, I3_CKPT_JAM_MAX, &bytes) != 0) {
        ckpt_skip(n, "jam-size");
        return;
    }
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!ckpt_digest(state, dig, &bytes))
        why = "jam";
    else if (!(sid = cold_store(state)))
        why = "store-state";
    else if (!noun_is_cell(loaded = cold_load_scratch(sid)) || !ckpt_digest(loaded, dig2, 0)
             || !digest_eq(dig, dig2))
        why = "verify-state";
    else {
        uint32_t arity = 5;
        uint8_t hdig[32];
        uint32_t i;
        for (i = 0; i < 32; i++)
            hdig[i] = dig[i];
        xs[0] = tas("i3-ckpt");
        xs[1] = direct(n);
        xs[2] = direct(sid);
#if defined(I3_CKPT_TEST_HDRSHAPE)
        if (I3_CKPT_BAD_HDR(n))
            arity = 4;
#elif defined(I3_CKPT_TEST_HDRSID)
        if (I3_CKPT_BAD_HDR(n))
            xs[2] = direct(sid ^ 1u);
#elif defined(I3_CKPT_TEST_HDRD) || defined(I3_CKPT_TEST_CRASH)
        if (I3_CKPT_BAD_HDR(n))
            hdig[0] ^= 1u;
#endif
        if (!bytes_atom(hdig, &xs[3]) || !bytes_atom(g_jam_blake3, &xs[4])
            || !tuple(xs, arity, &hdr) || !ckpt_digest(hdr, hd, 0))
            why = "alloc";
        /* The header read back must jam to the same bytes as the one
         * written (all five fields), not merely be a cell. */
#if defined(I3_CKPT_TEST_CRASH)
        else if (!(hid = cold_store(hdr)) || ckpt_test_crash(n)
                 || !noun_is_cell(loaded = cold_load_scratch(hid))
                 || !ckpt_digest(loaded, hd2, 0) || !digest_eq(hd, hd2))
            why = "verify-header";
#else
        else if (!(hid = cold_store(hdr)) || !noun_is_cell(loaded = cold_load_scratch(hid))
                 || !ckpt_digest(loaded, hd2, 0) || !digest_eq(hd, hd2))
            why = "verify-header";
#endif
    }
    if (!why)
        nv_flush();
    heap_set_mode(mode);
    if (why) {
        ckpt_skip(n, why);
        return;
    }
    uart_puts("I3H ckpt ok event=");
    put_u64(n);
    uart_puts(" bytes=");
    put_u64(bytes);
    uart_puts(" sha256=");
    put_hex(dig, 32);
    uart_puts("\r\n");
#if defined(COLD_LITE_LOG)
    ckpt_verified(n, state);
    compact_arm(n, dig);
#endif
}
#endif

static int crud_repoke(noun cause, uint64_t mote, noun trace,
                       i3_host_result_t *out)
{
    noun input_xs[4] = {direct(0), direct(0), direct(0), cause};
    noun job_input, goof, wire, arvo_rest, crud, ovum, ovo, subject, product;
    uint64_t t0, t1;
    int jumped;

    if (!tuple(input_xs, 4, &job_input))
        return 0;
    nock_budget_finish();
    if (!mook_goof(mote, trace, &goof))
        return 0;
    put_goof(goof);
    if (!nest(tas("arvo"), NOUN_ZERO, &arvo_rest))
        return 0;
    if (!nest(direct(0), arvo_rest, &wire))
        return 0;
    if (!nest(goof, job_input, &crud))
        return 0;
    if (!nest(wire, crud, &ovum))
        return 0;
    if (!nest(direct(g_event_num), ovum, &ovo))
        return 0;
    if (!nest(g_kernel, ovo, &subject))
        return 0;

    host_budget();
    t0 = cntvct();
    jumped = host_nock(subject, g_poke_fol, &product);
    t1 = cntvct();
    fill_eval(out, jumped, t1 - t0);
    if (jumped != 0) {
        /* A crash past %crud, or a host abort in the %crud step: no entry,
         * and the application stops (rows 141, 198). */
        host_stop(jumped == NOCK_ABORT_CRASH
                  ? "crud" : i3_host_abort_name(jumped, nock_budget_abort_reason()));
        nock_budget_finish();
        return 0;
    }
    if (noun_is_cell(product)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        noun next;
        if (!persist_prepare_live(c->tail, ovo, out, &next)) {
            host_stop(STOP_PERSIST);
            nock_budget_finish();
            return 0;
        }
        if (!log_append(ovo)) {
            nock_budget_finish();
            return 0;
        }
        if (out) {
            out->parse = 1;
            out->effects = c->head;
            out->effect_len = effect_list_len(c->head);
        }
        g_kernel = next;
        g_event_num++;
        nock_budget_finish();
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
        ckpt_maybe_write();
#endif
        return 1;
    }
    host_stop("crud");
    nock_budget_finish();
    return 0;
}

int i3_host_poke(noun cause, i3_host_result_t *out)
{
    noun job, subject, product;
    uint64_t t0, t1;
    int jumped;
    clear_result(out);
    if (!g_ready) {
        if (out)
            out->abort_reason = 0;
        return 0;
    }
    if (g_stop) {
        uart_puts("I3H refused stopped=");
        uart_puts(g_stop);
        uart_puts("\r\n");
        return 0;
    }
    if (!ovum_job(g_event_num, cause, &job) || !nest(g_kernel, job, &subject))
        return 0;
    host_budget();
    t0 = cntvct();
    jumped = host_nock(subject, g_poke_fol, &product);
    t1 = cntvct();
    fill_eval(out, jumped, t1 - t0);
    if (jumped != 0) {
        /* A bail propagates here from the de-moled fast
         * path (NOCK_ABORT_CRASH). Re-poke through ~[/arvo]; a budget abort
         * (NOCK_ABORT_BUDGET) is not a bail and gets no %crud re-entry.
         * Decision L2: each host abort (ops, wall, cells, stack) is a
         * host-set backstop like web fuel, so it stops the application
         * (row 141) with no entry. Kernel profile-budget refusals are
         * ordinary replies and never reach here. */
        if (jumped == NOCK_ABORT_CRASH)
            return crud_repoke(cause, nock_crash_mote(), nock_trace_get(), out);
        host_stop(i3_host_abort_name(jumped, nock_budget_abort_reason()));
        nock_budget_finish();
        return 0;
    }
    if (noun_is_cell(product)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        noun next;
        /* Row 200 persist stop: persist before append, so a failed persist
         * appends nothing, commits nothing, and stops the application
         * (row 141 trip, as a crash past %crud). */
        if (!persist_prepare_live(c->tail, job, out, &next)) {
            host_stop(STOP_PERSIST);
            nock_budget_finish();
            return 0;
        }
        if (!log_append(job)) {
            nock_budget_finish();
            return 0;
        }
        if (out) {
            out->parse = 1;
            out->effects = c->head;
            out->effect_len = effect_list_len(c->head);
        }
        g_kernel = next;
        g_event_num++;
        nock_budget_finish();
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
        ckpt_maybe_write();
#endif
        return 1;
    }
    nock_budget_finish();
    return 0;
}

int i3_host_peek(noun path, i3_host_result_t *out)
{
    noun subject, product;
    uint64_t t0, t1;
    int jumped;
    clear_result(out);
    if (!g_ready)
        return 0;
    if (!nest(g_kernel, path, &subject))
        return 0;
    host_budget();
    t0 = cntvct();
    jumped = host_nock(subject, g_peek_fol, &product);
    t1 = cntvct();
    fill_eval(out, jumped, t1 - t0);
    if (jumped != 0) {
        nock_budget_finish();
        return 0;
    }
    if (out)
        out->parse = 1;
    if (noun_is_cell(product)) {
        cell_t *u = (cell_t *)(uintptr_t)cell_ptr(product);
        if (noun_is_atom(u->head) && direct_val(u->head) == 0
            && noun_is_cell(u->tail)) {
            cell_t *v = (cell_t *)(uintptr_t)cell_ptr(u->tail);
            if (noun_is_atom(v->head) && direct_val(v->head) == 0)
                product = v->tail;
        }
    }
    if (out)
        out->product = product;
    nock_budget_finish();
    return 1;
}

/* Row 199 on the lite node: the kernel's /state-hash, (shax (jam state)),
 * paired with the host's event number N, the count of accepted log entries
 * after a clean replay. A stopped node (rows 141, 200) refuses the request.
 * Not on the step path: it runs only when asked, as a peek. The 32 hash bytes
 * are the atom's little-endian bytes, as the full node prints them. */
int i3_host_state_hash(uint64_t *event, uint8_t hash[32], i3_host_result_t *out)
{
    noun path;
    if (!out)
        return 0;
    clear_result(out);
    if (!g_ready || g_replaying)
        return 0;
    if (g_stop) {
        uart_puts("I3H state-hash refused stopped=");
        uart_puts(g_stop);
        uart_puts("\r\n");
        return 0;
    }
    if (!nest(tas("state-hash"), NOUN_ZERO, &path))
        return 0;
    if (!i3_host_peek(path, out) || !noun_is_atom(out->product))
        return 0;
    if (!noun_atom_read_fixed(out->product, hash, 32))
        return 0;
    *event = g_event_num - 1;
    return 1;
}

static int read_pill(const uint8_t **jam, uint64_t *jam_len, uint8_t *shape)
{
    volatile const uint8_t *base = (volatile const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t n = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        n |= (uint64_t)base[i] << (8u * i);
    *shape = base[8];
    *jam_len = n;
    *jam = (const uint8_t *)(uintptr_t)(PILL_BASE + 16u);
    return 1;
}

static void halt(void)
{
    for (;;)
        __asm__ volatile("wfe");
}

static int replay_fail(uint64_t i, const char *why)
{
    uart_puts("I3H replay fail entry=");
    put_u64(i);
    uart_puts(" reason=");
    uart_puts(why);
    uart_puts("\r\n");
    return 0;
}

/* Boot = core + replay of every logged job through the same slam, as the
 * full node's replay (form.rs:2692-2776): each job runs as logged (a crash
 * entry is the %crud ovo itself), its event number must be the next one,
 * and any failure stops the boot. Replay runs without the op budget
 * (decision 198); the cell and stack limits stay. */
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
/* Row 212 PR 1b: after a checkpoint boot at N, entries 1..N are read only
 * to move the cursor and to count their jobs into g_job_sum (so the row 213
 * reserve is the one a from-zero replay of the same log keeps); they are
 * not run. Entries after N run exactly as below. skip = 0: replay from zero. */
static int replay_log(uint64_t skip)
#else
static int replay_log(void)
#endif
{
#if defined(COLD_LITE_LOG)
    /* PR 1c: replay starts at the log base: entries 1..B are dropped, their
     * row 213 job sum comes from the base, and entry B+1 is the first LOG
     * object at or after the base offset. */
    uint64_t n = g_base.len, i, cur = g_base.off;
    /* Row 221 (7) Reboot: the job sum starts at 0 at the log base and adds
     * every entry read after it (counted-only up to the checkpoint, then
     * replayed). The base record's sum is not loaded. */
    g_job_sum = 0;
    g_last_ck_sum = 0;
#else
    uint64_t n = cold_log_len(), i, cur = 0;
#endif
    i3_host_result_t r;
    uart_puts("I3H replay entries=");
    put_u64(n);
    uart_puts("\r\n");
    g_replaying = 1;
#if defined(COLD_LITE_LOG)
    for (i = g_base.index; i < n; i++) {
#else
    for (i = 0; i < n; i++) {
#endif
        noun job, subject, product;
        int jumped;
        /* The job decodes into SCRATCH, as a live step's job does, and is
         * dropped by heap_scratch_reset below; i3_host_persist copies only
         * what the new state keeps. Decoding it into the persist heap left
         * every replayed job there for the whole boot, so replay ran out of
         * persist (reason=persist) before live use did. */
        heap_set_mode(HEAP_MODE_SCRATCH);
        job = cold_log_next(&cur);
        if (!noun_is_cell(job))
            return replay_fail(i, "read");
        cell_t *jc = (cell_t *)(uintptr_t)cell_ptr(job);
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
        if (i < skip) {
            if (!noun_is_atom(jc->head) || direct_val(jc->head) != i + 1)
                return replay_fail(i, "event-num");
            job_seen(job_cells(job));
#if defined(COLD_LITE_LOG)
            if (i + 1 == skip)
                g_last_ck_sum = g_job_sum;
#endif
            heap_scratch_reset();
            continue;
        }
#endif
        if (!noun_is_atom(jc->head) || direct_val(jc->head) != g_event_num)
            return replay_fail(i, "event-num");
        job_seen(job_cells(job));
        if (!nest(g_kernel, job, &subject))
            return replay_fail(i, "alloc");
        nock_budget_set_limits(0, I3_SLAM_MAX_CELLS);
        nock_eval_stack_set_limit(I3_SLAM_MAX_STACK);
        jumped = host_nock(subject, g_poke_fol, &product);
        nock_budget_finish();
        if (jumped != 0 || !noun_is_cell(product))
            return replay_fail(i, "crashed");
        g_kernel = ((cell_t *)(uintptr_t)cell_ptr(product))->tail;
        g_event_num++;
        clear_result(&r);
        if (!i3_host_persist(&r))
            return replay_fail(i, "persist");
        heap_scratch_reset();
    }
    g_replaying = 0;
    uart_puts("I3H replay done event=");
    put_u64(g_event_num);
    uart_puts("\r\n");
#if defined(COLD_LITE_LOG)
    /* Row 221 (7): the job sum counted from the log base. */
    uart_puts("I3H replay job_sum=");
    put_u64(g_job_sum);
    uart_puts("\r\n");
#endif
    return 1;
}

/* Row 141 after replay: a trip recorded at the last run stops the
 * application with a journaled %manage STOP before any input, the same
 * cause as the web node's stop_after_trip: [%turn [0 %manage 3 0 0] 0 0 0]. */
static void stop_after_trip(void)
{
    noun trip, manage, local, cause;
    noun m_xs[4], c_xs[5];
    i3_host_result_t r;
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (persist_trip_noun(g_event_num, &trip) && noun_is_cell(cold_load(cold_jam_hash(trip)))) {
        /* Row 200: a persist-stopped node stays stopped on every boot, logs
         * nothing, and does not rewrite its trip. */
        g_stop = STOP_PERSIST;
        uart_puts("I3H trip-stop reason=persist\r\n");
        heap_scratch_reset();
        return;
    }
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!trip_noun(g_event_num, &trip) || !noun_is_cell(cold_load(cold_jam_hash(trip))))
        return;
    heap_set_mode(HEAP_MODE_SCRATCH);
    m_xs[0] = tas("manage"); m_xs[1] = direct(3); m_xs[2] = NOUN_ZERO; m_xs[3] = NOUN_ZERO;
    if (!tuple(m_xs, 4, &manage) || !nest(NOUN_ZERO, manage, &local))
        return;
    c_xs[0] = tas("turn"); c_xs[1] = local;
    c_xs[2] = NOUN_ZERO; c_xs[3] = NOUN_ZERO; c_xs[4] = NOUN_ZERO;
    if (!tuple(c_xs, 5, &cause))
        return;
    uart_puts("I3H trip-stop ok=");
    uart_puts(i3_host_poke(cause, &r) ? "yes" : "no");
    uart_puts("\r\n");
    heap_scratch_reset();
}

#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
/* Row 212 PR 1b: boot from a checkpoint (docs/lite-checkpoint-writer.md,
 * Boot). Take the newest header [%i3-ckpt N sid D kernel-blake3] that
 * verifies: N within the log, kernel-blake3 equal to this boot's
 * g_jam_blake3 (BLAKE3-256 of the pill's kernel jam bytes as read), the
 * state blob sid loads and sha256(jam state) = D; then the state goes
 * through the versioned +load (the NockApp wrapper's outer +load, arm 4,
 * with [%0 desk-hash state]); the loaded core's state must again hash to D,
 * and it is copied into persist. Replay then runs only the entries after N.
 * Any failure rejects that header and the next older one is tried. Row 212
 * (3) fallback: if none verifies and the log still starts at entry 1,
 * replay from zero. No rotation exists yet (PR 1c), so the log always
 * starts at entry 1 and the "log rotated: stop" branch cannot arise here.
 * A rejected attempt leaves the booted core and event number as they were;
 * its scratch is reset, but persist cells a failed persist copy already
 * took are not returned (bump heap). Never boots from an unverified image:
 * the state is installed only after every check passed. */
#define I3_CKPT_HDR_MAX_BYTES 256u

typedef struct {
    noun tag;
    uint64_t below;   /* only headers with N < below */
#if defined(COLD_LITE_LOG)
    uint64_t min;     /* PR 1c: only headers with N >= the log base */
#endif
    int found, shape_ok;
    uint64_t n, sid;
    uint8_t d[32], kb[32];
} ckpt_find_t;

static int ckpt_find_cb(void *ctx, noun blob)
{
    ckpt_find_t *f = (ckpt_find_t *)ctx;
    noun x[5], cur = blob;
    uint32_t i;
    uint64_t n;
    uint8_t d[32], kb[32];
    int shape_ok = 1;
    for (i = 0; i < 4; i++) {
        cell_t *c;
        if (!noun_is_cell(cur)) {
            if (i < 2)
                goto done;
            shape_ok = 0;
            break;
        }
        c = (cell_t *)(uintptr_t)cell_ptr(cur);
        x[i] = c->head;
        cur = c->tail;
    }
    x[4] = cur;
    /* A header is a cell whose head is %i3-ckpt and whose second field is
     * the event number; anything else in the store is not a header. */
    if (x[0] != f->tag || !noun_is_direct(x[1]))
        goto done;
    n = direct_val(x[1]);
    if (n >= f->below || (f->found && n < f->n))
        goto done;
#if defined(COLD_LITE_LOG)
    if (n < f->min)
        goto done;
#endif
    if (shape_ok)
        shape_ok = noun_is_direct(x[2]) && noun_atom_read_fixed(x[3], d, 32)
                   && noun_atom_read_fixed(x[4], kb, 32);
    f->found = 1;
    f->shape_ok = shape_ok;
    f->n = n;
    f->sid = shape_ok ? direct_val(x[2]) : 0;
    for (i = 0; i < 32; i++) {
        f->d[i] = shape_ok ? d[i] : 0;
        f->kb[i] = shape_ok ? kb[i] : 0;
    }
done:
    heap_scratch_reset();
    return 0;
}

static int load_formula(noun *out)
{
    noun pul_xs[4] = {direct(9), direct(4), direct(0), direct(2)};
    noun sam_xs[3] = {direct(6), direct(0), direct(7)};
    noun pul, sam, fol_xs[8];
    if (!tuple(pul_xs, 4, &pul) || !tuple(sam_xs, 3, &sam))
        return 0;
    fol_xs[0] = direct(8);
    fol_xs[1] = pul;
    fol_xs[2] = direct(9);
    fol_xs[3] = direct(2);
    fol_xs[4] = direct(10);
    fol_xs[5] = sam;
    fol_xs[6] = direct(0);
    fol_xs[7] = direct(2);
    return tuple(fol_xs, 8, out);
}

/* Verify one header and, if every check passes, install its state.
 * Returns 0 on success, else the reject reason. */
static const char *ckpt_try(const ckpt_find_t *f, uint64_t log_len)
{
    noun state, booted, desk, old, fol, subject, product, xs[3];
    uint8_t dig[32];
    uint64_t saved_event = g_event_num;
    i3_host_result_t r;
    int jumped;
    if (!f->shape_ok)
        return "shape";
    if (f->n == 0 || f->n > log_len)
        return "n";
    if (!digest_eq(f->kb, g_jam_blake3))
        return "kernel";
    heap_set_mode(HEAP_MODE_SCRATCH);
    state = cold_load_scratch(f->sid);
    if (!noun_is_cell(state))
        return "sid";
    if (!ckpt_digest(state, dig, 0) || !digest_eq(dig, f->d))
        return "hash";
    /* The booted core must have the wrapper shape the writer saved from;
     * its desk-hash (axis 26) is the booted build's, as on any +load. */
    if (!ckpt_wrapper_ok(g_kernel, &booted) || !ckpt_axis(g_kernel, 26, &desk))
        return "wrapper";
    xs[0] = direct(0);
    xs[1] = desk;
    xs[2] = state;
    if (!tuple(xs, 3, &old) || !load_formula(&fol) || !nest(g_kernel, old, &subject))
        return "alloc";
    /* As replay (decision 198): no op budget, the cell and stack limits stay. */
    nock_budget_set_limits(0, I3_SLAM_MAX_CELLS);
    nock_eval_stack_set_limit(I3_SLAM_MAX_STACK);
    jumped = host_nock(subject, fol, &product);
    uart_puts("I3H ckpt boot load event=");
    put_u64(f->n);
    uart_puts(" abort=");
    uart_puts(i3_host_abort_name(jumped, nock_budget_abort_reason()));
    if (jumped == NOCK_ABORT_CRASH) {
        uint64_t m = nock_crash_mote();
        uart_puts(" mote=");
        while (m) {
            uart_putc((char)(m & 0xff));
            m >>= 8;
        }
    }
    uart_puts(" nock_ops_used=");
    put_u64(nock_ops_used());
    uart_puts(" nock_cells_used=");
    put_u64(nock_cells_used());
    uart_puts(" nock_eval_stack_peak=");
    put_u64(nock_eval_stack_peak());
    uart_puts("\r\n");
    nock_budget_finish();
    if (jumped != 0 || !noun_is_cell(product))
        return "load";
    if (!ckpt_wrapper_ok(product, &state) || !ckpt_digest(state, dig, 0)
        || !digest_eq(dig, f->d))
        return "load-hash";
    booted = g_kernel;
    g_kernel = product;
    clear_result(&r);
    if (!i3_host_persist(&r)) {
        g_kernel = booted;
        g_event_num = saved_event;
        return "persist";
    }
    g_event_num = f->n + 1;
    return 0;
}

/* Returns the N the boot resumes after (0: replay from zero). */
static uint64_t ckpt_boot(void)
{
    ckpt_find_t f;
#if defined(COLD_LITE_LOG)
    uint64_t log_len = g_base.len, rejected = 0;
#else
    uint64_t log_len = cold_log_len(), rejected = 0;
#endif
    const char *why;
    f.tag = tas("i3-ckpt");
    f.below = UINT64_MAX;
#if defined(COLD_LITE_LOG)
    /* A checkpoint before the base cannot boot: its entries are dropped. */
    f.min = g_base.index;
#endif
    for (;;) {
        f.found = 0;
        if (cold_blob_scan(I3_CKPT_HDR_MAX_BYTES, ckpt_find_cb, &f) != 0 || !f.found)
            break;
        why = ckpt_try(&f, log_len);
        heap_scratch_reset();
        if (!why) {
            uart_puts("I3H ckpt boot event=");
            put_u64(f.n);
            uart_puts(" sha256=");
            put_hex(f.d, 32);
            uart_puts(" log=");
            put_u64(log_len);
            uart_puts("\r\n");
#if defined(COLD_LITE_LOG)
            g_last_ck_n = f.n;
#endif
            return f.n;
        }
        uart_puts("I3H ckpt boot reject event=");
        put_u64(f.n);
        uart_puts(" reason=");
        uart_puts(why);
        uart_puts("\r\n");
        rejected++;
        f.below = f.n;
    }
    heap_scratch_reset();
#if defined(COLD_LITE_LOG)
    /* Row 212 (3): "if none is valid and the log has been rotated, the node
     * stops (row 141 stop) and reports it. It never boots from an unverified
     * image." Rotated = entries 1..B dropped (B > 0). */
    if (g_base.index > 0) {
        uart_puts("I3H ckpt boot none rejected=");
        put_u64(rejected);
        uart_puts(" fallback=stop base=");
        put_u64(g_base.index);
        uart_puts("\r\n");
        g_rotated = 1;
        return 0;
    }
#endif
    uart_puts("I3H ckpt boot none rejected=");
    put_u64(rejected);
    uart_puts(" fallback=zero\r\n");
    return 0;
}
#endif

#if defined(COLD_LITE_LOG)
/* PR 1c boot: read the log base, take a checkpoint (1b), replay the tail,
 * then open the recorder ring at the replayed log length. With no valid
 * checkpoint and a rotated log the node is stopped (row 141): nothing is
 * replayed, nothing is appended, every input and /state-hash is refused,
 * and no trip is written (the next boot finds the same and stops again). */
static int lite_boot(void)
{
    uint64_t from;
    if (cold_log_base(&g_base) != 0) {
        g_base.index = 0;
        g_base.off = 0;
        g_base.job_sum = 0;
        g_base.len = cold_log_len();
    }
    uart_puts("I3H log boot base=");
    put_u64(g_base.index);
    uart_puts(" len=");
    put_u64(g_base.len);
    uart_puts(" job_sum=");
    put_u64(g_base.job_sum);
    uart_puts("\r\n");
    from = ckpt_boot();
    if (g_rotated) {
        g_stop = STOP_ROTATED;
        uart_puts("I3H stop reason=rotated base=");
        put_u64(g_base.index);
        uart_puts(" log=");
        put_u64(g_base.len);
        uart_puts("\r\n");
        return 1;
    }
    if (!replay_log(from))
        return 0;
    i3_ring_boot(g_event_num - 1, g_jam_blake3);
    return 1;
}
#endif

/* Row 221 (3): a build that overflows the code region halts with its own
 * terminal reason. */
#if defined(I3_COMPACT)
static void code_region_check(void)
{
    if (heap_code_overflowed()) {
        uart_puts("I3H code region overflow bytes=");
        put_u64(heap_code_bytes());
        uart_puts(" size=");
        put_u64(I3_CODE_SIZE);
        uart_puts("\r\nI3H terminal=code-region\r\n");
        halt();
    }
}
#else
#define code_region_check() ((void)0)
#endif

void i3_host_boot(void)
{
    const uint8_t *jam;
    uint64_t jam_len, cue_len;
    uint8_t shape;
    noun root, kick_fol;
    cue_bounded_limits_t limits;
    cue_bounded_status_t status;
    uint64_t t0, t1;
    int jumped;
    i3_host_result_t persist;

    g_ready = 0;
    g_event_num = 1;
    g_stop = 0;
    g_replaying = 0;
    g_job_sum = 0;
    uart_puts("I3H start\r\n");
    fast_reset();

    (void)read_pill(&jam, &jam_len, &shape);
    if (shape != I3_PILL_SHAPE_NOCKAPP) {
        uart_puts("I3H terminal=pill-refuse\r\n");
        halt();
    }
    if (jam_len == 0 || jam_len > I3_CUE_MAX_INPUT_BYTES) {
        uart_puts("I3H cue status=input cells=0 cells_bound=");
        put_u64(I3_CUE_MAX_CELLS);
        uart_puts(" ticks=0 first_bound=input\r\n");
        uart_puts("I3H terminal=cue-refuse\r\n");
        halt();
    }

    g_jam_len = jam_len;
    blake3_hash(jam, (size_t)jam_len, g_jam_blake3);

    uart_puts("I3H jam bytes=");
    put_u64(jam_len);
    uart_puts("\r\n");

    cue_len = jam_len;
    while (cue_len > 1 && jam[cue_len - 1] == 0)
        cue_len--;

    limits = i3_limits();
#if defined(I3_COMPACT)
    /* Row 221 (3): the cue, the formulas and the kick build in the code
     * region, once. */
    heap_code_begin();
#endif
    t0 = cntvct();
    status = cue_bounded_bytes(jam, cue_len, &limits, HEAP_MODE_PERSIST, &root);
    t1 = cntvct();
    print_cue(status, t1 - t0);
    if (status != CUE_BOUNDED_OK) {
        code_region_check();
        uart_puts("I3H terminal=cue-refuse\r\n");
        halt();
    }
    noun_tx_commit();

    uart_puts("I3H kernel bytes=");
    put_u64(g_jam_len);
    uart_puts(" blake3=");
    put_hex(g_jam_blake3, 32);
    uart_puts("\r\n");

    heap_set_mode(HEAP_MODE_PERSIST);
    if (!kick_formula(&kick_fol) || !slam_formula(&g_poke_fol)
        || !peek_formula(&g_peek_fol)) {
        code_region_check();
        uart_puts("I3H terminal=formula-fail\r\n");
        halt();
    }

    host_budget();
    t0 = cntvct();
    jumped = host_nock(root, kick_fol, &g_kernel);
    t1 = cntvct();
    uart_puts("I3H kick nock_ops_used=");
    put_u64(nock_ops_used());
    uart_puts(" nock_cells_used=");
    put_u64(nock_cells_used());
    uart_puts(" nock_eval_stack_peak=");
    put_u64(nock_eval_stack_peak());
    uart_puts(" ticks=");
    put_u64(t1 - t0);
    uart_puts(" parse=");
    uart_puts((jumped == 0 && noun_is_cell(g_kernel)) ? "yes" : "no");
    uart_puts(" abort=");
    uart_puts(i3_host_abort_name(jumped, nock_budget_abort_reason()));
    uart_puts(" formula=");
    uart_puts(KICK_FORMULA_TEXT);
    uart_puts("\r\n");
    nock_budget_finish();
    if (jumped != 0 || !noun_is_cell(g_kernel)) {
        code_region_check();
        uart_puts("I3H terminal=kick-fail\r\n");
        halt();
    }
#if defined(I3_COMPACT)
    heap_code_end();
    uart_puts("I3H code region bytes=");
    put_u64(heap_code_bytes());
    uart_puts(" cells=");
    put_u64(heap_code_bytes() / sizeof(cell_t));
    uart_puts(" size=");
    put_u64(I3_CODE_SIZE);
    uart_puts("\r\n");
#endif

    g_ready = 1;
    clear_result(&persist);
    (void)i3_host_persist(&persist);
    uart_puts("I3H persist_copy ticks=");
    put_u64(persist.persist_ticks);
    uart_puts(" ok=");
    uart_puts(persist.persist_ok ? "yes" : "no");
    uart_puts(" copy_map_hwm=");
    put_u64(persist.persist_copy_map_hwm);
    uart_puts(" copy_map_capacity=");
    put_u64(persist.persist_copy_map_capacity);
    uart_puts("\r\n");
    if (!persist.persist_ok) {
        uart_puts("I3H terminal=persist-fail\r\n");
        g_ready = 0;
        halt();
    }
#if defined(I3_COMPACT)
    /* Row 221 (6): the atoms from the kernel cue are the fixed prefix. */
    atom_store_pin();
    uart_puts("I3H atom prefix bytes=");
    put_u64(atom_store_pin_bytes());
    uart_puts(" atoms=");
    put_u64(atom_store_index_occupancy());
    uart_puts(" persist_cells=");
    put_u64(heap_cells_used(HEAP_MODE_PERSIST));
    uart_puts("\r\n");
#endif

#if defined(COLD_MEDIA_SEMIHOST)
    cold_nv_arm();
#endif
#if defined(I3_PERSIST_HEADROOM_CELLS)
    heap_persist_cap_arm();
    uart_puts("I3H persist_headroom cells=");
    put_u64(I3_PERSIST_HEADROOM_CELLS);
    uart_puts("\r\n");
#endif
    g_persist_reserve = heap_persist_free_cells() / 16;
#if defined(COLD_LITE_LOG)
    if (!lite_boot()) {
#elif defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
    if (!replay_log(ckpt_boot())) {
#else
    if (!replay_log()) {
#endif
        uart_puts("I3H terminal=replay-fail\r\n");
        g_ready = 0;
        halt();
    }
#if defined(COLD_LITE_LOG)
    if (!g_rotated)
#endif
    stop_after_trip();
    uart_puts("I3H ready\r\n");
#if defined(I3_L1_PROBE)
    i3_l1_probe_boot();
#endif
    halt();
}
