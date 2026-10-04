#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "i2_admission_metrics.h"
#include "i3_admission.h"
#include "i3_host.h"
#if defined(I3_L1_PROBE)
#include "i3_l1_probe.h"
#endif
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

int i3_host_persist(i3_host_result_t *out)
{
    noun sample, copy, installed;
    uint64_t t0, t1;
    int ok;
    if (out) {
        out->persist_ok = 0;
        out->persist_ticks = 0;
        out->persist_copy_map_hwm = 0;
        out->persist_copy_map_capacity = noun_copy_map_capacity();
    }
    if (!g_ready || !noun_is_cell(g_kernel))
        return 0;
    sample = slot(direct(6), g_kernel);
    heap_set_mode(HEAP_MODE_PERSIST);
    noun_copy_map_hwm_reset();
    t0 = cntvct();
    ok = noun_copy_checked(sample, &copy);
    t1 = cntvct();
    if (ok && install_sample(g_kernel, copy, &installed))
        g_kernel = installed;
    else
        ok = 0;
    if (out) {
        out->persist_ok = ok;
        out->persist_ticks = t1 - t0;
        out->persist_copy_map_hwm = noun_copy_map_hwm();
        out->persist_copy_map_capacity = noun_copy_map_capacity();
    }
    return ok;
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

/* KP2 crash re-entry: the de-moled fast path lets a deterministic $exit bail
 * escape to the host as NOCK_ABORT_CRASH. Reproduce the NockApp/web-node
 * `poke_swap` re-poke: run the same event again through the wire ~[/arvo]
 * with a [%exit ~] goof, so the outer keep core's %crud branch (wrapper.hoon)
 * re-runs it in isolation and re-emits the planted [%block-crash …] effects
 * byte-identically.
 *
 *   wire      = [0 %arvo 0]                 (path ~[/arvo])
 *   goof      = [%exit ~]
 *   job_input = [eny our now cause] = [0 0 0 cause]   (as ovum_job builds)
 *   ovo       = [event_num [wire [goof job_input]]]
 *
 * The trinitite nock reports every consistence bail as a bare `nock_crash`
 * C string — it has no [mote tang] bail noun — and the only bail the lite
 * node exercises is the planted `~|(%planted-crash !!)`, i.e. %exit. A
 * budget failure is NOCK_ABORT_BUDGET and never reaches this path. The
 * goof's tang is consumed only by the wrapper's slog-on-refusal branch and
 * does not affect the %exit re-run's bytes, so tang = ~ here. */
static int crud_repoke(noun cause, i3_host_result_t *out)
{
    noun input_xs[4] = {direct(0), direct(0), direct(0), cause};
    noun job_input, goof, wire, arvo_rest, crud, ovum, ovo, subject, product;
    uint64_t t0, t1;
    int jumped;

    if (!tuple(input_xs, 4, &job_input))
        return 0;
    if (!nest(tas("exit"), NOUN_ZERO, &goof))
        return 0;
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
        nock_budget_finish();
        return 0;
    }
    if (noun_is_cell(product)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        if (out) {
            out->parse = 1;
            out->effects = c->head;
            out->effect_len = effect_list_len(c->head);
        }
        g_kernel = c->tail;
        g_event_num++;
        (void)i3_host_persist(out);
        nock_budget_finish();
        return 1;
    }
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
    if (!ovum_job(g_event_num, cause, &job) || !nest(g_kernel, job, &subject))
        return 0;
    host_budget();
    t0 = cntvct();
    jumped = host_nock(subject, g_poke_fol, &product);
    t1 = cntvct();
    fill_eval(out, jumped, t1 - t0);
    if (jumped != 0) {
        /* A deterministic $exit bail propagates here from the de-moled fast
         * path (NOCK_ABORT_CRASH). Re-poke through ~[/arvo]; a budget abort
         * (NOCK_ABORT_BUDGET) is not a bail and gets no %crud re-entry. */
        if (jumped == NOCK_ABORT_CRASH)
            return crud_repoke(cause, out);
        nock_budget_finish();
        return 0;
    }
    if (noun_is_cell(product)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        if (out) {
            out->parse = 1;
            out->effects = c->head;
            out->effect_len = effect_list_len(c->head);
        }
        g_kernel = c->tail;
        g_event_num++;
        (void)i3_host_persist(out);
        nock_budget_finish();
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
    t0 = cntvct();
    status = cue_bounded_bytes(jam, cue_len, &limits, HEAP_MODE_PERSIST, &root);
    t1 = cntvct();
    print_cue(status, t1 - t0);
    if (status != CUE_BOUNDED_OK) {
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
        uart_puts("I3H terminal=kick-fail\r\n");
        halt();
    }

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

    uart_puts("I3H ready\r\n");
#if defined(I3_L1_PROBE)
    i3_l1_probe_boot();
#endif
    halt();
}
