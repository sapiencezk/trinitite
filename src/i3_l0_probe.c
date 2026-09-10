#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_admission_envelope.h"
#include "i2_admission_metrics.h"
#include "i3_l0_probe.h"
#include "memory.h"
#include "nock.h"
#include "noun.h"
#include "setjmp.h"
#include "uart.h"

/*
 * I3 L0 / L0.1 measurement probe. Admission constants here are probe-local
 * and do not change production i2_admission_envelope.h.
 *
 * Slam formula is the NockApp shape from nockapp noun/ops.rs:
 *   [8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]  over  [kernel job]
 * Job encoding (L0.1): [num [wire [eny our now cause]]].
 */
#define POLICY_MAX_OPS 2000000ULL
#define POLICY_MAX_CELLS 128000ULL
#define POLICY_MAX_STACK 1024ULL
#define SLAM_FORMULA_TEXT "[8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]"
/* Probe table in bounded_cue.c; cue caches unique nodes plus backref sites. */
#define PROBE_MAX_CACHE_ENTRIES 1048576u
#define PROBE_MAX_WORK 200000000ULL
#define PROBE_MAX_BACKREFS 600000u
#define PROBE_MAX_DEPTH 1024u
#define PROBE_MAX_NODES 1200000u
#define PROBE_MAX_CELLS 600000u

extern uint8_t _pill_embed_start[];
extern uint8_t _pill_embed_end[];

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

/* jumped is setjmp; budget reason is 1=ops, 2=wall, 3=cells, 4=stack. */
static const char *abort_name(int jumped, uint64_t reason)
{
    if (jumped == 0)
        return "none";
    if (jumped == NOCK_ABORT_CRASH)
        return "crash";
    switch (reason) {
    case 1:
        return "ops";
    case 2:
        return "wall";
    case 3:
        return "cells";
    case 4:
        return "stack";
    default:
        return jumped == NOCK_ABORT_BUDGET ? "ops" : "crash";
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

static int jam_bytes(const uint8_t **bytes, uint64_t *len)
{
    volatile const uint8_t *base = (volatile const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t n = 0;
    for (uint32_t i = 0; i < 8; i++)
        n |= (uint64_t)base[i] << (8u * i);
    if (n > 0 && n <= cue_i2_limits.max_input_bytes) {
        *bytes = (const uint8_t *)(uintptr_t)(PILL_BASE + 16u);
        *len = n;
        return 1;
    }
    uint64_t embed = (uint64_t)(_pill_embed_end - _pill_embed_start);
    if (embed > 16u) {
        *bytes = _pill_embed_start;
        *len = embed;
        return 1;
    }
    return 0;
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

static int kick_formula(noun *out)
{
    /* serf boot: *[trap 9 2 0 1] */
    noun xs[4] = {direct(9), direct(2), direct(0), direct(1)};
    return tuple(xs, 4, out);
}

static int path3(const char *a, const char *b, noun *out)
{
    noun rest;
    if (!nest(tas(b), NOUN_ZERO, &rest))
        return 0;
    return nest(tas(a), rest, out);
}

static int ovum_job(uint64_t num, noun cause, noun *out)
{
    /* [num [wire [eny our now cause]]], num 1 = %init, 2 = [%tick 5]. */
    noun wire, input_xs[4], input, ovum;
    if (!path3("poke", "l0", &wire))
        return 0;
    input_xs[0] = direct(0); /* eny */
    input_xs[1] = direct(0); /* our */
    input_xs[2] = direct(0); /* now */
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

static const char *production_would_hit_first(void)
{
    /* L0 refused at production cache 98304 with cells 49296, nodes 98549,
     * work 1559683 — still under production cells/nodes/work. */
    return "cache";
}

static void print_cue(cue_bounded_status_t status, uint64_t ticks)
{
    uint64_t cells = g_i2_admission_metrics.cue_cells_hwm;
    uint64_t nodes = g_i2_admission_metrics.cue_nodes_hwm;
    uint64_t atoms = nodes > cells ? nodes - cells : 0;
    uart_puts("I3L0 cue status=");
    uart_puts(cue_bounded_status_name(status));
    uart_puts(" cells=");
    put_u64(cells);
    uart_puts(" atoms=");
    put_u64(atoms);
    uart_puts(" ticks=");
    put_u64(ticks);
    uart_puts(" first_bound=");
    uart_puts(status == CUE_BOUNDED_OK ? "none" : cue_bounded_status_name(status));
    uart_puts(" production_first_bound=");
    uart_puts(production_would_hit_first());
    uart_puts(" production_cache=");
    put_u64(I2_CUE_CACHE_ADMITTED);
    uart_puts(" work=");
    put_u64(g_i2_admission_metrics.cue_work_hwm);
    uart_puts(" nodes=");
    put_u64(nodes);
    uart_puts(" backrefs=");
    put_u64(g_i2_admission_metrics.cue_backrefs_hwm);
    uart_puts(" cache=");
    put_u64(g_i2_admission_metrics.cue_cache_entries_hwm);
    uart_puts(" depth=");
    put_u64(g_i2_admission_metrics.cue_depth_hwm);
    uart_puts(" atom_bytes=");
    put_u64(g_i2_admission_metrics.cue_atom_bytes_hwm);
    uart_puts("\r\n");
}

static void print_poke(const char *name, uint64_t ops, uint64_t cells,
                       uint64_t stack, uint64_t ticks, int parse,
                       uint64_t effect_len, const char *abort)
{
    uart_puts("I3L0 poke name=");
    uart_puts(name);
    uart_puts(" nock_ops_used=");
    put_u64(ops);
    uart_puts(" nock_cells_used=");
    put_u64(cells);
    uart_puts(" nock_eval_stack_peak=");
    put_u64(stack);
    uart_puts(" ticks=");
    put_u64(ticks);
    uart_puts(" parse=");
    uart_puts(parse ? "yes" : "no");
    uart_puts(" effect_len=");
    put_u64(effect_len);
    uart_puts(" abort=");
    uart_puts(abort ? abort : "none");
    uart_puts(" policy_ops=");
    put_u64(POLICY_MAX_OPS);
    uart_puts(" policy_cells=");
    put_u64(POLICY_MAX_CELLS);
    uart_puts(" policy_stack=");
    put_u64(POLICY_MAX_STACK);
    uart_puts(" formula=");
    uart_puts(SLAM_FORMULA_TEXT);
    uart_puts("\r\n");
}

static int slam_poke(noun kernel, noun formula, uint64_t num, noun cause,
                     const char *name, noun *new_core)
{
    noun job, subject, product;
    uint64_t t0, t1;
    int parse = 0;
    uint64_t effects = 0;
    if (!ovum_job(num, cause, &job) || !nest(kernel, job, &subject)) {
        print_poke(name, 0, 0, 0, 0, 0, 0, "none");
        return 0;
    }
    nock_budget_set(0);
    nock_eval_stack_set_limit(0);
    jmp_buf saved;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    t0 = cntvct();
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        uint64_t reason = nock_budget_abort_reason();
        t1 = cntvct();
        print_poke(name, nock_ops_used(), nock_cells_used(),
                   nock_eval_stack_peak(), t1 - t0, 0, 0,
                   abort_name(jumped, reason));
        nock_budget_finish();
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return 0;
    }
    product = nock(subject, formula);
    t1 = cntvct();
    parse = noun_is_cell(product);
    if (parse) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        effects = effect_list_len(c->head);
        if (new_core)
            *new_core = c->tail;
    }
    print_poke(name, nock_ops_used(), nock_cells_used(),
               nock_eval_stack_peak(), t1 - t0, parse, effects, "none");
    nock_budget_finish();
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    return parse;
}

static void persist_copy(noun root)
{
    noun copy;
    uint64_t t0, t1;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    noun_copy_map_hwm_reset();
    t0 = cntvct();
    int ok = noun_copy_checked(root, &copy);
    t1 = cntvct();
    if (ok)
        heap_persist_commit_tx();
    else
        heap_persist_abort_tx();
    uart_puts("I3L0 persist_copy ticks=");
    put_u64(t1 - t0);
    uart_puts(" ok=");
    uart_puts(ok ? "yes" : "no");
    uart_puts(" copy_map_hwm=");
    put_u64(noun_copy_map_hwm());
    uart_puts(" copy_map_capacity=");
    put_u64(noun_copy_map_capacity());
    uart_puts("\r\n");
}

void i3_l0_probe_boot(void)
{
    const uint8_t *bytes;
    uint64_t len;
    noun root, formula, kernel, cause, new_core;

    uart_puts("I3L0 start\r\n");
    cue_bounded_limits_t limits;
    limits.max_input_bytes = cue_i2_limits.max_input_bytes;
    limits.max_atom_bytes = cue_i2_limits.max_atom_bytes;
    limits.max_total_atom_bytes = cue_i2_limits.max_total_atom_bytes;
    limits.max_cache_entries = PROBE_MAX_CACHE_ENTRIES;
    limits.max_work = PROBE_MAX_WORK;
    limits.max_backrefs = PROBE_MAX_BACKREFS;
    limits.max_depth = PROBE_MAX_DEPTH;
    limits.max_nodes = PROBE_MAX_NODES;
    limits.max_cells = PROBE_MAX_CELLS;

    if (!jam_bytes(&bytes, &len)) {
        uart_puts("I3L0 cue status=input cells=0 atoms=0 ticks=0 first_bound=input production_first_bound=cache production_cache=");
        put_u64(I2_CUE_CACHE_ADMITTED);
        uart_puts("\r\n");
        uart_puts("I3L0 terminal=cue-refuse\r\n");
        return;
    }
    uart_puts("I3L0 jam bytes=");
    put_u64(len);
    uart_puts("\r\n");

    /* honk's source jam appends zero padding (mini.jam 817176 vs canonical
     * 817170). Bounded cue allows at most 7 leftover bits, not extra bytes. */
    while (len > 1 && bytes[len - 1] == 0)
        len--;

    uint64_t t0 = cntvct();
    cue_bounded_status_t status =
        cue_bounded_bytes(bytes, len, &limits, HEAP_MODE_PERSIST, &root);
    uint64_t t1 = cntvct();
    print_cue(status, t1 - t0);
    if (status != CUE_BOUNDED_OK) {
        uart_puts("I3L0 terminal=cue-refuse\r\n");
        return;
    }
    noun_tx_commit();

    heap_set_mode(HEAP_MODE_PERSIST);
    {
        noun kick_fol;
        uint64_t kt0, kt1;
        if (!kick_formula(&kick_fol)) {
            uart_puts("I3L0 terminal=formula-fail\r\n");
            return;
        }
        nock_budget_set(0);
        nock_eval_stack_set_limit(0);
        jmp_buf saved;
        __builtin_memcpy(saved, nock_abort, sizeof saved);
        kt0 = cntvct();
        int jumped = setjmp(nock_abort);
        if (jumped != 0) {
            kt1 = cntvct();
            uart_puts("I3L0 kick nock_ops_used=");
            put_u64(nock_ops_used());
            uart_puts(" nock_cells_used=");
            put_u64(nock_cells_used());
            uart_puts(" nock_eval_stack_peak=");
            put_u64(nock_eval_stack_peak());
            uart_puts(" ticks=");
            put_u64(kt1 - kt0);
            uart_puts(" parse=no abort=");
            uart_puts(abort_name(jumped, nock_budget_abort_reason()));
            uart_puts("\r\n");
            nock_budget_finish();
            __builtin_memcpy(nock_abort, saved, sizeof saved);
            uart_puts("I3L0 terminal=kick-fail\r\n");
            return;
        }
        kernel = nock(root, kick_fol);
        kt1 = cntvct();
        uart_puts("I3L0 kick nock_ops_used=");
        put_u64(nock_ops_used());
        uart_puts(" nock_cells_used=");
        put_u64(nock_cells_used());
        uart_puts(" nock_eval_stack_peak=");
        put_u64(nock_eval_stack_peak());
        uart_puts(" ticks=");
        put_u64(kt1 - kt0);
        uart_puts(" parse=");
        uart_puts(noun_is_cell(kernel) ? "yes" : "no");
        uart_puts(" abort=none\r\n");
        nock_budget_finish();
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        if (!noun_is_cell(kernel)) {
            uart_puts("I3L0 terminal=kick-fail\r\n");
            return;
        }
    }

    heap_set_mode(HEAP_MODE_PERSIST);
    if (!slam_formula(&formula)) {
        uart_puts("I3L0 terminal=formula-fail\r\n");
        return;
    }

    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!nest(tas("init"), NOUN_ZERO, &cause)) {
        persist_copy(root);
        uart_puts("I3L0 terminal=cause-fail\r\n");
        return;
    }
    if (slam_poke(kernel, formula, 1, cause, "init", &new_core))
        kernel = new_core;
    else {
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_SCRATCH);
    }

    if (!nest(tas("tick"), direct(5), &cause)) {
        persist_copy(root);
        uart_puts("I3L0 terminal=cause-fail\r\n");
        return;
    }
    (void)slam_poke(kernel, formula, 2, cause, "tick", &new_core);

    persist_copy(root);
    uart_puts("I3L0 terminal=done\r\n");
}
