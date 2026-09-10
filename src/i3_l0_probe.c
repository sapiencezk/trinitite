#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_admission_metrics.h"
#include "i3_l0_probe.h"
#include "memory.h"
#include "nock.h"
#include "noun.h"
#include "setjmp.h"
#include "uart.h"

/*
 * I3 L0 measurement probe. Admission constants here are probe-local and do
 * not change production i2_admission_envelope.h.
 *
 * Slam formula is the NockApp shape from nockapp noun/ops.rs:
 *   [8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]  over  [kernel job]
 * Job encoding is I3-PLAN.md §1: [wire [eny our now cause]].
 */
#define POLICY_MAX_OPS 2000000ULL
#define POLICY_MAX_CELLS 128000ULL
#define POLICY_MAX_STACK 1024ULL
#define SLAM_FORMULA_TEXT "[8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]"

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

static int path3(const char *a, const char *b, noun *out)
{
    noun rest;
    if (!nest(tas(b), NOUN_ZERO, &rest))
        return 0;
    return nest(tas(a), rest, out);
}

static int ovum_job(noun cause, noun *out)
{
    /* I3-PLAN.md §1: +poke takes [wire [eny our now cause]]. */
    noun wire, input_xs[4], input;
    if (!path3("poke", "l0", &wire))
        return 0;
    input_xs[0] = direct(0); /* eny */
    input_xs[1] = direct(0); /* our */
    input_xs[2] = direct(0); /* now */
    input_xs[3] = cause;
    if (!tuple(input_xs, 4, &input))
        return 0;
    return nest(wire, input, out);
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
                       uint64_t stack, uint64_t ticks, int parse, uint64_t abort_reason)
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
    uart_puts(" abort=");
    put_u64(abort_reason);
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

static int slam_poke(noun kernel, noun formula, noun cause, const char *name,
                     noun *new_core)
{
    noun job, subject, product;
    uint64_t t0, t1;
    int parse = 0;
    if (!ovum_job(cause, &job) || !nest(kernel, job, &subject)) {
        print_poke(name, 0, 0, 0, 0, 0, 0);
        return 0;
    }
    nock_budget_set(0);
    nock_eval_stack_set_limit(0);
    jmp_buf saved;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    t0 = cntvct();
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        t1 = cntvct();
        print_poke(name, nock_ops_used(), nock_cells_used(),
                   nock_eval_stack_peak(), t1 - t0, 0, nock_budget_abort_reason());
        nock_budget_finish();
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return 0;
    }
    product = nock(subject, formula);
    t1 = cntvct();
    parse = noun_is_cell(product);
    if (parse && new_core) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        *new_core = c->tail;
    }
    print_poke(name, nock_ops_used(), nock_cells_used(),
               nock_eval_stack_peak(), t1 - t0, parse, 0);
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
    limits.max_depth = cue_i2_limits.max_depth;
    limits.max_backrefs = cue_i2_limits.max_backrefs;
    limits.max_cache_entries = cue_i2_limits.max_cache_entries;
    limits.max_atom_bytes = cue_i2_limits.max_atom_bytes;
    limits.max_total_atom_bytes = cue_i2_limits.max_total_atom_bytes;
    limits.max_work = cue_i2_limits.max_work;
    limits.max_nodes = 1200000;
    limits.max_cells = 600000;

    if (!jam_bytes(&bytes, &len)) {
        uart_puts("I3L0 cue status=input cells=0 atoms=0 ticks=0 first_bound=input\r\n");
        uart_puts("I3L0 terminal=cue-refuse\r\n");
        return;
    }
    uart_puts("I3L0 jam bytes=");
    put_u64(len);
    uart_puts("\r\n");

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
    kernel = root;

    heap_set_mode(HEAP_MODE_PERSIST);
    if (!slam_formula(&formula)) {
        uart_puts("I3L0 terminal=formula-fail\r\n");
        return;
    }

    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!nest(tas("init"), NOUN_ZERO, &cause)) {
        uart_puts("I3L0 terminal=cause-fail\r\n");
        return;
    }
    if (slam_poke(kernel, formula, cause, "init", &new_core))
        kernel = new_core;

    if (!nest(tas("tick"), direct(5), &cause)) {
        uart_puts("I3L0 terminal=cause-fail\r\n");
        return;
    }
    (void)slam_poke(kernel, formula, cause, "tick", &new_core);

    persist_copy(root);
    uart_puts("I3L0 terminal=done\r\n");
}
