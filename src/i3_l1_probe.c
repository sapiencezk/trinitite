#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_admission_envelope.h"
#include "i2_admission_metrics.h"
#include "i3_admission.h"
#include "i3_l1_probe.h"
#include "memory.h"
#include "nock.h"
#include "noun.h"
#include "setjmp.h"
#include "uart.h"

/*
 * I3 L1 NockApp host probe. Cues with I3 production limits, honours %fast,
 * slams poke/peek, persists wrapper sample (axis 6) only.
 *
 * Loader at PILL_BASE:
 *   u64 jam_len, u64 plan_len, jam bytes, plan jam bytes.
 * plan_len == 0 → mini R0: %init then [%tick 5], persist sample.
 * plan is a list of [tag name payload]:
 *   %poke name cause
 *   %peek name path
 *   %persist name
 */
#define SLAM_FORMULA_TEXT "[8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]"
#define PEEK_FORMULA_TEXT "[8 [9 22 0 2] 9 2 10 [6 0 7] 0 2]"

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

static const char *abort_name(int jumped, uint64_t reason)
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

static int tag_is(noun n, const char *s)
{
    char buf[32];
    size_t want = 0;
    size_t i;
    while (s[want])
        want++;
    if (!noun_is_atom(n) || cord_to_cstr(n, buf, sizeof buf) != want)
        return 0;
    for (i = 0; i < want; i++) {
        if (buf[i] != s[i])
            return 0;
    }
    return 1;
}

static int jam_pair(const uint8_t **jam, uint64_t *jam_len,
                    const uint8_t **plan, uint64_t *plan_len)
{
    volatile const uint8_t *base = (volatile const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t n0 = 0, n1 = 0;
    uint32_t i;
    for (i = 0; i < 8; i++) {
        n0 |= (uint64_t)base[i] << (8u * i);
        n1 |= (uint64_t)base[8 + i] << (8u * i);
    }
    if (n0 == 0 || n0 > I3_CUE_MAX_INPUT_BYTES)
        return 0;
    if (n1 > I3_CUE_MAX_INPUT_BYTES)
        return 0;
    *jam = (const uint8_t *)(uintptr_t)(PILL_BASE + 16u);
    *jam_len = n0;
    if (n1 == 0) {
        *plan = 0;
        *plan_len = 0;
        return 1;
    }
    *plan = *jam + n0;
    *plan_len = n1;
    return 1;
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

static int path3(const char *a, const char *b, noun *out)
{
    noun rest;
    if (!nest(tas(b), NOUN_ZERO, &rest))
        return 0;
    return nest(tas(a), rest, out);
}

static int ovum_job(uint64_t num, noun cause, noun *out)
{
    noun wire, input_xs[4], input, ovum;
    if (!path3("poke", "l0", &wire))
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

static void print_atom(noun n)
{
    uint32_t i, size;
    if (noun_is_direct(n)) {
        put_u64(direct_val(n));
        return;
    }
    atom_t *at = atom_store_get(indirect_hash(n));
    if (!at || at->size == 0) {
        uart_puts("0");
        return;
    }
    size = (uint32_t)at->size;
    uart_puts("0x");
    {
        int started = 0;
        for (i = size; i-- > 0; ) {
            int shift;
            for (shift = 60; shift >= 0; shift -= 4) {
                uint32_t nib = (uint32_t)((at->limbs[i] >> shift) & 0xF);
                if (!started && nib == 0 && !(i == 0 && shift == 0))
                    continue;
                started = 1;
                uart_putc("0123456789abcdef"[nib]);
            }
        }
        if (!started)
            uart_putc('0');
    }
}

static void print_noun(noun n, int depth)
{
    if (depth > 64) {
        uart_puts("...");
        return;
    }
    if (noun_is_atom(n)) {
        print_atom(n);
        return;
    }
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    uart_puts("[");
    print_noun(c->head, depth + 1);
    uart_puts(" ");
    print_noun(c->tail, depth + 1);
    uart_puts("]");
}

static void print_name(noun n)
{
    char buf[32];
    size_t len = cord_to_cstr(n, buf, sizeof buf);
    if (len == 0) {
        print_atom(n);
        return;
    }
    uint32_t i;
    for (i = 0; i < (uint32_t)len; i++)
        uart_putc(buf[i]);
}

static void print_jet_hits(void)
{
    int i, n = hot_entry_count();
    int any = 0;
    uart_puts("I3L1 jet_hits");
    for (i = 0; i < n; i++) {
        uint64_t hits = hot_entry_hits(i);
        if (hits == 0)
            continue;
        uart_puts(" ");
        print_name(direct(hot_entry_label(i)));
        uart_puts("=");
        put_u64(hits);
        any = 1;
    }
    if (!any)
        uart_puts(" none");
    uart_puts("\r\n");
}

static void print_fast(void)
{
    int i, n;
    uart_puts("I3L1 fast clues=");
    put_u64(fast_clue_count());
    uart_puts(" registered=");
    put_u64((uint64_t)fast_reg_count());
    uart_puts("\r\n");
    if (fast_first_clue_ok()) {
        uart_puts("I3L1 fast_clue noun=");
        print_noun(fast_first_clue(), 0);
        uart_puts("\r\n");
    }
    n = fast_chum_count();
    for (i = 0; i < n; i++) {
        uart_puts("I3L1 fast_chum noun=");
        print_noun(fast_chum_at(i), 0);
        uart_puts("\r\n");
    }
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

static void print_cue(cue_bounded_status_t status, uint64_t ticks)
{
    uint64_t cells = g_i2_admission_metrics.cue_cells_hwm;
    uint64_t nodes = g_i2_admission_metrics.cue_nodes_hwm;
    uint64_t atoms = nodes > cells ? nodes - cells : 0;
    uart_puts("I3L1 cue status=");
    uart_puts(cue_bounded_status_name(status));
    uart_puts(" cells=");
    put_u64(cells);
    uart_puts(" atoms=");
    put_u64(atoms);
    uart_puts(" ticks=");
    put_u64(ticks);
    uart_puts(" first_bound=");
    uart_puts(status == CUE_BOUNDED_OK ? "none" : cue_bounded_status_name(status));
    uart_puts(" m12_cache=");
    put_u64(I2_CUE_CACHE_ADMITTED);
    uart_puts(" i3_cache=");
    put_u64(I3_CUE_CACHE_ADMITTED);
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

static void print_nock_line(const char *kind, const char *name, uint64_t ops,
                            uint64_t cells, uint64_t stack, uint64_t ticks,
                            int parse, uint64_t effect_len, const char *abort)
{
    uart_puts("I3L1 ");
    uart_puts(kind);
    uart_puts(" name=");
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
    uart_puts(" i3_ops=");
    put_u64(I3_SLAM_MAX_OPS);
    uart_puts(" i3_cells=");
    put_u64(I3_SLAM_MAX_CELLS);
    uart_puts(" i3_stack=");
    put_u64(I3_SLAM_MAX_STACK);
    uart_puts(" formula=");
    uart_puts(SLAM_FORMULA_TEXT);
    uart_puts("\r\n");
}

static int install_sample(noun template, noun sample, noun *out)
{
    /* Rebuild [battery [sample context]] in the current heap. */
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

static int persist_sample(noun core, noun *live, const char *name)
{
    noun sample, copy, installed;
    uint64_t t0, t1;
    if (!noun_is_cell(core)) {
        uart_puts("I3L1 persist_copy name=");
        uart_puts(name);
        uart_puts(" ticks=0 ok=no copy_map_hwm=0 copy_map_capacity=");
        put_u64(noun_copy_map_capacity());
        uart_puts("\r\n");
        return 0;
    }
    sample = slot(direct(6), core);
    /* Stay in the current persist semispace so the formula battery (cued
     * once at boot) is not abandoned by a compacting flip. */
    heap_set_mode(HEAP_MODE_PERSIST);
    noun_copy_map_hwm_reset();
    t0 = cntvct();
    int ok = noun_copy_checked(sample, &copy);
    t1 = cntvct();
    if (ok && live && install_sample(core, copy, &installed))
        *live = installed;
    else
        ok = 0;
    uart_puts("I3L1 persist_copy name=");
    uart_puts(name);
    uart_puts(" ticks=");
    put_u64(t1 - t0);
    uart_puts(" ok=");
    uart_puts(ok ? "yes" : "no");
    uart_puts(" copy_map_hwm=");
    put_u64(noun_copy_map_hwm());
    uart_puts(" copy_map_capacity=");
    put_u64(noun_copy_map_capacity());
    uart_puts("\r\n");
    return ok;
}

static uint64_t g_event_num = 1;

static int run_nock(noun subject, noun formula, noun *product)
{
    nock_budget_set(0);
    nock_eval_stack_set_limit(0);
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

static int slam_poke(noun *kernel, noun formula, noun cause, const char *name)
{
    noun job, subject, product;
    uint64_t t0, t1;
    int parse = 0;
    uint64_t effects = 0;
    if (!ovum_job(g_event_num, cause, &job) || !nest(*kernel, job, &subject)) {
        print_nock_line("poke", name, 0, 0, 0, 0, 0, 0, "none");
        return 0;
    }
    t0 = cntvct();
    int jumped = run_nock(subject, formula, &product);
    t1 = cntvct();
    if (jumped != 0) {
        print_nock_line("poke", name, nock_ops_used(), nock_cells_used(),
                        nock_eval_stack_peak(), t1 - t0, 0, 0,
                        abort_name(jumped, nock_budget_abort_reason()));
        nock_budget_finish();
        print_jet_hits();
        return 0;
    }
    parse = noun_is_cell(product);
    if (parse) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(product);
        effects = effect_list_len(c->head);
        uart_puts("I3L1 effects name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(c->head, 0);
        uart_puts("\r\n");
        *kernel = c->tail;
        g_event_num++;
    }
    print_nock_line("poke", name, nock_ops_used(), nock_cells_used(),
                    nock_eval_stack_peak(), t1 - t0, parse, effects, "none");
    nock_budget_finish();
    print_jet_hits();
    if (parse)
        persist_sample(*kernel, kernel, name);
    return parse;
}

static int slam_peek(noun kernel, noun formula, noun path, const char *name)
{
    noun subject, product;
    uint64_t t0, t1;
    if (!nest(kernel, path, &subject)) {
        print_nock_line("peek", name, 0, 0, 0, 0, 0, 0, "none");
        return 0;
    }
    t0 = cntvct();
    int jumped = run_nock(subject, formula, &product);
    t1 = cntvct();
    if (jumped != 0) {
        print_nock_line("peek", name, nock_ops_used(), nock_cells_used(),
                        nock_eval_stack_peak(), t1 - t0, 0, 0,
                        abort_name(jumped, nock_budget_abort_reason()));
        nock_budget_finish();
        return 0;
    }
    uart_puts("I3L1 peek name=");
    uart_puts(name);
    uart_puts(" noun=");
    /* Unwrap (unit (unit *)): [0 [0 value]] → value; 0 → ~ */
    if (noun_is_cell(product)) {
        cell_t *u = (cell_t *)(uintptr_t)cell_ptr(product);
        if (noun_is_atom(u->head) && direct_val(u->head) == 0
            && noun_is_cell(u->tail)) {
            cell_t *v = (cell_t *)(uintptr_t)cell_ptr(u->tail);
            if (noun_is_atom(v->head) && direct_val(v->head) == 0)
                print_noun(v->tail, 0);
            else
                print_noun(product, 0);
        } else {
            print_noun(product, 0);
        }
    } else {
        print_noun(product, 0);
    }
    uart_puts("\r\n");
    print_nock_line("peek", name, nock_ops_used(), nock_cells_used(),
                    nock_eval_stack_peak(), t1 - t0, 1, 0, "none");
    nock_budget_finish();
    return 1;
}

static int run_plan(noun *kernel, noun poke_fol, noun peek_fol, noun plan)
{
    while (noun_is_cell(plan)) {
        cell_t *step_cons = (cell_t *)(uintptr_t)cell_ptr(plan);
        noun step = step_cons->head;
        plan = step_cons->tail;
        if (!noun_is_cell(step))
            continue;
        cell_t *s = (cell_t *)(uintptr_t)cell_ptr(step);
        noun tag = s->head;
        if (!noun_is_cell(s->tail))
            continue;
        cell_t *rest = (cell_t *)(uintptr_t)cell_ptr(s->tail);
        noun name_n = rest->head;
        noun payload = rest->tail;
        char name[32];
        size_t nlen = cord_to_cstr(name_n, name, sizeof name);
        if (nlen == 0)
            __builtin_memcpy(name, "step", 5);
        heap_set_mode(HEAP_MODE_SCRATCH);
        if (tag_is(tag, "poke")) {
            (void)slam_poke(kernel, poke_fol, payload, name);
            heap_scratch_reset();
        } else if (tag_is(tag, "peek")) {
            (void)slam_peek(*kernel, peek_fol, payload, name);
            heap_scratch_reset();
        } else if (tag_is(tag, "persist")) {
            (void)persist_sample(*kernel, kernel, name);
        } else {
            uart_puts("I3L1 skip tag=");
            print_name(tag);
            uart_puts("\r\n");
        }
    }
    return 1;
}

static int mini_plan(noun *kernel, noun poke_fol)
{
    noun cause;
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!nest(tas("init"), NOUN_ZERO, &cause))
        return 0;
    if (!slam_poke(kernel, poke_fol, cause, "init")) {
        heap_scratch_reset();
        return 0;
    }
    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!nest(tas("tick"), direct(5), &cause))
        return 0;
    (void)slam_poke(kernel, poke_fol, cause, "tick");
    heap_scratch_reset();
    return persist_sample(*kernel, kernel, "state");
}

void i3_l1_probe_boot(void)
{
    const uint8_t *jam, *plan_bytes;
    uint64_t jam_len, plan_len;
    noun root, formula, peek_fol, kernel, plan = NOUN_ZERO;

    uart_puts("I3L1 start\r\n");
    fast_reset();
    cue_bounded_limits_t limits = i3_limits();

    if (!jam_pair(&jam, &jam_len, &plan_bytes, &plan_len)) {
        uart_puts("I3L1 cue status=input cells=0 atoms=0 ticks=0 first_bound=input\r\n");
        uart_puts("I3L1 terminal=cue-refuse\r\n");
        return;
    }
    uart_puts("I3L1 jam bytes=");
    put_u64(jam_len);
    uart_puts(" plan_bytes=");
    put_u64(plan_len);
    uart_puts("\r\n");

    while (jam_len > 1 && jam[jam_len - 1] == 0)
        jam_len--;

    uint64_t t0 = cntvct();
    cue_bounded_status_t status =
        cue_bounded_bytes(jam, jam_len, &limits, HEAP_MODE_PERSIST, &root);
    uint64_t t1 = cntvct();
    print_cue(status, t1 - t0);
    if (status != CUE_BOUNDED_OK) {
        uart_puts("I3L1 terminal=cue-refuse\r\n");
        return;
    }
    noun_tx_commit();

    if (plan_len > 0) {
        while (plan_len > 1 && plan_bytes[plan_len - 1] == 0)
            plan_len--;
        status = cue_bounded_bytes(plan_bytes, plan_len, &limits,
                                   HEAP_MODE_PERSIST, &plan);
        if (status != CUE_BOUNDED_OK) {
            uart_puts("I3L1 terminal=plan-cue-refuse\r\n");
            return;
        }
        noun_tx_commit();
    }

    heap_set_mode(HEAP_MODE_PERSIST);
    {
        noun kick_fol;
        if (!kick_formula(&kick_fol)) {
            uart_puts("I3L1 terminal=formula-fail\r\n");
            return;
        }
        uint64_t kt0 = cntvct();
        int jumped = run_nock(root, kick_fol, &kernel);
        uint64_t kt1 = cntvct();
        if (jumped != 0) {
            uart_puts("I3L1 kick nock_ops_used=");
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
            uart_puts("I3L1 terminal=kick-fail\r\n");
            return;
        }
        uart_puts("I3L1 kick nock_ops_used=");
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
        print_fast();
        print_jet_hits();
        if (!noun_is_cell(kernel)) {
            uart_puts("I3L1 terminal=kick-fail\r\n");
            return;
        }
    }

    heap_set_mode(HEAP_MODE_PERSIST);
    if (!slam_formula(&formula) || !peek_formula(&peek_fol)) {
        uart_puts("I3L1 terminal=formula-fail\r\n");
        return;
    }

    if (plan_len == 0) {
        if (!mini_plan(&kernel, formula)) {
            print_fast();
            uart_puts("I3L1 terminal=mini-fail\r\n");
            return;
        }
    } else {
        run_plan(&kernel, formula, peek_fol, plan);
        persist_sample(kernel, &kernel, "final");
    }
    print_fast();
    uart_puts("I3L1 terminal=done\r\n");
}
