#include <stddef.h>
#include <stdint.h>

#include "i3_admission.h"
#include "i3_host.h"
#include "i3_l1_probe.h"
#include "nock.h"
#include "noun.h"
#include "uart.h"

/*
 * I3 L1 diagnostic on the I3_HOST image. The host cues, kicks and installs
 * the kernel; this runner drives a plan through i3_host_poke / i3_host_peek.
 * No private cue or slam of the kernel.
 *
 * Plan at I3_PLAN_BASE: [u64 len][jam]. len == 0 → mini R0.
 */
#define SLAM_FORMULA_TEXT "[8 [9 23 0 2] 9 2 10 [6 0 7] 0 2]"

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

static void print_nock_line(const char *kind, const char *name,
                            const i3_host_result_t *r)
{
    uart_puts("I3L1 ");
    uart_puts(kind);
    uart_puts(" name=");
    uart_puts(name);
    uart_puts(" nock_ops_used=");
    put_u64(r->ops);
    uart_puts(" nock_cells_used=");
    put_u64(r->cells);
    uart_puts(" nock_eval_stack_peak=");
    put_u64(r->stack);
    uart_puts(" ticks=");
    put_u64(r->ticks);
    uart_puts(" parse=");
    uart_puts(r->parse ? "yes" : "no");
    uart_puts(" effect_len=");
    put_u64(r->effect_len);
    uart_puts(" abort=");
    uart_puts(i3_host_abort_name(r->jumped, r->abort_reason));
    uart_puts(" i3_ops=");
    put_u64(I3_SLAM_MAX_OPS);
    uart_puts(" i3_cells=");
    put_u64(I3_SLAM_MAX_CELLS);
    uart_puts(" i3_stack=");
    put_u64(I3_SLAM_MAX_STACK);
    uart_puts(" budget=");
    put_u64(r->ops);
    uart_puts("/");
    put_u64(I3_SLAM_MAX_OPS);
    uart_puts(",");
    put_u64(r->cells);
    uart_puts("/");
    put_u64(I3_SLAM_MAX_CELLS);
    uart_puts(",");
    put_u64(r->stack);
    uart_puts("/");
    put_u64(I3_SLAM_MAX_STACK);
    uart_puts(" formula=");
    uart_puts(SLAM_FORMULA_TEXT);
    uart_puts("\r\n");
}

static void print_persist(const char *name, const i3_host_result_t *r)
{
    uart_puts("I3L1 persist_copy name=");
    uart_puts(name);
    uart_puts(" ticks=");
    put_u64(r->persist_ticks);
    uart_puts(" ok=");
    uart_puts(r->persist_ok ? "yes" : "no");
    uart_puts(" copy_map_hwm=");
    put_u64(r->persist_copy_map_hwm);
    uart_puts(" copy_map_capacity=");
    put_u64(r->persist_copy_map_capacity);
    uart_puts("\r\n");
}

static int do_poke(noun cause, const char *name)
{
    i3_host_result_t r;
    int ok;
    heap_set_mode(HEAP_MODE_SCRATCH);
    ok = i3_host_poke(cause, &r);
    if (ok) {
        uart_puts("I3L1 effects name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(r.effects, 0);
        uart_puts("\r\n");
    }
    print_nock_line("poke", name, &r);
    print_jet_hits();
    if (ok)
        print_persist(name, &r);
    heap_scratch_reset();
    return ok;
}

static int do_peek(noun path, const char *name)
{
    i3_host_result_t r;
    int ok;
    heap_set_mode(HEAP_MODE_SCRATCH);
    ok = i3_host_peek(path, &r);
    if (ok) {
        uart_puts("I3L1 peek name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(r.product, 0);
        uart_puts("\r\n");
    }
    print_nock_line("peek", name, &r);
    heap_scratch_reset();
    return ok;
}

static int do_persist(const char *name)
{
    i3_host_result_t r;
    int ok = i3_host_persist(&r);
    print_persist(name, &r);
    return ok;
}

static int run_plan(noun plan)
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
        if (tag_is(tag, "poke")) {
            (void)do_poke(payload, name);
        } else if (tag_is(tag, "peek")) {
            (void)do_peek(payload, name);
        } else if (tag_is(tag, "persist")) {
            (void)do_persist(name);
        } else {
            uart_puts("I3L1 skip tag=");
            print_name(tag);
            uart_puts("\r\n");
        }
    }
    return 1;
}

static int mini_plan(void)
{
    noun cause;
    if (!nest(tas("init"), NOUN_ZERO, &cause))
        return 0;
    if (!do_poke(cause, "init"))
        return 0;
    if (!nest(tas("tick"), direct(5), &cause))
        return 0;
    (void)do_poke(cause, "tick");
    return do_persist("state");
}

static int read_plan(const uint8_t **plan, uint64_t *plan_len)
{
    volatile const uint8_t *base =
        (volatile const uint8_t *)(uintptr_t)I3_PLAN_BASE;
    uint64_t n = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        n |= (uint64_t)base[i] << (8u * i);
    if (n == 0) {
        *plan = 0;
        *plan_len = 0;
        return 1;
    }
    if (n > I3_CUE_MAX_INPUT_BYTES)
        return 0;
    *plan = (const uint8_t *)(uintptr_t)(I3_PLAN_BASE + 8u);
    *plan_len = n;
    return 1;
}

void i3_l1_probe_boot(void)
{
    const uint8_t *plan_bytes;
    uint64_t plan_len;
    noun plan = NOUN_ZERO;

    uart_puts("I3L1 start\r\n");
    if (!i3_host_ready()) {
        uart_puts("I3L1 terminal=host-not-ready\r\n");
        return;
    }
    print_fast();
    print_jet_hits();

    if (!read_plan(&plan_bytes, &plan_len)) {
        uart_puts("I3L1 terminal=plan-cue-refuse\r\n");
        return;
    }
    uart_puts("I3L1 plan_bytes=");
    put_u64(plan_len);
    uart_puts("\r\n");

    if (plan_len == 0) {
        if (!mini_plan()) {
            print_fast();
            uart_puts("I3L1 terminal=mini-fail\r\n");
            return;
        }
    } else {
        if (!i3_host_cue_bytes(plan_bytes, plan_len, &plan)) {
            uart_puts("I3L1 terminal=plan-cue-refuse\r\n");
            return;
        }
        run_plan(plan);
        (void)do_persist("final");
    }
    print_fast();
    uart_puts("I3L1 terminal=done\r\n");
}
