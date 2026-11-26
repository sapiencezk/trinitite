#include <stddef.h>
#include <stdint.h>

#include "lite_admission.h"
#include "lite_host.h"
#include "lite_probe.h"
#include "nock.h"
#include "noun.h"
#include "setjmp.h"
#include "uart.h"

/*
 * The diagnostic plan driver (LITE_PROBE). The host cues, kicks and installs
 * the kernel; this runner drives a plan through lite_host_poke / lite_host_peek.
 * No private cue or slam of the kernel.
 *
 * Plan at LITE_PLAN_BASE: [u64 len][jam]. len == 0 → the mini kernel's smoke.
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

static uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static int edit_sample(noun core, noun sample, noun *out)
{
    cell_t *c, *payload;
    noun new_payload;
    if (!noun_is_cell(core))
        return 0;
    c = (cell_t *)(uintptr_t)cell_ptr(core);
    if (!noun_is_cell(c->tail))
        return 0;
    payload = (cell_t *)(uintptr_t)cell_ptr(c->tail);
    if (!nest(sample, payload->tail, &new_payload))
        return 0;
    return nest(c->head, new_payload, out);
}

static void print_unjetted(void)
{
#if defined(LITE_UNJETTED)
    uart_puts("LITE1 unjetted=yes\r\n");
#else
    uart_puts("LITE1 unjetted=no\r\n");
#endif
}

static void print_pulled(void)
{
    int i, n = fast_core_count();
    int hot = hot_entry_count();
    uart_puts("LITE1 pulled count=");
    put_u64((uint64_t)n);
    uart_puts(" hot=");
    put_u64((uint64_t)hot);
    uart_puts("\r\n");
    for (i = 0; i < n; i++) {
        uart_puts("LITE1 pulled_label noun=");
        uart_puts(fast_core_name(i));
        uart_puts("\r\n");
    }
    for (i = 0; i < hot; i++) {
        int j, have = 0;
        for (j = 0; j < n && !have; j++)
            have = fast_core_name(j) == hot_entry_name(i);
        if (have)
            continue;
        uart_puts("LITE1 missing_label noun=");
        uart_puts(hot_entry_name(i));
        uart_puts("\r\n");
    }
}

static void print_jet_hits(void)
{
    int i, n = hot_entry_count();
    int any = 0;
    uart_puts("LITE1 jet_hits");
    for (i = 0; i < n; i++) {
        uint64_t hits = hot_entry_hits(i);
        if (hits == 0)
            continue;
        uart_puts(" ");
        uart_puts(hot_entry_name(i));
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
    uart_puts("LITE1 fast clues=");
    put_u64(fast_clue_count());
    uart_puts(" registered=");
    put_u64((uint64_t)fast_reg_count());
    uart_puts(" cold=");
    put_u64((uint64_t)fast_cold_count());
    uart_puts(" cold_dropped=");
    put_u64(fast_cold_dropped());
    uart_puts(" invalidations=");
    put_u64(fast_invalidations());
    uart_puts(" dups=");
    put_u64(fast_dups());
    uart_puts("\r\n");
    if (fast_first_clue_ok()) {
        uart_puts("LITE1 fast_clue noun=");
        print_noun(fast_first_clue(), 0);
        uart_puts("\r\n");
    }
    n = fast_cold_count();
    for (i = 0; i < n; i++) {
        noun ch; int par; uint64_t ax;
        if (!fast_cold_entry(i, &ch, &par, &ax))
            continue;
        uart_puts("LITE1 fast_cold i=");
        put_u64((uint64_t)i);
        uart_puts(" parent=");
        if (par < 0) uart_puts("root"); else put_u64((uint64_t)par);
        uart_puts(" axis=");
        put_u64(ax);
        uart_puts(" chum=");
        print_noun(ch, 0);
        uart_puts("\r\n");
    }
    n = fast_chum_count();
    for (i = 0; i < n; i++) {
        uart_puts("LITE1 fast_chum noun=");
        print_noun(fast_chum_at(i), 0);
        uart_puts("\r\n");
    }
}

static void print_nock_line(const char *kind, const char *name,
                            const lite_host_result_t *r)
{
    uart_puts("LITE1 ");
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
    uart_puts(lite_host_abort_name(r->jumped, r->abort_reason));
    uart_puts(" lite_ops=");
    put_u64(LITE_SLAM_MAX_OPS);
    uart_puts(" lite_cells=");
    put_u64(LITE_SLAM_MAX_CELLS);
    uart_puts(" lite_stack=");
    put_u64(LITE_SLAM_MAX_STACK);
    uart_puts(" budget=");
    put_u64(r->ops);
    uart_puts("/");
    put_u64(LITE_SLAM_MAX_OPS);
    uart_puts(",");
    put_u64(r->cells);
    uart_puts("/");
    put_u64(LITE_SLAM_MAX_CELLS);
    uart_puts(",");
    put_u64(r->stack);
    uart_puts("/");
    put_u64(LITE_SLAM_MAX_STACK);
    uart_puts(" formula=");
    uart_puts(SLAM_FORMULA_TEXT);
    uart_puts("\r\n");
}

static void print_persist(const char *name, const lite_host_result_t *r)
{
    uart_puts("LITE1 persist_copy name=");
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

static void do_jetcheck(noun payload, const char *name);

static int do_poke_with(noun cause, const char *name, noun jetcheck, int check)
{
    lite_host_result_t r;
    int ok;
    heap_set_mode(HEAP_MODE_SCRATCH);
    fast_epoch_bump();
    ok = lite_host_poke(cause, &r);
    if (ok) {
        uart_puts("LITE1 effects name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(r.effects, 0);
        uart_puts("\r\n");
    }
    print_nock_line("poke", name, &r);
    print_jet_hits();
    if (ok)
        print_persist(name, &r);
    if (check)
        do_jetcheck(jetcheck, name);   /* before the scratch reset: cores live */
    heap_scratch_reset();
#if defined(LITE_COMPACT)
    lite_host_handoff(); /* row 221: effects handed off, scratch reset */
#endif
    return ok;
}

static int do_poke(noun cause, const char *name)
{
    return do_poke_with(cause, name, NOUN_ZERO, 0);
}

static void fill_call_result(lite_host_result_t *r, int jumped, uint64_t ticks)
{
    r->parse = jumped == 0;
    r->jumped = jumped;
    r->ops = nock_ops_used();
    r->cells = nock_cells_used();
    r->stack = nock_eval_stack_peak();
    r->ticks = ticks;
    r->effect_len = 0;
    r->abort_reason = nock_budget_abort_reason();
    r->effects = NOUN_ZERO;
    r->product = NOUN_ZERO;
    r->persist_ok = 0;
    r->persist_ticks = 0;
    r->persist_copy_map_hwm = 0;
    r->persist_copy_map_capacity = 0;
}

/* [9 2 0 1] kicks the arm through jet dispatch. raw: [2 [0 1] 0 2] runs
 * the same arm as Nock, so the arm's own jet is skipped (jet parity); the
 * jets the arm calls inside stay on. */
static int call_formula(int raw, noun *fol)
{
    noun a, b;
    if (!raw)
        return nest(direct(0), direct(1), fol) && nest(direct(2), *fol, fol)
            && nest(direct(9), *fol, fol);
    return nest(direct(0), direct(1), &a) && nest(direct(0), direct(2), &b)
        && nest(a, b, fol) && nest(direct(2), *fol, fol);
}

static int do_call(noun label, noun sample, const char *name, int raw)
{
    lite_host_result_t r;
    noun gate, edited, product, fol;
    jmp_buf saved;
    uint64_t t0, t1;
    int jumped;
    gate = fast_core_lookup(label);
    if (gate == NOUN_ZERO || !noun_is_cell(gate)) {
        uart_puts("LITE1 call name=");
        uart_puts(name);
        uart_puts(" missing=yes abort=none\r\n");
        return 0;
    }
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!edit_sample(gate, sample, &edited)
        || !call_formula(raw, &fol)) {
        uart_puts("LITE1 call name=");
        uart_puts(name);
        uart_puts(" missing=yes abort=none\r\n");
        heap_scratch_reset();
        return 0;
    }
    /* call-nock is a parity diagnostic: 16x ops, and cells up to what the
     * 32 MiB scratch holds. The stack limit stays (it guards the C stack). */
    nock_budget_set_limits(raw ? LITE_SLAM_MAX_OPS * 16 : LITE_SLAM_MAX_OPS,
                           raw ? 1300000ULL : LITE_SLAM_MAX_CELLS);
    nock_eval_stack_set_limit(LITE_SLAM_MAX_STACK);
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    t0 = cntvct();
    jumped = setjmp(nock_abort);
    if (jumped != 0) {
        t1 = cntvct();
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        fill_call_result(&r, jumped, t1 - t0);
        print_nock_line("call", name, &r);
        print_jet_hits();
        heap_scratch_reset();
        nock_budget_finish();
        return 0;
    }
    product = nock(edited, fol);
    t1 = cntvct();
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    fill_call_result(&r, 0, t1 - t0);
    r.product = product;
    uart_puts("LITE1 call name=");
    uart_puts(name);
    uart_puts(" noun=");
    print_noun(product, 0);
    uart_puts("\r\n");
    print_nock_line("call", name, &r);
    print_jet_hits();
    heap_scratch_reset();
    nock_budget_finish();
    return 1;
}

/*
 * jetcheck: every registered %fast jet against the Hoon it replaces.
 * payload = list of [label (list sample)]. For each registered entry whose
 * label has vectors, slam the registered core on each sample twice: once
 * with dispatch as normal (the jet) and once with that entry suppressed
 * (its own Nock battery; other jets stay on). Products must be equal; both
 * crashing counts as equal; a budget abort on either side is inconclusive.
 */
#define JC_OK 0
#define JC_CRASH 1
#define JC_BUDGET 2

/* The jet side runs under the slam caps. The Hoon side is the reference,
 * not a production path: it gets call-nock's diagnostic cell bound and 64x
 * the ops (++jam and ++shax as plain Hoon take millions of ops). */
#define JC_HOON_OPS (LITE_SLAM_MAX_OPS * 64ULL)
#define JC_HOON_CELLS 1300000ULL

static uint64_t g_jc_reason;   /* the last budget abort's reason */

static int jc_slam(noun core, noun sample, noun *out, int hoon)
{
    noun edited, fol, product;
    jmp_buf saved;
    int jumped;
    if (!edit_sample(core, sample, &edited)
        || !nest(direct(0), direct(1), &fol)
        || !nest(direct(2), fol, &fol)
        || !nest(direct(9), fol, &fol))
        return JC_CRASH;
    if (hoon)
        nock_budget_set_limits(JC_HOON_OPS, JC_HOON_CELLS);
    else
        nock_budget_set_limits(LITE_SLAM_MAX_OPS, LITE_SLAM_MAX_CELLS);
    nock_eval_stack_set_limit(LITE_SLAM_MAX_STACK);
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    jumped = setjmp(nock_abort);
    if (jumped != 0) {
        int budget = nock_budget_abort_reason() != 0;
        g_jc_reason = nock_budget_abort_reason();
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        nock_budget_finish();
        return budget ? JC_BUDGET : JC_CRASH;
    }
    product = nock(edited, fol);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    nock_budget_finish();
    *out = product;
    return JC_OK;
}

static void jc_print(int st, noun n, uint64_t reason)
{
    if (st == JC_OK) {
        print_noun(n, 0);
    } else if (st == JC_CRASH) {
        uart_puts("crash");
    } else {
        /* nock.c's reasons: 1 ops, 2 wall, 3 cells, 4 stack */
        uart_puts("budget:");
        put_u64(reason);
    }
}

static noun jc_vectors(noun payload, const char *label)
{
    while (noun_is_cell(payload)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(payload);
        payload = c->tail;
        if (!noun_is_cell(c->head))
            continue;
        cell_t *e = (cell_t *)(uintptr_t)cell_ptr(c->head);
        if (hot_name_is(e->head, label))
            return e->tail;
    }
    return NOUN_ZERO;
}

static void do_jetcheck(noun payload, const char *name)
{
    int i, n = fast_reg_count();
    uint64_t checked = 0, match = 0, mismatch = 0, inconclusive = 0, bare = 0;
    for (i = 0; i < n; i++) {
        const char *label;
        noun core, vec;
        if (!fast_reg_entry(i, &label, &core)) {
            uart_puts("LITE1 jetcheck_stale entry=");
            put_u64((uint64_t)i);
            uart_puts("\r\n");
            continue;
        }
        vec = jc_vectors(payload, label);
        if (!noun_is_cell(vec)) {
            bare++;
            uart_puts("LITE1 jetcheck_unvectored label=");
            uart_puts(label);
            uart_puts("\r\n");
            continue;
        }
        while (noun_is_cell(vec)) {
            cell_t *v = (cell_t *)(uintptr_t)cell_ptr(vec);
            noun jet_p = NOUN_ZERO, hoon_p = NOUN_ZERO;
            uint64_t rj, rh;
            int sj, sh;
            const char *verdict;
            vec = v->tail;
            uint64_t mark;
            heap_set_mode(HEAP_MODE_SCRATCH);
            mark = heap_scratch_mark();
            fast_suppress(-1);
            sj = jc_slam(core, v->head, &jet_p, 0);
            rj = g_jc_reason;
            fast_suppress(i);
            sh = jc_slam(core, v->head, &hoon_p, 1);
            rh = g_jc_reason;
            fast_suppress(-1);
            checked++;
            if (sj == JC_BUDGET || sh == JC_BUDGET) {
                inconclusive++;
                verdict = "inconclusive";
            } else if (sj == sh && (sj == JC_CRASH || noun_eq(jet_p, hoon_p))) {
                match++;
                verdict = "match";
            } else {
                mismatch++;
                verdict = "mismatch";
            }
            uart_puts("LITE1 jetcheck name=");
            uart_puts(name);
            uart_puts(" label=");
            uart_puts(label);
            uart_puts(" entry=");
            put_u64((uint64_t)i);
            uart_puts(" verdict=");
            uart_puts(verdict);
            uart_puts(" sample=");
            print_noun(v->head, 0);
            uart_puts(" jet=");
            jc_print(sj, jet_p, rj);
            uart_puts(" hoon=");
            jc_print(sh, hoon_p, rh);
            uart_puts("\r\n");
            (void)heap_scratch_rewind(mark);
        }
    }
    uart_puts("LITE1 jetcheck_summary name=");
    uart_puts(name);
    uart_puts(" entries=");
    put_u64((uint64_t)n);
    uart_puts(" checked=");
    put_u64(checked);
    uart_puts(" match=");
    put_u64(match);
    uart_puts(" mismatch=");
    put_u64(mismatch);
    uart_puts(" inconclusive=");
    put_u64(inconclusive);
    uart_puts(" unvectored=");
    put_u64(bare);
    uart_puts("\r\n");
}

static int do_peek(noun path, const char *name)
{
    lite_host_result_t r;
    int ok;
    heap_set_mode(HEAP_MODE_SCRATCH);
    ok = lite_host_peek(path, &r);
    if (ok) {
        uart_puts("LITE1 peek name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(r.product, 0);
        uart_puts("\r\n");
    }
    print_nock_line("peek", name, &r);
    heap_scratch_reset();
    return ok;
}

/* Row 199: the state hash, its event number and its cost. The digest (a Tip5
 * digest since row 328, 80 hex digits) runs in scratch; persist_free_delta
 * shows whether it touched the persist heap. */
static int do_state_hash(const char *name)
{
    static const char hexd[] = "0123456789abcdef";
    lite_host_result_t r;
    uint8_t hash[LITE_DIGEST_BYTES];
    uint64_t event = 0, scratch0, free0;
    uint32_t i;
    int ok;
    heap_set_mode(HEAP_MODE_SCRATCH);
    scratch0 = heap_cells_used(HEAP_MODE_SCRATCH);
    free0 = heap_persist_free_cells();
    ok = lite_host_state_hash(&event, hash, &r);
    uart_puts("LITE1 state-hash name=");
    uart_puts(name);
    if (ok) {
        uart_puts(" event=");
        put_u64(event);
        uart_puts(" hash=");
        for (i = 0; i < LITE_DIGEST_BYTES; i++) {
            uart_putc(hexd[hash[i] >> 4]);
            uart_putc(hexd[hash[i] & 15u]);
        }
    } else {
        uart_puts(" refused=yes");
    }
    uart_puts(" scratch_cells=");
    put_u64(heap_cells_used(HEAP_MODE_SCRATCH) - scratch0);
    uart_puts(" persist_free_delta=");
    put_u64(free0 - heap_persist_free_cells());
    uart_puts("\r\n");
    print_nock_line("state-hash", name, &r);
    heap_scratch_reset();
    return ok;
}

static int do_persist(const char *name)
{
    lite_host_result_t r;
    int ok = lite_host_persist(&r);
    print_persist(name, &r);
    return ok;
}

static int read_app(const uint8_t **jam, uint64_t *jam_len, const char **hex)
{
    volatile const uint8_t *base =
        (volatile const uint8_t *)(uintptr_t)LITE_APP_BASE;
    uint64_t n = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        n |= (uint64_t)base[i] << (8u * i);
    if (n == 0 || n > LITE_CUE_MAX_INPUT_BYTES)
        return 0;
    *jam_len = n;
    *hex = (const char *)(uintptr_t)(LITE_APP_BASE + 8u);
    *jam = (const uint8_t *)(uintptr_t)(LITE_APP_BASE + 8u + LITE_APP_SHA256_HEX_LEN);
    return 1;
}

static int do_load_app(const char *name)
{
    lite_host_result_t r;
    const uint8_t *jam;
    const char *hex;
    uint64_t jam_len;
    int ok;
    if (!read_app(&jam, &jam_len, &hex)) {
        uart_puts("LITE1 load-app name=");
        uart_puts(name);
        uart_puts(" missing=yes abort=none\r\n");
        return 0;
    }
    heap_set_mode(HEAP_MODE_SCRATCH);
    ok = lite_host_load_app(jam, jam_len, hex, &r);
    if (ok) {
        uart_puts("LITE1 effects name=");
        uart_puts(name);
        uart_puts(" noun=");
        print_noun(r.effects, 0);
        uart_puts("\r\n");
    }
    print_nock_line("load-app", name, &r);
    print_jet_hits();
    if (ok)
        print_persist(name, &r);
    heap_scratch_reset();
#if defined(LITE_COMPACT)
    lite_host_handoff(); /* row 221: effects handed off, scratch reset */
#endif
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
        } else if (tag_is(tag, "state-hash")) {
            (void)do_state_hash(name);
        } else if (tag_is(tag, "persist")) {
            (void)do_persist(name);
        } else if (tag_is(tag, "call")) {
            if (noun_is_cell(payload)) {
                cell_t *p = (cell_t *)(uintptr_t)cell_ptr(payload);
                (void)do_call(p->head, p->tail, name, 0);
            }
        } else if (tag_is(tag, "call-nock")) {
            if (noun_is_cell(payload)) {
                cell_t *p = (cell_t *)(uintptr_t)cell_ptr(payload);
                (void)do_call(p->head, p->tail, name, 1);
            }
        } else if (tag_is(tag, "poke-without")) {
            /* [labels cause]: the poke with those hot entries as Nock */
            if (noun_is_cell(payload)) {
                cell_t *p = (cell_t *)(uintptr_t)cell_ptr(payload);
                uint64_t mask = 0;
                noun l = p->head;
                int ok = 1;
                while (noun_is_cell(l)) {
                    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(l);
                    int h = hot_index_of(c->head);
                    if (h < 0)
                        ok = 0;
                    else
                        mask |= 1ULL << h;
                    l = c->tail;
                }
                if (!ok) {
                    uart_puts("LITE1 without name=");
                    uart_puts(name);
                    uart_puts(" unknown-label=yes\r\n");
                } else {
                    fast_suppress_hot(mask);
                    (void)do_poke(p->tail, name);
                    fast_suppress_hot(0);
                }
            }
        } else if (tag_is(tag, "poke-jetcheck")) {
            if (noun_is_cell(payload)) {
                cell_t *p = (cell_t *)(uintptr_t)cell_ptr(payload);
                (void)do_poke_with(p->head, name, p->tail, 1);
            }
        } else if (tag_is(tag, "load-app")) {
            (void)do_load_app(name);
        } else {
            uart_puts("LITE1 skip tag=");
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

static int plan_has_call(noun plan)
{
    while (noun_is_cell(plan)) {
        cell_t *cons = (cell_t *)(uintptr_t)cell_ptr(plan);
        noun step = cons->head;
        plan = cons->tail;
        if (!noun_is_cell(step))
            continue;
        cell_t *s = (cell_t *)(uintptr_t)cell_ptr(step);
        if (tag_is(s->head, "call") || tag_is(s->head, "call-nock"))
            return 1;
    }
    return 0;
}

static int read_plan(const uint8_t **plan, uint64_t *plan_len)
{
    volatile const uint8_t *base =
        (volatile const uint8_t *)(uintptr_t)LITE_PLAN_BASE;
    uint64_t n = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        n |= (uint64_t)base[i] << (8u * i);
    if (n == 0) {
        *plan = 0;
        *plan_len = 0;
        return 1;
    }
    if (n > LITE_CUE_MAX_INPUT_BYTES)
        return 0;
    *plan = (const uint8_t *)(uintptr_t)(LITE_PLAN_BASE + 8u);
    *plan_len = n;
    return 1;
}

void lite_probe_boot(void)
{
    const uint8_t *plan_bytes;
    uint64_t plan_len;
    noun plan = NOUN_ZERO;

    uart_puts("LITE1 start\r\n");
    print_unjetted();
    if (!lite_host_ready()) {
        uart_puts("LITE1 terminal=host-not-ready\r\n");
        return;
    }
    print_fast();
    print_jet_hits();

    if (!read_plan(&plan_bytes, &plan_len)) {
        uart_puts("LITE1 terminal=plan-cue-refuse\r\n");
        return;
    }
    uart_puts("LITE1 plan_bytes=");
    put_u64(plan_len);
    uart_puts("\r\n");
#if defined(LITE_PERSIST_HEADROOM_CELLS)
    uint64_t plan_cells0 = heap_cells_used(HEAP_MODE_PERSIST);
#endif
    if (plan_len != 0) {
#if defined(LITE_COMPACT)
        /* Row 221: the plan is test input; a persist flip would drop it, so
         * it is cued into the bottom of scratch, which every reset keeps,
         * and it is a harness root of the atom store rebuild. */
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_SCRATCH);
        if (!lite_host_cue_bytes_scratch(plan_bytes, plan_len, &plan)) {
            uart_puts("LITE1 terminal=plan-cue-refuse\r\n");
            return;
        }
        heap_scratch_floor_set();
        lite_host_harness_root(plan);
#else
        heap_set_mode(HEAP_MODE_PERSIST);
        if (!lite_host_cue_bytes(plan_bytes, plan_len, &plan)) {
            uart_puts("LITE1 terminal=plan-cue-refuse\r\n");
            return;
        }
#endif
    }
#if defined(LITE_PERSIST_HEADROOM_CELLS)
    /* The plan is test input, not node state: move the cap past it, and
     * only by its size, so replay already done this boot still counts
     * against H (a write boot after replay must fit what the next boot
     * replays). Re-arming here gave live steps a fresh H after replay. */
    heap_persist_cap_extend(heap_cells_used(HEAP_MODE_PERSIST) - plan_cells0);
#endif

    if (plan_has_call(plan)) {
        heap_set_mode(HEAP_MODE_PERSIST);
        (void)fast_pull_hot();
        print_pulled();
        print_fast();
    }

    if (plan_len == 0) {
        if (!mini_plan()) {
            print_fast();
            uart_puts("LITE1 terminal=mini-fail\r\n");
            return;
        }
    } else {
        run_plan(plan);
        (void)do_persist("final");
    }
    print_fast();
    uart_puts("LITE1 terminal=done\r\n");
}
