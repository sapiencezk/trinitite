#include <stdint.h>
#include "noun.h"
#include "nock.h"
#include "bignum.h"
#include "uart.h"
#include "setjmp.h"
#include "forth.h"
#if defined(M38_D8_WAVE_B_B0)
#include "m38_resource_b0_observability.h"
#endif

/* ── Crash recovery point ────────────────────────────────────────────────── */

jmp_buf nock_abort;   /* established in QUIT's restart path */

/* ── Crash ───────────────────────────────────────────────────────────────── */

void nock_crash(const char *msg) {
    uart_puts("\r\nnock crash: ");
    uart_puts(msg);
    uart_puts("\r\n");
    longjmp(nock_abort, NOCK_ABORT_CRASH);   /* unwind to QUIT / kernel */
}

/* ── Slam op budget (WP2) ────────────────────────────────────────────────── */

static uint64_t g_budget_max;          /* 0 = unlimited */
static uint64_t g_ops_used;
static uint64_t g_cell_budget_max;     /* 0 = unlimited */
static uint64_t g_cells_used;
static uint64_t g_budget_abort_reason;
static int (*g_wall_check)(void);
static uint64_t g_eval_stack_current;
static uint64_t g_eval_stack_peak;
#define NOCK_EVALUATOR_STACK_LIMIT 1024ULL
static uint64_t g_eval_stack_limit = NOCK_EVALUATOR_STACK_LIMIT;
static wilt_t g_eval_wild[NOCK_EVALUATOR_STACK_LIMIT];

void nock_budget_set(uint64_t max_ops)
{
    nock_budget_set_limits(max_ops, 0);
}

void nock_budget_set_limits(uint64_t max_ops, uint64_t max_cells)
{
    g_budget_max = max_ops;
    g_cell_budget_max = max_cells;
    g_ops_used = 0;
    g_cells_used = 0;
    g_budget_abort_reason = 0;
    g_eval_stack_current = 0;
    g_eval_stack_peak = 0;
    g_eval_stack_limit = NOCK_EVALUATOR_STACK_LIMIT;
}

void nock_budget_finish(void)
{
    g_budget_max = 0;
    g_cell_budget_max = 0;
    g_eval_stack_current = 0;
    g_eval_stack_limit = NOCK_EVALUATOR_STACK_LIMIT;
}

#if defined(M38_D8_WAVE_B_B0)
void nock_b0_metrics_reset(void)
{
    g_ops_used = 0;
    g_cells_used = 0;
    g_budget_abort_reason = 0;
    g_eval_stack_current = 0;
    g_eval_stack_peak = 0;
}
#endif

uint64_t nock_budget_get(void)
{
    return g_budget_max;
}

uint64_t nock_ops_used(void)
{
    return g_ops_used;
}

uint64_t nock_cells_used(void)
{
    return g_cells_used;
}

uint64_t nock_budget_abort_reason(void)
{
    return g_budget_abort_reason;
}

uint64_t nock_eval_stack_peak(void)
{
    return g_eval_stack_peak;
}

void nock_eval_stack_set_limit(uint64_t limit)
{
    g_eval_stack_current = 0;
    g_eval_stack_peak = 0;
    g_eval_stack_limit = limit == 0 ? NOCK_EVALUATOR_STACK_LIMIT : limit;
}

void nock_wall_check_set(int (*fn)(void))
{
    g_wall_check = fn;
}

void nock_budget_tick(void)
{
    /* Allow exactly max_ops entries: abort when the next would exceed. */
    if (g_budget_max != 0 && g_ops_used >= g_budget_max) {
        g_budget_abort_reason = 1;
        longjmp(nock_abort, NOCK_ABORT_BUDGET);
    }
    g_ops_used++;
    /* Cooperative wall deadline: poll every 256 ops when armed */
    if (g_wall_check && (g_ops_used & 0xFFu) == 0 && g_wall_check()) {
        g_budget_abort_reason = 2;
        longjmp(nock_abort, NOCK_ABORT_BUDGET);
    }
}

static noun nock_alloc_cell(noun head, noun tail)
{
    if (g_cell_budget_max != 0 && g_cells_used >= g_cell_budget_max) {
        g_budget_abort_reason = 3;
        longjmp(nock_abort, NOCK_ABORT_BUDGET);
    }
    g_cells_used++;
    return alloc_cell(head, tail);
}

#ifdef M8_EVIDENCE
uint64_t nock_cell_budget_selftest(void)
{
    volatile uint64_t failures = 0;
    jmp_buf saved;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return UINT64_MAX;
    noun constant = alloc_cell(direct(1), direct(0));
    noun one_cell = alloc_cell(constant, constant);
    noun two_cells = alloc_cell(one_cell, constant);

    nock_budget_set_limits(64, 1);
    noun exact = nock(NOUN_ZERO, one_cell);
    if (!noun_is_cell(exact) || nock_cells_used() != 1)
        failures |= 1u;
    nock_budget_finish();

    int jumped = setjmp(nock_abort);
    if (jumped == 0) {
        nock_budget_set_limits(64, 1);
        (void)nock(NOUN_ZERO, two_cells);
        failures |= 2u;
    } else if (jumped != NOCK_ABORT_BUDGET
               || nock_budget_abort_reason() != 3
               || nock_cells_used() != 1) {
        failures |= 4u;
    }
    nock_budget_finish();

    /* Exercise the admitted selector-3 edge itself, not only a toy N/N+1
     * formula: exactly 20,000 wrapper allocations succeed and allocation
     * 20,001 aborts before touching the heap. */
    jumped = setjmp(nock_abort);
    if (jumped == 0) {
        noun cells = NOUN_ZERO;
        nock_budget_set_limits(0, 20000);
        for (uint64_t i = 0; i < 20000; i++)
            cells = nock_alloc_cell(direct(i & 1u), cells);
        if (!noun_is_cell(cells) || nock_cells_used() != 20000)
            failures |= 8u;
    } else {
        failures |= 16u;
    }
    nock_budget_finish();

    jumped = setjmp(nock_abort);
    if (jumped == 0) {
        nock_budget_set_limits(0, 20000);
        for (uint64_t i = 0; i <= 20000; i++)
            (void)nock_alloc_cell(NOUN_ZERO, NOUN_ZERO);
        failures |= 32u;
    } else if (jumped != NOCK_ABORT_BUDGET
               || nock_budget_abort_reason() != 3
               || nock_cells_used() != 20000) {
        failures |= 64u;
    }
    nock_budget_finish();
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return failures;
}
#endif

/* ── Noun printer (%slog, %xray) ─────────────────────────────────────────── */

static void uart_hex64(uint64_t v) {
    char buf[17];
    buf[16] = '\0';
    for (int i = 15; i >= 0; i--) {
        buf[i] = "0123456789abcdef"[v & 0xF];
        v >>= 4;
    }
    uart_puts(buf);
}

#define NOUN_PRINT_DEPTH_MAX 12

static void noun_print(noun n, int depth) {
    if (depth > NOUN_PRINT_DEPTH_MAX) { uart_puts("..."); return; }
    if (noun_is_atom(n)) {
        if (noun_is_direct(n))
            uart_hex64(direct_val(n));
        else
            uart_puts("<bignum>");
        return;
    }
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    uart_puts("[");
    noun_print(c->head, depth + 1);
    uart_puts(" ");
    noun_print(c->tail, depth + 1);
    uart_puts("]");
}

/* ── Hint tag constants (Urbit cord encoding: LSB = first char) ──────────── */

#define HINT_WILD  0x646C6977ULL   /* %wild */
#define HINT_FAST  0x74736166ULL   /* %fast */
#define HINT_SLOG  0x676F6C73ULL   /* %slog */
#define HINT_XRAY  0x79617278ULL   /* %xray */
#define HINT_MEAN  0x6E61656DULL   /* %mean */
#define HINT_MEMO  0x6F6D656DULL   /* %memo */
#define HINT_BOUT  0x74756F62ULL   /* %bout */
#define HINT_TAME  0x656D6174ULL   /* %tame = 't'+'a'<<8+'m'<<16+'e'<<24 */

static noun nock_eval(noun subject, noun formula, const wilt_t *jets, sky_fn_t sky);
static noun hax(uint64_t a, noun new_val, noun target);

/* ── Wilt parsing ────────────────────────────────────────────────────────── */

/*
 * Parse a $wilt noun (Hoon list of [label sock] pairs) into a wilt_t.
 * A Hoon list is either 0 (null) or [[head tail_of_pair] rest].
 *   element = [label [cape data]]
 */
static void parse_wilt(noun wilt_noun, wilt_t *out) {
    out->len = 0;
    while (noun_is_cell(wilt_noun) && out->len < WILT_MAX) {
        cell_t *cons  = (cell_t *)(uintptr_t)cell_ptr(wilt_noun);
        noun    elem  = cons->head;
        wilt_noun     = cons->tail;

        if (!noun_is_cell(elem))
            nock_crash("%wild: malformed wilt entry: expected [label sock] cell");
        cell_t *ep    = (cell_t *)(uintptr_t)cell_ptr(elem);
        noun    label = ep->head;
        noun    sock  = ep->tail;                   /* [cape data] */

        if (!noun_is_cell(sock))
            nock_crash("%wild: malformed wilt entry: sock must be [cape data] cell");
        cell_t *sp    = (cell_t *)(uintptr_t)cell_ptr(sock);

        out->e[out->len].label     = label;
        out->e[out->len].sock.cape = sp->head;
        out->e[out->len].sock.data = sp->tail;
        out->len++;
    }
}

/* ── Sock matching ────────────────────────────────────────────────────────── */

/*
 * Does (cape, data) match subject?
 *   cape == NOUN_YES (0) → exact: data must equal subject
 *   cape == NOUN_NO  (1) → wildcard: always matches
 *   cape is cell         → recurse into head and tail
 */
int sock_match(noun cape, noun data, noun subject) {
    if (noun_is_atom(cape)) {
        if (direct_val(cape) == 0)      /* & — exact match */
            return noun_eq(data, subject);
        return 1;                       /* | — wildcard */
    }
    if (!noun_is_cell(subject)) return 0;   /* structural mismatch */
    cell_t *cc = (cell_t *)(uintptr_t)cell_ptr(cape);
    cell_t *dc = (cell_t *)(uintptr_t)cell_ptr(data);
    cell_t *sc = (cell_t *)(uintptr_t)cell_ptr(subject);
    return sock_match(cc->head, dc->head, sc->head)
        && sock_match(cc->tail, dc->tail, sc->tail);
}

/* ── Jet implementations ─────────────────────────────────────────────────── */

/*
 * Each jet receives the full core and extracts its sample via slot().
 * Gate convention: sample = slot(6, core)
 *   Unary:  arg  = slot(6, core)
 *   Binary: a    = slot(12, core),  b = slot(13, core)
 */

static noun jet_dec(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun sample = slot(direct(6), core);
    if (!noun_is_atom(sample)) nock_crash("jet dec: sample not atom");
    return bn_dec(sample);
}

static noun jet_add(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet add: non-atom args");
    return bn_add(a, b);
}

static noun jet_sub(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet sub: non-atom args");
    return bn_sub(a, b);
}

static noun jet_mul(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet mul: non-atom args");
    return bn_mul(a, b);
}

static noun jet_lth(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    return bn_cmp(a, b) < 0 ? NOUN_YES : NOUN_NO;
}

static noun jet_gth(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    return bn_cmp(a, b) > 0 ? NOUN_YES : NOUN_NO;
}

static noun jet_lte(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    return bn_cmp(a, b) <= 0 ? NOUN_YES : NOUN_NO;
}

static noun jet_gte(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b))
        nock_crash("jet gte: non-atom args");
    return bn_cmp(a, b) >= 0 ? NOUN_YES : NOUN_NO;
}

static noun jet_div(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet div: non-atom args");
    return bn_div(a, b);
}

static noun jet_mod(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet mod: non-atom args");
    return bn_mod(a, b);
}

/* ── WP3 structural / list / bit jets ─────────────────────────────────────── */

/* Low 64 bits of an atom for axes and shift counts; larger → crash. */
static uint64_t jet_atom_u64(noun a, const char *who)
{
    if (!noun_is_atom(a))
        nock_crash(who);
    if (noun_is_direct(a))
        return direct_val(a);
    atom_t *at = atom_store_get(indirect_hash(a));
    if (!at || at->size == 0)
        return 0;
    if (at->size > 1)
        nock_crash(who);
    return at->limbs[0];
}

/*
 * Hoon $bite: bloq or [bloq step], step bunt 1.
 * Bit count is (bex bloq) * step, i.e. step << bloq.
 */
static uint64_t bite_bits(noun bite, const char *who)
{
    uint64_t bloq;
    uint64_t step = 1;
    if (noun_is_atom(bite)) {
        bloq = jet_atom_u64(bite, who);
    } else {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(bite);
        bloq = jet_atom_u64(c->head, who);
        step = jet_atom_u64(c->tail, who);
    }
    if (bloq >= 64)
        nock_crash(who);
    if (step != 0 && (1ULL << bloq) > (UINT64_MAX / step))
        nock_crash(who);
    return step << bloq;
}

/* %eq — structural equality (same as Nock op5 / noun_eq). sample [a b] */
static noun jet_eq(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    return noun_eq(a, b) ? NOUN_YES : NOUN_NO;
}

/* %lsh — left shift: sample [bite a] → a << ((bex bloq)*step) */
static noun jet_lsh(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun bite = slot(direct(12), core);
    noun a = slot(direct(13), core);
    if (!noun_is_atom(a)) nock_crash("jet lsh: non-atom");
    return bn_lsh(a, bite_bits(bite, "jet lsh: bad bite"));
}

/* %rsh — right shift: sample [bite a] → a >> ((bex bloq)*step) */
static noun jet_rsh(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun bite = slot(direct(12), core);
    noun a = slot(direct(13), core);
    if (!noun_is_atom(a)) nock_crash("jet rsh: non-atom");
    return bn_rsh(a, bite_bits(bite, "jet rsh: bad bite"));
}

/* %con — bitwise OR (Hoon con) */
static noun jet_con(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet con: non-atom");
    return bn_or(a, b);
}

/* %dis — bitwise AND (Hoon dis) */
static noun jet_dis(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet dis: non-atom");
    return bn_and(a, b);
}

/* %mix — bitwise XOR (Hoon mix) */
static noun jet_mix(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    if (!noun_is_atom(a) || !noun_is_atom(b)) nock_crash("jet mix: non-atom");
    return bn_xor(a, b);
}

/* %cap — tree axis side: 2 (head) or 3 (tail). sample = axis */
static noun jet_cap(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    uint64_t a = jet_atom_u64(slot(direct(6), core), "jet cap: bad axis");
    if (a < 2) nock_crash("jet cap: axis < 2");
    while (a > 3)
        a >>= 1;
    return direct(a);
}

/* %mas — address within head/tail subtree of axis */
static uint64_t axis_mas(uint64_t a)
{
    if (a <= 3)
        return 1;
    return (axis_mas(a >> 1) << 1) | (a & 1);
}

static noun jet_mas(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    uint64_t a = jet_atom_u64(slot(direct(6), core), "jet mas: bad axis");
    if (a < 2) nock_crash("jet mas: axis < 2");
    return direct(axis_mas(a));
}

/* %peg — compose axes: navigate a then b. sample [a b] */
static uint64_t axis_peg(uint64_t a, uint64_t b)
{
    if (b == 1)
        return a;
    if (b == 2)
        return a << 1;
    if (b == 3)
        return (a << 1) | 1;
    uint64_t c = axis_peg(a, b >> 1);
    return (b & 1) ? ((c << 1) | 1) : (c << 1);
}

static noun jet_peg(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    uint64_t a = jet_atom_u64(slot(direct(12), core), "jet peg: bad a");
    uint64_t b = jet_atom_u64(slot(direct(13), core), "jet peg: bad b");
    if (a == 0 || b == 0) nock_crash("jet peg: axis 0");
    return direct(axis_peg(a, b));
}

/* %lent — list length (null = 0 atom). sample = list */
static noun jet_lent(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun list = slot(direct(6), core);
    uint64_t n = 0;
    while (noun_is_cell(list)) {
        if (++n > 1000000ULL)
            nock_crash("jet lent: list too long");
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(list);
        list = c->tail;
    }
    return direct(n);
}

/* %flop — reverse null-terminated list. sample = list */
static noun jet_flop(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun list = slot(direct(6), core);
    noun acc  = NOUN_ZERO;
    uint64_t n = 0;
    while (noun_is_cell(list)) {
        if (++n > 1000000ULL)
            nock_crash("jet flop: list too long");
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(list);
        acc  = nock_alloc_cell(c->head, acc);
        list = c->tail;
    }
    return acc;
}

/* %weld — append lists a ++ b. sample [a b] */
static noun jet_weld(noun core, const wilt_t *jets, sky_fn_t sky) {
    (void)jets; (void)sky;
    noun a = slot(direct(12), core);
    noun b = slot(direct(13), core);
    /* reverse a, then reverse onto b (iterative, bounded) */
    noun rev = NOUN_ZERO;
    noun cur = a;
    uint64_t n = 0;
    while (noun_is_cell(cur)) {
        if (++n > 1000000ULL)
            nock_crash("jet weld: list too long");
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(cur);
        rev = nock_alloc_cell(c->head, rev);
        cur = c->tail;
    }
    noun out = b;
    cur = rev;
    while (noun_is_cell(cur)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(cur);
        out = nock_alloc_cell(c->head, out);
        cur = c->tail;
    }
    return out;
}

/* Slam a gate: edit axis 6 with sample, kick axis 2. */
static noun slam_gate(noun gate, noun sample, const wilt_t *jets, sky_fn_t sky)
{
    noun core = hax(6, sample, gate);
    return nock_eval(core, slot(direct(2), core), jets, sky);
}

/* %turn — map gate over list. sample [list gate] */
static noun jet_turn(noun core, const wilt_t *jets, sky_fn_t sky) {
    noun list = slot(direct(12), core);
    noun gate = slot(direct(13), core);
    noun rev = NOUN_ZERO;
    uint64_t n = 0;
    while (noun_is_cell(list)) {
        if (++n > 1000000ULL)
            nock_crash("jet turn: list too long");
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(list);
        noun item = slam_gate(gate, c->head, jets, sky);
        rev = nock_alloc_cell(item, rev);
        list = c->tail;
    }
    noun out = NOUN_ZERO;
    while (noun_is_cell(rev)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(rev);
        out = nock_alloc_cell(c->head, out);
        rev = c->tail;
    }
    return out;
}

/* %mole — run a trap; ~ on crash, [~ product] on success. */
static noun jet_mole(noun core, const wilt_t *jets, sky_fn_t sky) {
    noun tap = slot(direct(6), core);
    noun kick_fol = nock_alloc_cell(direct(9),
                    nock_alloc_cell(direct(2),
                    nock_alloc_cell(direct(0), direct(1))));
    uint64_t saved_stack = g_eval_stack_current;
    jmp_buf saved;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        g_eval_stack_current = saved_stack;
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return NOUN_ZERO;
    }
    noun product = nock_eval(tap, kick_fol, jets, sky);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    return nock_alloc_cell(NOUN_ZERO, product);
}

/* ── Hot state ────────────────────────────────────────────────────────────── */

/*
 * Keyed on Urbit cord values (LSB = first char of name).
 * Jets are matched against label atoms registered via %wild hints, and
 * against batteries registered by honk's %fast clues (first battery per
 * label; later same-name cores keep running as Nock).
 * Cord values: each char contributes 8 bits, LSB = first character.
 *   e.g. %dec = 'd' + 'e'<<8 + 'c'<<16 = 100 + 101*256 + 99*65536 = 6514020
 *
 * Dispatch priority (KERNEL / pure nock_eval op9): C hot_state only.
 * SKA nock_op9_continue: Forth dictionary (find_by_cord) first, then C.
 * Prefer C jets for production KERNEL path; Forth may shadow in REPL/SKA.
 */
typedef struct { uint64_t label_cord; jet_fn_t fn; uint64_t hits; } hot_entry_t;

static hot_entry_t hot_state[] = {
    /* arithmetic (Phase 5b) */
    { 6514020, jet_dec, 0 },   /* %dec */
    { 6579297, jet_add, 0 },   /* %add */
    { 6452595, jet_sub, 0 },   /* %sub */
    { 7107949, jet_mul, 0 },   /* %mul */
    { 6845548, jet_lth, 0 },   /* %lth */
    { 6845543, jet_gth, 0 },   /* %gth */
    { 6648940, jet_lte, 0 },   /* %lte */
    { 6648935, jet_gte, 0 },   /* %gte */
    { 7760228, jet_div, 0 },   /* %div */
    { 6582125, jet_mod, 0 },   /* %mod */
    /* WP3 structural / list / bit */
    { 29029,       jet_eq,   0 },  /* %eq   */
    { 6845292,     jet_lsh,  0 },  /* %lsh  */
    { 6845298,     jet_rsh,  0 },  /* %rsh  */
    { 7237475,     jet_con,  0 },  /* %con  */
    { 7563620,     jet_dis,  0 },  /* %dis  */
    { 7891309,     jet_mix,  0 },  /* %mix  */
    { 7364963,     jet_cap,  0 },  /* %cap  */
    { 7561581,     jet_mas,  0 },  /* %mas  */
    { 6776176,     jet_peg,  0 },  /* %peg  */
    { 1953391980,  jet_lent, 0 },  /* %lent */
    { 1886350438,  jet_flop, 0 },  /* %flop */
    { 1684825463,  jet_weld, 0 },  /* %weld */
    /* L1: honk %fast labels the R1 jam actually takes (deliverable 2) */
    { 1852994932,  jet_turn, 0 },  /* %turn */
    { 1701605229,  jet_mole, 0 },  /* %mole */
    { 0, NULL, 0 }                 /* sentinel */
};

jet_fn_t hot_lookup(noun label) {
    if (!noun_is_direct(label)) return NULL;
    uint64_t cord = direct_val(label);
    for (int i = 0; hot_state[i].fn != NULL; i++) {
        if (hot_state[i].label_cord == cord)
            return hot_state[i].fn;
    }
    return NULL;
}

uint64_t hot_reverse_label(jet_fn_t fn) {
    for (int i = 0; hot_state[i].fn != NULL; i++) {
        if (hot_state[i].fn == fn)
            return hot_state[i].label_cord;
    }
    return 0;
}

static void hot_hit(jet_fn_t fn)
{
    for (int i = 0; hot_state[i].fn != NULL; i++) {
        if (hot_state[i].fn == fn) {
            hot_state[i].hits++;
            return;
        }
    }
}

int hot_entry_count(void)
{
    int n = 0;
    while (hot_state[n].fn != NULL)
        n++;
    return n;
}

uint64_t hot_entry_label(int i)
{
    return hot_state[i].label_cord;
}

uint64_t hot_entry_hits(int i)
{
    return hot_state[i].hits;
}

void hot_hits_reset(void)
{
    for (int i = 0; hot_state[i].fn != NULL; i++)
        hot_state[i].hits = 0;
}

/* ── %fast battery registry (per-boot; no Vere ++ka.rout) ─────────────── */

#define FAST_REG_MAX 256   /* bounded in practice by hot_entry_count() */

typedef struct {
    noun battery;
    uint64_t label_cord;
    jet_fn_t fn;
} fast_reg_t;

static fast_reg_t g_fast_reg[FAST_REG_MAX];
static int g_fast_len;
static uint64_t g_fast_clues;
static noun g_fast_first_clue;
static int g_fast_first_ok;
#define FAST_CHUM_LOG 64   /* diagnostic ring; stops recording past 64 */
static noun g_fast_chums[FAST_CHUM_LOG];
static int g_fast_chum_n;
#if defined(I3_L1_PROBE)
static noun g_fast_first_core;
typedef struct { uint64_t label_cord; noun core; } fast_core_t;
static fast_core_t g_fast_cores[FAST_REG_MAX];
static int g_fast_core_n;
static noun g_fast_walk[FAST_CHUM_LOG];
static int g_fast_walk_n;
static int g_pull_n;
#define PULL_MAX 4096
#endif

void fast_reset(void)
{
    g_fast_len = 0;
    g_fast_clues = 0;
    g_fast_first_clue = NOUN_ZERO;
    g_fast_first_ok = 0;
    g_fast_chum_n = 0;
#if defined(I3_L1_PROBE)
    g_fast_first_core = NOUN_ZERO;
    g_fast_core_n = 0;
    g_fast_walk_n = 0;
    g_pull_n = 0;
#endif
    hot_hits_reset();
}

uint64_t fast_clue_count(void) { return g_fast_clues; }
int fast_reg_count(void) { return g_fast_len; }
int fast_first_clue_ok(void) { return g_fast_first_ok; }
noun fast_first_clue(void) { return g_fast_first_clue; }

/*
 * honk %fast clue after evaluation is [chum parent-formula hooks].
 * Register the constructed core's battery against chum if chum is hot.
 * First battery per label wins, so later same-name cores (rs/rd add, …)
 * are not stolen by the integer jet.
 */
int fast_chum_count(void) { return g_fast_chum_n; }
noun fast_chum_at(int i) { return g_fast_chums[i]; }

static void fast_register(noun core, noun clue)
{
    g_fast_clues++;
    if (!g_fast_first_ok) {
        g_fast_first_clue = clue;
        g_fast_first_ok = 1;
#if defined(I3_L1_PROBE)
        g_fast_first_core = core;
#endif
    }
    if (!noun_is_cell(clue) || !noun_is_cell(core))
        return;
    noun chum = slot(direct(2), clue);
    if (g_fast_chum_n < FAST_CHUM_LOG) {
        int seen = 0, i;
        for (i = 0; i < g_fast_chum_n; i++) {
            if (g_fast_chums[i] == chum || noun_eq(g_fast_chums[i], chum)) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
#if defined(I3_L1_PROBE)
            g_fast_walk[g_fast_chum_n] = core;
            g_fast_walk_n = g_fast_chum_n + 1;
#endif
            g_fast_chums[g_fast_chum_n++] = chum;
        }
    }
    jet_fn_t fn = hot_lookup(chum);
    if (fn == NULL)
        return;
    uint64_t cord = direct_val(chum);
    noun battery = slot(direct(2), core);
#if defined(I3_L1_PROBE)
    {
        int have = 0, i;
        for (i = 0; i < g_fast_core_n; i++) {
            if (g_fast_cores[i].label_cord == cord) {
                have = 1;
                break;
            }
        }
        if (!have && g_fast_core_n < FAST_REG_MAX) {
            g_fast_cores[g_fast_core_n].label_cord = cord;
            g_fast_cores[g_fast_core_n].core = core;
            g_fast_core_n++;
        }
    }
#endif
#if defined(I3_UNJETTED)
    (void)battery;
    return;
#else
    int i;
    for (i = 0; i < g_fast_len; i++) {
        if (g_fast_reg[i].label_cord == cord)
            return;
        if (g_fast_reg[i].battery == battery
            || noun_eq(g_fast_reg[i].battery, battery))
            return;
    }
    if (g_fast_len >= FAST_REG_MAX)
        return;
    g_fast_reg[g_fast_len].battery = battery;
    g_fast_reg[g_fast_len].label_cord = cord;
    g_fast_reg[g_fast_len].fn = fn;
    g_fast_len++;
#endif
}

static jet_fn_t fast_match(noun core)
{
    if (!noun_is_cell(core) || g_fast_len == 0)
        return NULL;
    noun battery = slot(direct(2), core);
    int i;
    for (i = 0; i < g_fast_len; i++) {
        if (g_fast_reg[i].battery == battery
            || noun_eq(g_fast_reg[i].battery, battery))
            return g_fast_reg[i].fn;
    }
    return NULL;
}

#if defined(I3_L1_PROBE)
noun fast_core_lookup(noun label)
{
    int i;
    uint64_t cord;
    if (!noun_is_direct(label))
        return NOUN_ZERO;
    cord = direct_val(label);
    for (i = 0; i < g_fast_core_n; i++) {
        if (g_fast_cores[i].label_cord == cord)
            return g_fast_cores[i].core;
    }
    return NOUN_ZERO;
}

int fast_core_count(void)
{
    return g_fast_core_n;
}

uint64_t fast_core_label(int i)
{
    return g_fast_cores[i].label_cord;
}

static int formula_is_fast(noun fol)
{
    cell_t *c, *args, *hc;
    if (!noun_is_cell(fol))
        return 0;
    c = (cell_t *)(uintptr_t)cell_ptr(fol);
    if (!noun_is_direct(c->head) || direct_val(c->head) != 11)
        return 0;
    if (!noun_is_cell(c->tail))
        return 0;
    args = (cell_t *)(uintptr_t)cell_ptr(c->tail);
    if (!noun_is_cell(args->head))
        return 0;
    hc = (cell_t *)(uintptr_t)cell_ptr(args->head);
    return noun_is_direct(hc->head) && direct_val(hc->head) == HINT_FAST;
}

static int formula_contains_fast(noun fol, int depth)
{
    cell_t *c;
    if (depth > 12 || !noun_is_cell(fol))
        return 0;
    if (formula_is_fast(fol))
        return 1;
    c = (cell_t *)(uintptr_t)cell_ptr(fol);
    return formula_contains_fast(c->head, depth + 1)
        || formula_contains_fast(c->tail, depth + 1);
}

static int battery_leaf(noun node)
{
    cell_t *c;
    if (!noun_is_cell(node))
        return 1;
    c = (cell_t *)(uintptr_t)cell_ptr(node);
    return noun_is_atom(c->head);
}

static void pull_walk(noun core, int depth);

static void pull_arm(noun core, uint64_t axis, int depth)
{
    noun fol, product;
    jmp_buf saved;
    int jumped;
    if (g_pull_n >= PULL_MAX || axis == 0)
        return;
    g_pull_n++;
    if (!alloc_cell_checked(direct(0), direct(1), &fol)
        || !alloc_cell_checked(direct(axis), fol, &fol)
        || !alloc_cell_checked(direct(9), fol, &fol))
        return;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    jumped = setjmp(nock_abort);
    if (jumped != 0) {
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return;
    }
    product = nock(core, fol);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
    if (noun_is_cell(product) && depth < 8)
        pull_walk(product, depth + 1);
}

static void pull_tree(noun core, uint64_t axis, noun node, int depth)
{
    cell_t *c;
    if (g_pull_n >= PULL_MAX || axis == 0)
        return;
    if (battery_leaf(node)) {
        if (formula_is_fast(node) || formula_contains_fast(node, 0))
            pull_arm(core, axis, depth);
        return;
    }
    if (axis > (UINT64_MAX / 2))
        return;
    c = (cell_t *)(uintptr_t)cell_ptr(node);
    pull_tree(core, axis << 1, c->head, depth);
    pull_tree(core, (axis << 1) | 1, c->tail, depth);
}

static void pull_walk(noun core, int depth)
{
    jmp_buf saved;
    int jumped;
    if (!noun_is_cell(core) || depth > 8)
        return;
    __builtin_memcpy(saved, nock_abort, sizeof saved);
    jumped = setjmp(nock_abort);
    if (jumped != 0) {
        __builtin_memcpy(nock_abort, saved, sizeof saved);
        return;
    }
    pull_tree(core, 2, slot(direct(2), core), depth);
    __builtin_memcpy(nock_abort, saved, sizeof saved);
}

int fast_pull_hot(void)
{
    int i;
    g_pull_n = 0;
    nock_budget_set(0);
    nock_eval_stack_set_limit(1024);
    if (noun_is_cell(g_fast_first_core))
        pull_walk(g_fast_first_core, 0);
    for (i = 0; i < g_fast_walk_n; i++) {
        if (noun_is_cell(g_fast_walk[i]))
            pull_walk(g_fast_walk[i], 0);
    }
    nock_budget_finish();
    return g_fast_core_n > 0;
}
#endif

/* ── Hax  (#[axis val target]) ──────────────────────────────────────────── */

/*
 * Tree edit: replace the noun at axis `a` within `target` with `new_val`.
 * Mirrors the slot path traversal but rebuilds cells on the way back up.
 *
 *   #[1 v t]     = v
 *   #[2 v [h t]] = [v t]
 *   #[3 v [h t]] = [h v]
 *   #[2k v t]    = #[k/even-step …]  (recurse into head subtree)
 *   #[2k+1 v t]  = #[k/odd-step …]   (recurse into tail subtree)
 */
static noun hax(uint64_t a, noun new_val, noun target) {
    if (a == 0)
        nock_crash("edit axis 0");
    if (a == 1)
        return new_val;
    if (!noun_is_cell(target))
        nock_crash("edit in atom");

    cell_t *t = (cell_t *)(uintptr_t)cell_ptr(target);

    /* depth = floor(log2(a)); first path bit selects head(0) vs tail(1) */
    int d = 0;
    uint64_t tmp = a;
    while (tmp > 1) { tmp >>= 1; d++; }

    int first = (int)((a >> (d - 1)) & 1);

    /* sub-axis within the chosen child: strip the leading 1-bit and the
     * first path bit, then re-attach the sentinel 1-bit. */
    uint64_t sub = (a & ((1ULL << (d - 1)) - 1)) | (1ULL << (d - 1));

    if (first == 0)
        return nock_alloc_cell(hax(sub, new_val, t->head), t->tail);
    else
        return nock_alloc_cell(t->head, hax(sub, new_val, t->tail));
}

/* ── Slot  (/[axis subject]) ─────────────────────────────────────────────── */

/*
 * Axis encodes a path through the binary tree.  The leading 1-bit is a
 * sentinel; the remaining bits, read MSB-first, form the path:  0 = head,
 * 1 = tail.
 *
 *   axis 1      → root (whole subject)
 *   axis 2      → head           (path: 0)
 *   axis 3      → tail           (path: 1)
 *   axis 4      → head of head   (path: 0 0)
 *   axis 5      → tail of head   (path: 0 1)
 *   axis 6      → head of tail   (path: 1 0)
 *   axis 7      → tail of tail   (path: 1 1)
 */
noun slot(noun axis, noun subject) {
    if (!noun_is_direct(axis))
        nock_crash("slot axis not direct");

    uint64_t a = direct_val(axis);
    if (a == 0)
        nock_crash("slot axis 0");

    /* find depth = floor(log2(a)) — the number of path bits */
    int depth = 0;
    uint64_t tmp = a;
    while (tmp > 1) { tmp >>= 1; depth++; }

    /* follow path bits from bit (depth-1) down to bit 0 */
    for (int i = depth - 1; i >= 0; i--) {
        if (!noun_is_cell(subject))
            nock_crash("slot in atom");
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(subject);
        if ((a >> i) & 1)
            subject = c->tail;
        else
            subject = c->head;
    }
    return subject;
}

/* ── Nock eval ───────────────────────────────────────────────────────────── */

/* ── %tame helper (noinline to isolate register allocation from nock_eval) ── */

static void __attribute__((noinline)) tame_compile(noun clue) {
    cell_t *tc = (cell_t *)(uintptr_t)cell_ptr(clue);
    noun label = tc->head;
    noun src   = tc->tail;
    char buf[512];
    size_t len = cord_to_cstr(src, buf, sizeof(buf) - 1);
    if (len > 0) {
        dict_entry_t *before = dict_get_latest();
        forth_eval_string(buf, len);
        dict_entry_t *after = dict_get_latest();
        if (after == before)
            nock_crash("%tame: source did not define a new word");
        if (!noun_is_direct(label) ||
            dict_entry_name(after) != direct_val(label))
            nock_crash("%tame: compiled word name does not match label");
    }
}

/*
 * Internal evaluator body.  Recursive calls go through the guarded wrapper
 * below so that `jets` and `sky` are threaded through the entire computation.
 *
 * `wild_buf` holds at most one %wild registration set per logical frame in
 * the bounded evaluator table.
 * When op 11 fires a %wild hint, we parse the clue into `wild_buf` and
 * update `jets` to point to it.  Because `goto loop` keeps us in the
 * same frame, `wild_buf` stays live until the frame returns.
 */
static noun nock_eval(noun subject, noun formula,
                      const wilt_t *jets, sky_fn_t sky);

static noun nock_eval_inner(noun subject, noun formula,
                            const wilt_t *jets, sky_fn_t sky) {
    wilt_t *wild_buf = &g_eval_wild[g_eval_stack_current - 1];
loop:
    nock_budget_tick();
    if (!noun_is_cell(formula))
        nock_crash("nock atom");

    cell_t *f = (cell_t *)(uintptr_t)cell_ptr(formula);
    noun head = f->head;
    noun tail = f->tail;

    /* ── Distribution rule: *[a [b c] d] = [*[a b c] *[a d]] ── */
    if (noun_is_cell(head)) {
        noun left  = nock_eval(subject, head, jets, sky);
        noun right = nock_eval(subject, tail, jets, sky);
        return nock_alloc_cell(left, right);
    }

    /* head is an atom — it's the opcode */
    if (!noun_is_direct(head))
        nock_crash("opcode not direct");
    uint64_t op = direct_val(head);

    switch (op) {

    /* ── 0  *[a 0 b]  =  /[b a]  ── */
    case 0:
        return slot(tail, subject);

    /* ── 1  *[a 1 b]  =  b  ── */
    case 1:
        return tail;

    /* ── 2  *[a 2 b c]  =  *[*[a b] *[a c]]  (TCO: loop) ── */
    case 2: {
        if (!noun_is_cell(tail))
            nock_crash("op2 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun new_subj = nock_eval(subject, args->head, jets, sky);
        noun new_form = nock_eval(subject, args->tail, jets, sky);
        subject = new_subj;
        formula = new_form;
        goto loop;
    }

    /* ── 3  *[a 3 b]  =  ?*[a b]  (wut: 0=cell, 1=atom) ── */
    case 3: {
        noun r = nock_eval(subject, tail, jets, sky);
        return noun_is_cell(r) ? NOUN_YES : NOUN_NO;
    }

    /* ── 4  *[a 4 b]  =  +*[a b]  (lus: increment atom) ── */
    case 4: {
        noun r = nock_eval(subject, tail, jets, sky);
        if (!noun_is_atom(r))
            nock_crash("op4 increment of cell");
        return bn_inc(r);
    }

    /* ── 5  *[a 5 b c]  =  =[*[a b] *[a c]]  (tis: 0=equal, 1=not) ── */
    case 5: {
        if (!noun_is_cell(tail))
            nock_crash("op5 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun left  = nock_eval(subject, args->head, jets, sky);
        noun right = nock_eval(subject, args->tail, jets, sky);
        return noun_eq(left, right) ? NOUN_YES : NOUN_NO;
    }

    /* ── 9  *[a 9 b c]  =  *[*[a c] 0 b]  (arm invocation, TCO) ──
     *
     * Evaluate c against subject to get a core, pull the arm formula
     * at axis b, then evaluate that arm with the core as its own subject.
     * This is every function call in Hoon.
     *
     * Before falling through to Nock eval, check the active %wild
     * registrations: if any sock matches the core, dispatch to the jet.
     */
    case 9: {
        if (!noun_is_cell(tail))
            nock_crash("op9 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun b    = args->head;
        noun core = nock_eval(subject, args->tail, jets, sky);
        noun arm  = slot(b, core);

        /* ── Jet dispatch ── */
        if (jets != NULL) {
            for (int i = 0; i < jets->len; i++) {
                if (sock_match(jets->e[i].sock.cape,
                               jets->e[i].sock.data, core)) {
                    jet_fn_t fn = hot_lookup(jets->e[i].label);
                    if (fn != NULL) {
                        hot_hit(fn);
                        return fn(core, jets, sky);
                    }
                }
            }
        }
        /* %fast: battery match on the $ arm (axis 2). %wild stays first. */
        if (noun_is_direct(b) && direct_val(b) == 2) {
            jet_fn_t fn = fast_match(core);
            if (fn != NULL) {
                hot_hit(fn);
                return fn(core, jets, sky);
            }
        }

        subject = core;
        formula = arm;
        goto loop;                      /* TCO */
    }

    /* ── 6  *[a 6 b c d]  =  if *[a b] then *[a c] else *[a d]  (TCO) ── */
    case 6: {
        if (!noun_is_cell(tail))
            nock_crash("op6 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun b = args->head;                    /* condition formula */
        if (!noun_is_cell(args->tail))
            nock_crash("op6 missing branches");
        cell_t *branches = (cell_t *)(uintptr_t)cell_ptr(args->tail);
        noun cond = nock_eval(subject, b, jets, sky);
        if (noun_eq(cond, NOUN_YES)) {
            formula = branches->head;           /* then-branch c */
            goto loop;
        } else if (noun_eq(cond, NOUN_NO)) {
            formula = branches->tail;           /* else-branch d */
            goto loop;
        } else {
            nock_crash("op6 condition not 0 or 1");
            return NOUN_ZERO;
        }
    }

    /* ── 7  *[a 7 b c]  =  *[*[a b] c]  (compose, TCO) ── */
    case 7: {
        if (!noun_is_cell(tail))
            nock_crash("op7 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        subject = nock_eval(subject, args->head, jets, sky);
        formula = args->tail;
        goto loop;
    }

    /* ── 8  *[a 8 b c]  =  *[[*[a b] a] c]  (pin, TCO) ── */
    case 8: {
        if (!noun_is_cell(tail))
            nock_crash("op8 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun pinned = nock_eval(subject, args->head, jets, sky);
        subject = nock_alloc_cell(pinned, subject);  /* [*[a b] a] */
        formula = args->tail;
        goto loop;
    }

    /* ── 10  tree edit (hax) ───────────────────────────────────────────────
     *
     *  *[a 10 [b c] d]  =  #[b *[a c] *[a d]]
     *
     *  Op 10 is exclusively the # hax operator: evaluate c and d against
     *  subject a, then replace address b in the result of d with the result
     *  of c.  The hint argument [b c] MUST be a cell; an atom head crashes.
     */
    case 10: {
        if (!noun_is_cell(tail))
            nock_crash("op10 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun hint = args->head;
        noun d    = args->tail;

        if (noun_is_cell(hint)) {
            cell_t *hc = (cell_t *)(uintptr_t)cell_ptr(hint);
            noun b = hc->head;
            if (!noun_is_direct(b))
                nock_crash("op10 edit axis not direct");
            noun val    = nock_eval(subject, hc->tail, jets, sky);
            noun target = nock_eval(subject, d, jets, sky);
            return hax(direct_val(b), val, target);
        } else {
            nock_crash("op10: hint must be a cell [axis val-formula]; atom hint is not valid Nock 4K");
            return NOUN_ZERO; /* unreachable */
        }
    }

    /* ── 11  hint ──────────────────────────────────────────────────────────
     *
     *  *[a 11 b c]       =  *[a c]                (static hint, b is atom)
     *  *[a 11 [b c] d]   =  hint fires, then *[a d]  (dynamic hint)
     *
     * Supported dynamic hint tags:
     *   %wild  — parse $wilt clue, scope jet registrations into *[a d]
     *   %fast  — post-hint: eval d (the core), register battery→hot label
     *   %slog  — print clue noun to UART (bare-metal printf)
     *   %xray  — print clue noun tree to UART (noun inspector)
     *   %mean  — stub (stack trace, Phase 8)
     *   %memo  — stub (memoization, Phase 5)
     *   %bout  — stub (timing, future)
     *   other  — silent no-op
     */
    case 11: {
        if (!noun_is_cell(tail))
            nock_crash("op11 tail not cell");
        cell_t *args = (cell_t *)(uintptr_t)cell_ptr(tail);
        noun hint = args->head;
        noun d    = args->tail;

        if (!noun_is_cell(hint)) {
            /* Static hint: atom tag, no clue evaluation — just eval d */
            formula = d;
            goto loop;
        }

        /* Dynamic hint: hint = [b c] */
        cell_t *hc  = (cell_t *)(uintptr_t)cell_ptr(hint);
        noun b      = hc->head;     /* hint tag */
        noun c      = hc->tail;     /* clue formula */

#if defined(M38_D5_NATIVE)
        /* M38-B diagnostic scopes use a long, opaque cord tag.  Hints are
         * semantically inert here; only the legacy direct tags below have
         * native side effects.  Accepting an indirect tag preserves the
         * frozen formula while keeping this evaluator total at the boundary. */
        uint64_t tag = noun_is_direct(b) ? direct_val(b) : UINT64_MAX;
#else
        if (!noun_is_direct(b))
            nock_crash("op11 hint tag not direct");
        uint64_t tag = direct_val(b);
#endif

        /* Evaluate clue (for side effects and/or %wild registration) */
        noun clue = nock_eval(subject, c, jets, sky);

        switch (tag) {

        case HINT_TAME:
            /* clue = [label source-cord]: compile Forth source into dictionary.
             * The compiled word's name must match the label cord; crash if not.
             * A non-cell clue is a malformed %tame hint → crash. */
            if (!noun_is_cell(clue))
                nock_crash("%tame: clue must be [label source-cord] cell");
            tame_compile(clue);
            break;

        case HINT_WILD:
            /* Parse $wilt clue into wild_buf; scope registrations into d */
            parse_wilt(clue, wild_buf);
            jets = wild_buf;
            break;

        case HINT_FAST: {
            /* Post-nock: construct the core, then match its battery. */
            noun core = nock_eval(subject, d, jets, sky);
            fast_register(core, clue);
            return core;
        }

        case HINT_SLOG:
            uart_puts("\r\nslog: ");
            noun_print(clue, 0);
            uart_puts("\r\n");
            break;

        case HINT_XRAY:
            uart_puts("\r\nxray: ");
            noun_print(clue, 0);
            uart_puts("\r\n");
            break;

        case HINT_MEAN:
        case HINT_MEMO:
        case HINT_BOUT:
        default:
            /* stub / no-op */
            (void)clue;
            break;
        }

        formula = d;
        goto loop;
    }

    default:
        nock_crash("unimplemented opcode");
        return NOUN_ZERO; /* unreachable */
    }
}

/* Measure logical evaluator frames independently of the physical C-stack
 * watermark.  Tail-recursive `goto loop` iterations remain one evaluator
 * frame, while every recursive formula call passes through this wrapper. */
static noun __attribute__((noinline)) nock_eval(noun subject, noun formula,
                                                const wilt_t *jets, sky_fn_t sky)
{
    if (g_eval_stack_current >= g_eval_stack_limit) {
        g_budget_abort_reason = 4;
        longjmp(nock_abort, NOCK_ABORT_BUDGET);
    }
    g_eval_stack_current++;
    if (g_eval_stack_current > g_eval_stack_peak)
        g_eval_stack_peak = g_eval_stack_current;
    noun result = nock_eval_inner(subject, formula, jets, sky);
    g_eval_stack_current--;
    return result;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

noun nock(noun subject, noun formula) {
    return nock_eval(subject, formula, NULL, NULL);
}

noun nock_ex(noun subject, noun formula, const wilt_t *jets, sky_fn_t sky) {
    return nock_eval(subject, formula, jets, sky);
}

noun nock_op9_continue(noun core, noun ax,
                       const wilt_t *jets, sky_fn_t sky) {
    /* jet check — same logic as op 9 in nock_eval */
    if (jets != NULL) {
        for (int i = 0; i < jets->len; i++) {
            if (sock_match(jets->e[i].sock.cape,
                           jets->e[i].sock.data, core)) {
                noun label = jets->e[i].label;
                /* Forth dict first: supports jets compiled via %tame */
                if (noun_is_direct(label)) {
                    dict_entry_t *fe = find_by_cord(label);
                    if (fe != NULL)
                        return forth_call_jet(fe, core);
                }
                jet_fn_t fn = hot_lookup(label);
                if (fn != NULL) {
                    hot_hit(fn);
                    return fn(core, jets, sky);
                }
            }
        }
    }
    if (noun_is_direct(ax) && direct_val(ax) == 2) {
        jet_fn_t fn = fast_match(core);
        if (fn != NULL) {
            hot_hit(fn);
            return fn(core, jets, sky);
        }
    }
    /* no jet — evaluate arm as Nock formula */
    noun arm = slot(ax, core);
    return nock_eval(core, arm, jets, sky);
}
