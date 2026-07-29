#include <stdint.h>
#include "noun.h"
#include "uart.h"
#include "memory.h"
#include "jam.h"
#include "nock.h"
#include "setjmp.h"
#include "ska.h"
#include "trace.h"
#include "net.h"
#include "cold.h"
#include "kernel.h"
#include "runtime_identity.h"
#include "i2_ingress.h"
#include "runtime_stats.h"

/* Effect tag cords (Urbit cord encoding: LSB = first char of name) */
#define CORD_OUT     7632239ULL              /* %out      */
#define CORD_BLIT    1953066082ULL           /* %blit     */
#define CORD_TIMEOUT 32780218601924980ULL    /* %timeout  */
#define CORD_MMIO    1869180269ULL           /* %mmio     */
#define CORD_TMRARM  120338028588404ULL      /* %tmrarm   */
#define CORD_TMRCAN  121364559326580ULL      /* %tmrcan   */
#define CORD_TSET    1952805748ULL           /* %tset     */
#define CORD_TCAN    1851876212ULL           /* %tcan     */
#define CORD_IRQ     7434857ULL              /* %irq      */
#define CORD_SWAPPED 28259031267243891ULL    /* %swapped  */
#define CORD_WDT     7627895ULL              /* %wdt = "wdt" */
/* WP4 — host hygiene (not all are kernel→app ISA; overflow/unk are host-visible) */

/* Kernel event ISA cords for timer fire (IEC host → kernel) */
#define CORD_EI      26981ULL                /* %ei       */
#define CORD_TICK    1262700884ULL           /* %TICK     */

/*
 * I2 Host ABI effect tags (docs/I2.md §12.4) — compared via cord_to_cstr
 * because several names exceed 63-bit direct atoms.
 *   i2-timer-set / i2-timer-cancel / i2-service-request / i2-service-cancel
 * Short direct aliases (Forth tests / compact emitters): i2ts i2tc i2sr i2sc
 * Timer fire reinjection: [%i2-timer token fired-at] when token map live.
 *
 * I2 slam product (hybrid battery): [%commit [effects [gate causes]]]
 *   or [%abort fault]. I1 shrine product remains [effects [gate causes]].
 */
#define CORD_COMMIT  127996156276579ULL      /* %commit   */
#define CORD_ABORT   500136108641ULL         /* %abort    */
#define CORD_I2TS    1936994921ULL           /* %i2ts  timer-set alias   */
#define CORD_I2TC    1668559465ULL           /* %i2tc  timer-cancel      */
#define CORD_I2SR    1920152169ULL           /* %i2sr  service-request   */
#define CORD_I2SC    1668493929ULL           /* %i2sc  service-cancel    */

/*
 * Long I2 cords exceed 63-bit direct atoms → type-10 (BLAKE3-62 identity).
 * Match by precomputed hash62 (same as make_atom) so dispatch does not depend
 * on atom-store residency / cord_to_cstr. Values from blake3(cord_bytes)[0:8]
 * little-endian, top 2 bits cleared (see tools/i2 + make_atom).
 */
#define H62_I2_TIMER_SET        0x1e999aebcdf5c5b9ULL  /* "i2-timer-set" */
#define H62_I2_TIMER_CANCEL     0x00a0daca2d33f298ULL  /* "i2-timer-cancel" */
#define H62_I2_SERVICE_REQUEST  0x35d925d61fab343bULL  /* "i2-service-request" */
#define H62_I2_SERVICE_CANCEL   0x36d39945d04ddb18ULL  /* "i2-service-cancel" */
#define CORD_I2_TIMER           0x72656d69742d3269ULL  /* "i2-timer" host→app */
#define H62_I2_SERVICE          0x30cfa0e9c7ed95b9ULL  /* "i2-service" host→app */
#define CORD_I2_CKPT            32774703826154089ULL   /* %i2-ckpt durable snap  */

/* Host ABI D0 ceilings (subset of tools/i2 HostAbiLimits) */
#define I2_MAX_TIMERS              TARM_MAX
#define I2_MAX_PENDING_SERVICES    4
#define I2_UART_TX_MAX_NS  1000000000ULL

/* Auto-checkpoint: save live roots to cold store every N successful commits */
static uint64_t g_ckpt_every;
static uint64_t g_ckpt_commits;
static noun g_activation_completions[I2_MAX_PENDING_SERVICES];
static int g_activation_completion_n;

#define TARM_MAX     16

#define HSTAT_IDLE    0
#define HSTAT_STAGED  1
#define HSTAT_PENDING 2

extern jmp_buf nock_abort;
extern int noun_pill_shape;
extern uint32_t noun_pill_version;
static int noun_take(noun n, noun *head, noun *tail);

/* ── Phase 6 — live kernel + staging ─────────────────────────────────────── */

static volatile noun g_kernel;
static int           g_shrine_mode;
static uint32_t      g_live_version;
static volatile int  g_i2_preparing;
static noun build_slam_formula(void);
static int build_slam_formula_checked(noun *out);
static int make_timer_event_checked(noun token, noun *out);
static noun g_slam_formula;

static noun     g_staged_kernel;
static int      g_staged_shape;
static uint32_t g_staged_version;
static int      g_hstat;   /* idle / staged / pending */

static void emit_swapped(uint32_t ver);

/* ── Phase 1 — deadline ──────────────────────────────────────────────────── */

static uint64_t g_deadline;

static inline uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

void deadline_set(uint64_t abs)
{
    g_deadline = abs;
}

uint64_t deadline_get(void)
{
    return g_deadline;
}

int deadline_expired(void)
{
    return g_deadline != 0 && cntvct() >= g_deadline;
}

/* ── Multi-arm periodic timers (%tset / %tcan) ───────────────────────────── */
/*
 * Each arm: absolute next fire time + period in CNTVCT ticks.
 * On fire: enqueue [%ei id %TICK 0], then next = now + period (slip on overrun).
 * Legacy g_deadline (%tmrarm) is independent — step-timeout, not IEC periods.
 */

typedef struct {
    int      active;
    uint64_t id;
    uint64_t period;
    uint64_t next;
    noun     i2_token;   /* NOUN_ZERO = I1 TICK path; else I2 reinjection */
    noun     i2_event_cell; /* prebuilt queue node for one-shot I2 fire */
} tarm_t;

static tarm_t g_tarms[TARM_MAX];
static uint64_t atom_u64_early(noun a);
static noun make_i2_timer_event(noun token, uint64_t fired_at);
static int evq_enq_timed(noun event, uint64_t admitted_tick,
                         uint64_t timer_due_tick, uint64_t flags);
static int evq_enq_prebuilt(noun cell, uint64_t admitted_tick,
                            uint64_t timer_due_tick, uint64_t flags);

static int tarm_find(uint64_t id)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active && g_tarms[i].id == id)
            return i;
    }
    return -1;
}

/* I2 lifecycle identity is the whole [generation incarnation owner sequence]
 * token.  Owner-only lookup was a D0 shortcut and aliases successive requests
 * from one instance, making cancellation and duplicate detection unsound. */
static int tarm_find_i2(noun token)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active && g_tarms[i].i2_token != NOUN_ZERO
            && noun_eq(g_tarms[i].i2_token, token))
            return i;
    }
    return -1;
}

static int tarm_free_slot(void)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (!g_tarms[i].active)
            return i;
    }
    return -1;
}

void tarm_set(uint64_t id, uint64_t period)
{
    tarm_set_i2(id, period, NOUN_ZERO);
}

/* I2: arm period and retain token for [%i2-timer token fired-at] reinjection */
void tarm_set_i2(uint64_t id, uint64_t period, noun i2_token)
{
    if (period == 0) {
        tarm_can(id);
        return;
    }
    int i = noun_is_cell(i2_token) ? tarm_find_i2(i2_token) : tarm_find(id);
    if (i < 0) {
        i = tarm_free_slot();
        if (i < 0)
            return;   /* full — silent drop (host capacity limit) */
    } else if (g_tarms[i].i2_token != NOUN_ZERO) {
        cell_dec(g_tarms[i].i2_token);
        g_tarms[i].i2_token = NOUN_ZERO;
    }
    g_tarms[i].active = 1;
    g_tarms[i].id     = id;
    g_tarms[i].period = period;
    g_tarms[i].next   = cntvct() + period;
    /* Retain full I2 cell tokens in PERSIST heap for reinjection after scratch reset */
    if (i2_token != NOUN_ZERO && noun_is_cell(i2_token)) {
        g_tarms[i].i2_token = noun_persist(i2_token);
        int old = heap_get_mode();
        heap_set_mode(HEAP_MODE_PERSIST);
        g_tarms[i].i2_event_cell = alloc_cell(
            make_i2_timer_event(g_tarms[i].i2_token, 0), NOUN_ZERO);
        heap_set_mode(old);
    } else {
        g_tarms[i].i2_token = NOUN_ZERO;
        g_tarms[i].i2_event_cell = NOUN_ZERO;
    }
    runtime_stats_count(RT_COUNT_TIMER_ARMS, 1);
}

static void tarm_can_i2(noun token)
{
    int i = noun_is_cell(token) ? tarm_find_i2(token) : tarm_find(atom_u64_early(token));
    if (i >= 0) {
        if (g_tarms[i].i2_token != NOUN_ZERO)
            cell_dec(g_tarms[i].i2_token);
        g_tarms[i].i2_token = NOUN_ZERO;
        g_tarms[i].i2_event_cell = NOUN_ZERO;
        g_tarms[i].active = 0;
        runtime_stats_count(RT_COUNT_TIMER_CANCELS, 1);
    }
}

void tarm_can(uint64_t id)
{
    int i = tarm_find(id);
    if (i >= 0) {
        if (g_tarms[i].i2_token != NOUN_ZERO) {
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
            g_tarms[i].i2_event_cell = NOUN_ZERO;
        }
        g_tarms[i].active = 0;
        g_tarms[i].i2_event_cell = NOUN_ZERO;
        runtime_stats_count(RT_COUNT_TIMER_CANCELS, 1);
    }
}

void tarm_clear(void)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].i2_token != NOUN_ZERO) {
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
        }
        g_tarms[i].i2_event_cell = NOUN_ZERO;
        g_tarms[i].active = 0;
    }
}

int tarm_active(uint64_t id)
{
    return tarm_find(id) >= 0;
}

uint64_t tarm_next(uint64_t id)
{
    int i = tarm_find(id);
    if (i < 0)
        return 0;
    return g_tarms[i].next;
}

static uint64_t atom_u64_early(noun a)
{
    if (noun_is_direct(a))
        return direct_val(a);
    return 0;
}

static noun make_tick_event(uint64_t id)
{
    /* [%ei id %TICK 0]  ≡  [ei [id [TICK 0]]] — allocate in persist for queue */
    int old = heap_get_mode();
    heap_set_mode(HEAP_MODE_PERSIST);
    noun ev = alloc_cell(direct(CORD_EI),
              alloc_cell(direct(id),
              alloc_cell(direct(CORD_TICK), NOUN_ZERO)));
    heap_set_mode(old);
    return ev;
}

static noun make_i2_timer_event(noun token, uint64_t fired_at)
{
    /* [%i2-timer token fired-at] — token already persist-retained on arm */
    int old = heap_get_mode();
    heap_set_mode(HEAP_MODE_PERSIST);
    noun tag = cord_from_bytes("i2-timer", 8);
    noun ev  = alloc_cell(tag, alloc_cell(token, direct(fired_at)));
    heap_set_mode(old);
    return ev;
}

/* [%i2-service token [status-code detail] data]  (HostRunner instant complete) */
static noun make_i2_service_event(noun token)
{
    int old = heap_get_mode();
    heap_set_mode(HEAP_MODE_PERSIST);
    noun tag = cord_from_bytes("i2-service", 10);
    noun tok = noun_is_cell(token) ? noun_copy(token) : token;
    noun st  = alloc_cell(direct(0), direct(0));           /* status, detail */
    noun ev  = alloc_cell(tag, alloc_cell(tok, alloc_cell(st, NOUN_ZERO)));
    heap_set_mode(old);
    return ev;
}

static int make_i2_service_event_checked(noun token, noun *out)
{
    static const uint64_t tag_limbs[2] = {
        0x69767265732d3269ULL, /* "i2-servi" */
        0x0000000000006563ULL  /* "ce" */
    };
    noun tag, tok = token, status, body1, body0;
    if (!make_atom_checked(tag_limbs, 2, &tag)
        || (noun_is_cell(token) && !noun_copy_checked(token, &tok)))
        return 0;
    return alloc_cell_checked(direct(0), direct(0), &status)
        && alloc_cell_checked(status, NOUN_ZERO, &body1)
        && alloc_cell_checked(tok, body1, &body0)
        && alloc_cell_checked(tag, body0, out);
}

/* CNTVCT ticks for delay_ns (I2 §16.2 publish conversion). */
static uint64_t ns_to_cntvct_ticks(uint64_t delay_ns)
{
    uint64_t frq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    if (frq == 0)
        frq = 54000000ULL; /* fallback Pi4-class */
    /* ticks = delay_ns * frq / 1e9 ; avoid overflow */
    if (delay_ns >= 1000000000ULL) {
        uint64_t sec = delay_ns / 1000000000ULL;
        uint64_t rem = delay_ns % 1000000000ULL;
        uint64_t t = sec * frq + (rem * frq) / 1000000000ULL;
        return t ? t : 1;
    }
    uint64_t t = (delay_ns * frq) / 1000000000ULL;
    return t ? t : 1;
}

/* timer-token ::= [gen [inc [owner seq]]] → owner; bare atom → owner (test alias) */
static uint64_t i2_token_owner(noun token)
{
    if (noun_is_atom(token))
        return atom_u64_early(token);
    if (!noun_is_cell(token))
        return 0;
    cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(token);
    /* skip gen */
    if (!noun_is_cell(c0->tail))
        return 0;
    cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
    /* skip inc */
    if (!noun_is_cell(c1->tail))
        return 0;
    cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
    return atom_u64_early(c2->head);
}

static int i2_token_valid(noun token)
{
    if (!noun_is_cell(token))
        return 0;
    cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(token);
    if (!noun_is_atom(c0->head) || atom_u64_early(c0->head) == 0 || !noun_is_cell(c0->tail))
        return 0;
    cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
    if (!noun_is_atom(c1->head) || atom_u64_early(c1->head) == 0 || !noun_is_cell(c1->tail))
        return 0;
    cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
    if (!noun_is_atom(c2->head) || atom_u64_early(c2->head) == 0 || !noun_is_atom(c2->tail))
        return 0;
    return atom_u64_early(c2->tail) != 0;
}

static int tag_is_name(noun tag, const char *name)
{
    char buf[48];
    size_t n = cord_to_cstr(tag, buf, sizeof buf);
    size_t m = 0;
    while (name[m])
        m++;
    if (n != m)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (buf[i] != name[i])
            return 0;
    return 1;
}

/* Indirect long-cord match via BLAKE3-62 identity (no atom-store decode). */
static int tag_is_h62(noun tag, uint64_t h62)
{
    return noun_is_indirect(tag) && (indirect_hash(tag) == h62);
}

static int tag_is_i2_timer_set(noun tag, uint64_t t)
{
    return t == CORD_I2TS
        || tag_is_h62(tag, H62_I2_TIMER_SET)
        || tag_is_name(tag, "i2-timer-set");
}

static int tag_is_i2_timer_cancel(noun tag, uint64_t t)
{
    return t == CORD_I2TC
        || tag_is_h62(tag, H62_I2_TIMER_CANCEL)
        || tag_is_name(tag, "i2-timer-cancel");
}

static int tag_is_i2_service_request(noun tag, uint64_t t)
{
    return t == CORD_I2SR
        || tag_is_h62(tag, H62_I2_SERVICE_REQUEST)
        || tag_is_name(tag, "i2-service-request");
}

static int tag_is_i2_service_cancel(noun tag, uint64_t t)
{
    return t == CORD_I2SC
        || tag_is_h62(tag, H62_I2_SERVICE_CANCEL)
        || tag_is_name(tag, "i2-service-cancel");
}

void tarm_force_due(uint64_t id)
{
    int i = tarm_find(id);
    if (i < 0)
        return;
    uint64_t now = cntvct();
    g_tarms[i].next = (now > 0) ? now - 1 : 0;
}

void tarm_poll(void)
{
    uint64_t now = cntvct();
    for (int i = 0; i < TARM_MAX; i++) {
        if (!g_tarms[i].active)
            continue;
        if (now < g_tarms[i].next)
            continue;
        if (g_tarms[i].i2_token != NOUN_ZERO) {
            /* I2 timer requests are one-shot.  The next E_CYCLE request has
             * a new full sequence token; retaining this arm aliases tokens
             * and exhausts the bounded registry after repeated periods. */
            /* The queue node and event noun were reserved when the timer was
             * armed.  Update only the diagnostic fired-at atom, then append. */
            noun event = ((cell_t *)(uintptr_t)cell_ptr(g_tarms[i].i2_event_cell))->head;
            cell_t *outer = (cell_t *)(uintptr_t)cell_ptr(event);
            cell_t *body = (cell_t *)(uintptr_t)cell_ptr(outer->tail);
            body->tail = direct(now);
            uint64_t due = g_tarms[i].next;
            (void)evq_enq_prebuilt(
                g_tarms[i].i2_event_cell, now, due, 1);
            runtime_stats_count(RT_COUNT_TIMER_FIRES, 1);
            runtime_stats_max(
                RT_COUNT_TIMER_LATENESS_MAX, now >= due ? now - due : 0);
            {
                uint64_t enqueued = runtime_counter_now();
                runtime_stats_record(
                    RT_PHASE_TIMER_DUE_TO_ENQUEUE,
                    enqueued >= due ? enqueued - due : 0);
            }
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
            g_tarms[i].i2_event_cell = NOUN_ZERO;
            g_tarms[i].active = 0;
        } else {
            uint64_t due = g_tarms[i].next;
            (void)evq_enq_timed(
                make_tick_event(g_tarms[i].id), now, due, 1);
            runtime_stats_count(RT_COUNT_TIMER_FIRES, 1);
            runtime_stats_max(
                RT_COUNT_TIMER_LATENESS_MAX, now >= due ? now - due : 0);
            {
                uint64_t enqueued = runtime_counter_now();
                runtime_stats_record(
                    RT_PHASE_TIMER_DUE_TO_ENQUEUE,
                    enqueued >= due ? enqueued - due : 0);
            }
            /* Legacy %tset is periodic and slips rather than catching up. */
            g_tarms[i].next = now + g_tarms[i].period;
        }
    }
}

/* ── Phase 3 — MMIO ──────────────────────────────────────────────────────── */

uint32_t mmio_read32(uint64_t addr)
{
    return *(volatile uint32_t *)(uintptr_t)addr;
}

void mmio_write32(uint64_t addr, uint32_t val)
{
    *(volatile uint32_t *)(uintptr_t)addr = val;
}

/* RAM scratch so tests can MMIO! without touching real peripherals */
static uint32_t g_mmio_scratch;

uint64_t mmio_scratch_addr(void)
{
    return (uint64_t)(uintptr_t)&g_mmio_scratch;
}

/* ── Phase 2 — FIFO event queue (WP4 capped) ─────────────────────────────── */
/*
 * Capacity EVQ_CAP. Policy: drop-newest (refuse enqueue when full).
 * Preserves earlier FIFO order; increments overflow counter + T_OVF.
 * Length maintained O(1) so enq does not walk the list for the cap check.
 */
#ifndef EVQ_CAP
#define EVQ_CAP  256u
#endif

static noun     g_evq;
static noun     g_evq_tail;   /* last cell for O(1) append */
static uint64_t g_evq_n;
static uint64_t g_evq_hwm;
static uint64_t g_evq_overflows;
static int      g_ovf_uart;   /* UART "overflow" once until QCLR */

typedef struct {
    uint64_t admitted_tick;
    uint64_t timer_due_tick;
    uint64_t flags;
} evq_timing_t;

#define EVQ_TIMING_TIMER    1u
#define EVQ_TIMING_RESTORED 2u

static evq_timing_t g_evq_timing[EVQ_CAP];
static evq_timing_t g_evq_timing_candidate[EVQ_CAP];
static uint32_t g_evq_timing_head;

static int i2_preflight_effects(noun effects, noun causes,
                                int consume_queued);

static void evq_note_depth(void)
{
    if (g_evq_n > g_evq_hwm)
        g_evq_hwm = g_evq_n;
    runtime_stats_max(RT_COUNT_QUEUE_HWM, g_evq_n);
}

static void evq_note_overflow(void)
{
    g_evq_overflows++;
    runtime_stats_count(RT_COUNT_QUEUE_OVERFLOWS, 1);
    trace_rec(T_OVF, (uint32_t)g_evq_overflows);
}

void evq_clear(void)
{
    g_evq            = NOUN_ZERO;
    g_evq_tail       = NOUN_ZERO;
    g_evq_n          = 0;
    g_ovf_uart       = 0;
    g_evq_timing_head = 0;
    /* keep hwm + overflow totals across clear for session metrics */
}

uint64_t evq_cap(void)
{
    return EVQ_CAP;
}

uint64_t evq_hwm(void)
{
    return g_evq_hwm;
}

uint64_t evq_overflows(void)
{
    return g_evq_overflows;
}

void evq_metrics_reset(void)
{
    g_evq_hwm       = g_evq_n;
    g_evq_overflows = 0;
    g_ovf_uart      = 0;
}

static int evq_enq_timed(noun event, uint64_t admitted_tick,
                         uint64_t timer_due_tick, uint64_t flags)
{
    if (g_evq_n >= EVQ_CAP) {
        evq_note_overflow();
        if (!g_ovf_uart) {
            g_ovf_uart = 1;
            uart_puts("overflow\r\n");
        }
        return 0;   /* drop-newest */
    }

    /* Queue lives in PERSIST so scratch reset cannot free pending events */
    int old = heap_get_mode();
    heap_set_mode(HEAP_MODE_PERSIST);
    noun ev   = noun_copy(event);
    noun cell = alloc_cell(ev, NOUN_ZERO);
    heap_set_mode(old);

    if (!noun_is_cell(g_evq)) {
        g_evq      = cell;
        g_evq_tail = cell;
    } else {
        cell_t *t = (cell_t *)(uintptr_t)cell_ptr(g_evq_tail);
        t->tail    = cell;
        g_evq_tail = cell;
    }
    uint32_t timing_slot =
        (g_evq_timing_head + (uint32_t)g_evq_n) & (EVQ_CAP - 1u);
    g_evq_timing[timing_slot].admitted_tick = admitted_tick;
    g_evq_timing[timing_slot].timer_due_tick = timer_due_tick;
    g_evq_timing[timing_slot].flags = flags;
    g_evq_n++;
    evq_note_depth();
    return 1;
}

void evq_enq(noun event)
{
    (void)evq_enq_timed(event, runtime_counter_now(), 0, 0);
}

/* Transaction-reserved queue node: append without copying or allocation. */
static int evq_enq_prebuilt(noun cell, uint64_t admitted_tick,
                            uint64_t timer_due_tick, uint64_t flags)
{
    if (g_evq_n >= EVQ_CAP) {
        evq_note_overflow();
        return 0;
    }
    if (!noun_is_cell(g_evq)) {
        g_evq = cell;
        g_evq_tail = cell;
    } else {
        ((cell_t *)(uintptr_t)cell_ptr(g_evq_tail))->tail = cell;
        g_evq_tail = cell;
    }
    uint32_t timing_slot =
        (g_evq_timing_head + (uint32_t)g_evq_n) & (EVQ_CAP - 1u);
    g_evq_timing[timing_slot].admitted_tick = admitted_tick;
    g_evq_timing[timing_slot].timer_due_tick = timer_due_tick;
    g_evq_timing[timing_slot].flags = flags;
    g_evq_n++;
    evq_note_depth();
    return 1;
}

static int evq_deq_timed(noun *out, evq_timing_t *timing)
{
    if (!noun_is_cell(g_evq))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(g_evq);
    *out = c->head;
    if (timing)
        *timing = g_evq_timing[g_evq_timing_head];
    g_evq_timing_head = (g_evq_timing_head + 1u) & (EVQ_CAP - 1u);
    g_evq = c->tail;
    if (g_evq_n > 0)
        g_evq_n--;
    if (!noun_is_cell(g_evq))
        g_evq_tail = NOUN_ZERO;
    return 1;
}

static int evq_peek_timed(noun *out, evq_timing_t *timing)
{
    if (!noun_is_cell(g_evq))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(g_evq);
    *out = c->head;
    if (timing)
        *timing = g_evq_timing[g_evq_timing_head];
    return 1;
}

int evq_deq(noun *out)
{
    return evq_deq_timed(out, 0);
}

int evq_peek(noun *out)
{
    return evq_peek_timed(out, 0);
}

uint64_t evq_len(void)
{
    return g_evq_n;
}

void evq_enq_list(noun list)
{
    while (noun_is_cell(list)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(list);
        evq_enq(c->head);
        list = c->tail;
    }
}

uint64_t kernel_queue_pressure_selftest(uint64_t percent)
{
    uint64_t failures = 0;
    if (percent != 0 && percent != 50 && percent != 90)
        return 1;
    if (g_evq_n != 0)
        return 2;

    uint64_t target = (EVQ_CAP * percent) / 100;
    runtime_stats_set(RT_COUNT_PRESSURE_PERCENT, percent);
    runtime_stats_set(RT_COUNT_PRESSURE_DEPTH, target);
    evq_metrics_reset();
    for (uint64_t i = 0; i < target; i++)
        evq_enq(direct(i + 1));
    if (g_evq_n != target || g_evq_hwm != target
        || g_evq_overflows != 0)
        failures |= 1ULL << 0;
    for (uint64_t i = 0; i < target; i++) {
        noun event = NOUN_ZERO;
        if (!evq_deq(&event) || event != direct(i + 1))
            failures |= 1ULL << 1;
    }
    if (g_evq_n != 0)
        failures |= 1ULL << 2;

    /* Each case also proves the full/drop-newest rejection edge. */
    evq_metrics_reset();
    for (uint64_t i = 0; i < EVQ_CAP; i++)
        evq_enq(direct(i + 1));
    evq_enq(direct(EVQ_CAP + 1));
    runtime_stats_count(RT_COUNT_EXPECTED_PRESSURE_REJECTS, 1);
    if (g_evq_n != EVQ_CAP || g_evq_overflows != 1)
        failures |= 1ULL << 3;
    for (uint64_t i = 0; i < EVQ_CAP; i++) {
        noun event = NOUN_ZERO;
        if (!evq_deq(&event) || event != direct(i + 1))
            failures |= 1ULL << 4;
    }
    if (g_evq_n != 0)
        failures |= 1ULL << 5;
    evq_clear();
    return failures;
}

uint64_t kernel_queue_retry_selftest(void)
{
    uint64_t failures = 0;
    noun event = NOUN_ZERO;
    evq_timing_t timing = {0};
    if (g_evq_n != 0)
        return 1;

    evq_enq(direct(0x51));
    evq_enq(direct(0x52));
    noun retained_head = g_evq;
    uint64_t retained_n = g_evq_n;
    if (!evq_peek_timed(&event, &timing) || event != direct(0x51)
        || g_evq != retained_head || g_evq_n != retained_n)
        failures |= 1ULL << 0;

    /* A failed I2 preflight is a retry boundary: the peeked FIFO head and
     * its timing metadata stay live until a later successful publication. */
    if (i2_preflight_effects(direct(1), NOUN_ZERO, 1)
        || g_evq != retained_head || g_evq_n != retained_n
        || !evq_peek_timed(&event, &timing) || event != direct(0x51))
        failures |= 1ULL << 1;

    if (!evq_deq_timed(&event, &timing) || event != direct(0x51)
        || !evq_deq_timed(&event, &timing) || event != direct(0x52)
        || g_evq_n != 0)
        failures |= 1ULL << 2;
    evq_clear();
    return failures;
}

/*
 * Persist semispace compaction (ArenaHost-shaped).
 *
 * Call while SCRATCH holds the slam product and the *current* persist half
 * still holds the previous gate/queue/tokens (readable).
 *
 * Flip to the empty half, deep-copy live roots there (may still read old half
 * for shared battery cells), abandon the old half until the next flip.
 *
 * Caller must retain scratch until after the corresponding activation pass
 * (the effect nouns remain in scratch until UART activation completes).
 */
static int candidate_enqueue(noun event, int copy_event,
                             evq_timing_t timing, noun *head,
                             noun *tail, uint64_t *count)
{
    noun retained = event, node;
    if ((copy_event && !noun_copy_checked(event, &retained))
        || !alloc_cell_checked(retained, NOUN_ZERO, &node))
        return 0;
    if (!noun_is_cell(*head))
        *head = *tail = node;
    else {
        ((cell_t *)(uintptr_t)cell_ptr(*tail))->tail = node;
        *tail = node;
    }
    if (*count >= EVQ_CAP)
        return 0;
    g_evq_timing_candidate[*count] = timing;
    (*count)++;
    return 1;
}

static int persist_compact(noun new_gate, noun new_causes, noun effects,
                           int consume_queued, noun *slam_out)
{
    enum { QCAP = 256 };
    if (!slam_out)
        return 0;

    /* Capture queue chain head before we rebuild (still in old half) */
    noun old_q = g_evq;
    uint32_t old_timing_head = g_evq_timing_head;
    if (consume_queued) {
        if (!noun_is_cell(old_q) || g_evq_n == 0)
            return 0;
        old_q = ((cell_t *)(uintptr_t)cell_ptr(old_q))->tail;
        old_timing_head = (old_timing_head + 1u) & (EVQ_CAP - 1u);
    }
    tarm_t candidate_tarms[TARM_MAX];
    for (int i = 0; i < TARM_MAX; i++) {
        candidate_tarms[i] = g_tarms[i];
        candidate_tarms[i].i2_token =
            (g_tarms[i].active && noun_is_cell(g_tarms[i].i2_token))
                ? NOUN_ONE : NOUN_ZERO; /* copy below in candidate space */
        candidate_tarms[i].i2_event_cell = NOUN_ZERO;
    }

    /* Write into the other semispace; old half remains readable */
    heap_persist_begin_tx();
    heap_set_mode(HEAP_MODE_PERSIST);

    /* Build every candidate root without publishing a live root. */
    noun candidate_gate;
    noun candidate_q = NOUN_ZERO;
    noun candidate_tail = NOUN_ZERO;
    uint64_t candidate_n = 0;
    noun candidate_completions[I2_MAX_PENDING_SERVICES];
    int candidate_completion_n = 0;
    uint64_t candidate_timer_arms = 0;
    uint64_t candidate_timer_cancels = 0;
    if (!noun_copy_checked(new_gate, &candidate_gate))
        goto alloc_fail;

    /* Prior queue events (old half) then new causes (scratch) */
    {
        noun q = old_q;
        uint64_t n = 0;
        while (noun_is_cell(q) && n < QCAP) {
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(q);
            evq_timing_t timing = g_evq_timing[
                (old_timing_head + (uint32_t)n) & (EVQ_CAP - 1u)];
            if (!candidate_enqueue(
                    c->head, 1, timing,
                    &candidate_q, &candidate_tail, &candidate_n))
                goto alloc_fail;
            q = c->tail;
            n++;
        }
    }
    while (noun_is_cell(new_causes)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(new_causes);
        evq_timing_t timing = {0};
        if (!candidate_enqueue(
                c->head, 1, timing,
                &candidate_q, &candidate_tail, &candidate_n))
            goto alloc_fail;
        new_causes = c->tail;
    }

    for (int i = 0; i < TARM_MAX; i++) {
        if (candidate_tarms[i].i2_token != NOUN_ZERO) {
            if (!noun_copy_checked(
                    g_tarms[i].i2_token, &candidate_tarms[i].i2_token)
                || !make_timer_event_checked(
                    candidate_tarms[i].i2_token,
                    &candidate_tarms[i].i2_event_cell))
                goto alloc_fail;
        }
    }

    /* Materialize every timer token and instant service completion before the
     * publication point.  Activation below only copies this candidate array
     * and writes UART bytes; it does not allocate or enqueue. */
    noun fxcur = effects;
    while (noun_is_cell(fxcur)) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(fxcur);
        cell_t *fx = (cell_t *)(uintptr_t)cell_ptr(list->head);
        noun tag = fx->head;
        noun data = fx->tail;
        uint64_t t = noun_is_direct(tag) ? direct_val(tag) : 0;
        if (tag_is_i2_timer_set(tag, t)) {
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
            noun token = c->head;
            int slot = -1;
            for (int i = 0; i < TARM_MAX; i++)
                if (!candidate_tarms[i].active) { slot = i; break; }
            if (slot < 0)
                nock_crash("preflight/timer candidate divergence");
            candidate_tarms[slot].active = 1;
            candidate_tarms[slot].id = i2_token_owner(token);
            candidate_tarms[slot].period = ns_to_cntvct_ticks(atom_u64_early(c->tail));
            candidate_tarms[slot].next = cntvct() + candidate_tarms[slot].period;
            if (!noun_copy_checked(token, &candidate_tarms[slot].i2_token)
                || !make_timer_event_checked(
                    candidate_tarms[slot].i2_token,
                    &candidate_tarms[slot].i2_event_cell))
                goto alloc_fail;
            candidate_timer_arms++;
        } else if (tag_is_i2_timer_cancel(tag, t)) {
            int slot = -1;
            for (int i = 0; i < TARM_MAX; i++)
                if (candidate_tarms[i].active
                    && candidate_tarms[i].i2_token != NOUN_ZERO
                    && noun_eq(candidate_tarms[i].i2_token, data)) { slot = i; break; }
            if (slot < 0)
                nock_crash("preflight/timer cancel divergence");
            candidate_tarms[slot].active = 0;
            candidate_tarms[slot].i2_token = NOUN_ZERO;
            candidate_tarms[slot].i2_event_cell = NOUN_ZERO;
            candidate_timer_cancels++;
        } else if (tag_is_i2_service_request(tag, t)) {
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
            noun completion;
            if (candidate_completion_n >= I2_MAX_PENDING_SERVICES
                || !make_i2_service_event_checked(c->head, &completion)
                || !candidate_enqueue(
                    completion, 0, (evq_timing_t){0},
                    &candidate_q, &candidate_tail, &candidate_n))
                goto alloc_fail;
            candidate_completions[candidate_completion_n++] = completion;
        }
        fxcur = list->tail;
    }

    /* The fixed slam formula is a persistent root too.  Materialize it before
     * publication so formula allocation can still abort the transaction. */
    noun candidate_slam;
    if (!build_slam_formula_checked(&candidate_slam))
        goto alloc_fail;

    /* The one publication point: no candidate allocation follows. */
    uint64_t publication_tick = runtime_counter_now();
    for (uint64_t i = 0; i < candidate_n; i++) {
        if (g_evq_timing_candidate[i].admitted_tick == 0)
            g_evq_timing_candidate[i].admitted_tick = publication_tick;
    }
    g_kernel = candidate_gate;
    g_slam_formula = candidate_slam;
    g_evq = candidate_q;
    g_evq_tail = candidate_tail;
    g_evq_n = candidate_n;
    g_evq_timing_head = 0;
    for (uint64_t i = 0; i < candidate_n; i++)
        g_evq_timing[i] = g_evq_timing_candidate[i];
    if (g_evq_n > g_evq_hwm)
        g_evq_hwm = g_evq_n;
    for (int i = 0; i < TARM_MAX; i++)
        g_tarms[i] = candidate_tarms[i];
    for (int i = 0; i < candidate_completion_n; i++)
        g_activation_completions[i] = candidate_completions[i];
    g_activation_completion_n = candidate_completion_n;
    heap_persist_commit_tx();
    runtime_stats_count(RT_COUNT_TIMER_ARMS, candidate_timer_arms);
    runtime_stats_count(RT_COUNT_TIMER_CANCELS, candidate_timer_cancels);
    runtime_stats_note_memory();
    *slam_out = candidate_slam;
    return 1;

alloc_fail:
    heap_persist_abort_tx();
    return 0;
}

static int promotion_depth_selftest(void)
{
    noun old_kernel = g_kernel;
    noun old_slam = g_slam_formula;
    noun old_q = g_evq;
    noun old_tail = g_evq_tail;
    uint64_t old_qn = g_evq_n;
    uint64_t old_cells = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t old_atoms = atom_store_bytes_used();
    int old_completion_n = g_activation_completion_n;
    tarm_t old_tarms[TARM_MAX];
    for (int i = 0; i < TARM_MAX; i++)
        old_tarms[i] = g_tarms[i];

    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return 0;
    noun deep = NOUN_ZERO, node;
    for (int i = 0; i < 256; i++) {
        if (!alloc_cell_checked(NOUN_ZERO, deep, &node)) {
            noun_tx_abort();
            return 0;
        }
        deep = node;
    }

    noun unused_slam;
    int rejected = !persist_compact(
        deep, NOUN_ZERO, NOUN_ZERO, 0, &unused_slam);
    int unchanged = rejected
        && g_kernel == old_kernel && g_slam_formula == old_slam
        && g_evq == old_q && g_evq_tail == old_tail && g_evq_n == old_qn
        && heap_cells_used(HEAP_MODE_PERSIST) == old_cells
        && atom_store_bytes_used() == old_atoms
        && g_activation_completion_n == old_completion_n;
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active != old_tarms[i].active
            || g_tarms[i].id != old_tarms[i].id
            || g_tarms[i].period != old_tarms[i].period
            || g_tarms[i].next != old_tarms[i].next
            || g_tarms[i].i2_token != old_tarms[i].i2_token
            || g_tarms[i].i2_event_cell != old_tarms[i].i2_event_cell)
            unchanged = 0;
    }
    noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return unchanged;
}

/* ── Phase 3 — IRQ ring (SPSC; capacity SIZE-1) ───────────────────────────── */

#define IRQ_RING_SIZE 64

static volatile uint32_t irq_head;
static volatile uint32_t irq_tail;
static uint64_t irq_slot[IRQ_RING_SIZE];

void irq_ring_clear(void)
{
    irq_head = 0;
    irq_tail = 0;
}

int irq_ring_push(uint64_t code)
{
    uint32_t h = irq_head;
    uint32_t n = (h + 1u) % IRQ_RING_SIZE;
    if (n == irq_tail)
        return 0;   /* full */
    irq_slot[h] = code;
    irq_head = n;
    return 1;
}

static int irq_ring_pop(uint64_t *out)
{
    uint32_t t = irq_tail;
    if (t == irq_head)
        return 0;
    *out = irq_slot[t];
    irq_tail = (t + 1u) % IRQ_RING_SIZE;
    return 1;
}

void irq_ring_drain(void)
{
    uint64_t code;
    while (irq_ring_pop(&code))
        evq_enq(direct(code));
}

/* ── UART noun framing ────────────────────────────────────────────────────── */

noun uart_recv_noun(void) {
    uint64_t nbytes = 0;
    for (int i = 0; i < 8; i++)
        nbytes |= (uint64_t)(uint8_t)uart_getc() << (i * 8);

    if (nbytes == 0) return NOUN_ZERO;
    if (nbytes > UART_RXBUF_SIZE) nbytes = UART_RXBUF_SIZE;

    uint8_t *buf = (uint8_t *)UART_RXBUF_BASE;
    uart_read_bytes(buf, nbytes);

    uint64_t nbytes_padded = (nbytes + 7) & ~(uint64_t)7;
    for (uint64_t i = nbytes; i < nbytes_padded; i++) buf[i] = 0;

    uint64_t nlimbs = nbytes_padded / 8;
    while (nlimbs > 1 && ((uint64_t *)buf)[nlimbs - 1] == 0) nlimbs--;

    noun jam_atom = make_atom((uint64_t *)buf, nlimbs);
    return cue(jam_atom);
}

void uart_send_noun(noun n) {
    noun a = jam(n);
    const uint8_t *data;
    uint64_t nbytes;
    uint8_t direct_bytes[8];

    if (noun_is_direct(a)) {
        uint64_t val = direct_val(a);
        nbytes = 0;
        for (int i = 0; i < 8; i++) {
            direct_bytes[i] = (uint8_t)(val & 0xFF);
            if (direct_bytes[i]) nbytes = (uint64_t)i + 1;
            val >>= 8;
        }
        if (nbytes == 0) nbytes = 1;
        data = direct_bytes;
    } else {
        atom_t *at = atom_store_get(indirect_hash(a));
        if (!at) return;
        data   = (const uint8_t *)at->limbs;
        nbytes = at->size * 8;
        while (nbytes > 1 && data[nbytes - 1] == 0) nbytes--;
    }

    uint8_t hdr[8];
    for (int i = 0; i < 8; i++) hdr[i] = (uint8_t)(nbytes >> (i * 8));
    uart_write_bytes(hdr, 8);
    uart_write_bytes(data, nbytes);
}

/* ── Effect dispatch ──────────────────────────────────────────────────────── */

static void atom_print_uart(noun a) {
    if (noun_is_direct(a)) {
        uint64_t val = direct_val(a);
        while (val) {
            uart_putc((char)(val & 0xFF));
            val >>= 8;
        }
    } else if (noun_is_indirect(a)) {
        atom_t *at = atom_store_get(indirect_hash(a));
        if (!at) return;
        const uint8_t *bytes = (const uint8_t *)at->limbs;
        uint64_t nbytes = at->size * 8;
        while (nbytes > 0 && bytes[nbytes - 1] == 0) nbytes--;
        for (uint64_t i = 0; i < nbytes; i++)
            uart_putc((char)bytes[i]);
    }
}

static uint64_t atom_u64(noun a)
{
    if (noun_is_direct(a))
        return direct_val(a);
    return 0;
}

/* I2 service-request payload → UART bytes.  Completion admission is handled
 * separately by the transaction candidate builder. */
static int atom_byte(noun atom, uint64_t offset, uint8_t *out)
{
    if (!noun_is_atom(atom) || !out)
        return 0;
    if (noun_is_direct(atom)) {
        uint64_t v = direct_val(atom);
        *out = offset < 8 ? (uint8_t)(v >> (offset * 8)) : 0;
        return 1;
    }
    atom_t *at = atom_store_get(indirect_hash(atom));
    if (!at)
        return 0;
    *out = offset < at->size * 8
        ? ((const uint8_t *)at->limbs)[offset] : 0;
    return 1;
}

static int i2_service_uart_print_bounded(noun data)
{
    /* service-request ::= [token [cap [op [deadline payload]]]] */
    if (!noun_is_cell(data))
        return 0;
    cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(data);
    if (!noun_is_cell(c0->tail))
        return 0;
    cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
    if (!noun_is_cell(c1->tail))
        return 0;
    cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
    if (!noun_is_cell(c2->tail))
        return 0;
    cell_t *c3 = (cell_t *)(uintptr_t)cell_ptr(c2->tail);
    uint64_t deadline_ns = atom_u64(c3->head);
    if (deadline_ns == 0 || deadline_ns > I2_UART_TX_MAX_NS)
        return 0;
    noun payload = c3->tail;
    /* typed STRING: [tid [len bytes-atom]] */
    if (!noun_is_cell(payload))
        return 0;
    cell_t *pv = (cell_t *)(uintptr_t)cell_ptr(payload);
    if (!noun_is_direct(pv->head) || direct_val(pv->head) == 0
        || !noun_is_cell(pv->tail))
        return 0;
    cell_t *sv = (cell_t *)(uintptr_t)cell_ptr(pv->tail);
    uint64_t len = atom_u64(sv->head);
    if (len > 256 || !noun_is_atom(sv->tail))
        return 0;
    uint64_t ticks = ns_to_cntvct_ticks(deadline_ns);
    uint64_t now = cntvct();
    uint64_t deadline = UINT64_MAX - now < ticks ? UINT64_MAX : now + ticks;
    for (uint64_t i = 0; i < len; i++) {
        uint8_t byte;
        if (!atom_byte(sv->tail, i, &byte)
            || !uart_putc_bounded((char)byte, deadline))
            return 0;
    }
    return 1;
}

/* Legacy direct dispatcher: print then allocate/enqueue an instant completion.
 * I2 commit activation uses dispatch_i2_activate() below instead. */
static void i2_service_uart_tx(noun data)
{
    noun token = noun_is_cell(data)
        ? ((cell_t *)(uintptr_t)cell_ptr(data))->head : NOUN_ZERO;
    (void)i2_service_uart_print_bounded(data);
    /* Instant completion (HostRunner instant_services): success status 0 */
    evq_enq(make_i2_service_event(token));
}

static void i2_service_completion_status(noun event, uint64_t code)
{
    if (!noun_is_cell(event))
        return;
    cell_t *outer = (cell_t *)(uintptr_t)cell_ptr(event);
    if (!noun_is_cell(outer->tail))
        return;
    cell_t *body0 = (cell_t *)(uintptr_t)cell_ptr(outer->tail);
    if (!noun_is_cell(body0->tail))
        return;
    cell_t *body1 = (cell_t *)(uintptr_t)cell_ptr(body0->tail);
    if (!noun_is_cell(body1->head))
        return;
    ((cell_t *)(uintptr_t)cell_ptr(body1->head))->head = direct(code);
}

static void dispatch_i2_activate(noun effects)
{
    /* This is intentionally guarded in production and QEMU: a future effect
     * implementation cannot silently reintroduce a post-publish allocation. */
    int completion_i = 0;
    heap_noalloc_begin();
    while (noun_is_cell(effects)) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(effects);
        cell_t *fx = (cell_t *)(uintptr_t)cell_ptr(list->head);
        noun tag = fx->head;
        noun data = fx->tail;
        uint64_t t = noun_is_direct(tag) ? direct_val(tag) : 0;
        if (tag_is_i2_service_request(tag, t)) {
            int ok = i2_service_uart_print_bounded(data);
            runtime_stats_count(
                ok ? RT_COUNT_SERVICE_SUCCESS : RT_COUNT_SERVICE_FAILURE, 1);
            if (completion_i < g_activation_completion_n)
                i2_service_completion_status(
                    g_activation_completions[completion_i], ok ? 0 : 6);
            completion_i++;
        }
        /* Timer set/cancel and service completion insertion were fully
         * materialized in persist_compact(); cancellation has no driver work. */
        effects = list->tail;
    }
    heap_noalloc_end();
    g_activation_completion_n = 0;
}

static int test_completion(noun token, uint64_t status_code, noun *out)
{
    if (!make_i2_service_event_checked(token, out))
        return 0;
    i2_service_completion_status(*out, status_code);
    return 1;
}

static int test_completion_code(noun event, uint64_t *out)
{
    noun tag, body0, token, body1, status, data, code, detail;
    return noun_take(event, &tag, &body0)
        && noun_take(body0, &token, &body1)
        && noun_take(body1, &status, &data)
        && noun_take(status, &code, &detail)
        && noun_is_direct(code)
        && ((*out = direct_val(code)), 1);
}

uint64_t kernel_tx_stuck_selftest(void)
{
    uint64_t failures = 0;
    noun n0, n1, token, payload, req3, req2, req1, request;
    noun effect, effects, completion0, completion1;

    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return UINT64_MAX;
    /* token = [1 1 7 1] */
    if (!alloc_cell_checked(direct(7), direct(1), &n0)
        || !alloc_cell_checked(direct(1), n0, &n1)
        || !alloc_cell_checked(direct(1), n1, &token)
        /* typed STRING = [1 [1 "X"]] */
        || !alloc_cell_checked(direct(1), direct('X'), &n0)
        || !alloc_cell_checked(direct(1), n0, &payload)
        /* request = [token [CAP_UART [op [1ms payload]]]] */
        || !alloc_cell_checked(direct(1000000), payload, &req3)
        || !alloc_cell_checked(direct(1), req3, &req2)
        || !alloc_cell_checked(direct(1), req2, &req1)
        || !alloc_cell_checked(token, req1, &request)
        || !alloc_cell_checked(
            indirect(H62_I2_SERVICE_REQUEST), request, &effect)
        || !alloc_cell_checked(effect, NOUN_ZERO, &effects)
        || !test_completion(token, 0, &completion0)
        || !test_completion(token, 99, &completion1)) {
        noun_tx_abort();
        heap_scratch_reset();
        return UINT64_MAX;
    }

    noun reserved_q = NOUN_ZERO, reserved_tail = NOUN_ZERO;
    uint64_t reserved_n = 0;
    if (!candidate_enqueue(
            completion0, 0, (evq_timing_t){0},
            &reserved_q, &reserved_tail, &reserved_n)
        || reserved_n != 1 || !noun_is_cell(reserved_q)
        || ((cell_t *)(uintptr_t)cell_ptr(reserved_q))->head != completion0) {
        noun_tx_abort();
        heap_scratch_reset();
        return UINT64_MAX;
    }
    noun reserved_completion =
        ((cell_t *)(uintptr_t)cell_ptr(reserved_q))->head;
    uint64_t cells_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms_before = atom_store_bytes_used();
    g_activation_completions[0] = completion0;
    g_activation_completions[1] = completion1;
    g_activation_completion_n = 1;
    uart_test_tx_stuck(1);
    dispatch_i2_activate(effects);
    uart_test_tx_stuck(0);

    uint64_t code0 = 0, code1 = 0;
    if (!test_completion_code(completion0, &code0) || code0 != 6)
        failures++;
    if (!test_completion_code(reserved_completion, &code0) || code0 != 6)
        failures++;
    if (!test_completion_code(completion1, &code1) || code1 != 99)
        failures++;
    if (g_activation_completion_n != 0)
        failures++;
    if (heap_cells_used(HEAP_MODE_SCRATCH) != cells_before
        || atom_store_bytes_used() != atoms_before)
        failures++;

    noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    if (!promotion_depth_selftest())
        failures++;
    return failures;
}

/*
 * I2 effect preflight before promote (Host ABI §12.5 subset).
 * On failure: do not replace g_kernel, do not dispatch, do not enqueue causes.
 */
static int i2_preflight_effects(noun effects, noun causes,
                                int consume_queued)
{
    int new_timers = 0;
    int new_svcs   = 0;
    noun seen[2 * TARM_MAX + I2_MAX_PENDING_SERVICES];
    int seen_n = 0;
    int live_tarms = 0;
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active)
            live_tarms++;
    }

    noun cur = effects;
    while (noun_is_cell(cur)) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(cur);
        noun head = list->head;
        cur = list->tail;
        if (!noun_is_cell(head))
            return 0;   /* malformed */
        cell_t *fx = (cell_t *)(uintptr_t)cell_ptr(head);
        noun tag = fx->head;
        noun data = fx->tail;
        if (!noun_is_atom(tag))
            return 0;
        uint64_t t = noun_is_direct(tag) ? direct_val(tag) : 0;

        if (tag_is_i2_timer_set(tag, t)) {
            if (!noun_is_cell(data))
                return 0;
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
            uint64_t delay = atom_u64(c->tail);
            if (delay == 0)
                return 0;
            if (!i2_token_valid(c->head))
                return 0;
            for (int i = 0; i < seen_n; i++)
                if (noun_eq(seen[i], c->head)) return 0;
            if (seen_n >= (int)(sizeof seen / sizeof seen[0])) return 0;
            seen[seen_n++] = c->head;
            if (tarm_find_i2(c->head) >= 0)
                return 0;
            new_timers++;
            if (live_tarms + new_timers > I2_MAX_TIMERS)
                return 0;
        } else if (tag_is_i2_timer_cancel(tag, t)) {
            if (!i2_token_valid(data))
                return 0;
            for (int i = 0; i < seen_n; i++)
                if (noun_eq(seen[i], data)) return 0;
            if (seen_n >= (int)(sizeof seen / sizeof seen[0])) return 0;
            seen[seen_n++] = data;
            if (tarm_find_i2(data) < 0)
                return 0; /* strict unknown-cancel */
            live_tarms--;
        } else if (tag_is_i2_service_request(tag, t)) {
            if (!noun_is_cell(data))
                return 0;
            cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(data);
            if (!i2_token_valid(c0->head))
                return 0;
            for (int i = 0; i < seen_n; i++)
                if (noun_eq(seen[i], c0->head)) return 0;
            if (seen_n >= (int)(sizeof seen / sizeof seen[0])) return 0;
            seen[seen_n++] = c0->head;
            if (!noun_is_cell(c0->tail))
                return 0;
            cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
            uint64_t cap = atom_u64(c1->head);
            if (cap != 1)   /* CAP_UART_OUTPUT */
                return 0;
            if (!noun_is_cell(c1->tail))
                return 0;
            cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
            if (!noun_is_cell(c2->tail))
                return 0;
            cell_t *c3 = (cell_t *)(uintptr_t)cell_ptr(c2->tail);
            uint64_t deadline = atom_u64(c3->head);
            if (deadline == 0 || deadline > I2_UART_TX_MAX_NS)
                return 0;
            noun payload = c3->tail;
            if (!noun_is_cell(payload))
                return 0;
            cell_t *pv = (cell_t *)(uintptr_t)cell_ptr(payload);
            if (!noun_is_direct(pv->head) || direct_val(pv->head) == 0
                || !noun_is_cell(pv->tail))
                return 0;
            cell_t *sv = (cell_t *)(uintptr_t)cell_ptr(pv->tail);
            if (!noun_is_direct(sv->head) || direct_val(sv->head) > 256
                || !noun_is_atom(sv->tail))
                return 0;
            new_svcs++;
            if (new_svcs > I2_MAX_PENDING_SERVICES)
                return 0;
        } else if (tag_is_i2_service_cancel(tag, t)) {
            /* Current UART service completes synchronously; it has no live
             * driver registry.  Therefore every cancel is an unknown cancel
             * and must reject rather than become a misleading no-op. */
            (void)data;
            return 0;
        } else {
            /* Unknown tag on I2 commit path → reject */
            return 0;
        }
    }
    /* improper list (non-null terminator) */
    if (cur != NOUN_ZERO && !noun_is_cell(cur))
        return 0;

    /* A commit's entire cause list and every instant service completion must
     * fit before promote.  evq_enq() remains drop-newest for asynchronous
     * ingress, but an I2 transaction never calls it speculatively. */
    uint64_t cause_n = 0;
    cur = causes;
    while (noun_is_cell(cur)) {
        cause_n++;
        if (cause_n > EVQ_CAP)
            return 0;
        cur = ((cell_t *)(uintptr_t)cell_ptr(cur))->tail;
    }
    if (cur != NOUN_ZERO)
        return 0;
    if (consume_queued && (!noun_is_cell(g_evq) || g_evq_n == 0))
        return 0;
    uint64_t retained_queue = g_evq_n - (consume_queued ? 1u : 0u);
    if (retained_queue + cause_n + (uint64_t)new_svcs > EVQ_CAP)
        return 0;
    return 1;
}

static void dispatch_one(noun tag, noun data) {
    if (!noun_is_atom(tag)) return;
    uint64_t t = noun_is_direct(tag) ? direct_val(tag) : 0;

    /* ── I2 Host ABI effects (full names + short direct aliases) ──────── */
    if (tag_is_i2_timer_set(tag, t)) {
        /* data = [token delay-ns] */
        if (!noun_is_cell(data))
            return;
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
        noun token = c->head;
        uint64_t delay_ns = atom_u64(c->tail);
        uint64_t owner = i2_token_owner(token);
        if (owner == 0)
            return;
        uint64_t ticks = ns_to_cntvct_ticks(delay_ns);
        tarm_set_i2(owner, ticks, token);
        return;
    }
    if (tag_is_i2_timer_cancel(tag, t)) {
        tarm_can_i2(data);
        return;
    }
    if (tag_is_i2_service_request(tag, t)) {
        i2_service_uart_tx(data);
        return;
    }
    if (tag_is_i2_service_cancel(tag, t)) {
        /* one-shot UART: no driver cancel in D0 substrate */
        return;
    }

    if (t == CORD_OUT || t == CORD_BLIT) {
        atom_print_uart(data);
        return;
    }
    if (t == CORD_TIMEOUT) {
        uart_puts("timeout\r\n");
        return;
    }
    if (t == CORD_MMIO) {
        /* data = [addr val] */
        if (!noun_is_cell(data)) return;
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
        uint64_t addr = atom_u64(c->head);
        uint32_t val  = (uint32_t)atom_u64(c->tail);
        mmio_write32(addr, val);
        return;
    }
    if (t == CORD_TMRARM) {
        deadline_set(atom_u64(data));
        return;
    }
    if (t == CORD_TMRCAN) {
        deadline_set(0);
        return;
    }
    if (t == CORD_TSET) {
        /* data = [id period] */
        if (!noun_is_cell(data)) return;
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(data);
        tarm_set(atom_u64(c->head), atom_u64(c->tail));
        return;
    }
    if (t == CORD_TCAN) {
        tarm_can(atom_u64(data));
        return;
    }
    if (t == CORD_IRQ) {
        evq_enq(data);
        return;
    }
    if (t == CORD_SWAPPED) {
        uart_puts("swapped\r\n");
        return;
    }
    if (t == CORD_WDT) {
        uart_puts("wdt\r\n");
        return;
    }
    if (t == CORD_ETX) {
        net_handle_etx(data);
        return;
    }
    if (t == CORD_MTX) {
        net_handle_mtx(data);
        return;
    }
    if (t == CORD_CTX) {
        net_handle_ctx(data);
        return;
    }
    /* WP4: unknown tag — always trace; UART once per session */
    {
        static int unk_uart;
        trace_rec(T_UFX, (uint32_t)t);
        if (!unk_uart) {
            unk_uart = 1;
            uart_puts("unkfx\r\n");
        }
    }
}

void dispatch_effects(noun effects) {
    while (noun_is_cell(effects)) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(effects);
        noun head    = list->head;
        effects      = list->tail;
        if (noun_is_cell(head)) {
            cell_t *fx = (cell_t *)(uintptr_t)cell_ptr(head);
            dispatch_one(fx->head, fx->tail);
        }
    }
}

void emit_timeout(uint64_t elapsed)
{
    trace_rec(T_TOUT, (uint32_t)elapsed);
    noun fx = alloc_cell(alloc_cell(direct(CORD_TIMEOUT), direct(elapsed)),
                         NOUN_ZERO);
    dispatch_effects(fx);
}

static void emit_swapped(uint32_t ver)
{
    trace_rec(T_SWAP, ver);
    noun fx = alloc_cell(alloc_cell(direct(CORD_SWAPPED), direct(ver)),
                         NOUN_ZERO);
    dispatch_effects(fx);
}

static void emit_wdt(void)
{
    noun fx = alloc_cell(alloc_cell(direct(CORD_WDT), NOUN_ZERO),
                         NOUN_ZERO);
    dispatch_effects(fx);
}

/* ── Phase 6 — hot-swap ──────────────────────────────────────────────────── */

void swap_stage(noun kernel, int shape, uint32_t version)
{
    g_staged_kernel  = kernel;
    g_staged_shape   = shape ? 1 : 0;
    g_staged_version = version;
    g_hstat          = HSTAT_STAGED;
}

void swap_cancel(void)
{
    g_staged_kernel  = NOUN_ZERO;
    g_staged_shape   = 0;
    g_staged_version = 0;
    g_hstat          = HSTAT_IDLE;
}

uint32_t swap_live_version(void)
{
    return g_live_version;
}

int swap_status(void)
{
    return g_hstat;
}

int swap_apply_if_ready(void)
{
    if (g_hstat != HSTAT_PENDING)
        return 0;
    if (evq_len() != 0)
        return 0;

    g_kernel       = g_staged_kernel;
    g_shrine_mode  = g_staged_shape;
    g_live_version = g_staged_version;
    noun_pill_shape = g_staged_shape;

    ska_cache_clear();

    g_hstat = HSTAT_IDLE;
    emit_swapped(g_live_version);
    return 1;
}

int swap_request(void)
{
    if (g_hstat == HSTAT_IDLE)
        return 0;
    g_hstat = HSTAT_PENDING;
    /* REPL / idle: apply immediately if queue empty */
    return swap_apply_if_ready();
}

/* ── Slam formula ────────────────────────────────────────────────────────── */

static noun build_slam_formula(void) {
    return alloc_cell(direct(9),
           alloc_cell(direct(2),
           alloc_cell(direct(10),
           alloc_cell(
               alloc_cell(direct(6), alloc_cell(direct(0), direct(3))),
               alloc_cell(direct(0), direct(2))))));
}

static int build_slam_formula_checked(noun *out)
{
    noun n0, n1, n2, n3, n4, n5, n6;
    return alloc_cell_checked(direct(0), direct(3), &n0)
        && alloc_cell_checked(direct(6), n0, &n1)
        && alloc_cell_checked(direct(0), direct(2), &n2)
        && alloc_cell_checked(n1, n2, &n3)
        && alloc_cell_checked(direct(10), n3, &n4)
        && alloc_cell_checked(direct(2), n4, &n5)
        && alloc_cell_checked(direct(9), n5, &n6)
        && ((*out = n6), 1);
}

/* ── Crash recovery policy (WP4) ─────────────────────────────────────────── */
/*
 * Hard crash (default): clear evq + IRQ ring + all tarms.
 *   Why clear tarms? After nock_crash the gate may be mid-invariants; IEC
 *   periods re-armed from app state on the next cold event is safer than
 *   firing TICKs into a recovered shrine with stale arms.
 * Soft crash (g_soft_crash): keep tarms; still clear queue + IRQ ring so
 *   partial cause cascades do not resume. For demos that re-arm themselves.
 */
static int g_soft_crash;

void crash_soft_set(int soft)
{
    g_soft_crash = soft ? 1 : 0;
}

int crash_soft_get(void)
{
    return g_soft_crash;
}

/* Shared host recovery (kernel_loop longjmp + CREC for tests). */
void crash_recover_host(void)
{
    evq_clear();
    irq_ring_clear();
    if (!g_soft_crash)
        tarm_clear();
}

/* ── Kernel event loops ──────────────────────────────────────────────────── */

/* Default slam op budget (WP2). 0 = unlimited. Large enough for moderate
 * Nock products; runaway self-calls abort without hanging QEMU. */
#ifndef SLAM_BUDGET_DEFAULT
#define SLAM_BUDGET_DEFAULT  1000000ULL
#endif

static uint64_t g_slam_budget = SLAM_BUDGET_DEFAULT;

void slam_budget_set(uint64_t max_ops)
{
    g_slam_budget = max_ops;
}

uint64_t slam_budget_get(void)
{
    return g_slam_budget;
}

static void reject_event_scratch(void)
{
    if (noun_tx_active())
        noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
}

static void kernel_loop(noun kernel_init, int shrine, uint64_t max_commits)
{
    g_kernel       = kernel_init;
    g_shrine_mode  = shrine ? 1 : 0;
    g_live_version = noun_pill_version;  /* from pill header if any */
    if (!noun_is_cell(g_slam_formula))
        g_slam_formula = build_slam_formula();
    noun slam = g_slam_formula;
    /* Mid-eval wall: poll deadline every 256 ops inside nock_budget_tick */
    nock_wall_check_set(deadline_expired);
    uart_puts(g_shrine_mode ? "\r\ntrinitite shrine\r\n"
                             : "\r\ntrinitite arvo\r\n");
    volatile uint64_t completed = 0;

    for (;;) {
        int jr = setjmp(nock_abort);
        if (jr == NOCK_ABORT_CRASH) {
            uart_puts("\r\nkernel crash\r\n");
            heap_noalloc_end();
            heap_persist_abort_tx();
            if (noun_tx_active())
                noun_tx_abort();
            if (g_i2_preparing) {
                /* Candidate allocation failed before publication.  Roll back
                 * allocator state only; old gate/FIFO/registries are still
                 * live and must not be treated as a structural Nock crash. */
                g_i2_preparing = 0;
                runtime_stats_count(RT_COUNT_PROMOTE_COPY_FAULTS, 1);
                runtime_stats_count(RT_COUNT_ABORTS, 1);
                heap_set_mode(HEAP_MODE_PERSIST);
                heap_scratch_reset();
                continue;
            }
            crash_recover_host();
            continue;
        }
        if (jr == NOCK_ABORT_BUDGET) {
            /*
             * WP2: budget / mid-eval wall — no product commit, keep tarms
             * (unlike crash). Emit %timeout so apps see the same host effect
             * as cooperative deadline; UART marks "budget" for operators.
             */
            uart_puts("\r\nbudget\r\n");
            trace_rec(T_BUD, (uint32_t)nock_ops_used());
            runtime_stats_count(
                nock_budget_abort_reason() == 2
                    ? RT_COUNT_DEADLINE_FAULTS : RT_COUNT_BUDGET_FAULTS, 1);
            runtime_stats_count(RT_COUNT_ABORTS, 1);
            emit_timeout(nock_ops_used());
            deadline_set(0);
            reject_event_scratch();
            continue;
        }

        /* Phase 6 safe point: apply staged kernel if queue is idle */
        swap_apply_if_ready();

        /* Phase 7: software WDT + canary at loop head */
        if (wdt_check()) {
            runtime_stats_count(RT_COUNT_WDT_FAILURES, 1);
            emit_wdt();
        }
        wdt_kick();
        if (!canary_ok()) {
            runtime_stats_count(RT_COUNT_CANARY_FAILURES, 1);
            trace_rec(T_CAN, 0);
            uart_puts("canary\r\n");
        }

        /* Phase 3: IRQ ring → event queue before schedule */
        irq_ring_drain();

        /* Multi-arm timers → [%ei id %TICK 0] into queue */
        tarm_poll();

        noun event;
        int event_from_i2_rx = 0;
        int event_from_queue = 0;
        evq_timing_t event_timing = {0};
        uint64_t event_admit_tick = 0;
        if ((runtime_identity_live()
             ? evq_peek_timed(&event, &event_timing)
             : evq_deq_timed(&event, &event_timing))) {
            event_from_queue = 1;
            event_admit_tick = event_timing.admitted_tick;
        } else {
            /*
             * Idle path (WP1): do not block forever in uart_recv_noun.
             * While the queue is empty and no UART frame has started,
             * keep polling multi-arm timers + soft WDT so period-driven
             * IEC graphs advance without a second host poke.
             *
             * RX advances by a fixed byte budget per pass. Partial/malformed
             * frames therefore coexist with timer and watchdog polling.
             */
            for (;;) {
                if (runtime_identity_live()) {
                    if (i2_rx_poll(32)) {
                        heap_scratch_reset();
                        heap_set_mode(HEAP_MODE_SCRATCH);
                        if (i2_rx_take(&event)) {
                            event_from_i2_rx = 1;
                            event_admit_tick = runtime_counter_now();
                            break;
                        }
                    }
                } else if (uart_rx_ready()) {
                    event = uart_recv_noun();
                    event_admit_tick = runtime_counter_now();
                    break;
                }
                tarm_poll();
                if ((runtime_identity_live()
                     ? evq_peek_timed(&event, &event_timing)
                     : evq_deq_timed(&event, &event_timing))) {
                    event_from_queue = 1;
                    event_admit_tick = event_timing.admitted_tick;
                    break;
                }
                if (wdt_check()) {
                    runtime_stats_count(RT_COUNT_WDT_FAILURES, 1);
                    emit_wdt();
                }
                wdt_kick();
                if (!canary_ok()) {
                    runtime_stats_count(RT_COUNT_CANARY_FAILURES, 1);
                    trace_rec(T_CAN, 0);
                    uart_puts("canary\r\n");
                }
            }
        }

        uint64_t slam_start = runtime_counter_now();
        if (event_admit_tick == 0)
            event_admit_tick = slam_start;
        runtime_stats_count(RT_COUNT_EVENTS_ADMITTED, 1);
        if (event_from_queue
            && !(event_timing.flags & EVQ_TIMING_RESTORED)) {
            uint64_t residence = slam_start >= event_admit_tick
                ? slam_start - event_admit_tick : 0;
            runtime_stats_record(RT_PHASE_QUEUE_RESIDENCE, residence);
            if (event_timing.flags & EVQ_TIMING_TIMER)
                runtime_stats_record(
                    RT_PHASE_TIMER_ENQUEUE_TO_SLAM, residence);
        }
        uint64_t t0 = 0;
        if (trace_enabled()) {
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
            trace_rec(T_EV0, 0);
        }

        /* Per-event scratch: Nock product dies after promote/dispatch */
        if (!event_from_i2_rx)
            heap_scratch_reset();
        heap_set_mode(HEAP_MODE_SCRATCH);

        nock_budget_set(g_slam_budget);
        noun subject = alloc_cell(g_kernel, event);
        slam_start = runtime_counter_now();
        noun result  = nock(subject, slam);
        uint64_t slam_end = runtime_counter_now();
        runtime_stats_record(
            RT_PHASE_NOCK_SLAM,
            slam_end >= slam_start ? slam_end - slam_start : 0);
        runtime_stats_note_memory();

        if (trace_enabled()) {
            uint64_t t1;
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
            trace_rec(T_EV1, (uint32_t)(t1 - t0));
        }

        if (deadline_expired()) {
            runtime_stats_count(RT_COUNT_DEADLINE_FAULTS, 1);
            runtime_stats_count(RT_COUNT_ABORTS, 1);
            emit_timeout(0);
            deadline_set(0);
            reject_event_scratch();
            continue;
        }

        if (!noun_is_cell(result)) {
            runtime_stats_count(RT_COUNT_ABORTS, 1);
            uart_puts("bad result\r\n");
            reject_event_scratch();
            continue;
        }
        cell_t *r = (cell_t *)(uintptr_t)cell_ptr(result);

        /*
         * I2 hybrid product (shrine):
         *   [%commit [effects [gate causes]]]  → preflight → persist gate/causes
         *                                        → dispatch → scratch reset
         *   [%abort  fault]                    → no promote, no effects
         * I1 shrine product remains [effects [gate causes]].
         */
        if (g_shrine_mode && noun_is_direct(r->head)) {
            uint64_t rh = direct_val(r->head);
            if (rh == CORD_COMMIT) {
                uint64_t promote_start = runtime_counter_now();
                if (!noun_is_cell(r->tail)) {
                    runtime_stats_count(RT_COUNT_ABORTS, 1);
                    uart_puts("bad result\r\n");
                    reject_event_scratch();
                    continue;
                }
                cell_t *prod = (cell_t *)(uintptr_t)cell_ptr(r->tail);
                noun effects = prod->head;
                if (!noun_is_cell(prod->tail)) {
                    runtime_stats_count(RT_COUNT_ABORTS, 1);
                    uart_puts("bad result\r\n");
                    reject_event_scratch();
                    continue;
                }
                cell_t *gc = (cell_t *)(uintptr_t)cell_ptr(prod->tail);
                if (!i2_preflight_effects(
                        effects, gc->tail, event_from_queue)) {
                    runtime_stats_count(RT_COUNT_PREFLIGHT_REJECTS, 1);
                    runtime_stats_count(RT_COUNT_ABORTS, 1);
                    static int pf_uart;
                    if (!pf_uart) {
                        pf_uart = 1;
                        uart_puts("preflight\r\n");
                    }
                    reject_event_scratch();
                    continue;
                }
                /*
                 * Compact PERSIST to live roots (gate + queue + tokens + causes).
                 * Slam formula was on old persist — rebuild after compact.
                 * Effects stay in SCRATCH until dispatch finishes.
                */
                g_i2_preparing = 1;
                if (!persist_compact(
                        gc->head, gc->tail, effects,
                        event_from_queue, &slam)) {
                    g_i2_preparing = 0;
                    runtime_stats_count(RT_COUNT_PROMOTE_COPY_FAULTS, 1);
                    runtime_stats_count(RT_COUNT_ABORTS, 1);
                    uart_puts("promote\r\n");
                    reject_event_scratch();
                    continue;
                }
                g_i2_preparing = 0;
                if (noun_tx_active())
                    noun_tx_commit();
                {
                    uint64_t promoted = runtime_counter_now();
                    runtime_stats_record(
                        RT_PHASE_VALIDATE_RESERVE_PROMOTE,
                        promoted >= promote_start
                            ? promoted - promote_start : 0);
                }
                uint64_t activate_start = runtime_counter_now();
                dispatch_i2_activate(effects);
                uint64_t activated = runtime_counter_now();
                runtime_stats_record(
                    RT_PHASE_ACTIVATE,
                    activated >= activate_start
                        ? activated - activate_start : 0);
                runtime_stats_record(
                    RT_PHASE_ADMIT_TO_ACTIVATE,
                    activated >= event_admit_tick
                        ? activated - event_admit_tick : 0);
                runtime_stats_count(RT_COUNT_COMMITS, 1);
                completed++;
                heap_set_mode(HEAP_MODE_PERSIST);
                heap_scratch_reset();
                runtime_stats_note_memory();
                /* Optional durable checkpoint (cold RAM store; SD later) */
                if (g_ckpt_every) {
                    g_ckpt_commits++;
                    if (g_ckpt_commits % g_ckpt_every == 0)
                        checkpoint_save();
                }
                if (max_commits && completed >= max_commits)
                    return;
                continue;
            }
            if (rh == CORD_ABORT) {
                /* keep g_kernel; drop effects (Host ABI abort path) */
                if (event_from_queue) {
                    noun consumed;
                    (void)evq_deq_timed(&consumed, 0);
                }
                runtime_stats_count(RT_COUNT_ABORTS, 1);
                reject_event_scratch();
                continue;
            }
        }

        /* An identity-admitted I2 gate may not fall back to the legacy I1
         * Shrine product grammar. The compatibility path is selected only by
         * a legacy pill lacking the I2 magic/identity anchor. */
        if (runtime_identity_live()) {
            runtime_stats_count(RT_COUNT_ABORTS, 1);
            uart_puts("bad result\r\n");
            reject_event_scratch();
            continue;
        }

        noun effects = r->head;

        if (g_shrine_mode) {
            if (!noun_is_cell(r->tail)) {
                runtime_stats_count(RT_COUNT_ABORTS, 1);
                uart_puts("bad result\r\n");
                reject_event_scratch();
                continue;
            }
            cell_t *r2 = (cell_t *)(uintptr_t)cell_ptr(r->tail);
            if (!persist_compact(
                    r2->head, r2->tail, NOUN_ZERO, 0, &slam)) {
                runtime_stats_count(RT_COUNT_PROMOTE_COPY_FAULTS, 1);
                runtime_stats_count(RT_COUNT_ABORTS, 1);
                uart_puts("promote\r\n");
                reject_event_scratch();
                continue;
            }
        } else {
            g_kernel = noun_persist(r->tail);
        }

        dispatch_effects(effects);
        runtime_stats_count(RT_COUNT_COMMITS, 1);
        completed++;
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        runtime_stats_note_memory();
        if (max_commits && completed >= max_commits)
            return;
    }
}

void arvo_loop(noun kernel_init)
{
    kernel_loop(kernel_init, 0, 0);
}

void shrine_loop(noun kernel_init)
{
    kernel_loop(kernel_init, 1, 0);
}

int kernel_run_bounded(uint64_t max_commits)
{
    if (max_commits == 0 || !g_shrine_mode || !noun_is_cell(g_kernel)
        || !runtime_identity_live())
        return -1;
    uint64_t start = runtime_counter_now();
    kernel_loop(g_kernel, 1, max_commits);
    uint64_t end = runtime_counter_now();
    runtime_stats_finish_run(end >= start ? end - start : 0);
    return 0;
}

/* ── Durable checkpoint (live roots → cold store) ───────────────────────── */

void shrine_gate_set(noun gate)
{
    heap_set_mode(HEAP_MODE_PERSIST);
    g_kernel = noun_persist(gate);
    g_shrine_mode = 1;
    g_slam_formula = NOUN_ZERO;
    runtime_identity_clear();
}

noun shrine_gate_get(void)
{
    return g_kernel;
}

int shrine_mode_get(void)
{
    return g_shrine_mode;
}

void checkpoint_auto_every(uint64_t n)
{
    g_ckpt_every   = n;
    g_ckpt_commits = 0;
}

uint64_t checkpoint_auto_get(void)
{
    return g_ckpt_every;
}

#define CKPT_VER 2ULL
#define H62_I2_LIFECYCLE 0x13ee37098c30ee2fULL
#define H62_I2_CONTROL   0x3c349df1606d200dULL
#define CORD_I2_EI       0x69652d3269ULL

typedef struct {
    noun gate;
    noun queue;
    noun tarms;
    runtime_identity_t identity;
    uint64_t incarnation;
    uint64_t queue_n;
    uint64_t timer_n;
} checkpoint_view_t;

static int g_checkpoint_last_result;
static uint64_t g_checkpoint_selected_generation;

static int noun_take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int i2_tag_is(noun tag, const char *text, size_t len)
{
    char buffer[16];
    if (!noun_is_atom(tag) || len + 1 > sizeof(buffer)
        || cord_to_cstr(tag, buffer, sizeof(buffer)) != len)
        return 0;
    for (size_t i = 0; i < len; i++)
        if (buffer[i] != text[i])
            return 0;
    return 1;
}

static int i2_live_instance(uint64_t wanted, noun *instance_state)
{
    noun battery, sample, axis, state;
    noun tag, rest, header, program, dynamic, states, formula;
    noun gate = g_kernel;
    if (!instance_state || !noun_take(gate, &battery, &sample)
        || !noun_take(sample, &axis, &state)
        || !noun_is_direct(axis) || direct_val(axis) != 0
        || !noun_take(state, &tag, &rest)
        || !i2_tag_is(tag, "i2-state", 8)
        || !noun_take(rest, &header, &rest)
        || !noun_take(rest, &program, &dynamic)
        || !noun_take(dynamic, &states, &formula))
        return 0;

    for (uint64_t count = 0; count < 64 && noun_is_cell(states); count++) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(states);
        noun id, body;
        if (!noun_take(list->head, &id, &body)
            || !noun_is_direct(id) || direct_val(id) == 0)
            return 0;
        if (direct_val(id) == wanted) {
            *instance_state = body;
            return 1;
        }
        states = list->tail;
    }
    return 0;
}

uint64_t kernel_i2_active_state(uint64_t instance_id)
{
    noun state, tag, rest, active;
    if (!i2_live_instance(instance_id, &state)
        || !noun_take(state, &tag, &rest)
        || !i2_tag_is(tag, "bfb-state", 9)
        || !noun_take(rest, &active, &rest)
        || !noun_is_direct(active))
        return UINT64_MAX;
    return direct_val(active);
}

uint64_t kernel_i2_output_atom(uint64_t instance_id, uint64_t variable_id)
{
    noun state, tag, rest, field, outputs;
    if (!i2_live_instance(instance_id, &state)
        || !noun_take(state, &tag, &rest)
        || !i2_tag_is(tag, "bfb-state", 9)
        || !noun_take(rest, &field, &rest) /* active state */
        || !noun_take(rest, &field, &rest) /* inputs */
        || !noun_take(rest, &outputs, &field))
        return UINT64_MAX;

    for (uint64_t count = 0; count < 64 && noun_is_cell(outputs); count++) {
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(outputs);
        noun id, typed, type_id, payload;
        if (!noun_take(list->head, &id, &typed)
            || !noun_is_direct(id) || direct_val(id) == 0
            || !noun_take(typed, &type_id, &payload)
            || !noun_is_direct(type_id) || direct_val(type_id) == 0)
            return UINT64_MAX;
        if (direct_val(id) == variable_id)
            return noun_is_direct(payload) ? direct_val(payload) : UINT64_MAX;
        outputs = list->tail;
    }
    return UINT64_MAX;
}

static int positive_direct(noun n, uint64_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) == 0)
        return 0;
    if (out)
        *out = direct_val(n);
    return 1;
}

static int token_fields(noun token, uint64_t *gen, uint64_t *inc,
                        uint64_t *owner, uint64_t *seq)
{
    noun h, rest;
    return noun_take(token, &h, &rest) && positive_direct(h, gen)
        && noun_take(rest, &h, &rest) && positive_direct(h, inc)
        && noun_take(rest, &h, &rest) && positive_direct(h, owner)
        && positive_direct(rest, seq);
}

static int token_unique(noun token, noun *tokens, uint64_t *count,
                        uint64_t cap)
{
    for (uint64_t i = 0; i < *count; i++)
        if (noun_eq(tokens[i], token))
            return 0;
    if (*count >= cap)
        return 0;
    tokens[(*count)++] = token;
    return 1;
}

static int proper_samples(noun samples)
{
    uint64_t last = 0;
    uint64_t n = 0;
    while (noun_is_cell(samples)) {
        if (++n > 256)
            return 0;
        cell_t *list = (cell_t *)(uintptr_t)cell_ptr(samples);
        noun id, value;
        if (!noun_take(list->head, &id, &value)
            || !noun_is_direct(id) || direct_val(id) <= last)
            return 0;
        last = direct_val(id);
        samples = list->tail;
    }
    return samples == NOUN_ZERO;
}

static int validate_queued_event(noun event, uint64_t generation,
                                 uint64_t incarnation, noun *tokens,
                                 uint64_t *token_n, uint64_t token_cap)
{
    noun tag, rest;
    if (!noun_take(event, &tag, &rest) || !noun_is_atom(tag))
        return 0;
    uint64_t direct_tag = noun_is_direct(tag) ? direct_val(tag) : 0;
    uint64_t h = noun_is_indirect(tag) ? indirect_hash(tag) : 0;
    if (noun_is_direct(tag) && direct_val(tag) == CORD_I2_EI) {
        noun target, input, samples;
        return noun_take(rest, &target, &rest) && positive_direct(target, 0)
            && noun_take(rest, &input, &samples) && positive_direct(input, 0)
            && proper_samples(samples);
    }
    if (h == H62_I2_LIFECYCLE || h == H62_I2_CONTROL)
        return noun_is_atom(rest) && rest != NOUN_ZERO;
    int timer_event = direct_tag == CORD_I2_TIMER;
    if (timer_event || h == H62_I2_SERVICE) {
        noun token, tail;
        uint64_t gen, inc, owner, seq;
        if (!noun_take(rest, &token, &tail)
            || !token_fields(token, &gen, &inc, &owner, &seq)
            || gen != generation || inc != incarnation
            || !token_unique(token, tokens, token_n, token_cap))
            return 0;
        if (timer_event)
            return noun_is_direct(tail);
        noun status, data, code, detail;
        return noun_take(tail, &status, &data)
            && noun_take(status, &code, &detail)
            && noun_is_direct(code) && noun_is_direct(detail);
    }
    return 0;
}

static int checkpoint_validate(noun ckpt, checkpoint_view_t *view)
{
    noun tag, rest, version, identity_noun, shrine, gate, queue, tarms;
    const runtime_identity_t *live = runtime_identity_get();
    if (!view || !live
        || !noun_take(ckpt, &tag, &rest)
        || !noun_is_direct(tag) || direct_val(tag) != CORD_I2_CKPT
        || !noun_take(rest, &version, &rest)
        || !noun_is_direct(version) || direct_val(version) != CKPT_VER
        || !noun_take(rest, &identity_noun, &rest)
        || !runtime_identity_from_noun(identity_noun, &view->identity)
        || !runtime_identity_equal(&view->identity, live)
        || !noun_take(rest, &shrine, &rest)
        || !noun_is_direct(shrine) || direct_val(shrine) != 1
        || !noun_take(rest, &gate, &rest)
        || !noun_take(rest, &queue, &tarms)
        || !runtime_identity_validate_gate(
            gate, &view->identity, &view->incarnation))
        return 0;

    noun tokens[EVQ_CAP + TARM_MAX];
    uint64_t token_n = 0;
    noun q = queue;
    uint64_t qn = 0;
    while (noun_is_cell(q)) {
        if (++qn > EVQ_CAP)
            return 0;
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(q);
        if (!validate_queued_event(
                c->head, view->identity.generation, view->incarnation,
                tokens, &token_n, EVQ_CAP + TARM_MAX))
            return 0;
        q = c->tail;
    }
    if (q != NOUN_ZERO)
        return 0;

    noun ids[TARM_MAX];
    uint64_t id_n = 0;
    noun tl = tarms;
    uint64_t tn = 0;
    while (noun_is_cell(tl)) {
        if (++tn > TARM_MAX)
            return 0;
        cell_t *le = (cell_t *)(uintptr_t)cell_ptr(tl);
        noun id_noun, erest, period_noun, remain_noun, token;
        uint64_t id, period, remain, gen, inc, owner, seq;
        if (!noun_take(le->head, &id_noun, &erest)
            || !positive_direct(id_noun, &id)
            || !noun_take(erest, &period_noun, &erest)
            || !positive_direct(period_noun, &period)
            || !noun_take(erest, &remain_noun, &token)
            || !positive_direct(remain_noun, &remain)
            || !token_fields(token, &gen, &inc, &owner, &seq)
            || gen != view->identity.generation
            || inc != view->incarnation || owner != id
            || !token_unique(token, tokens, &token_n, EVQ_CAP + TARM_MAX))
            return 0;
        for (uint64_t i = 0; i < id_n; i++)
            if (direct_val(ids[i]) == id)
                return 0;
        ids[id_n++] = id_noun;
        tl = le->tail;
    }
    if (tl != NOUN_ZERO)
        return 0;
    view->gate = gate;
    view->queue = queue;
    view->tarms = tarms;
    view->queue_n = qn;
    view->timer_n = tn;
    return 1;
}

static int checkpoint_identity_matches(noun ckpt, int *identity_represented)
{
    noun tag, rest, version, identity_noun;
    runtime_identity_t identity;
    const runtime_identity_t *live = runtime_identity_get();
    *identity_represented = 0;
    if (!live
        || !noun_take(ckpt, &tag, &rest)
        || !noun_is_direct(tag) || direct_val(tag) != CORD_I2_CKPT
        || !noun_take(rest, &version, &rest)
        || !noun_is_direct(version) || direct_val(version) != CKPT_VER
        || !noun_take(rest, &identity_noun, &rest)
        || !runtime_identity_from_noun(identity_noun, &identity))
        return 0;
    *identity_represented = 1;
    return runtime_identity_equal(&identity, live);
}

static int make_timer_event_checked(noun token, noun *out)
{
    noun body, event, cell;
    return alloc_cell_checked(token, direct(0), &body)
        && alloc_cell_checked(direct(CORD_I2_TIMER), body, &event)
        && alloc_cell_checked(event, NOUN_ZERO, &cell)
        && ((*out = cell), 1);
}

static int checkpoint_capture_checked(noun *out)
{
    const runtime_identity_t *identity = runtime_identity_get();
    uint64_t incarnation;
    if (!out || !identity || !noun_is_cell(g_kernel) || !g_shrine_mode
        || !runtime_identity_validate_gate(g_kernel, identity, &incarnation))
        return 0;
    noun identity_noun, queue, gate;
    if (!runtime_identity_to_noun(identity, &identity_noun)
        || !noun_copy_checked(g_evq, &queue)
        || !noun_copy_checked(g_kernel, &gate))
        return 0;
    uint64_t now = cntvct();
    noun tarms = NOUN_ZERO;
    for (int i = TARM_MAX - 1; i >= 0; i--) {
        if (!g_tarms[i].active)
            continue;
        uint64_t gen, inc, owner, seq;
        if (!token_fields(g_tarms[i].i2_token, &gen, &inc, &owner, &seq)
            || gen != identity->generation || inc != incarnation
            || owner != g_tarms[i].id || g_tarms[i].period == 0)
            return 0;
        uint64_t remain = g_tarms[i].next > now
            ? g_tarms[i].next - now : 1;
        noun tok, n0, n1, ent, list;
        if (!noun_copy_checked(g_tarms[i].i2_token, &tok)
            || !alloc_cell_checked(direct(remain), tok, &n0)
            || !alloc_cell_checked(direct(g_tarms[i].period), n0, &n1)
            || !alloc_cell_checked(direct(g_tarms[i].id), n1, &ent)
            || !alloc_cell_checked(ent, tarms, &list))
            return 0;
        tarms = list;
    }
    noun n0, n1, n2, n3, n4, ckpt;
    if (!alloc_cell_checked(queue, tarms, &n0)
        || !alloc_cell_checked(gate, n0, &n1)
        || !alloc_cell_checked(direct(1), n1, &n2)
        || !alloc_cell_checked(identity_noun, n2, &n3)
        || !alloc_cell_checked(direct(CKPT_VER), n3, &n4)
        || !alloc_cell_checked(direct(CORD_I2_CKPT), n4, &ckpt))
        return 0;
    *out = ckpt;
    return 1;
}

noun checkpoint_capture(void)
{
    noun out = NOUN_ZERO;
    if (!checkpoint_capture_checked(&out))
        return NOUN_ZERO;
    return out;
}

int checkpoint_install(noun ckpt)
{
    checkpoint_view_t view = {0};
    int identity_represented = 0;
    if (!checkpoint_identity_matches(ckpt, &identity_represented)) {
        g_checkpoint_last_result = identity_represented
            ? COLD_RESULT_IDENTITY : COLD_RESULT_SHAPE;
        if (noun_tx_active())
            noun_tx_abort();
        return -1;
    }
    if (!checkpoint_validate(ckpt, &view)) {
        g_checkpoint_last_result = COLD_RESULT_SHAPE;
        if (noun_tx_active())
            noun_tx_abort();
        return -1;
    }

    tarm_t candidate_tarms[TARM_MAX] = {0};
    noun candidate_gate, candidate_q = NOUN_ZERO, candidate_tail = NOUN_ZERO;
    noun candidate_slam;
    uint64_t candidate_n = 0;
    uint64_t now = cntvct();

    heap_persist_begin_tx();
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(view.gate, &candidate_gate))
        goto alloc_fail;

    noun q = view.queue;
    while (noun_is_cell(q)) {
        cell_t *old = (cell_t *)(uintptr_t)cell_ptr(q);
        noun event, node;
        if (!noun_copy_checked(old->head, &event)
            || !alloc_cell_checked(event, NOUN_ZERO, &node))
            goto alloc_fail;
        if (!noun_is_cell(candidate_q))
            candidate_q = candidate_tail = node;
        else {
            ((cell_t *)(uintptr_t)cell_ptr(candidate_tail))->tail = node;
            candidate_tail = node;
        }
        g_evq_timing_candidate[candidate_n].admitted_tick = now;
        g_evq_timing_candidate[candidate_n].timer_due_tick = 0;
        g_evq_timing_candidate[candidate_n].flags = EVQ_TIMING_RESTORED;
        candidate_n++;
        q = old->tail;
    }

    noun tl = view.tarms;
    int ti = 0;
    while (noun_is_cell(tl)) {
        cell_t *le = (cell_t *)(uintptr_t)cell_ptr(tl);
        noun id_noun = 0, erest = 0, period_noun = 0;
        noun remain_noun = 0, token = 0;
        noun copied_token, event_cell;
        if (!noun_take(le->head, &id_noun, &erest)
            || !noun_take(erest, &period_noun, &erest)
            || !noun_take(erest, &remain_noun, &token))
            goto alloc_fail;
        uint64_t remain = direct_val(remain_noun);
        if (UINT64_MAX - now < remain
            || !noun_copy_checked(token, &copied_token)
            || !make_timer_event_checked(copied_token, &event_cell))
            goto alloc_fail;
        candidate_tarms[ti].active = 1;
        candidate_tarms[ti].id = direct_val(id_noun);
        candidate_tarms[ti].period = direct_val(period_noun);
        candidate_tarms[ti].next = now + remain;
        candidate_tarms[ti].i2_token = copied_token;
        candidate_tarms[ti].i2_event_cell = event_cell;
        ti++;
        tl = le->tail;
    }
    if (!build_slam_formula_checked(&candidate_slam))
        goto alloc_fail;

    /* One publication after complete validation and candidate allocation. */
    g_kernel = candidate_gate;
    g_slam_formula = candidate_slam;
    g_shrine_mode = 1;
    g_evq = candidate_q;
    g_evq_tail = candidate_tail;
    g_evq_n = candidate_n;
    g_evq_timing_head = 0;
    for (uint64_t i = 0; i < candidate_n; i++)
        g_evq_timing[i] = g_evq_timing_candidate[i];
    if (g_evq_n > g_evq_hwm)
        g_evq_hwm = g_evq_n;
    for (int i = 0; i < TARM_MAX; i++)
        g_tarms[i] = candidate_tarms[i];
    heap_persist_commit_tx();
    if (noun_tx_active())
        noun_tx_commit();
    g_checkpoint_last_result = COLD_RESULT_VALID;
    g_checkpoint_selected_generation = cold_selected_generation();
    return 0;

alloc_fail:
    heap_persist_abort_tx();
    if (noun_tx_active())
        noun_tx_abort();
    g_checkpoint_last_result = COLD_RESULT_ALLOC;
    return -1;
}

int checkpoint_save(void)
{
    uint64_t capture_start = runtime_counter_now();
    if (!runtime_identity_live() || !noun_is_cell(g_kernel)) {
        runtime_stats_count(RT_COUNT_CHECKPOINT_FAILURES, 1);
        return -1;
    }
    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH)) {
        runtime_stats_count(RT_COUNT_CHECKPOINT_FAILURES, 1);
        return -1;
    }
    noun ck;
    if (!checkpoint_capture_checked(&ck)) {
        noun_tx_abort();
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        uint64_t capture_end = runtime_counter_now();
        runtime_stats_record(
            RT_PHASE_CHECKPOINT_CAPTURE,
            capture_end >= capture_start
                ? capture_end - capture_start : 0);
        runtime_stats_count(RT_COUNT_CHECKPOINT_FAILURES, 1);
        return -1;
    }
    uint64_t capture_end = runtime_counter_now();
    runtime_stats_record(
        RT_PHASE_CHECKPOINT_CAPTURE,
        capture_end >= capture_start ? capture_end - capture_start : 0);
    int result = cold_snap_save(ck);
    noun_tx_abort(); /* save image owns bytes; temporary noun owns no live root */
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    if (result == 0 && cold_nv_enabled()) {
        uint64_t flush_start = runtime_counter_now();
        result = cold_nv_flush();
        uint64_t flush_end = runtime_counter_now();
        runtime_stats_record(
            RT_PHASE_CHECKPOINT_MEDIA_FLUSH,
            flush_end >= flush_start ? flush_end - flush_start : 0);
    }
    if (result == 0) {
        runtime_stats_count(RT_COUNT_CHECKPOINTS, 1);
        runtime_stats_set(
            RT_COUNT_CHECKPOINT_GENERATION, cold_selected_generation());
        runtime_stats_set(RT_COUNT_COLD_DATA_HEAD, cold_data_head());
    } else {
        runtime_stats_count(RT_COUNT_CHECKPOINT_FAILURES, 1);
    }
    return result;
}

int checkpoint_load(void)
{
    noun ck;
    if (!runtime_identity_live()) {
        g_checkpoint_last_result = COLD_RESULT_IDENTITY;
        return -1;
    }
    heap_scratch_reset();
    if (cold_snap_decode(&ck) != 0) {
        g_checkpoint_last_result = cold_last_result();
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        return -1;
    }
    int result = checkpoint_install(ck);
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    if (result == 0) {
        runtime_stats_count(RT_COUNT_RESTARTS, 1);
        runtime_stats_note_memory();
    }
    return result;
}

int checkpoint_last_result(void)
{
    return g_checkpoint_last_result;
}

uint64_t checkpoint_selected_generation(void)
{
    return g_checkpoint_selected_generation;
}

typedef struct {
    noun kernel;
    noun slam;
    noun evq;
    noun evq_tail;
    uint64_t evq_n;
    uint64_t persist_cells;
    uint64_t atom_bytes;
    tarm_t tarms[TARM_MAX];
    runtime_identity_t identity;
} checkpoint_test_live_t;

static void checkpoint_test_snapshot(checkpoint_test_live_t *s)
{
    s->kernel = g_kernel;
    s->slam = g_slam_formula;
    s->evq = g_evq;
    s->evq_tail = g_evq_tail;
    s->evq_n = g_evq_n;
    s->persist_cells = heap_cells_used(HEAP_MODE_PERSIST);
    s->atom_bytes = atom_store_bytes_used();
    for (int i = 0; i < TARM_MAX; i++)
        s->tarms[i] = g_tarms[i];
    s->identity = *runtime_identity_get();
}

static int checkpoint_test_unchanged(const checkpoint_test_live_t *s)
{
    if (g_kernel != s->kernel || g_slam_formula != s->slam
        || g_evq != s->evq || g_evq_tail != s->evq_tail
        || g_evq_n != s->evq_n
        || heap_cells_used(HEAP_MODE_PERSIST) != s->persist_cells
        || atom_store_bytes_used() != s->atom_bytes
        || !runtime_identity_equal(runtime_identity_get(), &s->identity))
        return 0;
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active != s->tarms[i].active
            || g_tarms[i].id != s->tarms[i].id
            || g_tarms[i].period != s->tarms[i].period
            || g_tarms[i].next != s->tarms[i].next
            || g_tarms[i].i2_token != s->tarms[i].i2_token
            || g_tarms[i].i2_event_cell != s->tarms[i].i2_event_cell)
            return 0;
    }
    return 1;
}

static int checkpoint_test_capture(noun *ckpt, noun *queue_tarms)
{
    noun rest, field;
    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return 0;
    if (!checkpoint_capture_checked(ckpt)) {
        noun_tx_abort();
        return 0;
    }
    rest = *ckpt;
    for (int i = 0; i < 5; i++) {
        if (!noun_take(rest, &field, &rest)) {
            noun_tx_abort();
            return 0;
        }
    }
    if (!noun_is_cell(rest)) {
        noun_tx_abort();
        return 0;
    }
    *queue_tarms = rest;
    return 1;
}

static int checkpoint_test_token(uint64_t generation, uint64_t incarnation,
                                 uint64_t owner, uint64_t sequence, noun *out)
{
    noun n0, n1;
    return alloc_cell_checked(direct(owner), direct(sequence), &n0)
        && alloc_cell_checked(direct(incarnation), n0, &n1)
        && alloc_cell_checked(direct(generation), n1, out);
}

static int checkpoint_test_timer_entry(
    uint64_t id, uint64_t generation, uint64_t incarnation,
    uint64_t sequence, noun token_override, noun *out)
{
    noun token = token_override, n0, n1;
    if (token == NOUN_ZERO
        && !checkpoint_test_token(
            generation, incarnation, id, sequence, &token))
        return 0;
    return alloc_cell_checked(direct(1), token, &n0)
        && alloc_cell_checked(direct(1), n0, &n1)
        && alloc_cell_checked(direct(id), n1, out);
}

static int checkpoint_test_reject(noun ckpt,
                                  const checkpoint_test_live_t *live)
{
    int rejected = checkpoint_install(ckpt) != 0;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return rejected && checkpoint_test_unchanged(live);
}

uint64_t checkpoint_m2_selftest(void)
{
    if (!runtime_identity_live() || !noun_is_cell(g_kernel))
        return UINT64_MAX;
    noun_test_copy_fail_after(-1);
    checkpoint_test_live_t live;
    checkpoint_test_snapshot(&live);
    uint64_t failures = 0;
    noun ckpt, pair;

    if (!checkpoint_test_reject(NOUN_ZERO, &live))
        failures |= 1ULL << 0;

    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 1;
    } else {
        ((cell_t *)(uintptr_t)cell_ptr(pair))->head = direct(7);
        if (!checkpoint_test_reject(ckpt, &live))
            failures |= 1ULL << 1;
    }

    /* 257 proper, individually valid lifecycle events: never truncate. */
    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 2;
    } else {
        noun tag = cord_from_bytes("i2-lifecycle", 12);
        noun event, queue = NOUN_ZERO, node;
        int built = 1;
        if (!alloc_cell_checked(tag, direct(0x646c6f63), &event)) {
            noun_tx_abort();
            failures |= 1ULL << 2;
        } else {
            for (int i = 0; i < 257; i++) {
                if (!alloc_cell_checked(event, queue, &node)) {
                    noun_tx_abort();
                    failures |= 1ULL << 2;
                    built = 0;
                    break;
                }
                queue = node;
            }
            if (built) {
                ((cell_t *)(uintptr_t)cell_ptr(pair))->head = queue;
                if (!checkpoint_test_reject(ckpt, &live))
                    failures |= 1ULL << 2;
            }
        }
    }

    uint64_t incarnation = 0;
    runtime_identity_validate_gate(
        g_kernel, runtime_identity_get(), &incarnation);
    uint64_t generation = runtime_identity_get()->generation;

    /* 17 valid timer entries: never skip/truncate the seventeenth. */
    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 3;
    } else {
        noun timers = NOUN_ZERO, entry, node;
        int built = 1;
        for (int i = 17; i >= 1; i--) {
            if (!checkpoint_test_timer_entry(
                    (uint64_t)i, generation, incarnation,
                    (uint64_t)i, NOUN_ZERO, &entry)
                || !alloc_cell_checked(entry, timers, &node)) {
                noun_tx_abort();
                failures |= 1ULL << 3;
                built = 0;
                break;
            }
            timers = node;
        }
        if (built) {
            ((cell_t *)(uintptr_t)cell_ptr(pair))->tail = timers;
            if (!checkpoint_test_reject(ckpt, &live))
                failures |= 1ULL << 3;
        }
    }

    /* Duplicate full lifecycle token. */
    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 4;
    } else {
        noun token, entry0, entry1, list0, list1;
        if (!checkpoint_test_token(
                generation, incarnation, 1, 1, &token)
            || !checkpoint_test_timer_entry(
                1, generation, incarnation, 1, token, &entry0)
            || !checkpoint_test_timer_entry(
                1, generation, incarnation, 1, token, &entry1)
            || !alloc_cell_checked(entry1, NOUN_ZERO, &list1)
            || !alloc_cell_checked(entry0, list1, &list0)) {
            noun_tx_abort();
            failures |= 1ULL << 4;
        } else {
            ((cell_t *)(uintptr_t)cell_ptr(pair))->tail = list0;
            if (!checkpoint_test_reject(ckpt, &live))
                failures |= 1ULL << 4;
        }
    }

    /* Stale generation and malformed short token. */
    for (int which = 0; which < 2; which++) {
        uint64_t bit = 5 + (uint64_t)which;
        if (!checkpoint_test_capture(&ckpt, &pair)) {
            failures |= 1ULL << bit;
            continue;
        }
        noun token = NOUN_ZERO, entry, list;
        if (which == 1)
            token = direct(1);
        if ((which == 0
             && !checkpoint_test_token(
                 generation + 1, incarnation, 1, 1, &token))
            || !checkpoint_test_timer_entry(
                1, generation, incarnation, 1, token, &entry)
            || !alloc_cell_checked(entry, NOUN_ZERO, &list)) {
            noun_tx_abort();
            failures |= 1ULL << bit;
            continue;
        }
        ((cell_t *)(uintptr_t)cell_ptr(pair))->tail = list;
        if (!checkpoint_test_reject(ckpt, &live))
            failures |= 1ULL << bit;
    }

    /* Candidate semispace copy failure occurs after full validation. */
    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 7;
    } else {
        noun_test_copy_fail_after(0);
        if (!checkpoint_test_reject(ckpt, &live)
            || g_checkpoint_last_result != COLD_RESULT_ALLOC)
            failures |= 1ULL << 7;
        noun_test_copy_fail_after(-1);
    }

    /* Canonical queued timer/service completions with full distinct tokens. */
    if (!checkpoint_test_capture(&ckpt, &pair)) {
        failures |= 1ULL << 8;
    } else {
        noun timer_token, service_token, timer_node;
        noun service_event, service_node;
        checkpoint_view_t view = {0};
        if (!checkpoint_test_token(
                generation, incarnation, 1, 1, &timer_token)
            || !checkpoint_test_token(
                generation, incarnation, 2, 2, &service_token)
            || !make_timer_event_checked(timer_token, &timer_node)
            || !make_i2_service_event_checked(
                service_token, &service_event)
            || !alloc_cell_checked(
                service_event, NOUN_ZERO, &service_node)) {
            noun_tx_abort();
            failures |= 1ULL << 8;
        } else {
            ((cell_t *)(uintptr_t)cell_ptr(timer_node))->tail = service_node;
            ((cell_t *)(uintptr_t)cell_ptr(pair))->head = timer_node;
            if (!checkpoint_validate(ckpt, &view)
                || view.queue_n != 2 || view.timer_n != 0)
                failures |= 1ULL << 8;
            noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            if (!checkpoint_test_unchanged(&live))
                failures |= 1ULL << 8;
        }
    }

    noun_test_copy_fail_after(-1);
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return failures;
}

/* ── Boot policy (pill vs durable snap) ─────────────────────────────────── */

static int g_boot_policy = BOOT_PILL;

void boot_policy_set(int policy)
{
    if (policy < BOOT_PILL || policy > BOOT_SNAP)
        policy = BOOT_PILL;
    g_boot_policy = policy;
}

int boot_policy_get(void)
{
    return g_boot_policy;
}

static void uart_hex64_kernel(uint64_t value)
{
    char buf[17];
    buf[16] = 0;
    for (int i = 15; i >= 0; i--) {
        buf[i] = "0123456789abcdef"[value & 15];
        value >>= 4;
    }
    uart_puts(buf);
}

static int install_clean_pill(noun pill_gate)
{
    if (!noun_is_cell(pill_gate))
        return -1;
    if (runtime_identity_live()
        && !runtime_identity_validate_gate(
            pill_gate, runtime_identity_get(), 0))
        return -1;
    heap_persist_begin_tx();
    heap_set_mode(HEAP_MODE_PERSIST);
    noun candidate_gate, candidate_slam;
    if (!noun_copy_checked(pill_gate, &candidate_gate)
        || !build_slam_formula_checked(&candidate_slam)) {
        heap_persist_abort_tx();
        return -1;
    }
    tarm_t empty_tarms[TARM_MAX] = {0};
    g_kernel = candidate_gate;
    g_slam_formula = candidate_slam;
    g_shrine_mode = noun_pill_shape ? 1 : 0;
    g_evq = NOUN_ZERO;
    g_evq_tail = NOUN_ZERO;
    g_evq_n = 0;
    for (int i = 0; i < TARM_MAX; i++)
        g_tarms[i] = empty_tarms[i];
    heap_persist_commit_tx();
    return 0;
}

int kernel_prepare_pill(void)
{
    noun gate = kernel_pill_load();
    return noun_is_cell(gate) && install_clean_pill(gate) == 0 ? 0 : -1;
}

int kernel_boot(noun pill_gate)
{
    int want_snap = (g_boot_policy == BOOT_SNAP ||
                     g_boot_policy == BOOT_SNAP_ELSE_PILL);

    if (want_snap) {
        if (checkpoint_load() == 0) {
            uart_puts("boot: snap\r\n");
            uart_puts("boot: identity ");
            const runtime_identity_t *identity = runtime_identity_get();
            uint64_t prefix = 0;
            if (identity)
                for (int i = 0; i < 8; i++)
                    prefix |= (uint64_t)identity->package_hash[i] << (i * 8);
            uart_hex64_kernel(prefix);
            uart_puts(" generation ");
            uart_hex64_kernel(checkpoint_selected_generation());
            uart_puts("\r\n");
            if (g_shrine_mode)
                shrine_loop(g_kernel);
            else
                arvo_loop(g_kernel);
            return -1; /* unreachable */
        }
        if (g_boot_policy == BOOT_SNAP) {
            uart_puts("boot: no snap ");
            uart_puts(cold_result_name(
                (cold_result_t)checkpoint_last_result()));
            uart_puts("\r\n");
            return -1;
        }
        uart_puts("boot: snap reject ");
        uart_puts(cold_result_name(
            (cold_result_t)checkpoint_last_result()));
        uart_puts(" -> pill\r\n");
    }

    if (!noun_is_cell(pill_gate)) {
        uart_puts("boot: no pill\r\n");
        return -1;
    }

    if (install_clean_pill(pill_gate) != 0) {
        uart_puts("boot: pill reject\r\n");
        return -1;
    }
    uart_puts("boot: pill\r\n");
    if (g_shrine_mode)
        shrine_loop(g_kernel);
    else
        arvo_loop(g_kernel);
    return -1;
}

noun kernel_pill_load(void)
{
    noun gate = NOUN_ZERO;
    pill_i2_status_t status = pill_i2_load(&gate);
    if (status == PILL_I2_OK)
        return gate;
    if (status == PILL_I2_NOT_I2 || status == PILL_I2_ABSENT) {
        /* Frozen I1 compatibility: the old PILL v2 + recursive cue path is
         * reachable only when the I2 magic is absent. */
        runtime_identity_clear();
        noun atom = pill_load();
        if (!noun_is_atom(atom) || atom == NOUN_ZERO)
            return NOUN_ZERO;
        return cue(atom);
    }
    uart_puts("pill: reject ");
    uart_puts(pill_i2_status_name(status));
    uart_puts("\r\n");
    return NOUN_ZERO;
}
