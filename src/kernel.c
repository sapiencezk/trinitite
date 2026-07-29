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
#define H62_I2_SERVICE          0x30cfa0e9c7ed95b9ULL  /* "i2-service" host→app */
#define CORD_I2_CKPT            32774703826154089ULL   /* %i2-ckpt durable snap  */
#define CKPT_VER                1ULL

/* Host ABI D0 ceilings (subset of tools/i2 HostAbiLimits) */
#define I2_MAX_TIMERS              TARM_MAX
#define I2_MAX_PENDING_SERVICES    4

/* Auto-checkpoint: save live roots to cold store every N successful commits */
static uint64_t g_ckpt_every;
static uint64_t g_ckpt_commits;

#define TARM_MAX     16

#define HSTAT_IDLE    0
#define HSTAT_STAGED  1
#define HSTAT_PENDING 2

extern jmp_buf nock_abort;
extern int noun_pill_shape;
extern uint32_t noun_pill_version;

/* ── Phase 6 — live kernel + staging ─────────────────────────────────────── */

static volatile noun g_kernel;
static int           g_shrine_mode;
static uint32_t      g_live_version;
static volatile int  g_i2_preparing;
static noun build_slam_formula(void);

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
} tarm_t;

static tarm_t g_tarms[TARM_MAX];
static uint64_t atom_u64_early(noun a);

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
    } else {
        g_tarms[i].i2_token = NOUN_ZERO;
    }
}

static void tarm_can_i2(noun token)
{
    int i = noun_is_cell(token) ? tarm_find_i2(token) : tarm_find(atom_u64_early(token));
    if (i >= 0) {
        if (g_tarms[i].i2_token != NOUN_ZERO)
            cell_dec(g_tarms[i].i2_token);
        g_tarms[i].i2_token = NOUN_ZERO;
        g_tarms[i].active = 0;
    }
}

void tarm_can(uint64_t id)
{
    int i = tarm_find(id);
    if (i >= 0) {
        if (g_tarms[i].i2_token != NOUN_ZERO) {
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
        }
        g_tarms[i].active = 0;
    }
}

void tarm_clear(void)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].i2_token != NOUN_ZERO) {
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
        }
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
            evq_enq(make_i2_timer_event(g_tarms[i].i2_token, now));
            cell_dec(g_tarms[i].i2_token);
            g_tarms[i].i2_token = NOUN_ZERO;
            g_tarms[i].active = 0;
        } else {
            evq_enq(make_tick_event(g_tarms[i].id));
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

void evq_clear(void)
{
    g_evq            = NOUN_ZERO;
    g_evq_tail       = NOUN_ZERO;
    g_evq_n          = 0;
    g_ovf_uart       = 0;
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

void evq_enq(noun event)
{
    if (g_evq_n >= EVQ_CAP) {
        g_evq_overflows++;
        trace_rec(T_OVF, (uint32_t)g_evq_overflows);
        if (!g_ovf_uart) {
            g_ovf_uart = 1;
            uart_puts("overflow\r\n");
        }
        return;   /* drop-newest */
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
    g_evq_n++;
    if (g_evq_n > g_evq_hwm)
        g_evq_hwm = g_evq_n;
}

int evq_deq(noun *out)
{
    if (!noun_is_cell(g_evq))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(g_evq);
    *out = c->head;
    g_evq = c->tail;
    if (g_evq_n > 0)
        g_evq_n--;
    if (!noun_is_cell(g_evq))
        g_evq_tail = NOUN_ZERO;
    return 1;
}

int evq_peek(noun *out)
{
    if (!noun_is_cell(g_evq))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(g_evq);
    *out = c->head;
    return 1;
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

/*
 * Persist semispace compaction (ArenaHost-shaped).
 *
 * Call while SCRATCH holds the slam product and the *current* persist half
 * still holds the previous gate/queue/tokens (readable).
 *
 * Flip to the empty half, deep-copy live roots there (may still read old half
 * for shared battery cells), abandon the old half until the next flip.
 *
 * Caller must rebuild slam formula afterward (it lived on the old half).
 * Do NOT scratch_reset until after dispatch_effects (effects still in scratch).
 */
static noun persist_compact(noun new_gate, noun new_causes)
{
    enum { QCAP = 256 };

    /* Capture queue chain head before we rebuild (still in old half) */
    noun old_q = g_evq;
    noun old_tok[TARM_MAX];
    int  tok_on[TARM_MAX];
    noun new_tok[TARM_MAX];
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active && g_tarms[i].i2_token != NOUN_ZERO
            && noun_is_cell(g_tarms[i].i2_token)) {
            old_tok[i] = g_tarms[i].i2_token;
            tok_on[i]  = 1;
        } else {
            old_tok[i] = NOUN_ZERO;
            tok_on[i]  = 0;
        }
        new_tok[i] = NOUN_ZERO;
    }

    /* Write into the other semispace; old half remains readable */
    heap_persist_begin_tx();
    heap_set_mode(HEAP_MODE_PERSIST);

    /* Build every candidate root without publishing a live root. */
    noun candidate_gate = noun_copy(new_gate);
    noun candidate_q = NOUN_ZERO;
    noun candidate_tail = NOUN_ZERO;
    uint64_t candidate_n = 0;

#define CANDIDATE_ENQ(ev) do { \
    noun ce = noun_copy((ev)); \
    noun cc = alloc_cell(ce, NOUN_ZERO); \
    if (!noun_is_cell(candidate_q)) { candidate_q = cc; candidate_tail = cc; } \
    else { ((cell_t *)(uintptr_t)cell_ptr(candidate_tail))->tail = cc; candidate_tail = cc; } \
    candidate_n++; \
} while (0)

    /* Prior queue events (old half) then new causes (scratch) */
    {
        noun q = old_q;
        uint64_t n = 0;
        while (noun_is_cell(q) && n < QCAP) {
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(q);
            CANDIDATE_ENQ(c->head);
            q = c->tail;
            n++;
        }
    }
    while (noun_is_cell(new_causes)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(new_causes);
        CANDIDATE_ENQ(c->head);
        new_causes = c->tail;
    }

    for (int i = 0; i < TARM_MAX; i++) {
        if (tok_on[i])
            new_tok[i] = noun_copy(old_tok[i]);
    }

    /* The fixed slam formula is a persistent root too.  Materialize it before
     * publication so formula allocation can still abort the transaction. */
    noun candidate_slam = build_slam_formula();

    /* The one publication point: no candidate allocation follows. */
    g_kernel = candidate_gate;
    g_evq = candidate_q;
    g_evq_tail = candidate_tail;
    g_evq_n = candidate_n;
    if (g_evq_n > g_evq_hwm)
        g_evq_hwm = g_evq_n;
    for (int i = 0; i < TARM_MAX; i++)
        g_tarms[i].i2_token = new_tok[i];
    heap_persist_commit_tx();
#undef CANDIDATE_ENQ
    return candidate_slam;
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

/* I2 service-request payload → UART print + reinject [%i2-service …] (instant) */
static void i2_service_uart_tx(noun data)
{
    /* service-request ::= [token [cap [op [deadline payload]]]] */
    if (!noun_is_cell(data))
        return;
    cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(data);
    noun token = c0->head;
    if (!noun_is_cell(c0->tail))
        return;
    cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
    if (!noun_is_cell(c1->tail))
        return;
    cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
    if (!noun_is_cell(c2->tail))
        return;
    cell_t *c3 = (cell_t *)(uintptr_t)cell_ptr(c2->tail);
    noun payload = c3->tail;
    /* typed STRING: [tid [len bytes-atom]] */
    if (noun_is_cell(payload)) {
        cell_t *pv = (cell_t *)(uintptr_t)cell_ptr(payload);
        if (noun_is_cell(pv->tail)) {
            cell_t *sv = (cell_t *)(uintptr_t)cell_ptr(pv->tail);
            atom_print_uart(sv->tail);
            evq_enq(make_i2_service_event(token));
            return;
        }
    }
    if (noun_is_atom(payload))
        atom_print_uart(payload);
    /* Instant completion (HostRunner instant_services): success status 0 */
    evq_enq(make_i2_service_event(token));
}

/*
 * I2 effect preflight before promote (Host ABI §12.5 subset).
 * On failure: do not replace g_kernel, do not dispatch, do not enqueue causes.
 */
static int i2_preflight_effects(noun effects, noun causes)
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
            if (deadline == 0)
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
    if (g_evq_n + cause_n + (uint64_t)new_svcs > EVQ_CAP)
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

static void kernel_loop(noun kernel_init, int shrine)
{
    g_kernel       = kernel_init;
    g_shrine_mode  = shrine ? 1 : 0;
    g_live_version = noun_pill_version;  /* from pill header if any */
    noun slam = build_slam_formula();
    /* Mid-eval wall: poll deadline every 256 ops inside nock_budget_tick */
    nock_wall_check_set(deadline_expired);
    uart_puts(g_shrine_mode ? "\r\ntrinitite shrine\r\n"
                             : "\r\ntrinitite arvo\r\n");

    for (;;) {
        int jr = setjmp(nock_abort);
        if (jr == NOCK_ABORT_CRASH) {
            uart_puts("\r\nkernel crash\r\n");
            heap_persist_abort_tx();
            if (g_i2_preparing) {
                /* Candidate allocation failed before publication.  Roll back
                 * allocator state only; old gate/FIFO/registries are still
                 * live and must not be treated as a structural Nock crash. */
                g_i2_preparing = 0;
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
            emit_timeout(nock_ops_used());
            deadline_set(0);
            continue;
        }

        /* Phase 6 safe point: apply staged kernel if queue is idle */
        swap_apply_if_ready();

        /* Phase 7: software WDT + canary at loop head */
        if (wdt_check())
            emit_wdt();
        wdt_kick();
        if (!canary_ok()) {
            trace_rec(T_CAN, 0);
            uart_puts("canary\r\n");
        }

        /* Phase 3: IRQ ring → event queue before schedule */
        irq_ring_drain();

        /* Multi-arm timers → [%ei id %TICK 0] into queue */
        tarm_poll();

        noun event;
        if (!evq_deq(&event)) {
            /*
             * Idle path (WP1): do not block forever in uart_recv_noun.
             * While the queue is empty and no UART frame has started,
             * keep polling multi-arm timers + soft WDT so period-driven
             * IEC graphs advance without a second host poke.
             *
             * Once RX has a byte, take a full framed noun (remaining
             * bytes may still block briefly mid-frame — acceptable).
             */
            for (;;) {
                if (uart_rx_ready()) {
                    event = uart_recv_noun();
                    break;
                }
                tarm_poll();
                if (evq_deq(&event))
                    break;
                if (wdt_check())
                    emit_wdt();
                wdt_kick();
                if (!canary_ok()) {
                    trace_rec(T_CAN, 0);
                    uart_puts("canary\r\n");
                }
            }
        }

        uint64_t t0 = 0;
        if (trace_enabled()) {
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
            trace_rec(T_EV0, 0);
        }

        /* Per-event scratch: Nock product dies after promote/dispatch */
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_SCRATCH);

        nock_budget_set(g_slam_budget);
        noun subject = alloc_cell(g_kernel, event);
        noun result  = nock(subject, slam);

        if (trace_enabled()) {
            uint64_t t1;
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
            trace_rec(T_EV1, (uint32_t)(t1 - t0));
        }

        if (deadline_expired()) {
            emit_timeout(0);
            deadline_set(0);
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            continue;
        }

        if (!noun_is_cell(result)) {
            uart_puts("bad result\r\n");
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
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
                if (!noun_is_cell(r->tail)) {
                    uart_puts("bad result\r\n");
                    heap_set_mode(HEAP_MODE_PERSIST);
                    heap_scratch_reset();
                    continue;
                }
                cell_t *prod = (cell_t *)(uintptr_t)cell_ptr(r->tail);
                noun effects = prod->head;
                if (!noun_is_cell(prod->tail)) {
                    uart_puts("bad result\r\n");
                    heap_set_mode(HEAP_MODE_PERSIST);
                    heap_scratch_reset();
                    continue;
                }
                cell_t *gc = (cell_t *)(uintptr_t)cell_ptr(prod->tail);
                if (!i2_preflight_effects(effects, gc->tail)) {
                    static int pf_uart;
                    if (!pf_uart) {
                        pf_uart = 1;
                        uart_puts("preflight\r\n");
                    }
                    heap_set_mode(HEAP_MODE_PERSIST);
                    heap_scratch_reset();
                    continue;
                }
                /*
                 * Compact PERSIST to live roots (gate + queue + tokens + causes).
                 * Slam formula was on old persist — rebuild after compact.
                 * Effects stay in SCRATCH until dispatch finishes.
                 */
                g_i2_preparing = 1;
                slam = persist_compact(gc->head, gc->tail);
                g_i2_preparing = 0;
                dispatch_effects(effects); /* arms timers / service completions */
                heap_set_mode(HEAP_MODE_PERSIST);
                heap_scratch_reset();
                /* Optional durable checkpoint (cold RAM store; SD later) */
                if (g_ckpt_every) {
                    g_ckpt_commits++;
                    if (g_ckpt_commits % g_ckpt_every == 0)
                        checkpoint_save();
                }
                continue;
            }
            if (rh == CORD_ABORT) {
                /* keep g_kernel; drop effects (Host ABI abort path) */
                heap_set_mode(HEAP_MODE_PERSIST);
                heap_scratch_reset();
                continue;
            }
        }

        noun effects = r->head;

        if (g_shrine_mode) {
            if (!noun_is_cell(r->tail)) {
                uart_puts("bad result\r\n");
                heap_set_mode(HEAP_MODE_PERSIST);
                heap_scratch_reset();
                continue;
            }
            cell_t *r2 = (cell_t *)(uintptr_t)cell_ptr(r->tail);
            slam = persist_compact(r2->head, r2->tail);
        } else {
            g_kernel = noun_persist(r->tail);
        }

        dispatch_effects(effects);
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
    }
}

void arvo_loop(noun kernel_init)
{
    kernel_loop(kernel_init, 0);
}

void shrine_loop(noun kernel_init)
{
    kernel_loop(kernel_init, 1);
}

/* ── Durable checkpoint (live roots → cold store) ───────────────────────── */

void shrine_gate_set(noun gate)
{
    heap_set_mode(HEAP_MODE_PERSIST);
    g_kernel = noun_persist(gate);
    g_shrine_mode = 1;
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

/*
 * Capture: [%i2-ckpt ver shrine gate queue tarms]
 * tarms entry: [id [period [remain-ticks token]]]
 * remain-ticks relative so restore is phase-preserving without absolute CNTVCT.
 */
noun checkpoint_capture(void)
{
    int old = heap_get_mode();
    heap_set_mode(HEAP_MODE_PERSIST);

    uint64_t now = cntvct();
    noun tarms = NOUN_ZERO;
    for (int i = TARM_MAX - 1; i >= 0; i--) {
        if (!g_tarms[i].active)
            continue;
        uint64_t remain = 1;
        if (g_tarms[i].next > now)
            remain = g_tarms[i].next - now;
        noun tok = g_tarms[i].i2_token;
        if (noun_is_cell(tok))
            tok = noun_copy(tok);
        noun ent = alloc_cell(direct(g_tarms[i].id),
                   alloc_cell(direct(g_tarms[i].period),
                   alloc_cell(direct(remain), tok)));
        tarms = alloc_cell(ent, tarms);
    }

    noun queue = noun_copy(g_evq);
    noun gate  = noun_copy(g_kernel);
    noun ckpt  = alloc_cell(direct(CORD_I2_CKPT),
                 alloc_cell(direct(CKPT_VER),
                 alloc_cell(direct(g_shrine_mode ? 1ULL : 0ULL),
                 alloc_cell(gate,
                 alloc_cell(queue, tarms)))));

    heap_set_mode(old);
    return ckpt;
}

int checkpoint_install(noun ckpt)
{
    if (!noun_is_cell(ckpt))
        return -1;
    cell_t *c0 = (cell_t *)(uintptr_t)cell_ptr(ckpt);
    if (!noun_is_direct(c0->head) || direct_val(c0->head) != CORD_I2_CKPT)
        return -1;
    if (!noun_is_cell(c0->tail))
        return -1;
    cell_t *c1 = (cell_t *)(uintptr_t)cell_ptr(c0->tail);
    if (!noun_is_direct(c1->head) || direct_val(c1->head) != CKPT_VER)
        return -1;
    if (!noun_is_cell(c1->tail))
        return -1;
    cell_t *c2 = (cell_t *)(uintptr_t)cell_ptr(c1->tail);
    uint64_t shrine = atom_u64_early(c2->head);
    if (!noun_is_cell(c2->tail))
        return -1;
    cell_t *c3 = (cell_t *)(uintptr_t)cell_ptr(c2->tail);
    noun gate = c3->head;
    if (!noun_is_cell(c3->tail))
        return -1;
    cell_t *c4 = (cell_t *)(uintptr_t)cell_ptr(c3->tail);
    noun queue = c4->head;
    noun tarms = c4->tail;

    /* Fresh persist half; install roots (old half readable during copy) */
    tarm_clear();
    evq_clear();
    heap_persist_flip();
    heap_set_mode(HEAP_MODE_PERSIST);

    g_kernel      = noun_copy(gate);
    g_shrine_mode = shrine ? 1 : 0;

    {
        noun q = queue;
        uint64_t n = 0;
        while (noun_is_cell(q) && n < EVQ_CAP) {
            cell_t *c = (cell_t *)(uintptr_t)cell_ptr(q);
            evq_enq(c->head);
            q = c->tail;
            n++;
        }
    }

    uint64_t now = cntvct();
    noun tl = tarms;
    while (noun_is_cell(tl)) {
        cell_t *le = (cell_t *)(uintptr_t)cell_ptr(tl);
        noun ent = le->head;
        tl = le->tail;
        if (!noun_is_cell(ent))
            continue;
        cell_t *e0 = (cell_t *)(uintptr_t)cell_ptr(ent);
        uint64_t id = atom_u64_early(e0->head);
        if (!noun_is_cell(e0->tail))
            continue;
        cell_t *e1 = (cell_t *)(uintptr_t)cell_ptr(e0->tail);
        uint64_t period = atom_u64_early(e1->head);
        if (!noun_is_cell(e1->tail))
            continue;
        cell_t *e2 = (cell_t *)(uintptr_t)cell_ptr(e1->tail);
        uint64_t remain = atom_u64_early(e2->head);
        noun tok = e2->tail;
        if (period == 0 || id == 0)
            continue;
        int i = tarm_free_slot();
        if (i < 0)
            break;
        if (remain == 0)
            remain = 1;
        g_tarms[i].active   = 1;
        g_tarms[i].id       = id;
        g_tarms[i].period   = period;
        g_tarms[i].next     = now + remain;
        if (noun_is_cell(tok))
            g_tarms[i].i2_token = noun_copy(tok);
        else
            g_tarms[i].i2_token = NOUN_ZERO;
    }

    return 0;
}

int checkpoint_save(void)
{
    if (!noun_is_cell(g_kernel))
        return -1;
    noun ck = checkpoint_capture();
    /* RAM cold window only — NVFLUSH separately (needs QEMU -semihosting) */
    return cold_snap_save(ck);
}

int checkpoint_load(void)
{
    noun ck = cold_snap_load();
    if (!noun_is_cell(ck))
        return -1;
    return checkpoint_install(ck);
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

int kernel_boot(noun pill_gate)
{
    int want_snap = (g_boot_policy == BOOT_SNAP ||
                     g_boot_policy == BOOT_SNAP_ELSE_PILL);

    if (want_snap) {
        if (checkpoint_load() == 0) {
            uart_puts("boot: snap\r\n");
            if (g_shrine_mode)
                shrine_loop(g_kernel);
            else
                arvo_loop(g_kernel);
            return -1; /* unreachable */
        }
        if (g_boot_policy == BOOT_SNAP) {
            uart_puts("boot: no snap\r\n");
            return -1;
        }
        uart_puts("boot: snap miss → pill\r\n");
    }

    if (!noun_is_cell(pill_gate)) {
        uart_puts("boot: no pill\r\n");
        return -1;
    }

    uart_puts("boot: pill\r\n");
    g_kernel      = noun_persist(pill_gate);
    g_shrine_mode = noun_pill_shape ? 1 : 0;
    if (g_shrine_mode)
        shrine_loop(g_kernel);
    else
        arvo_loop(g_kernel);
    return -1;
}
