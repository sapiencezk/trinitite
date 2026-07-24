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

/* Kernel event ISA cords for timer fire (IEC host → kernel) */
#define CORD_EI      26981ULL                /* %ei       */
#define CORD_TICK    1262700884ULL           /* %TICK     */

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
} tarm_t;

static tarm_t g_tarms[TARM_MAX];

static int tarm_find(uint64_t id)
{
    for (int i = 0; i < TARM_MAX; i++) {
        if (g_tarms[i].active && g_tarms[i].id == id)
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
    if (period == 0) {
        tarm_can(id);
        return;
    }
    int i = tarm_find(id);
    if (i < 0) {
        i = tarm_free_slot();
        if (i < 0)
            return;   /* full — silent drop (host capacity limit) */
    }
    g_tarms[i].active = 1;
    g_tarms[i].id     = id;
    g_tarms[i].period = period;
    g_tarms[i].next   = cntvct() + period;
}

void tarm_can(uint64_t id)
{
    int i = tarm_find(id);
    if (i >= 0)
        g_tarms[i].active = 0;
}

void tarm_clear(void)
{
    for (int i = 0; i < TARM_MAX; i++)
        g_tarms[i].active = 0;
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

static noun make_tick_event(uint64_t id)
{
    /* [%ei id %TICK 0]  ≡  [ei [id [TICK 0]]] */
    return alloc_cell(direct(CORD_EI),
           alloc_cell(direct(id),
           alloc_cell(direct(CORD_TICK), NOUN_ZERO)));
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
        evq_enq(make_tick_event(g_tarms[i].id));
        /* slip: do not catch up missed periods */
        g_tarms[i].next = now + g_tarms[i].period;
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

/* ── Phase 2 — FIFO event queue ──────────────────────────────────────────── */

static noun g_evq;

void evq_clear(void)
{
    g_evq = NOUN_ZERO;
}

void evq_enq(noun event)
{
    noun cell = alloc_cell(event, NOUN_ZERO);
    if (!noun_is_cell(g_evq)) {
        g_evq = cell;
        return;
    }
    noun cur = g_evq;
    for (;;) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(cur);
        if (!noun_is_cell(c->tail)) {
            c->tail = cell;
            return;
        }
        cur = c->tail;
    }
}

int evq_deq(noun *out)
{
    if (!noun_is_cell(g_evq))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(g_evq);
    *out = c->head;
    g_evq = c->tail;
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
    uint64_t n = 0;
    noun cur = g_evq;
    while (noun_is_cell(cur)) {
        n++;
        cur = ((cell_t *)(uintptr_t)cell_ptr(cur))->tail;
    }
    return n;
}

void evq_enq_list(noun list)
{
    while (noun_is_cell(list)) {
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(list);
        evq_enq(c->head);
        list = c->tail;
    }
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

static void dispatch_one(noun tag, noun data) {
    if (!noun_is_atom(tag)) return;
    uint64_t t = noun_is_direct(tag) ? direct_val(tag) : 0;

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
    /* unknown: silent ignore */
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

/* ── Kernel event loops ──────────────────────────────────────────────────── */

static void kernel_loop(noun kernel_init, int shrine)
{
    g_kernel       = kernel_init;
    g_shrine_mode  = shrine ? 1 : 0;
    g_live_version = noun_pill_version;  /* from pill header if any */
    noun slam = build_slam_formula();
    uart_puts(g_shrine_mode ? "\r\ntrinitite shrine\r\n"
                             : "\r\ntrinitite arvo\r\n");

    for (;;) {
        if (setjmp(nock_abort) != 0) {
            uart_puts("\r\nkernel crash\r\n");
            evq_clear();
            irq_ring_clear();
            tarm_clear();
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
        if (!evq_deq(&event))
            event = uart_recv_noun();

        uint64_t t0 = 0;
        if (trace_enabled()) {
            __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
            trace_rec(T_EV0, 0);
        }

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
            continue;
        }

        if (!noun_is_cell(result)) {
            uart_puts("bad result\r\n");
            continue;
        }
        cell_t *r = (cell_t *)(uintptr_t)cell_ptr(result);
        noun effects = r->head;

        if (g_shrine_mode) {
            if (!noun_is_cell(r->tail)) {
                uart_puts("bad result\r\n");
                continue;
            }
            cell_t *r2 = (cell_t *)(uintptr_t)cell_ptr(r->tail);
            g_kernel = r2->head;
            evq_enq_list(r2->tail);
        } else {
            g_kernel = r->tail;
        }

        dispatch_effects(effects);
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
