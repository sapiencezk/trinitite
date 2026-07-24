#include <stdint.h>
#include "trace.h"
#include "memory.h"

#define TRACE_SIZE 256u   /* power of 2 */

static trace_rec_t tr_slot[TRACE_SIZE];
static volatile uint32_t tr_head;
static volatile uint32_t tr_tail;
static int tr_on;
static uint64_t tr_drop_count;
static uint32_t tr_last_tag;
static uint32_t tr_last_data;
static int tr_have_last;

static uint64_t wdt_period;
static uint64_t wdt_deadline;

static inline uint64_t cntvct(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

void trace_enable(int on)
{
    tr_on = on ? 1 : 0;
}

int trace_enabled(void)
{
    return tr_on;
}

void trace_clear(void)
{
    tr_head = 0;
    tr_tail = 0;
    tr_drop_count = 0;
    tr_have_last = 0;
    tr_last_tag = 0;
    tr_last_data = 0;
}

void trace_rec(uint32_t tag, uint32_t data)
{
    if (!tr_on)
        return;

    uint64_t now = cntvct();
    tr_last_tag = tag;
    tr_last_data = data;
    tr_have_last = 1;

    uint32_t h = tr_head;
    uint32_t n = (h + 1u) & (TRACE_SIZE - 1u);
    if (n == tr_tail) {
        /* Drop oldest to keep recent history */
        tr_tail = (tr_tail + 1u) & (TRACE_SIZE - 1u);
        tr_drop_count++;
    }
    tr_slot[h].t = now;
    tr_slot[h].tag = tag;
    tr_slot[h].data = data;
    tr_head = n;
}

uint64_t trace_len(void)
{
    return (uint64_t)((tr_head - tr_tail) & (TRACE_SIZE - 1u));
}

uint64_t trace_drops(void)
{
    return tr_drop_count;
}

int trace_last(uint32_t *tag, uint32_t *data)
{
    if (!tr_have_last)
        return 0;
    if (tag) *tag = tr_last_tag;
    if (data) *data = tr_last_data;
    return 1;
}

void wdt_set(uint64_t period_ticks)
{
    wdt_period = period_ticks;
    if (period_ticks)
        wdt_deadline = cntvct() + period_ticks;
    else
        wdt_deadline = 0;
}

void wdt_kick(void)
{
    if (wdt_period)
        wdt_deadline = cntvct() + wdt_period;
}

int wdt_check(void)
{
    if (!wdt_period || !wdt_deadline)
        return 0;
    if (cntvct() < wdt_deadline)
        return 0;
    trace_rec(T_WDT, 0);
    wdt_kick();
    return 1;
}

int canary_ok(void)
{
    return *(volatile uint32_t *)(uintptr_t)DSTACK_GUARD == STACK_CANARY;
}
