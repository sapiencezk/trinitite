#pragma once
#include <stdint.h>

/*
 * Phase 7 — observability: trace ring, software WDT, stack canary.
 * Core 0 only. No GIC / hardware WDT / MPU.
 */

/* Trace tags */
#define T_NOP   0u
#define T_MARK  1u   /* manual TREC */
#define T_EV0   2u   /* event start */
#define T_EV1   3u   /* event end; data = duration low 32 */
#define T_TOUT  4u   /* deadline / budget timeout */
#define T_SWAP  5u   /* hot-swap applied; data = version */
#define T_WDT   6u   /* software watchdog fired */
#define T_CAN   7u   /* stack canary failure */
#define T_NTX   8u   /* net TX stub; data = family 0/1/2 */
#define T_NRX   9u   /* net RX loopback inject; data = family */
#define T_BUD   10u  /* slam op budget fired; data = ops used low 32 */
#define T_OVF   11u  /* event queue overflow (drop-newest); data = total drops */
#define T_UFX   12u  /* unknown effect tag; data = cord low 32 */

typedef struct {
    uint64_t t;
    uint32_t tag;
    uint32_t data;
} trace_rec_t;

void     trace_enable(int on);
int      trace_enabled(void);
void     trace_clear(void);
void     trace_rec(uint32_t tag, uint32_t data);
uint64_t trace_len(void);
uint64_t trace_drops(void);
/* Last written record; returns 0 if empty. Fills *tag and *data. */
int      trace_last(uint32_t *tag, uint32_t *data);

/* Software watchdog: period 0 = off. Kick resets deadline. */
void     wdt_set(uint64_t period_ticks);
void     wdt_kick(void);
/* If expired: record T_WDT, return 1, and re-kick. Else 0. */
int      wdt_check(void);

/* Stack canary at DSTACK_GUARD */
int      canary_ok(void);
