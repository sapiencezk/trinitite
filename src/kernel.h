#pragma once
#include <stdint.h>
#include "noun.h"

/*
 * Kernel loop + industrial Phases 1–8 + multi-arm timers.
 *
 * Effects: walk [[tag data] rest]. Known tags (cords, LSB-first ASCII):
 *   %out %blit %timeout %mmio %tmrarm %tmrcan %irq
 *   %tset     1952805748         data = [id period]  multi-arm periodic
 *   %tcan     1851876212         data = id           cancel arm
 *   %swapped  28259031267243891  data = version atom
 *   %wdt      7627895            software watchdog fired
 *   %etx/%mtx/%ctx  net stubs (see net.h); loopback → evq RX events
 *
 * Multi-arm timers fire [%ei id %TICK 0] into the event queue (slip on overrun).
 * Legacy %tmrarm/%tmrcan remain the single global cooperative deadline.
 *
 * Phase 6 hot-swap: STAGE + HSWAP at cooperative safe points (empty evq).
 * Phase 7: trace ring + soft WDT + canary (see trace.h).
 * Phase 8: networking stubs (see net.h).
 * arvo_loop / shrine_loop: never return.
 */

noun uart_recv_noun(void);
void uart_send_noun(noun n);
void dispatch_effects(noun effects);
void arvo_loop(noun kernel);
void shrine_loop(noun kernel);

/* Phase 1 — deadline */
void     deadline_set(uint64_t abs);
uint64_t deadline_get(void);
int      deadline_expired(void);
void     emit_timeout(uint64_t elapsed);

/* Multi-arm periodic timers (%tset / %tcan) — IEC host contract */
void     tarm_set(uint64_t id, uint64_t period);  /* period 0 = cancel */
void     tarm_can(uint64_t id);
void     tarm_poll(void);           /* fire due arms → evq as [%ei id %TICK 0] */
void     tarm_clear(void);          /* disarm all (tests / crash recovery) */
int      tarm_active(uint64_t id);  /* 1 if armed */
uint64_t tarm_next(uint64_t id);    /* next abs deadline, 0 if inactive */
void     tarm_force_due(uint64_t id); /* test helper: next = now-1 if armed */

/* Phase 2 — event queue */
void     evq_enq(noun event);
int      evq_deq(noun *out);
int      evq_peek(noun *out);
void     evq_clear(void);
uint64_t evq_len(void);
void     evq_enq_list(noun list);

/* Phase 3 — MMIO (32-bit) */
uint32_t mmio_read32(uint64_t addr);
void     mmio_write32(uint64_t addr, uint32_t val);
uint64_t mmio_scratch_addr(void);   /* RAM scratch for tests */

/* Phase 3 — IRQ ring (SPSC, single-core; no GIC yet) */
int  irq_ring_push(uint64_t code);  /* 1 ok, 0 full */
void irq_ring_drain(void);          /* pop all → evq_enq(direct(code)) */
void irq_ring_clear(void);

/* Phase 6 — cooperative kernel hot-swap */
void     swap_stage(noun kernel, int shape, uint32_t version);
int      swap_request(void);          /* arm pending; try apply; 1 if applied */
int      swap_apply_if_ready(void);   /* 1 if applied this call */
void     swap_cancel(void);
uint32_t swap_live_version(void);
int      swap_status(void);           /* 0 idle, 1 staged, 2 pending */
