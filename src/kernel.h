#pragma once
#include <stdint.h>
#include "noun.h"
#include "runtime_identity.h"

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
 *   I2 Host ABI: i2-timer-set / i2-timer-cancel / i2-service-request /
 *     i2-service-cancel (hash62 + string + short aliases i2ts/i2tc/i2sr/i2sc)
 *
 * I2 slam product (hybrid battery, shrine): [%commit [effects [gate causes]]]
 *   or [%abort fault] (no promote). I1 product [effects [gate causes]] still
 *   accepted only for an isolated legacy pill. I2 performs device preflight,
 *   complete reservation/candidate construction, one publication, and a
 *   no-allocation activation pass.
 *
 * Heap/atom ceilings (noun.c): bump past HEAP_TOP or atom-data/index full →
 *   nock_crash (never silent overrun into atom index). Persist semispace
 *   compact on promote; durable CKPT!/CKLOAD jam live roots to cold store.
 *
 * Multi-arm timers fire [%ei id %TICK 0] into the event queue (slip on overrun),
 * or [%i2-timer token fired-at] when armed via i2-timer-set.
 * Legacy %tmrarm/%tmrcan remain the single global cooperative deadline.
 *
 * Idle schedule: I2 consumes a fixed UART byte budget through an incremental
 * framed parser, then polls tarm/WDT. Inter-byte/total-frame timeouts reset to
 * magic scan. Legacy uart_recv_noun remains reachable only on the I1 path.
 *
 * Slam budget (WP2): each event arms nock_budget_set(slam_budget); runaway
 * eval longjmps NOCK_ABORT_BUDGET — no product commit, tarms kept, %timeout.
 *
 * Queue (WP4): cap EVQ_CAP (default 256); drop-newest on overflow (T_OVF +
 * UART "overflow" once until clear). Unknown effect tags: T_UFX + UART
 * "unkfx" once/session. Crash: hard clears tarms (default); soft keeps them.
 *
 * Full host contract for IEC authors: docs/HOST-CONTRACT.md
 * M6 adds one closed capability-selected digital bank. It does not expose
 * addresses and does not make the retained legacy %mmio effect public I2 API.
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
/* M3 lab runner: execute exactly max_commits through the existing admitted
 * I2 scheduler, then return to Forth.  Requires kernel_prepare_pill(). */
int kernel_run_bounded(uint64_t max_commits);
/* Run one closed supervisor lifecycle intent ahead of the application FIFO.
 * Returns 0 only when that exact intent committed; every evaluator,
 * preflight, promotion, activation, or timeout terminal is a bounded failure.
 * This is not a public application ingress path. */
int kernel_m7_execute_lifecycle(noun event, int stopping);

/* Phase 1 — deadline */
void     deadline_set(uint64_t abs);
uint64_t deadline_get(void);
int      deadline_expired(void);
void     emit_timeout(uint64_t elapsed);

/* WP2 — per-slam Nock op budget (0 = unlimited; legacy default 1e6).
 * An identity-admitted I2 gate replaces it with its bounded execution request,
 * capped by the target at 2e6. */
void     slam_budget_set(uint64_t max_ops);
uint64_t slam_budget_get(void);
uint64_t slam_cell_budget_get(void);

/* Multi-arm periodic timers (%tset / %tcan) — IEC host contract */
void     tarm_set(uint64_t id, uint64_t period);  /* period 0 = cancel */
void     tarm_set_i2(uint64_t id, uint64_t period, noun i2_token);
/* I2: period arm + token → fire [%i2-timer token fired-at] instead of TICK */
void     tarm_can(uint64_t id);
void     tarm_poll(void);           /* fire due arms → evq as [%ei id %TICK 0] or I2 */
void     tarm_clear(void);          /* disarm all (tests / crash recovery) */
int      tarm_active(uint64_t id);  /* 1 if armed */
uint64_t tarm_next(uint64_t id);    /* next abs deadline, 0 if inactive */
void     tarm_force_due(uint64_t id); /* test helper: next = now-1 if armed */

/* Phase 2 — event queue (WP4: capped, drop-newest) */
void     evq_enq(noun event);           /* drop-newest if full */
int      evq_deq(noun *out);
int      evq_peek(noun *out);
void     evq_clear(void);               /* empty queue; keeps overflow totals */
uint64_t evq_len(void);
void     evq_enq_list(noun list);
uint64_t evq_cap(void);                 /* EVQ_CAP */
uint64_t evq_hwm(void);                 /* high-water depth this session */
uint64_t evq_overflows(void);           /* drop-newest count */
void     evq_metrics_reset(void);       /* zero overflows + hwm baseline */
uint64_t kernel_queue_pressure_selftest(uint64_t percent);
uint64_t kernel_queue_retry_selftest(void);
uint64_t kernel_i2_limit_shape_selftest(void);
#ifdef M8_EVIDENCE
uint64_t kernel_m8_external_ingress_selftest(void);
uint64_t kernel_m8_input_failure_safe_selftest(void);
uint64_t kernel_m8_service_state(void);
uint64_t kernel_m8_checkpoint_restore_selftest(void);
uint64_t kernel_m8_profile_admission_selftest(void);
uint64_t kernel_m8_state_matrix_selftest(void);
#endif

/* WP4 — crash recovery: 0 hard (clear tarms), 1 soft (keep tarms) */
void     crash_soft_set(int soft);
int      crash_soft_get(void);
void     crash_recover_host(void);  /* clear queue/IRQ; tarms per policy */

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

/*
 * Durable checkpoint of live host+resource roots (RAM cold store for now;
 * SD backend later via cold_*). Noun shape:
 *   [%i2-ckpt 2 [152 runtime-identity-record] shrine gate queue tarms]
 * tarms ::= * [id period remain-ticks token]
 */
void     shrine_gate_set(noun gate);   /* install live gate (persist copy) */
noun     shrine_gate_get(void);
int      shrine_mode_get(void);

noun     checkpoint_capture(void);     /* build ckpt noun (persist heap) */
int      checkpoint_install(noun ckpt);/* 0 ok, -1 bad shape */
int      checkpoint_save(void);        /* capture → cold_snap_save; 0 ok */
int      checkpoint_load(void);        /* cold_snap_load → install; 0 ok */
void     checkpoint_auto_every(uint64_t n); /* 0=off; save every n commits */
uint64_t checkpoint_auto_get(void);
int      checkpoint_last_result(void);
uint64_t checkpoint_selected_generation(void);

/*
 * Boot policy for KERNEL:
 *   0 BOOT_PILL           — pill only (default; ignore snap)
 *   1 BOOT_SNAP_ELSE_PILL — CKLOAD if snap present, else pill
 *   2 BOOT_SNAP           — require snap (fail to REPL if none)
 */
#define BOOT_PILL            0
#define BOOT_SNAP_ELSE_PILL  1
#define BOOT_SNAP            2
void     boot_policy_set(int policy);
int      boot_policy_get(void);
/* Apply policy and enter arvo/shrine loop. pill_gate may be 0.
 * Never returns on success; returns -1 to fall back to REPL. */
int      kernel_boot(noun pill_gate);
/* M7 publication after durable candidate selection. */
int      kernel_m7_publish(noun gate, const runtime_identity_t *identity,
                           uint8_t capability_profile);
int      kernel_m7_prepare_publish(noun gate,
                                   const runtime_identity_t *identity,
                                   noun *slam_out);
void     kernel_m7_publish_prepared(noun gate,
                                    const runtime_identity_t *identity,
                                    uint8_t capability_profile, noun slam);
uint64_t kernel_m7_lifecycle_root_commits(void);
uint64_t kernel_m7_lifecycle_destination_commits(void);
int      kernel_m7_replace_gate(noun gate);
int      kernel_m7_gate_with_incarnation(noun source, uint64_t incarnation,
                                          noun *out);
int      kernel_m7_gate_with_identity_incarnation(
             noun source, const runtime_identity_t *identity,
             uint64_t incarnation, noun *out);
int      kernel_m7_checkpoint_capture_roots(noun *gate, noun *queue,
                                             noun *tarms);
int      kernel_m7_restore_checkpoint(const runtime_identity_t *identity,
                                      uint8_t capability_profile,
                                      uint64_t mode, noun gate, noun queue, noun tarms,
                                      noun manager_result);
/* Strict PILL2 bounded/identity load, with isolated legacy I1 fallback. */
noun     kernel_pill_load(void);
/* Lab/test preparation: admit PILL2 and install its clean roots without
 * entering the scheduler. This is used to construct restart fixtures. */
int      kernel_prepare_pill(void);

/* Generic, read-only I2 lab probes over the currently installed live gate.
 * They address instances/variables by admitted numeric IDs and contain no
 * application-specific knowledge.  UINT64_MAX means missing or malformed. */
uint64_t kernel_i2_active_state(uint64_t instance_id);
uint64_t kernel_i2_output_atom(uint64_t instance_id, uint64_t variable_id);

/* Focused M2 device-code probe; zero means bounded TX activation passed. */
uint64_t kernel_tx_stuck_selftest(void);
/* Requires kernel_prepare_pill() first; zero means restore matrix passed. */
uint64_t checkpoint_m2_selftest(void);
