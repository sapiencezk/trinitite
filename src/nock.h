#pragma once
#include "noun.h"

/*
 * Nock 4K evaluator + jets + slam budget.
 *
 * nock(subject, formula)            → product  (crashes on error)
 * nock_ex(subject, formula, j, sky) → product  (full API)
 * slot(axis, subject)               → noun     (Nock / operator)
 *
 * Jet pack (C hot_state, pure — no MMIO): arithmetic + WP3 structural/list/bit
 *   %dec %add %sub %mul %lth %gth %lte %gte %div %mod
 *   %eq %lsh %rsh %con %dis %mix %cap %mas %peg %lent %flop %weld
 * KERNEL path (nock_eval op9): C only. SKA nock_op9_continue: Forth then C.
 */

/* ── Scry handler (Nock 12) ────────────────────────────────────────────── */
/* Returns the scry result or crashes.  NULL = crash on any op 12.         */
typedef noun (*sky_fn_t)(noun path);

/* ── Sock: noun template for jet matching (%wild / SKA) ─────────────────── */
/*
 * cape: & (NOUN_YES = 0) → positions in `data` must match subject exactly
 *        | (NOUN_NO  = 1) → wildcard, any noun matches
 *        cell             → recurse into head/tail
 */
typedef struct { noun cape; noun data; } sock_t;

/* ── Wilt: scoped %wild registration list ────────────────────────────────── */
/* The evaluator owns one bounded slot per logical frame.                  */
#define WILT_MAX 16
typedef struct { noun label; sock_t sock; } wilt_entry_t;
typedef struct { int len; wilt_entry_t e[WILT_MAX]; } wilt_t;

/* ── Jet function type ────────────────────────────────────────────────────── */
typedef noun (*jet_fn_t)(noun core, const wilt_t *jets, sky_fn_t sky);

/* ── Crash recovery ──────────────────────────────────────────────────────── */
/* QUIT's restart path calls setjmp(nock_abort) to establish the recovery    */
/* point.  nock_crash() calls longjmp(nock_abort, NOCK_ABORT_CRASH).         */
/* Slam budget exhaustion uses longjmp(nock_abort, NOCK_ABORT_BUDGET).      */
#include "setjmp.h"
extern jmp_buf nock_abort;

#define NOCK_ABORT_CRASH  1
#define NOCK_ABORT_BUDGET 2

/* ── Crash ───────────────────────────────────────────────────────────────── */
__attribute__((noreturn)) void nock_crash(const char *msg);

/* ── Slam op budget (WP2) ────────────────────────────────────────────────── */
/*
 * Deterministic op counter checked on every nock_eval / SKA eval entry.
 * max_ops == 0 → unlimited (REPL / unit tests default).
 * On fire: longjmp(nock_abort, NOCK_ABORT_BUDGET) — no product returned.
 * Optional wall: every 256 ops call wall_check if set (kernel deadline).
 */
void     nock_budget_set(uint64_t max_ops);   /* also resets ops_used */
void     nock_budget_set_limits(uint64_t max_ops, uint64_t max_cells);
void     nock_budget_finish(void);
uint64_t nock_budget_get(void);               /* current max (0 = off) */
uint64_t nock_ops_used(void);
uint64_t nock_cells_used(void);
/* Reason: 1=op budget, 2=wall deadline, 3=cell budget, 4=evaluator stack. */
uint64_t nock_budget_abort_reason(void);
uint64_t nock_eval_stack_peak(void);
void     nock_eval_stack_set_limit(uint64_t limit);
void     nock_wall_check_set(int (*fn)(void)); /* 1 → budget abort */
/* Tick one op; may longjmp. Public so SKA eval paths share the same budget. */
void     nock_budget_tick(void);
#if defined(M38_D8_WAVE_B_B0)
void     nock_b0_metrics_reset(void);
#endif
#ifdef M8_EVIDENCE
uint64_t nock_cell_budget_selftest(void);
#endif

/* ── Public API ──────────────────────────────────────────────────────────── */
noun nock(noun subject, noun formula);
noun nock_ex(noun subject, noun formula, const wilt_t *jets, sky_fn_t sky);
noun slot(noun axis, noun subject);

/*
 * nock_op9_continue: complete an op-9 invocation starting from an already-
 * evaluated core.  Checks the active %wild registrations; if a jet matches,
 * dispatches directly.  Otherwise slots the arm at `ax` from `core` and
 * evaluates (core, arm) via TCO.
 *
 * Used by eval_nomm in ska.c so that NOMM_9 nodes benefit from jet dispatch
 * without having to re-evaluate the core formula through nock_eval.
 */
noun nock_op9_continue(noun core, noun ax,
                       const wilt_t *jets, sky_fn_t sky);

/* ── Jet lookup and sock matching ────────────────────────────────────────── */
/*
 * hot_lookup: look up a jet by its label cord.  Returns NULL if not found.
 * Used by the SKA cook pass to pre-wire jet pointers at NOMM_DS2 sites.
 */
jet_fn_t hot_lookup(noun label);

/*
 * hot_reverse_label: given a jet function pointer, return its label cord.
 * Returns 0 if not found.  Used by ska_print_stats (Stage 9d) to print
 * the name of a C hot_state jet at a jetted call site.
 */
uint64_t hot_reverse_label(jet_fn_t fn);

/*
 * sock_match: structural pattern match against a (cape, data, subject) triple.
 *   cape == 0 (& / NOUN_YES) → exact match: noun_eq(data, subject) required
 *   cape == 1 (| / NOUN_NO)  → wildcard: always matches
 *   cape is cell              → recurse into head and tail
 */
int sock_match(noun cape, noun data, noun subject);
