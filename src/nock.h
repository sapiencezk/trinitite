#pragma once
#include "noun.h"

/*
 * Nock 4K evaluator + jets + slam budget.
 *
 * nock(subject, formula)            → product  (crashes on error)
 * slot(axis, subject)               → noun     (Nock / operator)
 *
 * Jet pack (C hot_state, pure — no MMIO): arithmetic + WP3 structural/list/bit
 *   %dec %add %sub %mul %lth %gth %lte %gte %div %mod
 *   %eq %lsh %rsh %con %dis %mix %cap %mas %peg %lent %flop %weld
 *   L1 %fast: %turn %mole
 * Op 9 dispatches to C jets only.
 * honk %fast clues register the first battery per hot label; op 9 axis 2
 * matches that battery. %wild is unchanged and still wins when present.
 */

/* ── Scry handler (Nock 12) ────────────────────────────────────────────── */
/* Returns the scry result or crashes.  NULL = crash on any op 12.         */
typedef noun (*sky_fn_t)(noun path);

/* ── Sock: noun template for jet matching (%wild) ───────────────────────── */
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
/* As nock_crash, but the bail's mote is %meme (memory exhausted), not %exit. */
__attribute__((noreturn)) void nock_crash_meme(const char *msg);

/* ── Bail mote and trace (the full node's goof = [mote tang]) ────────────── */
/*
 * The last crash's mote: %exit, or %meme for nock_crash_meme.  The trace is
 * the nockvm mean stack: a list of [tag clue] for the enclosing dynamic
 * %hand/%hunk/%lose/%mean/%spot hints, innermost first, as it stood at the
 * crash.  nock_trace_set(0) before an eval; read it after NOCK_ABORT_CRASH.
 * nock_mook renders a trace into a tang as nockvm's +mook does.
 */
uint64_t nock_crash_mote(void);
noun     nock_trace_get(void);
void     nock_trace_set(noun trace);
noun     nock_mook(noun trace);

/* ── Slam op budget (WP2) ────────────────────────────────────────────────── */
/*
 * Deterministic op counter checked on every nock_eval entry.
 * max_ops == 0 → unlimited (REPL / unit tests default).
 * On fire: longjmp(nock_abort, NOCK_ABORT_BUDGET) — no product returned.
 */
void     nock_budget_set(uint64_t max_ops);   /* also resets ops_used */
void     nock_budget_set_limits(uint64_t max_ops, uint64_t max_cells);
void     nock_budget_finish(void);
uint64_t nock_ops_used(void);
uint64_t nock_cells_used(void);
/* Reason: 1=op budget, 3=cell budget, 4=evaluator stack. */
uint64_t nock_budget_abort_reason(void);
uint64_t nock_eval_stack_peak(void);
void     nock_eval_stack_set_limit(uint64_t limit);
/* Tick one op; may longjmp. */
void     nock_budget_tick(void);

/* ── Public API ──────────────────────────────────────────────────────────── */
noun nock(noun subject, noun formula);
noun slot(noun axis, noun subject);

/* ── Jet lookup and sock matching ────────────────────────────────────────── */
/*
 * hot_lookup: look up a jet by its label cord.  Returns NULL if not found.
 */
jet_fn_t hot_lookup(noun label);


int      hot_entry_count(void);
const char *hot_entry_name(int i);
/* hot_name_is: is atom `label` the cord `name` (any width)? */
int      hot_name_is(noun label, const char *name);
uint64_t hot_entry_hits(int i);
void     hot_hits_reset(void);

/* 1499kernel row 328: ++digest of a noun (hash-hashable-noun:digest-lib, then
 * digest-to-atom), as 40 little-endian bytes: what the kernel's /state-hash
 * gives for its state. 0 if the walk's tables or stacks are too small. */
int      nock_tip5_digest(noun n, uint8_t out[40]);

void     fast_reset(void);
void     nock_host_roots(void (*f)(noun, int)); /* row 221, LITE_COMPACT only */
uint64_t fast_clue_count(void);
int      fast_reg_count(void);
int      fast_cold_count(void);
int      fast_cold_entry(int i, noun *chum, int *parent, uint64_t *axis);
uint64_t fast_cold_dropped(void);
uint64_t fast_invalidations(void);
uint64_t fast_dups(void);
int      fast_first_clue_ok(void);
noun     fast_first_clue(void);
int      fast_chum_count(void);
noun     fast_chum_at(int i);
#if defined(LITE_PROBE)
noun     fast_core_lookup(noun label);
int      fast_core_count(void);
const char *fast_core_name(int i);
int      fast_pull_hot(void);
void     fast_suppress(int i);
void     fast_suppress_hot(uint64_t mask);
int      hot_index_of(noun label);
void     fast_epoch_bump(void);
int      fast_reg_entry(int i, const char **label, noun *core);
#endif

/*
 * sock_match: structural pattern match against a (cape, data, subject) triple.
 *   cape == 0 (& / NOUN_YES) → exact match: noun_eq(data, subject) required
 *   cape == 1 (| / NOUN_NO)  → wildcard: always matches
 *   cape is cell              → recurse into head and tail
 */
int sock_match(noun cape, noun data, noun subject);
