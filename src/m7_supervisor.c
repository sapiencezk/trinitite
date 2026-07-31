#include <stddef.h>
#include <stdint.h>
#include "m7_supervisor.h"
#include "runtime_identity.h"
#include "bounded_cue.h"
#include "blake3.h"
#include "cold.h"
#include "digital_out.h"
#include "digital_in.h"
#include "kernel.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "uart.h"

/* One volatile stage.  It intentionally reuses the existing bounded PILL
 * scratch window; no staged bytes or decoded standby gate enter the live root. */
#define M7_STAGE_BASE PILL_SCRATCH_BASE
/* The jam writer has a 131072-byte output buffer.  A raw PILL atom of N
 * bytes needs 1 + 2*bitlen(bitlen(N*8)) + N*8 bits, so 131066 is the exact
 * conservative byte ceiling that cannot overflow that writer.  This is the
 * one end-to-end M7 deployment ceiling; larger PILL2 containers remain
 * admissible to the generic loader but not to TRI_DEPLOY. */
#define M7_STAGE_BYTES 131066u
#define M7_SNAPSHOT_BYTES 65536u
#define M7_MAX_CHUNK 4096u
#define M7_MAX_CHUNKS 256u
#define M7_MANAGER_BYTES 512u

#define CORD_COLD 0x646c6f63ULL
#define CORD_WARM 0x6d726177ULL
#define CORD_STOP 0x706f7473ULL

/* TRI_DEPLOY never returns IEC Table-7 values. */
enum {
    M7_DEPLOY_BUSY = -20,
    M7_DEPLOY_BOUNDS = -21,
    M7_DEPLOY_OFFSET = -22,
    M7_DEPLOY_DIGEST = -23,
    M7_DEPLOY_CANDIDATE = -24,
    M7_DEPLOY_STATE = -25,
    M7_DEPLOY_STORAGE = -26,
    M7_DEPLOY_MEDIA = -27,
    /* Final selection or its barrier returned an error after the new
     * superblock might have reached media.  This is intentionally not an IEC
     * Table-7 status and not an ordinary activation failure. */
    M7_DEPLOY_DURABILITY_UNKNOWN = -28
};

typedef struct {
    int ready;
    int manager_initialized;
    int pending;
    uint64_t pending_command;
    uint64_t pending_object_len;
    uint8_t pending_object[M7_MANAGER_BYTES];
    uint64_t mode;
    uint64_t incarnation;
    uint64_t req_plus;
    uint64_t confirmations;
    uint64_t last_status;
    uint64_t last_restart;
    uint64_t qo;
    noun formula;
    noun tag[8];
    noun table8_tag[18];
    noun lifecycle_event_tag;
    noun lifecycle_cold;
    noun lifecycle_warm;
    noun lifecycle_stop;
    int safe;
    uint8_t stage_digest[32];
    uint64_t stage_id;
    uint64_t stage_total;
    uint64_t stage_received;
    uint64_t stage_chunks;
    int stage_open;
    int stage_sealed;
    runtime_identity_t stage_identity;
    uint8_t stage_capability;
    uint64_t active_pill_hash;
    uint64_t active_pill_len;
    uint8_t active_pill_digest[32];
    int active_pill_valid;
    /* Physical deployment media was touched without a verified selected
     * result. Keep the prepared candidate safe/IDLE in RAM, but reject START
     * and all further persistent mutations until a reboot remounts media. */
    int durability_unknown;
    /* MANAGER OBJECT/RESULT are volatile bounded byte envelopes.  Keeping
     * either decoded noun in the live semispace made serial QUERY requests
     * consume seven cells each; the supervisor root retains no query tree. */
    uint64_t result_len;
    uint8_t result[M7_MANAGER_BYTES];
} m7_state_t;

static m7_state_t g_m7;
/* A clean deploy supervisor is constructed in the inactive semispace before
 * the cold pair is selected. It is not a standby application gate and is
 * never reachable from the live root. */
static m7_state_t g_m7_candidate;
static int g_m7_candidate_ready;

static int m7_reject(uint64_t status)
{
    g_m7.result_len = 0;
    g_m7.last_status = status;
    g_m7.qo = 0;
    return (int)status;
}

static noun pair(noun a, noun b)
{
    noun out = NOUN_ZERO;
    return alloc_cell_checked(a, b, &out) ? out : NOUN_ZERO;
}

static noun f_lit(noun value) { return pair(direct(1), value); }
static noun f_slot(uint64_t axis) { return pair(direct(0), direct(axis)); }
static noun f_op(uint64_t op, noun args) { return pair(direct(op), args); }
static noun f_unary(uint64_t op, noun a) { return f_op(op, a); }
static noun f_binary(uint64_t op, noun a, noun b)
{
    return f_op(op, pair(a, b));
}
static noun f_head(noun f) { return f_binary(7, f, f_slot(2)); }
static noun f_tail(noun f) { return f_binary(7, f, f_slot(3)); }
static noun f_eq(noun a, noun b) { return f_binary(5, a, b); }
static noun f_wut(noun a) { return f_unary(3, a); }
static noun f_iff(noun cond, noun yes, noun no)
{
    return f_op(6, pair(cond, pair(yes, no)));
}

static noun f_any_eq(noun value, const noun *values, size_t count)
{
    noun out = f_lit(direct(1));
    while (count != 0) {
        count--;
        out = f_iff(f_eq(value, f_lit(values[count])),
                    f_lit(direct(0)), out);
    }
    return out;
}

static noun f_result(noun status, noun next_mode, noun reason)
{
    return pair(f_lit(status), pair(next_mode, reason));
}

static noun manager_formula(const m7_state_t *state)
{
    noun mode = f_slot(2);
    noun rest = f_slot(3);
    noun pending = f_head(rest);
    noun request = f_tail(rest);
    noun command = f_head(request);
    noun object = f_tail(request);
    noun object_cell = f_wut(object);
    noun object_tag = f_head(object);
    noun object_id = f_tail(object);
    noun known[26];
    noun aggregates[3];
    noun queries[5];
    for (size_t i = 0; i < 8; i++) known[i] = state->tag[i];
    for (size_t i = 0; i < 18; i++) known[8 + i] = state->table8_tag[i];
    aggregates[0] = state->tag[0];
    aggregates[1] = state->tag[1];
    aggregates[2] = state->tag[2];
    queries[0] = state->tag[3];
    queries[1] = state->tag[4];
    queries[2] = state->tag[5];
    queries[3] = state->tag[6];
    queries[4] = state->tag[7];

    noun command_values[9];
    for (uint64_t i = 0; i < 9; i++) command_values[i] = direct(i);
    noun start_stop[2] = { direct(2), direct(3) };
    noun start_modes[2] = { direct(M7_MODE_IDLE), direct(M7_MODE_STOPPED) };
    noun operation_queries = f_any_eq(object_tag, queries, 5);
    noun aggregate = f_any_eq(object_tag, aggregates, 3);
    noun known_tag = f_any_eq(object_tag, known, 26);
    noun command_known = f_any_eq(command, command_values, 9);
    noun start_stop_ok = f_any_eq(command, start_stop, 2);
    noun valid_id = f_iff(f_wut(object_id), f_lit(direct(1)),
                          f_iff(f_eq(object_id, f_lit(direct(0))),
                                f_lit(direct(1)), f_lit(direct(0))));
    noun object_shape_ok = f_iff(object_cell, valid_id, f_lit(direct(1)));
    noun object_kind_ok = f_iff(known_tag, f_lit(direct(0)), f_lit(direct(1)));
    noun object_exists = f_iff(f_eq(object_id, f_lit(direct(1))),
                               f_lit(direct(0)), f_lit(direct(1)));
    noun operation_ok = f_iff(
        f_eq(command, f_lit(direct(7))), operation_queries,
        f_iff(start_stop_ok, aggregate, f_lit(direct(1))));
    noun start_state_ok = f_any_eq(mode, start_modes, 2);
    noun stop_state_ok = f_eq(mode, f_lit(direct(M7_MODE_RUNNING)));
    noun state_ok = f_iff(
        f_eq(command, f_lit(direct(2))), start_state_ok,
        f_iff(f_eq(command, f_lit(direct(3))), stop_state_ok,
              f_lit(direct(0))));
    noun next_mode = f_iff(f_eq(command, f_lit(direct(2))),
                           f_lit(direct(M7_MODE_RUNNING)),
                           f_lit(direct(M7_MODE_STOPPED)));
    noun start_reason = f_iff(
        f_eq(mode, f_lit(direct(M7_MODE_IDLE))),
        f_lit(state->lifecycle_cold), f_lit(state->lifecycle_warm));
    noun lifecycle_reason = f_iff(
        f_eq(command, f_lit(direct(2))), start_reason,
        f_iff(f_eq(command, f_lit(direct(3))),
              f_lit(state->lifecycle_stop), f_lit(direct(0))));
    noun state_result = f_iff(
        state_ok,
        f_result(direct(M7_STATUS_RDY), next_mode, lifecycle_reason),
        f_result(direct(M7_STATUS_INVALID_STATE), mode, f_lit(direct(0))));
    noun operation_result = f_iff(
        f_eq(command, f_lit(direct(7))),
        f_result(direct(M7_STATUS_RDY), mode, f_lit(direct(0))),
        state_result);
    noun existence_result = f_iff(
        operation_ok, operation_result,
        f_result(direct(M7_STATUS_INVALID_OPERATION), mode, f_lit(direct(0))));
    noun type_result = f_iff(
        object_exists, existence_result,
        f_result(direct(M7_STATUS_NO_SUCH_OBJECT), mode, f_lit(direct(0))));
    noun shape_result = f_iff(
        object_kind_ok, type_result,
        f_result(direct(M7_STATUS_UNSUPPORTED_TYPE), mode, f_lit(direct(0))));
    noun command_result = f_iff(
        object_shape_ok, shape_result,
        f_result(direct(M7_STATUS_INVALID_OBJECT), mode, f_lit(0)));
    return f_iff(
        f_eq(pending, f_lit(direct(1))),
        f_result(direct(M7_STATUS_OVERFLOW), mode, f_lit(direct(0))),
        f_iff(command_known, command_result,
              f_result(direct(M7_STATUS_UNSUPPORTED_CMD), mode,
                       f_lit(direct(0)))));
}

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int m7_is_identity(const runtime_identity_t *id)
{
    return id && id->runtime_abi[0] == 1 && id->runtime_abi[1] == 2
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 2
        && id->host_abi[0] == 1 && id->host_abi[1] == 2
        && id->deployment_schema[0] == 1
        && id->deployment_schema[1] == 2;
}

int m7_identity_active(void)
{
    return m7_is_identity(runtime_identity_get());
}

static int stage_digest_matches(void)
{
    uint8_t digest[32];
    blake3_hash((const void *)(uintptr_t)M7_STAGE_BASE,
                (size_t)g_m7.stage_total, digest);
    for (size_t i = 0; i < sizeof digest; i++)
        if (digest[i] != g_m7.stage_digest[i]) return 0;
    return 1;
}

static noun stage_digest_noun(void)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(g_m7.stage_digest); i++)
        ((uint8_t *)limbs)[i] = g_m7.stage_digest[i];
    return make_atom(limbs, 4);
}

static noun active_digest_noun(void)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(g_m7.active_pill_digest); i++)
        ((uint8_t *)limbs)[i] = g_m7.active_pill_digest[i];
    return make_atom(limbs, 4);
}

static int m7_manager_snapshot_root(const m7_state_t *state, noun *out)
{
    noun n0, n1, n2;
    /* RESULT is a volatile 512-byte reply buffer, deliberately excluded
     * from durable/live roots.  Old M7 snapshots carrying a noun RESULT are
     * a different binary shape and fail closed at restore. */
    if (!state || !out || !alloc_cell_checked(direct(state->qo), NOUN_ZERO, &n0)
        || !alloc_cell_checked(direct(state->last_status), n0, &n1)
        || !alloc_cell_checked(direct(state->manager_initialized != 0), n1, &n2))
        return 0;
    *out = n2;
    return 1;
}

static int m7_snapshot_build(uint64_t pill_hash, uint64_t pill_len,
                             noun pill_digest, noun identity, uint64_t mode,
                             noun reason, uint64_t incarnation, noun gate,
                             noun queue, noun tarms,
                             const m7_state_t *supervisor, noun *out)
{
    noun manager, rest, snapshot;
    if (!out || pill_hash == 0 || pill_len == 0
        || !noun_is_atom(pill_digest) || !noun_is_cell(identity)
        || !noun_is_cell(gate)
        || !m7_manager_snapshot_root(supervisor, &manager))
        return 0;
    rest = pair(queue, tarms);
    rest = pair(manager, rest);
    rest = pair(gate, rest);
    rest = pair(direct(incarnation), rest);
    rest = pair(reason, rest);
    rest = pair(direct(mode), rest);
    rest = pair(identity, rest);
    rest = pair(pill_digest, rest);
    rest = pair(direct(pill_len), rest);
    rest = pair(direct(pill_hash), rest);
    snapshot = pair(cord_from_bytes("M7-SUPERVISOR", 14), rest);
    uint64_t snapshot_bytes;
    if (!noun_is_cell(snapshot)
        || jam_size_checked(snapshot, M7_SNAPSHOT_BYTES, &snapshot_bytes) != 0)
        return 0;
    *out = snapshot;
    return 1;
}

static int m7_advance_incarnation(void)
{
    if (g_m7.incarnation == UINT64_MAX)
        return 0;
    uint64_t next = g_m7.incarnation + 1;
    noun next_gate;
    noun retained_formula, retained_result;
    heap_persist_begin_tx();
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!kernel_m7_gate_with_incarnation(
            shrine_gate_get(), next, &next_gate)
        || !m7_supervisor_retain_roots(
            &retained_formula, &retained_result)
        || kernel_m7_replace_gate(next_gate) != 0) {
        heap_persist_abort_tx();
        heap_set_mode(HEAP_MODE_PERSIST);
        return 0;
    }
    m7_supervisor_publish_roots(retained_formula, retained_result);
    heap_persist_commit_tx();
    g_m7.incarnation = next;
    return 1;
}

static int m7_capture_active_pill(void)
{
    const uint8_t *base = (const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t payload_len = 0;
    for (int i = 0; i < 8; i++)
        payload_len |= (uint64_t)base[16 + i] << (i * 8);
    if (payload_len == 0 || payload_len > M7_STAGE_BYTES - 256)
        return 0;
    uint64_t total = 256 + payload_len;
    uint64_t aligned = (total + 7) & ~7ULL;
    for (uint64_t i = 0; i < total; i++)
        ((uint8_t *)(uintptr_t)M7_STAGE_BASE)[i] = base[i];
    for (uint64_t i = total; i < aligned; i++)
        ((uint8_t *)(uintptr_t)M7_STAGE_BASE)[i] = 0;
    noun pill_atom;
    if (!make_atom_checked(
            (const uint64_t *)(uintptr_t)M7_STAGE_BASE,
            (total + 7) / 8, &pill_atom))
        return 0;
    uint64_t hash = cold_store(pill_atom);
    if (hash == 0)
        return 0;
    blake3_hash((const uint8_t *)(uintptr_t)M7_STAGE_BASE,
                (size_t)total, g_m7.active_pill_digest);
    g_m7.active_pill_hash = hash;
    g_m7.active_pill_len = total;
    g_m7.active_pill_valid = 1;
    return 1;
}

static int m7_initial_state(m7_state_t *out)
{
    if (!out) return 0;
    m7_state_t candidate = {0};
    candidate.tag[0] = cord_from_bytes("MANAGER", 7);
    candidate.tag[1] = cord_from_bytes("RESOURCE", 8);
    candidate.tag[2] = cord_from_bytes("APPLICATION", 11);
    candidate.tag[3] = cord_from_bytes("INVENTORY", 9);
    candidate.tag[4] = cord_from_bytes("IDENTITY", 8);
    candidate.tag[5] = cord_from_bytes("STATE", 5);
    candidate.tag[6] = cord_from_bytes("FB_INVENTORY", 12);
    candidate.tag[7] = cord_from_bytes("FB_STATUS", 9);
    const char *table8[] = {
        "TYPE_DECLARATION", "FB_TYPE_DECLARATION",
        "FB_INSTANCE_DEFINITION", "CONNECTION_DEFINITION",
        "DATA_TYPE_NAME", "FB_TYPE_NAME", "FB_INSTANCE_REFERENCE",
        "CONNECTION_START_POINT", "APPLICATION_NAME", "ALL_DATA_TYPES",
        "ALL_FB_TYPES", "EVENT_INPUT", "EVENT_OUTPUT", "DATA_INPUT",
        "DATA_OUTPUT", "PARAMETER_REFERENCE", "REFERENCED_PARAMETER",
        "PARAMETER"
    };
    const size_t table8_len[] = {
        16, 19, 22, 21, 14, 12, 21, 22, 16, 14, 12, 11, 12, 10,
        11, 19, 20, 9
    };
    for (size_t i = 0; i < 18; i++)
        candidate.table8_tag[i] = cord_from_bytes(table8[i], table8_len[i]);
    candidate.lifecycle_event_tag = cord_from_bytes("i2-lifecycle", 12);
    candidate.lifecycle_cold = cord_from_bytes("cold", 4);
    candidate.lifecycle_warm = cord_from_bytes("warm", 4);
    candidate.lifecycle_stop = cord_from_bytes("stop", 4);
    for (size_t i = 0; i < 8; i++)
        if (candidate.tag[i] == NOUN_ZERO) return 0;
    for (size_t i = 0; i < 18; i++)
        if (candidate.table8_tag[i] == NOUN_ZERO) return 0;
    if (candidate.lifecycle_event_tag == NOUN_ZERO
        || candidate.lifecycle_cold == NOUN_ZERO
        || candidate.lifecycle_warm == NOUN_ZERO
        || candidate.lifecycle_stop == NOUN_ZERO)
        return 0;
    candidate.formula = manager_formula(&candidate);
    if (!noun_is_cell(candidate.formula)) return 0;
    candidate.mode = M7_MODE_IDLE;
    candidate.incarnation = 1;
    candidate.last_status = M7_STATUS_RDY;
    candidate.qo = 1;
    candidate.safe = 1;
    candidate.manager_initialized = 1;
    candidate.ready = 1;
    *out = candidate;
    return 1;
}

int m7_init_for_identity(noun gate, const runtime_identity_t *id)
{
    if (!m7_is_identity(id) || !runtime_identity_validate_gate(gate, id, 0))
        return M7_STATUS_NOT_READY;
    if (!g_m7.ready) {
        m7_state_t candidate;
        int owns_transaction = !noun_tx_active();
        if (owns_transaction && !noun_tx_begin(HEAP_MODE_PERSIST))
            return M7_STATUS_SYSTEM_TERMINATION;
        if (!m7_initial_state(&candidate)) {
            /* Snapshot validation can deliberately hold the encompassing
             * candidate transaction.  Its caller owns that rollback. */
            if (owns_transaction)
                noun_tx_abort();
            return M7_STATUS_SYSTEM_TERMINATION;
        }
        if (owns_transaction)
            noun_tx_commit();
        /* No fallible operation follows this assignment.  Callers construct
         * and retain the full candidate before publishing their live root. */
        g_m7 = candidate;
    }
    return M7_STATUS_RDY;
}

int m7_init_clean_for_identity(noun gate, const runtime_identity_t *id)
{
    m7_state_t candidate;
    if (!m7_is_identity(id) || !runtime_identity_validate_gate(gate, id, 0)
        || !m7_initial_state(&candidate))
        return M7_STATUS_NOT_READY;
    /* The caller owns the clean-install candidate transaction. Once this
     * assignment occurs it performs no further fallible preparation. */
    g_m7 = candidate;
    return M7_STATUS_RDY;
}

int m7_init(noun gate)
{
    return m7_init_for_identity(gate, runtime_identity_get());
}

int m7_manager_init(int qi)
{
    if (!g_m7.ready) {
        return m7_reject(M7_STATUS_NOT_READY);
    }
    g_m7.manager_initialized = qi != 0;
    g_m7.pending = 0;
    g_m7.result_len = 0;
    g_m7.qo = g_m7.manager_initialized;
    g_m7.last_status = g_m7.manager_initialized
        ? M7_STATUS_RDY : M7_STATUS_NOT_READY;
    return (int)g_m7.last_status;
}

int m7_ready(void) { return g_m7.ready; }
uint64_t m7_mode(void) { return g_m7.mode; }
uint64_t m7_incarnation(void) { return g_m7.incarnation; }
uint64_t m7_req_plus(void) { return g_m7.req_plus; }
uint64_t m7_confirmations(void) { return g_m7.confirmations; }
uint64_t m7_qo(void) { return g_m7.qo; }
uint64_t m7_last_status(void) { return g_m7.last_status; }
uint64_t m7_last_restart(void) { return g_m7.last_restart; }
uint64_t m7_persist_cells(void) { return heap_cells_used(HEAP_MODE_PERSIST); }
uint64_t m7_atom_bytes(void) { return atom_store_bytes_used(); }
uint64_t m7_durability_unknown(void) { return g_m7.durability_unknown != 0; }

noun m7_last_result_noun(void)
{
    if (g_m7.result_len == 0 || g_m7.result_len > M7_MANAGER_BYTES)
        return NOUN_ZERO;
    cue_bounded_limits_t limits = cue_i2_limits;
    limits.max_input_bytes = M7_MANAGER_BYTES;
    limits.max_depth = 64;
    limits.max_cells = 64;
    limits.max_atom_bytes = 256;
    noun result = NOUN_ZERO;
    heap_scratch_reset();
    if (cue_bounded_bytes(g_m7.result, g_m7.result_len, &limits,
                          HEAP_MODE_SCRATCH, &result) != CUE_BOUNDED_OK) {
        if (noun_tx_active()) noun_tx_abort();
        heap_set_mode(HEAP_MODE_PERSIST);
        return NOUN_ZERO;
    }
    noun_tx_commit();
    heap_set_mode(HEAP_MODE_PERSIST);
    return result;
}

noun m7_formula_root(void)
{
    return g_m7.formula;
}

int m7_supervisor_retain_roots(noun *formula_out, noun *result_out)
{
    if (!formula_out || !result_out)
        return 0;
    noun formula = g_m7.formula;
    noun retained_formula = formula;
    if (noun_is_cell(formula)
        && !noun_copy_checked(formula, &retained_formula))
        return 0;
    *formula_out = retained_formula;
    *result_out = NOUN_ZERO;
    return 1;
}

void m7_supervisor_publish_roots(noun formula, noun result)
{
    g_m7.formula = formula;
    (void)result;
}

void m7_formula_publish(noun formula)
{
    g_m7.formula = formula;
}

void m7_result_publish(noun result)
{
    (void)result;
    g_m7.result_len = 0;
}

void m7_restore_state_commit(uint64_t mode, noun reason,
                             uint64_t incarnation,
                             uint64_t manager_initialized,
                             uint64_t last_status, uint64_t qo)
{
    g_m7.pending = 0;
    g_m7.pending_command = 0;
    g_m7.pending_object_len = 0;
    g_m7.mode = mode;
    g_m7.last_restart = reason;
    g_m7.incarnation = incarnation;
    g_m7.manager_initialized = manager_initialized != 0;
    g_m7.last_status = last_status;
    g_m7.qo = qo;
    g_m7.safe = 1;
}

void m7_restore_discard(void)
{
    g_m7 = (m7_state_t){0};
}

noun m7_object(uint64_t kind, uint64_t object_id)
{
    if (kind == 0 || kind > M7_OBJECT_COUNT || object_id == 0)
        return NOUN_ZERO;
    noun tag = kind <= 8 ? g_m7.tag[kind - 1]
                         : g_m7.table8_tag[kind - 9];
    heap_set_mode(HEAP_MODE_SCRATCH);
    noun object = pair(tag, direct(object_id));
    heap_set_mode(HEAP_MODE_PERSIST);
    return object;
}

static int m7_encode_noun(noun value, uint8_t *out, uint64_t *len_out)
{
    uint64_t len;
    noun atom;
    if (!out || !len_out || jam_size_checked(value, M7_MANAGER_BYTES, &len) != 0
        || len == 0 || len > M7_MANAGER_BYTES)
        return 0;
    atom = jam(value);
    if (!noun_atom_read_fixed(atom, out, (size_t)len))
        return 0;
    *len_out = len;
    return 1;
}

static int m7_store_request(uint64_t command, const uint8_t *object,
                            uint64_t object_len)
{
    if (!g_m7.ready || !g_m7.manager_initialized)
        return m7_reject(M7_STATUS_NOT_READY);
    g_m7.result_len = 0;
    if (g_m7.pending)
        return m7_reject(M7_STATUS_OVERFLOW);
    if (command > 8)
        return m7_reject(M7_STATUS_UNSUPPORTED_CMD);
    if (!object || object_len == 0 || object_len > M7_MANAGER_BYTES)
        return m7_reject(M7_STATUS_INVALID_OBJECT);
    for (uint64_t i = 0; i < object_len; i++)
        g_m7.pending_object[i] = object[i];
    g_m7.pending_object_len = object_len;
    g_m7.pending = 1;
    g_m7.pending_command = command;
    g_m7.last_status = M7_STATUS_RDY; /* receipt, not REQ+ */
    g_m7.qo = 1;
    return M7_STATUS_RDY;
}

int m7_manager_request(uint64_t command, noun object)
{
    uint8_t raw[M7_MANAGER_BYTES];
    uint64_t len = 0;
    int encoded = noun_is_cell(object) && noun_tx_begin(HEAP_MODE_SCRATCH)
        && m7_encode_noun(object, raw, &len);
    if (noun_tx_active()) noun_tx_abort();
    if (!encoded)
        return m7_reject(M7_STATUS_INVALID_OBJECT);
    return m7_manager_request_bytes(command, raw, len);
}

int m7_manager_request_bytes(uint64_t command, const uint8_t *object,
                             uint64_t object_len)
{
    if (!g_m7.ready || !g_m7.manager_initialized)
        return m7_reject(M7_STATUS_NOT_READY);
    if (g_m7.pending)
        return m7_reject(M7_STATUS_OVERFLOW);
    if (command > 8)
        return m7_reject(M7_STATUS_UNSUPPORTED_CMD);
    if (!object || object_len == 0 || object_len > M7_MANAGER_BYTES)
        return m7_reject(M7_STATUS_INVALID_OBJECT);
    cue_bounded_limits_t limits = cue_i2_limits;
    limits.max_input_bytes = M7_MANAGER_BYTES;
    limits.max_depth = 64;
    limits.max_cells = 64;
    limits.max_atom_bytes = 256;
    noun decoded = NOUN_ZERO;
    heap_scratch_reset();
    cue_bounded_status_t status = cue_bounded_bytes(
        object, object_len, &limits, HEAP_MODE_SCRATCH, &decoded);
    uint8_t canonical[M7_MANAGER_BYTES];
    uint64_t canonical_len = 0;
    int canonical_ok = status == CUE_BOUNDED_OK
        && m7_encode_noun(decoded, canonical, &canonical_len)
        && canonical_len == object_len;
    if (canonical_ok) {
        for (uint64_t i = 0; i < object_len; i++)
            if (canonical[i] != object[i]) { canonical_ok = 0; break; }
    }
    if (noun_tx_active()) noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    if (!canonical_ok)
        return m7_reject(M7_STATUS_INVALID_OBJECT);
    return m7_store_request(command, object, object_len);
}

static int m7_deliver_restart(noun reason)
{
    if (!g_m7.ready || !noun_is_atom(reason)) return 0;
    heap_set_mode(HEAP_MODE_PERSIST);
    noun event = pair(g_m7.lifecycle_event_tag, reason);
    if (!noun_is_cell(event)) return 0;
    /* One closed supervisor slot runs before the drop-newest application FIFO.
     * Completion is reported only when this exact event commits; every other
     * terminal outcome is returned as non-delivery. */
    return kernel_m7_execute_lifecycle(
        event, reason == g_m7.lifecycle_stop) == 0;
}

/* QUERY results are built from the admitted live root at REQ+; no package
 * bytes or decoded standby root are consulted. The result vocabulary is
 * intentionally small but truthful for the static profile. */
static int m7_inventory_result(noun tag, int status, noun *out)
{
    noun gate = shrine_gate_get();
    noun battery, sample, axis, state, state_tag, rest;
    noun header, program, dynamic, states, formula;
    (void)battery; (void)axis; (void)state_tag;
    (void)header; (void)program; (void)formula;
    if (!out || !take(gate, &battery, &sample)
        || !take(sample, &axis, &state)
        || !take(state, &state_tag, &rest)
        || !take(rest, &header, &rest)
        || !take(rest, &program, &dynamic)
        || !take(dynamic, &states, &formula))
        return 0;
    noun entries[64];
    uint64_t count = 0;
    while (noun_is_cell(states) && count < 64) {
        noun entry, tail, id, body, kind;
        if (!take(states, &entry, &tail) || !take(entry, &id, &body)
            || !noun_is_direct(id) || direct_val(id) == 0
            || !take(body, &kind, &rest))
            return 0;
        entries[count] = status
            ? pair(id, cord_from_bytes("MANAGED", 7))
            : pair(id, kind);
        if (!noun_is_cell(entries[count])) return 0;
        count++;
        states = tail;
    }
    if (states != NOUN_ZERO) return 0;
    noun list = NOUN_ZERO;
    while (count != 0) {
        noun next;
        if (!alloc_cell_checked(entries[--count], list, &next)) return 0;
        list = next;
    }
    return alloc_cell_checked(tag, list, out);
}

static int m7_query_result(noun object, noun *out)
{
    noun tag, id;
    if (!out || !take(object, &tag, &id)
        || !noun_is_direct(id) || direct_val(id) != 1)
        return 0;
    if (noun_eq(tag, g_m7.tag[3])) {
        noun app = pair(g_m7.tag[2], direct(1));
        noun list = pair(app, NOUN_ZERO);
        return noun_is_cell(app) && noun_is_cell(list)
            && alloc_cell_checked(tag, list, out);
    }
    if (noun_eq(tag, g_m7.tag[4])) {
        noun identity;
        return runtime_identity_to_noun(runtime_identity_get(), &identity)
            && alloc_cell_checked(tag, identity, out);
    }
    if (noun_eq(tag, g_m7.tag[5])) {
        noun state = pair(direct(g_m7.mode), direct(g_m7.incarnation));
        return noun_is_cell(state) && alloc_cell_checked(tag, state, out);
    }
    if (noun_eq(tag, g_m7.tag[6]))
        return m7_inventory_result(tag, 0, out);
    if (noun_eq(tag, g_m7.tag[7]))
        return m7_inventory_result(tag, 1, out);
    return 0;
}

int m7_scheduler_boundary(void)
{
    if (!g_m7.ready || !g_m7.pending)
        return 0;
    uint64_t command = g_m7.pending_command;
    uint64_t object_len = g_m7.pending_object_len;
    g_m7.pending = 0;
    g_m7.pending_object_len = 0;
    g_m7.result_len = 0;
    g_m7.req_plus++;
    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);
    /* Decode the retained bytes only at REQ+. The decoded subject dies with
     * this scheduler pass, so serial management cannot grow PERSIST. */
    cue_bounded_limits_t limits = cue_i2_limits;
    limits.max_input_bytes = M7_MANAGER_BYTES;
    limits.max_depth = 64;
    limits.max_cells = 64;
    limits.max_atom_bytes = 256;
    noun object = NOUN_ZERO;
    if (cue_bounded_bytes(g_m7.pending_object, object_len,
                          &limits, HEAP_MODE_SCRATCH,
                          &object) != CUE_BOUNDED_OK) {
        if (noun_tx_active()) noun_tx_abort();
        g_m7.last_status = M7_STATUS_INVALID_OBJECT;
        g_m7.qo = 0;
        g_m7.confirmations++;
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        return (int)g_m7.last_status;
    }
    noun_tx_commit();
    noun subject = pair(
        direct(g_m7.mode),
        /* The mailbox was pending at receipt, but is no longer pending at
         * REQ+.  OVERFLOW is decided by the receipt path, not self-applied
         * to the request being dequeued. */
        pair(direct(0), pair(direct(command), object)));
    noun result = nock(subject, g_m7.formula);
    noun status, rest, next_mode, reason;
    if (!take(result, &status, &rest) || !take(rest, &next_mode, &reason)
        || !noun_is_direct(status) || !noun_is_direct(next_mode)) {
        g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
        g_m7.qo = 0;
        g_m7.confirmations++;
        heap_set_mode(HEAP_MODE_PERSIST);
        return (int)g_m7.last_status;
    }
    g_m7.last_status = direct_val(status);
    g_m7.last_restart = noun_is_atom(reason) ? reason : NOUN_ZERO;
    g_m7.qo = g_m7.last_status == M7_STATUS_RDY;
    if (g_m7.last_status == M7_STATUS_RDY) {
        if (command == 2 && g_m7.durability_unknown) {
            /* A caller that saw TRI_DEPLOY_DURABILITY_UNKNOWN must remount
             * before ordinary operation. Do not run a RAM-only candidate
             * when media may contain old, new, or no valid selected pair. */
            g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
            g_m7.qo = 0;
        }
        else if (command == 7) {
            noun query = NOUN_ZERO;
            /* The jam atom used to serialize RESULT belongs to this scratch
             * transaction too. Abort it after copying bytes so serial QUERY
             * cannot grow either cells or the atom store. */
            int query_ok = noun_tx_begin(HEAP_MODE_SCRATCH)
                && m7_query_result(object, &query)
                && m7_encode_noun(query, g_m7.result, &g_m7.result_len);
            if (noun_tx_active()) noun_tx_abort();
            if (!query_ok) {
                g_m7.result_len = 0;
                g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                g_m7.qo = 0;
            }
        }
        else if (command == 2 || command == 3) {
            if (command == 3) {
                g_m7.mode = M7_MODE_STOPPING;
            }
            int prepared = 1;
            if (command == 2
                && runtime_identity_capability_profile()
                    == RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO) {
                /* Closed M8 lifecycle restart is the only recovery boundary
                 * for a latched process-output failure.  Both fixed services
                 * are prepared while the resource is fenced and safe. */
                prepared = digital_out_prepare_clean_pill()
                    && digital_in_prepare();
            }
            int delivered = prepared
                && m7_deliver_restart(g_m7.last_restart);
            if (!delivered) {
                g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                g_m7.qo = 0;
                g_m7.mode = M7_MODE_STOPPED;
                evq_clear();
                tarm_clear();
                g_m7.safe = digital_out_force_safe();
                if (!g_m7.safe)
                    g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                uart_puts("M7 LIFECYCLE FAIL ");
            } else if (g_m7.pending_command == 3) {
                evq_clear();
                tarm_clear();
                g_m7.safe = digital_out_force_safe();
                if (!g_m7.safe) {
                    g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                    g_m7.qo = 0;
                }
                if (g_m7.incarnation == UINT64_MAX) {
                    g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                    g_m7.qo = 0;
                } else {
                    if (!m7_advance_incarnation()) {
                        g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
                        g_m7.qo = 0;
                    } else {
                        g_m7.mode = M7_MODE_STOPPED;
                    }
                }
            } else {
                /* Ordinary ingress stays fenced until the exact COLD/WARM
                 * lifecycle event has committed. */
                g_m7.mode = direct_val(next_mode);
                g_m7.safe = 0;
            }
            if (delivered)
                uart_puts("M7 LIFECYCLE COMMIT ");
            if (command == 2)
                uart_puts(g_m7.last_restart == g_m7.lifecycle_cold ? "COLD\r\n" : "WARM\r\n");
            else
                uart_puts("STOP\r\n");
            if (delivered && g_m7.last_status == M7_STATUS_RDY) {
                uart_puts("M7 RESTART ");
                if (command == 2)
                    uart_puts(g_m7.last_restart == g_m7.lifecycle_cold ? "COLD\r\n" : "WARM\r\n");
                else
                    uart_puts("STOP\r\n");
            }
        }
    }
    g_m7.confirmations++;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return (int)g_m7.last_status;
}

int m7_force_stop(void)
{
    if (!g_m7.ready) return M7_STATUS_NOT_READY;
    g_m7.pending = 0;
    evq_clear();
    tarm_clear();
    g_m7.safe = digital_out_force_safe();
    int safe_ok = g_m7.safe;
    if (g_m7.incarnation == UINT64_MAX || !m7_advance_incarnation()) {
        g_m7.mode = M7_MODE_STOPPED;
        g_m7.qo = 0;
        g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
        return M7_STATUS_SYSTEM_TERMINATION;
    }
    g_m7.mode = M7_MODE_STOPPED;
    g_m7.qo = 0;
    if (!safe_ok) {
        g_m7.last_status = M7_STATUS_SYSTEM_TERMINATION;
        return M7_STATUS_SYSTEM_TERMINATION;
    }
    return 0;
}

int m7_reset(void)
{
    int status = m7_force_stop();
    if (status != 0 && status != M7_STATUS_SYSTEM_TERMINATION) return status;
    if (status == M7_STATUS_SYSTEM_TERMINATION) {
        g_m7.last_status = status;
        g_m7.qo = 0;
        return status;
    }
    g_m7.mode = M7_MODE_IDLE;
    g_m7.last_status = M7_STATUS_RDY;
    g_m7.qo = 1;
    return status;
}

int m7_test_copy_fail_after(uint64_t cells)
{
    noun_test_copy_fail_after(cells == UINT64_MAX ? -1 : (int64_t)cells);
    return 0;
}

int m7_test_query_storm(uint64_t count)
{
    /* Trusted-lab exhaustion witness: repeated completed QUERY/CNF pairs
     * must not consume the live supervisor semispace. The ceiling keeps the
     * diagnostic itself bounded while exceeding the historic 61-query
     * reproducer. */
    if (count == 0 || count > 100000 || !g_m7.ready)
        return -1;
    uint64_t cells_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atoms_before = atom_store_bytes_used();
    static const uint64_t result_kinds[] = {
        M7_OBJECT_INVENTORY,
        M7_OBJECT_IDENTITY,
        M7_OBJECT_STATE,
        M7_OBJECT_FB_INVENTORY,
        M7_OBJECT_FB_STATUS
    };
    for (uint64_t i = 0; i < count; i++) {
        /* Cycle every published QUERY RESULT shape.  The observable
         * request/CNF counters are checked by the target harness. */
        noun object = m7_object(
            result_kinds[i % (sizeof result_kinds / sizeof result_kinds[0])], 1);
        if (!noun_is_cell(object)
            || m7_manager_request(7, object) != M7_STATUS_RDY
            || m7_scheduler_boundary() != M7_STATUS_RDY)
            return -1;
    }
    return heap_cells_used(HEAP_MODE_PERSIST) == cells_before
        && atom_store_bytes_used() == atoms_before ? 0 : -1;
}

int m7_deploy_begin(uint64_t stage_id, uint64_t total, noun digest)
{
    if (!g_m7.ready) return M7_STATUS_NOT_READY;
    if (g_m7.durability_unknown) return M7_DEPLOY_DURABILITY_UNKNOWN;
    if (g_m7.stage_open) return M7_DEPLOY_BUSY;
    if (stage_id == 0 || total == 0 || total > M7_STAGE_BYTES
        || !noun_atom_read_fixed(digest, g_m7.stage_digest, 32))
        return M7_DEPLOY_BOUNDS;
    g_m7.stage_id = stage_id;
    g_m7.stage_total = total;
    g_m7.stage_received = 0;
    g_m7.stage_chunks = 0;
    g_m7.stage_open = 1;
    g_m7.stage_sealed = 0;
    /* make_atom_checked consumes complete limbs; clear the unused tail of
     * the final limb so the cold blob represents exactly `total` bytes. */
    uint64_t aligned = (total + 7) & ~7ULL;
    for (uint64_t i = total; i < aligned; i++)
        ((uint8_t *)(uintptr_t)M7_STAGE_BASE)[i] = 0;
    return 0;
}

int m7_deploy_chunk(uint64_t stage_id, uint64_t offset,
                    const uint8_t *bytes, uint64_t len)
{
    if (!g_m7.stage_open || g_m7.stage_sealed || stage_id != g_m7.stage_id)
        return M7_DEPLOY_BUSY;
    if (!bytes || len == 0 || len > M7_MAX_CHUNK
        || offset != g_m7.stage_received
        || g_m7.stage_chunks >= M7_MAX_CHUNKS
        || len > g_m7.stage_total - g_m7.stage_received)
        return M7_DEPLOY_OFFSET;
    uint8_t *dst = (uint8_t *)(uintptr_t)(M7_STAGE_BASE + offset);
    for (uint64_t i = 0; i < len; i++) dst[i] = bytes[i];
    g_m7.stage_received += len;
    g_m7.stage_chunks++;
    return 0;
}

int m7_deploy_seal(void)
{
    if (!g_m7.stage_open || g_m7.stage_sealed
        || g_m7.stage_received != g_m7.stage_total || g_m7.pending)
        return M7_DEPLOY_OFFSET;
    if (g_m7.mode != M7_MODE_IDLE && g_m7.mode != M7_MODE_STOPPED)
        return M7_DEPLOY_STATE;
    if (!digital_out_force_safe()) {
        g_m7.safe = 0;
        return M7_DEPLOY_MEDIA;
    }
    g_m7.safe = 1;
    if (!stage_digest_matches()) return M7_DEPLOY_DIGEST;
    noun gate;
    runtime_identity_t identity;
    uint8_t capability;
    pill_i2_status_t status = pill_i2_validate_buffer(
        (const uint8_t *)(uintptr_t)M7_STAGE_BASE, g_m7.stage_total,
        HEAP_MODE_SCRATCH, &gate, &identity, &capability);
    if (status != PILL_I2_OK) return M7_DEPLOY_CANDIDATE;
    noun_tx_abort(); /* seal is a pure validation probe */
    if (!m7_is_identity(&identity)) return M7_DEPLOY_CANDIDATE;
    g_m7.stage_identity = identity;
    g_m7.stage_capability = capability;
    g_m7.stage_sealed = 1;
    return 0;
}

static noun m7_identity_noun(const runtime_identity_t *identity)
{
    noun out = NOUN_ZERO;
    return runtime_identity_to_noun(identity, &out) ? out : NOUN_ZERO;
}

static void m7_candidate_discard(void)
{
    g_m7_candidate = (m7_state_t){0};
    g_m7_candidate_ready = 0;
}

static int m7_prepare_deployment_candidate(uint64_t pill_hash,
                                           uint64_t pill_len,
                                           uint64_t incarnation)
{
    m7_state_t candidate;
    if (!m7_initial_state(&candidate))
        return 0;
    candidate.mode = M7_MODE_IDLE;
    candidate.incarnation = incarnation;
    candidate.last_restart = candidate.lifecycle_cold;
    candidate.active_pill_hash = pill_hash;
    candidate.active_pill_len = pill_len;
    for (size_t i = 0; i < sizeof(candidate.active_pill_digest); i++)
        candidate.active_pill_digest[i] = g_m7.stage_digest[i];
    candidate.active_pill_valid = 1;
    candidate.safe = 1;
    g_m7_candidate = candidate;
    g_m7_candidate_ready = 1;
    return 1;
}

static void m7_publish_deployment_candidate(void)
{
    /* Assignment-only companion to kernel_m7_publish_prepared. */
    g_m7 = g_m7_candidate;
    m7_candidate_discard();
}

int m7_deploy_activate(void)
{
    if (g_m7.durability_unknown)
        return M7_DEPLOY_DURABILITY_UNKNOWN;
    if (!g_m7.stage_open || !g_m7.stage_sealed
        || g_m7.pending
        || (g_m7.mode != M7_MODE_IDLE && g_m7.mode != M7_MODE_STOPPED))
        return M7_DEPLOY_STATE;
    if (!digital_out_force_safe()) {
        g_m7.safe = 0;
        return M7_DEPLOY_MEDIA;
    }
    g_m7.safe = 1;
    if (!stage_digest_matches()) return M7_DEPLOY_DIGEST;

    /* Candidate decode and every fallible RAM root live in the inactive
     * semispace before the atomic cold blob+snapshot selection. */
    m7_candidate_discard();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    noun candidate_gate;
    runtime_identity_t identity;
    uint8_t capability;
    pill_i2_status_t status = pill_i2_validate_buffer(
        (const uint8_t *)(uintptr_t)M7_STAGE_BASE, g_m7.stage_total,
        HEAP_MODE_PERSIST, &candidate_gate, &identity, &capability);
    if (status != PILL_I2_OK || !m7_is_identity(&identity)) {
        if (noun_tx_active()) noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_CANDIDATE;
    }
    noun pill_atom;
    if (!make_atom_checked(
            (const uint64_t *)(uintptr_t)M7_STAGE_BASE,
            (g_m7.stage_total + 7) / 8, &pill_atom)) {
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_STORAGE;
    }
    uint64_t pill_hash = cold_jam_hash(pill_atom);
    noun identity_noun = m7_identity_noun(&identity);
    noun pill_digest_noun = stage_digest_noun();
    if (pill_hash == 0 || !noun_is_cell(identity_noun)
        || !noun_is_atom(pill_digest_noun)
        || g_m7.incarnation == UINT64_MAX) {
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_STORAGE;
    }
    uint64_t new_incarnation = g_m7.incarnation + 1;
    noun published_gate;
    if (!kernel_m7_gate_with_incarnation(
            candidate_gate, new_incarnation, &published_gate)) {
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_CANDIDATE;
    }
    candidate_gate = published_gate;
    if (!m7_prepare_deployment_candidate(
            pill_hash, g_m7.stage_total, new_incarnation)) {
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_STORAGE;
    }
    noun candidate_slam;
    if (kernel_m7_prepare_publish(candidate_gate, &identity,
                                  &candidate_slam) != 0) {
        m7_candidate_discard();
        noun_tx_abort();
        heap_persist_abort_tx();
        g_m7.safe = 0;
        digital_out_force_safe();
        return M7_DEPLOY_STORAGE;
    }
    if (capability == RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO
        && !digital_in_prepare()) {
        m7_candidate_discard();
        noun_tx_abort();
        heap_persist_abort_tx();
        g_m7.safe = 0;
        digital_out_force_safe();
        return M7_DEPLOY_STORAGE;
    }
    noun snapshot;
    if (!m7_snapshot_build(
            pill_hash, g_m7.stage_total, pill_digest_noun, identity_noun,
            M7_MODE_IDLE, direct(CORD_COLD), new_incarnation,
            candidate_gate, NOUN_ZERO, NOUN_ZERO, &g_m7_candidate, &snapshot)) {
        m7_candidate_discard();
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_MEDIA;
    }
    uint64_t stored_pill_hash = 0;
    cold_deploy_result_t cold_result = cold_store_deployment(
        pill_atom, snapshot, &stored_pill_hash);
    if (cold_result == COLD_DEPLOY_REJECTED) {
        m7_candidate_discard();
        noun_tx_abort();
        heap_persist_abort_tx();
        return M7_DEPLOY_MEDIA;
    }
    /* No fallible operation remains after cold selection. */
    noun_tx_commit();
    heap_persist_commit_tx();
    (void)stored_pill_hash; /* identical by construction to pill_hash */
    kernel_m7_publish_prepared(candidate_gate, &identity, capability,
                               candidate_slam);
    m7_publish_deployment_candidate();
    g_m7.stage_open = 0;
    g_m7.stage_sealed = 0;
    if (cold_result == COLD_DEPLOY_DURABILITY_UNKNOWN) {
        /* The assignment-only publication makes live RAM agree with the
         * prepared candidate.  It remains inhibited/IDLE and cannot START
         * until reboot has authoritatively selected and verified media. */
        g_m7.durability_unknown = 1;
        return M7_DEPLOY_DURABILITY_UNKNOWN;
    }
    return 0;
}

int m7_deploy_query(void)
{
    return g_m7.stage_open ? (g_m7.stage_sealed ? 2 : 1) : 0;
}

int m7_deploy_abort(void)
{
    g_m7.stage_open = 0;
    g_m7.stage_sealed = 0;
    g_m7.stage_received = 0;
    g_m7.stage_chunks = 0;
    return 0;
}

noun m7_current_pill_digest(void)
{
    const uint8_t *base = (const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t len = 0;
    for (int i = 0; i < 8; i++) len |= (uint64_t)base[16 + i] << (i * 8);
    if (len == 0 || len > M7_STAGE_BYTES) return NOUN_ZERO;
    uint8_t digest[32];
    uint64_t limbs[4] = {0, 0, 0, 0};
    blake3_hash(base, (size_t)(256 + len), digest);
    for (size_t i = 0; i < 32; i++) ((uint8_t *)limbs)[i] = digest[i];
    return make_atom(limbs, 4);
}

int m7_deploy_demo(void)
{
    const uint8_t *base = (const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t len = 0;
    for (int i = 0; i < 8; i++) len |= (uint64_t)base[16 + i] << (i * 8);
    noun digest = m7_current_pill_digest();
    if (len == 0 || 256 + len > M7_STAGE_BYTES || digest == NOUN_ZERO)
        return M7_DEPLOY_BOUNDS;
    uint64_t total = 256 + len;
    int status = m7_deploy_begin(1, total, digest);
    for (uint64_t offset = 0; status == 0 && offset < total; ) {
        uint64_t chunk = total - offset;
        if (chunk > M7_MAX_CHUNK) chunk = M7_MAX_CHUNK;
        status = m7_deploy_chunk(1, offset, base + offset, chunk);
        offset += chunk;
    }
    if (status == 0) status = m7_deploy_seal();
    if (status == 0) status = m7_deploy_activate();
    return status;
}

int m7_checkpoint_save(void)
{
    if (!g_m7.ready || g_m7.durability_unknown || g_m7.pending || g_m7.stage_open
        || g_m7.incarnation == 0)
        return -1;
    if (!g_m7.active_pill_valid && !m7_capture_active_pill())
        return -1;

    heap_scratch_reset();
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return -1;
    noun gate, queue, tarms, identity, digest, snapshot;
    if (!kernel_m7_checkpoint_capture_roots(&gate, &queue, &tarms)
        || !runtime_identity_to_noun(runtime_identity_get(), &identity)
        || !noun_copy_checked(active_digest_noun(), &digest)
        || !m7_snapshot_build(
            g_m7.active_pill_hash, g_m7.active_pill_len, digest, identity,
            g_m7.mode, g_m7.last_restart, g_m7.incarnation,
            gate, queue, tarms, &g_m7, &snapshot)) {
        noun_tx_abort();
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        return -1;
    }
    int result = cold_snap_save(snapshot);
    noun_tx_abort();
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return result;
}

int m7_boot_snapshot(void)
{
    noun root = cold_snap_load();
    if (!noun_is_cell(root)) return 1;
    noun schema, rest, pill_hash, pill_len, pill_digest_noun, identity_noun;
    noun mode, reason, incarnation, gate, manager, queue, timer;
    noun manager_init, manager_rest, manager_status, manager_qo;
    noun manager_result;
    if (!take(root, &schema, &rest))
        return -1;
    if (!noun_eq(schema, cord_from_bytes("M7-SUPERVISOR", 14)))
        return 1;
    if (!take(rest, &pill_hash, &rest)
        || !take(rest, &pill_len, &rest)
        || !take(rest, &pill_digest_noun, &rest)
        || !take(rest, &identity_noun, &rest)
        || !take(rest, &mode, &rest)
        || !take(rest, &reason, &rest)
        || !take(rest, &incarnation, &rest)
        || !take(rest, &gate, &rest)
        || !take(rest, &manager, &rest)
        || !take(rest, &queue, &timer)
        || !noun_is_direct(pill_hash) || !noun_is_direct(pill_len)
        || !noun_is_direct(mode) || !noun_is_direct(incarnation)
        || !take(manager, &manager_init, &manager_rest)
        || !take(manager_rest, &manager_status, &manager_rest)
        || !take(manager_rest, &manager_qo, &manager_result)
        || !noun_is_direct(manager_init) || !noun_is_direct(manager_status)
        || !noun_is_direct(manager_qo)
        || manager_result != NOUN_ZERO
        || direct_val(manager_init) > 1 || direct_val(manager_qo) > 1
        || direct_val(manager_status) > M7_STATUS_OVERFLOW
        || direct_val(pill_len) == 0 || direct_val(pill_len) > M7_STAGE_BYTES
        || direct_val(mode) == M7_MODE_STOPPING
        || direct_val(mode) > M7_MODE_STOPPED || !noun_is_atom(reason)
        || direct_val(incarnation) == 0)
        return -1;
    noun pill_atom = cold_load(direct_val(pill_hash));
    if (!noun_is_atom(pill_atom)
        || !noun_atom_read_fixed(pill_atom,
                                 (uint8_t *)(uintptr_t)M7_STAGE_BASE,
                                 direct_val(pill_len)))
        return -1;
    uint8_t digest[32];
    blake3_hash((const void *)(uintptr_t)M7_STAGE_BASE,
                (size_t)direct_val(pill_len), digest);
    uint8_t expected_digest[32];
    if (!noun_atom_read_fixed(pill_digest_noun, expected_digest,
                              sizeof expected_digest))
        return -1;
    for (size_t i = 0; i < sizeof expected_digest; i++)
        if (expected_digest[i] != digest[i]) return -1;
    if (cold_jam_hash(pill_atom) != direct_val(pill_hash)) return -1;
    runtime_identity_t snapshot_identity;
    uint64_t snapshot_gate_incarnation;
    if (!runtime_identity_from_noun(identity_noun, &snapshot_identity)
        || !m7_is_identity(&snapshot_identity)
        || !runtime_identity_validate_gate(
            gate, &snapshot_identity, &snapshot_gate_incarnation)
        || snapshot_gate_incarnation != direct_val(incarnation))
        return -1;
    noun pill_gate;
    runtime_identity_t pill_identity;
    uint8_t capability;
    pill_i2_status_t status = pill_i2_validate_buffer(
        (const uint8_t *)(uintptr_t)M7_STAGE_BASE,
        direct_val(pill_len), HEAP_MODE_PERSIST,
        &pill_gate, &pill_identity, &capability);
    if (status != PILL_I2_OK
        || !runtime_identity_equal(&pill_identity, &snapshot_identity)
        || !runtime_identity_validate_gate(pill_gate, &snapshot_identity, 0)) {
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    noun live_gate;
    int m7_was_ready = m7_ready();
    if (!kernel_m7_gate_with_identity_incarnation(
            pill_gate, &snapshot_identity, direct_val(incarnation),
            &live_gate)) {
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    if (m7_init_for_identity(live_gate, &snapshot_identity) != M7_STATUS_RDY) {
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    if (kernel_m7_restore_checkpoint(
            &snapshot_identity, capability, direct_val(mode),
            gate, queue, timer,
            NOUN_ZERO) != 0) {
        if (!m7_was_ready)
            m7_restore_discard();
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    m7_restore_state_commit(
        direct_val(mode), reason, direct_val(incarnation),
        direct_val(manager_init), direct_val(manager_status),
        direct_val(manager_qo));
    g_m7.active_pill_hash = direct_val(pill_hash);
    g_m7.active_pill_len = direct_val(pill_len);
    for (size_t i = 0; i < sizeof(g_m7.active_pill_digest); i++)
        g_m7.active_pill_digest[i] = expected_digest[i];
    g_m7.active_pill_valid = 1;
    /* The atomic restore installer already performed the checked safe-low
     * transition before its single RAM publication point. */
    g_m7.safe = 1;
    return 0;
}
