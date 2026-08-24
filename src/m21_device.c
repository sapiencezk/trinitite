/* Exact M21 two-slot target authority.
 *
 * This module is deliberately a literal two-slot/two-link implementation.
 * It owns no registry, deployment parser, generic scheduler, retry path, or
 * host implementation of IEC behavior. Resource steps remain pure Nock.
 */
#include <stddef.h>
#include <stdint.h>

#include "m21_device.h"
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "setjmp.h"
#include "uart.h"

#define CORD_COMMIT 127996156276579ULL
#define CORD_ABORT 500136108641ULL
#define CORD_I2_RX_ORIGIN_V1 0x3178723269ULL
#define CORD_I2_INTERNAL_ORIGIN_V1 0x316e693269ULL

#define M21_SLOTS 2u
#define M21_FIFO_CAP 16u
#define M21_PLAN_EPOCH 1u
#define M21_OPS 2000000ULL
#define M21_CELLS 128000ULL
#define M21_CHECKPOINT_MAX_BYTES JAM_MAX_BYTES

extern uint8_t _m21_sink_embed_start[];
extern uint8_t _m21_sink_embed_end[];

static noun g_gate[M21_SLOTS];
static noun g_queue[M21_SLOTS];
static uint64_t g_queue_n[M21_SLOTS];
static runtime_identity_t g_identity[M21_SLOTS];
static uint64_t g_cursor;
static uint64_t g_sequence;
static uint64_t g_faults;
static uint64_t g_last_error;
static int g_active;
/* Target-only hostile control: fail exactly the next root reservation before
 * it starts.  It verifies the terminal retirement path without weakening the
 * real allocator or treating a test hook as a runtime policy. */
static int g_test_publish_reservation_fail_once;
static uint8_t g_checkpoint_bytes[M21_CHECKPOINT_MAX_BYTES];
static uint64_t g_checkpoint_len;
static int g_checkpoint_valid;

static noun g_tag_external, g_tag_ei, g_tag_device_ei, g_tag_egress, g_tag_carrier, g_tag_checkpoint;
static noun g_plan_anchor;

static int live_instance(noun gate, uint64_t wanted, noun *out);
static int source_samples_match_candidate(noun gate, uint64_t event,
                                          uint64_t ordinal, noun samples);

typedef struct {
    noun gate0, gate1, queue0, queue1;
    uint64_t n0, n1, cursor, sequence, faults, last_error;
} root_snapshot_t;

static root_snapshot_t root_snapshot(void);
static int root_unchanged(const root_snapshot_t *before);
static int root_restore(const root_snapshot_t *before);
static int publish_root(noun next_gate0, noun next_gate1,
                        noun next_queue0, noun next_queue1,
                        uint64_t next_queue_n0, uint64_t next_queue_n1,
                        uint64_t next_sequence, uint64_t next_cursor,
                        uint64_t next_faults, uint64_t next_error);

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head; *tail = cell->tail;
    return 1;
}

static int direct_is(noun n, uint64_t expected)
{
    return noun_is_direct(n) && direct_val(n) == expected;
}

static int typed_bool(noun n)
{
    noun type, value;
    return take(n, &type, &value) && direct_is(type, 1)
        && noun_is_direct(value) && direct_val(value) <= 1;
}

static int tag_is(noun n, const char *text)
{
    char buffer[32]; size_t length = 0;
    while (text[length]) length++;
    if (!noun_is_atom(n) || length + 1 > sizeof buffer
        || cord_to_cstr(n, buffer, sizeof buffer) != length) return 0;
    for (size_t i = 0; i < length; i++) if (buffer[i] != text[i]) return 0;
    return 1;
}

static int cons(noun head, noun tail, noun *out)
{
    return alloc_cell_checked(head, tail, out);
}

static int gate_parts(noun gate, noun *battery, noun *program, noun *formula)
{
    noun sample, zero, state, tag, rest, header, dynamic, states;
    return take(gate, battery, &sample) && take(sample, &zero, &state)
        && direct_is(zero, 0) && take(state, &tag, &rest)
        && tag_is(tag, "i2-state") && take(rest, &header, &rest)
        && take(rest, program, &dynamic) && take(dynamic, &states, formula);
}

static int gate_resource_id(noun gate, uint64_t *out)
{
    noun battery, sample, zero, state, tag, rest, header, dynamic;
    noun versions, resource_id;
    if (!take(gate, &battery, &sample) || !take(sample, &zero, &state)
        || !take(state, &tag, &rest) || !take(rest, &header, &dynamic)
        || !take(header, &versions, &rest) || !take(rest, &resource_id, &rest)
        || !noun_is_direct(resource_id)) return 0;
    *out = direct_val(resource_id);
    return 1;
}

static int build_slam(noun *out)
{
    noun n0, n1, n2, n3, n4, n5, n6;
    return cons(direct(0), direct(3), &n0)
        && cons(direct(6), n0, &n1) && cons(direct(0), direct(2), &n2)
        && cons(n1, n2, &n3) && cons(direct(10), n3, &n4)
        && cons(direct(2), n4, &n5) && cons(direct(9), n5, &n6)
        && ((*out = n6), 1);
}

static int queue_append_copy(noun queue, noun event, noun *out)
{
    noun copy, cursor, node;
    if (!noun_copy_checked(queue, &copy) || !noun_copy_checked(event, &event)
        || !cons(event, NOUN_ZERO, &node)) return 0;
    if (!noun_is_cell(copy)) { *out = node; return 1; }
    cursor = copy;
    while (noun_is_cell(((cell_t *)(uintptr_t)cell_ptr(cursor))->tail))
        cursor = ((cell_t *)(uintptr_t)cell_ptr(cursor))->tail;
    ((cell_t *)(uintptr_t)cell_ptr(cursor))->tail = node;
    *out = copy;
    return 1;
}

static int queue_head_tail(noun queue, noun *head, noun *tail)
{
    return take(queue, head, tail);
}

static int build_source_external(uint64_t a, uint64_t b, noun *out)
{
    noun va, vb, sa, sb, list, ei, event;
    /* [%i2-external [%i2-ei 5 1 [[1 [1 a]] [2 [1 b]]]]] */
    if (a > 1 || b > 1 || !cons(direct(1), direct(a), &va)
        || !cons(direct(1), direct(b), &vb) || !cons(direct(1), va, &sa)
        || !cons(direct(2), vb, &sb) || !cons(sb, NOUN_ZERO, &list)
        || !cons(sa, list, &ei)
        || !cons(direct(1), ei, &va) || !cons(direct(5), va, &vb)
        || !cons(g_tag_ei, vb, &ei) || !cons(g_tag_external, ei, &event)) return 0;
    *out = event; return 1;
}

/* The sole external device ingress grammar is the fixed source REQ with two
 * canonical BOOL samples.  Raw EI, route, egress, and carrier nouns never
 * reach either resource FIFO. */
static int source_external_valid(noun event)
{
    noun tag, body, instance, event_id, samples;
    noun first, second, tail, first_id, first_value, second_id, second_value;
    return take(event, &tag, &body) && noun_eq(tag, g_tag_external)
        && take(body, &tag, &body) && noun_eq(tag, g_tag_ei)
        && take(body, &instance, &body) && take(body, &event_id, &samples)
        && direct_is(instance, 5) && direct_is(event_id, 1)
        && take(samples, &first, &tail) && take(tail, &second, &tail)
        && direct_is(tail, 0) && take(first, &first_id, &first_value)
        && take(second, &second_id, &second_value)
        && direct_is(first_id, 1) && direct_is(second_id, 2)
        && typed_bool(first_value) && typed_bool(second_value);
}

static int unwrap_egress(noun cause, uint64_t *event, uint64_t *ordinal,
                         noun *samples)
{
    noun tag, rest, instance, source_event, source_ordinal;
    if (!take(cause, &tag, &rest) || !noun_eq(tag, g_tag_egress)
        || !take(rest, &instance, &rest) || !take(rest, &source_event, &rest)
        || !take(rest, &source_ordinal, samples)
        || !direct_is(instance, 5) || !noun_is_direct(source_event)
        || !noun_is_direct(source_ordinal)) return 0;
    *event = direct_val(source_event); *ordinal = direct_val(source_ordinal);
    return 1;
}

static int samples_for_link(noun source_samples, uint64_t source_event,
                            uint64_t ordinal, noun *target_samples,
                            uint64_t *target_event, uint64_t *link_id)
{
    uint64_t expected0, expected1, target0, target1;
    noun first, second, tail, source_var0, value0, source_var1, value1;
    if (source_event == 3 && ordinal == 9) {
        expected0 = 4; expected1 = 5; target0 = 2; target1 = 3;
        *target_event = 2; *link_id = 2;
    } else if (source_event == 2 && ordinal == 8) {
        expected0 = 3; expected1 = 5; target0 = 1; target1 = 3;
        *target_event = 1; *link_id = 1;
    } else return 0;
    if (!take(source_samples, &first, &tail) || !take(tail, &second, &tail)
        || !direct_is(tail, 0) || !take(first, &source_var0, &value0)
        || !take(second, &source_var1, &value1)
        || !direct_is(source_var0, expected0) || !direct_is(source_var1, expected1)
        || !noun_is_cell(value0) || !noun_is_cell(value1)) return 0;
    noun type0, atom0, type1, atom1, pair0, pair1, list;
    if (!take(value0, &type0, &atom0) || !take(value1, &type1, &atom1)
        || !direct_is(type0, 1) || !direct_is(type1, 1)
        || !noun_is_direct(atom0) || !noun_is_direct(atom1)
        || direct_val(atom0) > 1 || direct_val(atom1) > 1
        || !cons(direct(target0), value0, &pair0)
        || !cons(direct(target1), value1, &pair1)
        || !cons(pair1, NOUN_ZERO, &list) || !cons(pair0, list, target_samples)) return 0;
    return 1;
}

/* The full carrier is always rechecked before the sink sees its local cause.
 * This is intentionally literal: one M21 plan, two links, two BOOL samples. */
static int target_samples_valid(uint64_t link, noun samples)
{
    uint64_t first_expected, second_expected;
    noun first, second, tail, first_id, first_value, second_id, second_value;
    noun type, value;
    if (link == 1) { first_expected = 1; second_expected = 3; }
    else if (link == 2) { first_expected = 2; second_expected = 3; }
    else return 0;
    if (!take(samples, &first, &tail) || !take(tail, &second, &tail)
        || !direct_is(tail, 0) || !take(first, &first_id, &first_value)
        || !take(second, &second_id, &second_value)
        || !direct_is(first_id, first_expected)
        || !direct_is(second_id, second_expected)) return 0;
    if (!take(first_value, &type, &value) || !direct_is(type, 1)
        || !noun_is_direct(value) || direct_val(value) > 1) return 0;
    if (!take(second_value, &type, &value) || !direct_is(type, 1)
        || !noun_is_direct(value) || direct_val(value) > 1) return 0;
    return 1;
}

static int build_carrier(uint64_t link_id, uint64_t source_event,
                         uint64_t ordinal, uint64_t target_event,
                         noun samples, uint64_t sequence,
                         uint64_t source_generation,
                         uint64_t target_generation, noun *out)
{
    /* ``samples`` is the terminal tail of the canonical right-nested noun,
     * not a sixteenth list element: [tag plan epoch ... target-EI samples]. */
    noun values[15]; noun tail = samples;
    values[14] = direct(target_event); values[13] = direct(6);
    values[12] = direct(1); values[11] = direct(target_generation); values[10] = direct(2);
    values[9] = direct(ordinal); values[8] = direct(source_event); values[7] = direct(5);
    values[6] = direct(1); values[5] = direct(source_generation); values[4] = direct(1);
    values[3] = direct(link_id); values[2] = direct(sequence);
    values[1] = direct(M21_PLAN_EPOCH); values[0] = g_plan_anchor;
    for (int i = 14; i >= 0; i--) if (!cons(values[i], tail, &tail)) return 0;
    return cons(g_tag_carrier, tail, out);
}

static int carrier_to_device_ei(noun carrier, noun *out,
                                uint64_t expected_sequence)
{
    noun tag, rest, value[15];
    if (!take(carrier, &tag, &rest) || !noun_eq(tag, g_tag_carrier)) return 0;
    for (unsigned i = 0; i < 15; i++) {
        if (!take(rest, &value[i], &rest)) return 0;
    }
    if (!noun_eq(value[0], g_plan_anchor)
        || !direct_is(value[1], M21_PLAN_EPOCH) || !direct_is(value[2], expected_sequence)
        || !noun_is_direct(value[3]) || !direct_is(value[4], 1)
        || !direct_is(value[5], 1) || !direct_is(value[6], 1)
        || !direct_is(value[7], 5) || !noun_is_direct(value[8])
        || !noun_is_direct(value[9]) || !direct_is(value[10], 2)
        || !direct_is(value[11], 1) || !direct_is(value[12], 1)
        || !direct_is(value[13], 6) || !noun_is_direct(value[14])) return 0;
    uint64_t link = direct_val(value[3]);
    if (!((link == 1 && direct_is(value[8], 2) && direct_is(value[9], 8)
           && direct_is(value[14], 1))
          || (link == 2 && direct_is(value[8], 3) && direct_is(value[9], 9)
              && direct_is(value[14], 2)))
        || !target_samples_valid(link, rest)) return 0;
    noun tail = rest;
    if (!cons(value[14], tail, &tail)
        || !cons(direct(6), tail, &tail) || !cons(g_tag_device_ei, tail, out)) return 0;
    return 1;
}

static int product_parts(noun result, noun *candidate, noun *causes)
{
    noun tag, product, effects, rest;
    return take(result, &tag, &product) && direct_is(tag, CORD_COMMIT)
        && take(product, &effects, &rest) && direct_is(effects, 0)
        && take(rest, candidate, causes);
}

static int slam_slot(unsigned slot, noun event, int external,
                     noun *candidate, noun *causes)
{
    noun carrier, slam, subject, result;
    /* A destination local EI is decoded into this same scratch epoch.  Its
     * external counterpart already resides in the private source FIFO. */
    if (external) heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!build_slam(&slam)
        || !cons(external ? direct(CORD_I2_RX_ORIGIN_V1)
                          : direct(CORD_I2_INTERNAL_ORIGIN_V1), event, &carrier)
        || !cons(g_gate[slot], carrier, &subject)) return 0;
    int jump = setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(M21_OPS, M21_CELLS);
    result = nock(subject, slam);
    nock_budget_finish();
    if (!product_parts(result, candidate, causes)
        || !runtime_identity_validate_gate(*candidate, &g_identity[slot], 0)) return 0;
    return 1;
}

/* The M21 root is exactly two gates and two FIFOs.  Every change crosses one
 * fresh semispace, including unchanged roots; retaining a root in the old
 * half would let the next publication overwrite it. */
static int publish_root(noun next_gate0, noun next_gate1,
                        noun next_queue0, noun next_queue1,
                        uint64_t next_queue_n0, uint64_t next_queue_n1,
                        uint64_t next_sequence, uint64_t next_cursor,
                        uint64_t next_faults, uint64_t next_error)
{
    noun gate0, gate1, queue0, queue1;
    if (g_test_publish_reservation_fail_once) {
        g_test_publish_reservation_fail_once = 0;
        return 0;
    }
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(next_gate0, &gate0)
        || !noun_copy_checked(next_gate1, &gate1)
        || !noun_copy_checked(next_queue0, &queue0)
        || !noun_copy_checked(next_queue1, &queue1)) {
        heap_persist_abort_tx();
        return 0;
    }
    /* The one in-process authority-root publication: no allocation below. */
    g_gate[0] = gate0; g_gate[1] = gate1;
    g_queue[0] = queue0; g_queue[1] = queue1;
    g_queue_n[0] = next_queue_n0; g_queue_n[1] = next_queue_n1;
    g_sequence = next_sequence; g_cursor = next_cursor;
    g_faults = next_faults; g_last_error = next_error;
    heap_persist_commit_tx();
    return 1;
}

static int target_capacity_available(uint64_t queued, uint64_t append_count)
{
    return queued <= M21_FIFO_CAP && append_count <= M21_FIFO_CAP - queued;
}

static int enqueue_source_external(noun event)
{
    noun queue;
    if (!g_active || !source_external_valid(event)
        || !target_capacity_available(g_queue_n[0], 1)) return -1;
    if (!queue_append_copy(g_queue[0], event, &queue)) return -1;
    return publish_root(g_gate[0], g_gate[1], queue, g_queue[1],
                        g_queue_n[0] + 1u, g_queue_n[1], g_sequence,
                        g_cursor, g_faults, g_last_error)
        ? 0 : -1;
}

static int retire_head(unsigned slot, noun tail, uint64_t error)
{
    noun next_queue0 = slot == 0 ? tail : g_queue[0];
    noun next_queue1 = slot == 1 ? tail : g_queue[1];
    uint64_t next_n0 = g_queue_n[0] - (slot == 0 ? 1u : 0u);
    uint64_t next_n1 = g_queue_n[1] - (slot == 1 ? 1u : 0u);
    return publish_root(g_gate[0], g_gate[1], next_queue0, next_queue1,
                        next_n0, next_n1, g_sequence, 1u - slot,
                        g_faults + 1u, error);
}

/* A bridge/product fault must never retry its source event.  The normal
 * bounded path retires that head through a fresh complete device root.  If
 * that root itself cannot be copied (persistent exhaustion), no second
 * mutable attempt is safe: fence this authority with the old root intact.
 * This is fail-closed supervisor fencing, not a claim of power-loss atomicity.
 */
static int terminal_retire_or_fence(unsigned slot, noun tail, uint64_t error)
{
    if (retire_head(slot, tail, error)) return 1;
    g_active = 0;
    return 0;
}

static int publish_no_egress(unsigned slot, noun candidate, noun old_tail)
{
    return slot == 0
        ? publish_root(candidate, g_gate[1], old_tail, g_queue[1],
                       g_queue_n[0] - 1u, g_queue_n[1], g_sequence,
                       1u, g_faults, g_last_error)
        : publish_root(g_gate[0], candidate, g_queue[0], old_tail,
                       g_queue_n[0], g_queue_n[1] - 1u, g_sequence,
                       0u, g_faults, g_last_error);
}

static int publish_egress(noun candidate, noun source_tail, noun carrier)
{
    noun target_queue;
    if (!target_capacity_available(g_queue_n[1], 1)) return 0;
    /* The carrier/payload and complete target queue are prepared before the
     * root transaction.  A failure therefore publishes neither candidate. */
    /* candidate and carrier were just built in scratch by the slam.  Keep
     * them live while the complete destination replacement queue is staged. */
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!queue_append_copy(g_queue[1], carrier, &target_queue)) return 0;
    return publish_root(candidate, g_gate[1], source_tail, target_queue,
                        g_queue_n[0] - 1u, g_queue_n[1] + 1u,
                        g_sequence + 1u, 1u, g_faults, g_last_error);
}

int m21_device_boot(noun source_gate, const runtime_identity_t *source_id,
                    uint8_t capability_profile)
{
    runtime_identity_t sink_id; uint8_t sink_capability; noun sink_gate;
    noun source_battery, source_program, source_formula;
    noun sink_battery, sink_program, sink_formula;
    uint64_t source_resource, sink_resource;
    uint64_t limbs[4] = {
        0x4609ca122477fce6ULL, 0x79598351e07dcb9eULL,
        0xd4ae03fe6836bb54ULL, 0x73f2afc41273d60eULL,
    };
    if (!source_id || source_id->runtime_abi[0] != 1
        || source_id->runtime_abi[1] != 8 || source_id->formula_abi[1] != 8
        || capability_profile != RUNTIME_CAPABILITY_PROFILE_STATIC_RESOURCE
        || !runtime_identity_validate_gate(source_gate, source_id, 0)
        || !gate_resource_id(source_gate, &source_resource) || source_resource != 1)
        return -1;
    /* Source cue is a candidate only; seal it before independently decoding
     * the embedded exact sink PILL. Neither is yet a live M21 root. */
    if (noun_tx_active()) noun_tx_commit();
    pill_i2_status_t status = pill_i2_validate_buffer(
        _m21_sink_embed_start,
        (uint64_t)(_m21_sink_embed_end - _m21_sink_embed_start),
        HEAP_MODE_PERSIST, &sink_gate, &sink_id, &sink_capability);
    if (status != PILL_I2_OK || sink_capability != RUNTIME_CAPABILITY_PROFILE_STATIC_RESOURCE
        || sink_id.runtime_abi[0] != 1 || sink_id.runtime_abi[1] != 8
        || sink_id.formula_abi[1] != 8
        || !runtime_identity_validate_gate(sink_gate, &sink_id, 0)
        || !gate_resource_id(sink_gate, &sink_resource) || sink_resource != 2
        || runtime_identity_equal(source_id, &sink_id)
        || !gate_parts(source_gate, &source_battery, &source_program, &source_formula)
        || !gate_parts(sink_gate, &sink_battery, &sink_program, &sink_formula)
        || !noun_eq(source_battery, sink_battery) || !noun_eq(source_formula, sink_formula)) {
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    noun source_copy, sink_copy;
    if (!noun_copy_checked(source_gate, &source_copy)
        || !noun_copy_checked(sink_gate, &sink_copy)) {
        heap_persist_abort_tx(); if (noun_tx_active()) noun_tx_abort(); return -1;
    }
    if (noun_tx_active()) noun_tx_commit();
    g_gate[0] = source_copy; g_gate[1] = sink_copy;
    g_queue[0] = g_queue[1] = NOUN_ZERO; g_queue_n[0] = g_queue_n[1] = 0;
    g_identity[0] = *source_id; g_identity[1] = sink_id;
    g_cursor = 0; g_sequence = 0; g_faults = 0; g_last_error = 0;
    g_test_publish_reservation_fail_once = 0;
    g_tag_external = cord_from_bytes("i2-external", 11);
    g_tag_ei = cord_from_bytes("i2-ei", 5);
    g_tag_device_ei = cord_from_bytes("i2-device-ei", 12);
    g_tag_egress = cord_from_bytes("i2-resource-egress-v1", 21);
    g_tag_carrier = cord_from_bytes("i2-inter-resource-v1", 20);
    g_tag_checkpoint = cord_from_bytes("i2-m21-checkpoint-v1", 20);
    g_plan_anchor = make_atom(limbs, 4);
    if (!noun_is_atom(g_tag_external) || !noun_is_atom(g_tag_device_ei)
        || !noun_is_atom(g_tag_egress) || !noun_is_atom(g_tag_carrier)
        || !noun_is_atom(g_tag_checkpoint)
        || !noun_is_atom(g_plan_anchor)) {
        heap_persist_abort_tx(); return -1;
    }
    g_active = 1;
    g_checkpoint_valid = 0; g_checkpoint_len = 0;
    heap_persist_commit_tx();
    (void)source_program; (void)sink_program;
    return 0;
}

int m21_device_active(void) { return g_active; }

int m21_device_enqueue_source_bool(uint64_t a, uint64_t b)
{
    noun event;
    if (!g_active) return -1;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    return build_source_external(a, b, &event) ? enqueue_source_external(event) : -1;
}

int m21_device_step(void)
{
    unsigned slot;
    if (!g_active) return -1;
    if (g_queue_n[g_cursor] != 0) slot = (unsigned)g_cursor;
    else if (g_queue_n[1u - g_cursor] != 0) slot = (unsigned)(1u - g_cursor);
    else return 0;
    noun head, tail, event, candidate, causes;
    if (!queue_head_tail(g_queue[slot], &head, &tail)) return -1;
    if (slot == 1) {
        heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
        if (!carrier_to_device_ei(head, &event, g_sequence)) {
            (void)terminal_retire_or_fence(slot, tail, 1);
            return -1;
        }
    } else event = head;
    if (!slam_slot(slot, event, slot == 0, &candidate, &causes)) {
        (void)terminal_retire_or_fence(slot, tail, 2);
        return -1;
    }
    if (slot == 1) {
        if (!direct_is(causes, 0) || !publish_no_egress(slot, candidate, tail)) {
            (void)terminal_retire_or_fence(slot, tail, 3);
            return -1;
        }
        return 1;
    }
    noun cause, rest, source_samples, target_samples, carrier;
    uint64_t event_id, ordinal, target_event, link_id;
    if (direct_is(causes, 0))
        return publish_no_egress(slot, candidate, tail) ? 1 : -1;
    if (!take(causes, &cause, &rest) || !direct_is(rest, 0)
        || !unwrap_egress(cause, &event_id, &ordinal, &source_samples)
        || !source_samples_match_candidate(candidate, event_id, ordinal, source_samples)
        || !samples_for_link(source_samples, event_id, ordinal, &target_samples,
                             &target_event, &link_id)
        || !build_carrier(link_id, event_id, ordinal, target_event, target_samples,
                          g_sequence + 1u, 1, 1, &carrier)
        || !publish_egress(candidate, tail, carrier)) {
        /* Post-slam bridge failure: retire source head, publish no candidate. */
        (void)terminal_retire_or_fence(0, tail, 4);
        return -1;
    }
    return 1;
}

static int live_instance(noun gate, uint64_t wanted, noun *out)
{
    noun battery, program, formula, sample, zero, state, tag, rest, header, dynamic, states;
    if (!take(gate, &battery, &sample) || !take(sample, &zero, &state)
        || !take(state, &tag, &rest) || !take(rest, &header, &rest)
        || !take(rest, &program, &dynamic) || !take(dynamic, &states, &formula)) return 0;
    for (unsigned i = 0; i < 4 && noun_is_cell(states); i++) {
        noun entry, next, id, body;
        if (!take(states, &entry, &next) || !take(entry, &id, &body)) return 0;
        if (direct_is(id, wanted)) { *out = body; return 1; }
        states = next;
    }
    return 0;
}

static int source_samples_match_candidate(noun gate, uint64_t event,
                                          uint64_t ordinal, noun samples)
{
    uint64_t source0, source1;
    noun body, tag, rest, active, inputs, outputs;
    noun first, second, tail, first_id, first_value, second_id, second_value;
    noun output0 = NOUN_ZERO, output1 = NOUN_ZERO;
    if (event == 2 && ordinal == 8) { source0 = 3; source1 = 5; }
    else if (event == 3 && ordinal == 9) { source0 = 4; source1 = 5; }
    else return 0;
    if (!live_instance(gate, 5, &body) || !take(body, &tag, &rest)
        || !tag_is(tag, "bfb-state") || !take(rest, &active, &rest)
        || !take(rest, &inputs, &rest) || !take(rest, &outputs, &rest)
        || !take(samples, &first, &tail) || !take(tail, &second, &tail)
        || !direct_is(tail, 0) || !take(first, &first_id, &first_value)
        || !take(second, &second_id, &second_value)
        || !direct_is(first_id, source0) || !direct_is(second_id, source1)) return 0;
    for (unsigned i = 0; i < 8 && noun_is_cell(outputs); i++) {
        noun entry, next, id, typed;
        if (!take(outputs, &entry, &next) || !take(entry, &id, &typed)) return 0;
        if (direct_is(id, source0)) output0 = typed;
        if (direct_is(id, source1)) output1 = typed;
        outputs = next;
    }
    return noun_eq(first_value, output0) && noun_eq(second_value, output1);
}

uint64_t m21_device_sink_input(uint64_t variable_id)
{
    noun body, tag, rest, field, inputs;
    if (!g_active || !live_instance(g_gate[1], 6, &body)
        || !take(body, &tag, &rest) || !tag_is(tag, "bfb-state")
        || !take(rest, &field, &rest) || !take(rest, &inputs, &rest)) return UINT64_MAX;
    for (unsigned i = 0; i < 8 && noun_is_cell(inputs); i++) {
        noun entry, next, id, typed, type, value;
        if (!take(inputs, &entry, &next) || !take(entry, &id, &typed)
            || !take(typed, &type, &value)) return UINT64_MAX;
        if (direct_is(id, variable_id) && direct_is(type, 1) && noun_is_direct(value)) return direct_val(value);
        inputs = next;
    }
    return UINT64_MAX;
}

uint64_t m21_device_queue_len(uint64_t slot)
{
    return g_active && slot >= 1 && slot <= 2 ? g_queue_n[slot - 1] : UINT64_MAX;
}

uint64_t m21_device_last_error(void) { return g_last_error; }

static int queue_count_exact(noun queue, uint64_t expected)
{
    uint64_t count = 0;
    while (noun_is_cell(queue) && count <= M21_FIFO_CAP) {
        noun head, tail;
        if (!take(queue, &head, &tail)) return 0;
        queue = tail; count++;
    }
    return count == expected && direct_is(queue, 0);
}

static int checkpoint_noun(noun *out)
{
    noun values[12]; noun tail = NOUN_ZERO;
    values[0] = g_plan_anchor; values[1] = direct(M21_PLAN_EPOCH);
    values[2] = g_gate[0]; values[3] = g_gate[1];
    values[4] = g_queue[0]; values[5] = g_queue[1];
    values[6] = direct(g_queue_n[0]); values[7] = direct(g_queue_n[1]);
    values[8] = direct(g_cursor); values[9] = direct(g_sequence);
    values[10] = direct(g_faults); values[11] = direct(g_last_error);
    for (int i = 11; i >= 0; i--)
        if (!cons(values[i], tail, &tail)) return 0;
    return cons(g_tag_checkpoint, tail, out);
}

static int checkpoint_unpack(noun checkpoint, noun *gate0, noun *gate1,
                             noun *queue0, noun *queue1,
                             uint64_t *n0, uint64_t *n1, uint64_t *cursor,
                             uint64_t *sequence, uint64_t *faults,
                             uint64_t *last_error)
{
    noun tag, rest, value[12];
    if (!take(checkpoint, &tag, &rest) || !noun_eq(tag, g_tag_checkpoint)) return 0;
    for (unsigned i = 0; i < 12; i++)
        if (!take(rest, &value[i], &rest)) return 0;
    if (!direct_is(rest, 0) || !noun_eq(value[0], g_plan_anchor)
        || !direct_is(value[1], M21_PLAN_EPOCH)
        || !noun_is_direct(value[6]) || !noun_is_direct(value[7])
        || !noun_is_direct(value[8]) || !noun_is_direct(value[9])
        || !noun_is_direct(value[10]) || !noun_is_direct(value[11])) return 0;
    *gate0 = value[2]; *gate1 = value[3]; *queue0 = value[4]; *queue1 = value[5];
    *n0 = direct_val(value[6]); *n1 = direct_val(value[7]);
    *cursor = direct_val(value[8]); *sequence = direct_val(value[9]);
    *faults = direct_val(value[10]); *last_error = direct_val(value[11]);
    return 1;
}

static int checkpoint_queues_valid(noun queue0, noun queue1,
                                   uint64_t n0, uint64_t n1,
                                   uint64_t sequence)
{
    noun head, tail, event;
    if (!queue_count_exact(queue0, n0) || !queue_count_exact(queue1, n1)
        || n0 > M21_FIFO_CAP || n1 > M21_FIFO_CAP) return 0;
    while (noun_is_cell(queue0)) {
        if (!take(queue0, &head, &tail) || !source_external_valid(head)) return 0;
        queue0 = tail;
    }
    while (noun_is_cell(queue1)) {
        if (!take(queue1, &head, &tail)
            || !carrier_to_device_ei(head, &event, sequence)) return 0;
        queue1 = tail;
    }
    return 1;
}

int m21_device_checkpoint_capture(void)
{
    noun checkpoint; const uint8_t *bytes; uint64_t bytes_len;
    if (!g_active || !runtime_identity_validate_gate(g_gate[0], &g_identity[0], 0)
        || !runtime_identity_validate_gate(g_gate[1], &g_identity[1], 0)
        || !queue_count_exact(g_queue[0], g_queue_n[0])
        || !queue_count_exact(g_queue[1], g_queue_n[1])) return -1;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!checkpoint_noun(&checkpoint)
        || jam_encode_bytes_checked(checkpoint, &bytes, &bytes_len) != 0
        || bytes_len == 0 || bytes_len > M21_CHECKPOINT_MAX_BYTES) return -1;
    for (uint64_t i = 0; i < bytes_len; i++) g_checkpoint_bytes[i] = bytes[i];
    g_checkpoint_len = bytes_len; g_checkpoint_valid = 1;
    return 0;
}

int m21_device_checkpoint_restore(void)
{
    noun checkpoint, gate0, gate1, queue0, queue1;
    uint64_t n0, n1, cursor, sequence, faults, last_error;
    if (!g_active || !g_checkpoint_valid || g_checkpoint_len == 0
        || g_checkpoint_len > M21_CHECKPOINT_MAX_BYTES) return -1;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(g_checkpoint_bytes, g_checkpoint_len, &cue_i2_limits,
                          HEAP_MODE_PERSIST, &checkpoint) != CUE_BOUNDED_OK
        || !checkpoint_unpack(checkpoint, &gate0, &gate1, &queue0, &queue1,
                              &n0, &n1, &cursor, &sequence, &faults, &last_error)
        || cursor > 1 || !runtime_identity_validate_gate(gate0, &g_identity[0], 0)
        || !runtime_identity_validate_gate(gate1, &g_identity[1], 0)
        || !checkpoint_queues_valid(queue0, queue1, n0, n1, sequence)) {
        if (noun_tx_active()) noun_tx_abort();
        heap_persist_abort_tx();
        return -1;
    }
    /* All copies and queue/carrier validation completed in the inactive half.
     * This is one in-process device-root publication, not crash atomicity. */
    g_gate[0] = gate0; g_gate[1] = gate1;
    g_queue[0] = queue0; g_queue[1] = queue1;
    g_queue_n[0] = n0; g_queue_n[1] = n1;
    g_cursor = cursor; g_sequence = sequence;
    g_faults = faults; g_last_error = last_error;
    if (noun_tx_active()) noun_tx_commit();
    heap_persist_commit_tx();
    return 0;
}

int m21_device_checkpoint_tamper_refuses(void)
{
    root_snapshot_t before = root_snapshot();
    if (!g_checkpoint_valid || g_checkpoint_len == 0) return -1;
    g_checkpoint_bytes[0] ^= 1u;
    int rejected = m21_device_checkpoint_restore() != 0;
    g_checkpoint_bytes[0] ^= 1u;
    return rejected && root_unchanged(&before)
        ? 0 : -1;
}

static int test_link1_samples(noun *out)
{
    noun value0, value1, first, second, list;
    return cons(direct(1), direct(0), &value0)
        && cons(direct(1), direct(0), &value1)
        && cons(direct(1), value0, &first)
        && cons(direct(3), value1, &second)
        && cons(second, NOUN_ZERO, &list) && cons(first, list, out);
}

static root_snapshot_t root_snapshot(void)
{
    root_snapshot_t snapshot = {
        g_gate[0], g_gate[1], g_queue[0], g_queue[1],
        g_queue_n[0], g_queue_n[1], g_cursor, g_sequence,
        g_faults, g_last_error,
    };
    return snapshot;
}

static int root_unchanged(const root_snapshot_t *before)
{
    return before && noun_eq(g_gate[0], before->gate0)
        && noun_eq(g_gate[1], before->gate1)
        && noun_eq(g_queue[0], before->queue0)
        && noun_eq(g_queue[1], before->queue1)
        && g_queue_n[0] == before->n0 && g_queue_n[1] == before->n1
        && g_cursor == before->cursor && g_sequence == before->sequence
        && g_faults == before->faults && g_last_error == before->last_error;
}

static int root_restore(const root_snapshot_t *before)
{
    return before && publish_root(before->gate0, before->gate1,
                                  before->queue0, before->queue1,
                                  before->n0, before->n1, before->sequence,
                                  before->cursor, before->faults,
                                  before->last_error);
}

int m21_device_raw_ingress_refuses(void)
{
    root_snapshot_t before = root_snapshot();
    noun raw;
    if (!g_active) return -1;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    /* An outer external tag cannot smuggle a raw carrier through source
     * admission; it is rejected before either FIFO is changed. */
    if (!cons(g_tag_external, g_tag_carrier, &raw)
        || enqueue_source_external(raw) != -1) return -1;
    return root_unchanged(&before) ? 0 : -1;
}

int m21_device_stale_carrier_refuses(void)
{
    noun samples, carrier, event;
    root_snapshot_t before = root_snapshot();
    if (!g_active) return -1;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!test_link1_samples(&samples)
        || !build_carrier(1, 2, 8, 1, samples, g_sequence, 2, 1, &carrier)) return -1;
    /* This is a complete typed carrier with only source generation stale. */
    if (carrier_to_device_ei(carrier, &event, g_sequence)) return -1;
    return root_unchanged(&before) ? 0 : -1;
}

int m21_device_destination_full_refuses(void)
{
    noun source_event, source_queue, samples, carrier, target_queue = NOUN_ZERO;
    root_snapshot_t before, staged;
    int passed = 0;
    if (!g_active) return -1;
    before = root_snapshot();
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!build_source_external(0, 0, &source_event)
        || !cons(source_event, NOUN_ZERO, &source_queue)
        || !test_link1_samples(&samples)
        || !build_carrier(1, 2, 8, 1, samples, g_sequence + 1u, 1, 1, &carrier))
        return -1;
    /* Build a real 15-deep destination FIFO, then drive a genuine source
     * egress through the normal scheduler.  The carrier entries are valid
     * private pending work; they are never serviced by this focused probe. */
    for (unsigned i = 0; i < 15; i++)
        if (!cons(carrier, target_queue, &target_queue)) return -1;
    if (!publish_root(g_gate[0], g_gate[1], source_queue, target_queue,
                      1, 15, g_sequence, 0, g_faults, g_last_error))
        return -1;
    staged = root_snapshot();
    if (m21_device_step() == -1
        && noun_eq(g_gate[0], staged.gate0) && noun_eq(g_gate[1], staged.gate1)
        && noun_eq(g_queue[1], staged.queue1) && g_queue_n[0] == 0
        && g_queue_n[1] == 15 && g_sequence == staged.sequence
        && g_faults == staged.faults + 1u && g_last_error == 4)
        passed = 1;
    return passed && root_restore(&before) ? 0 : -1;
}

int m21_device_publish_reservation_fault_refuses(void)
{
    noun source_event;
    root_snapshot_t before, staged;
    int passed = 0;
    if (!g_active) return -1;
    before = root_snapshot();
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!build_source_external(1, 1, &source_event)
        || enqueue_source_external(source_event) != 0) return -1;
    staged = root_snapshot();
    /* Fail only the final root reservation.  The fallback terminal root must
     * retire the source head and preserve both gates, the target FIFO, and
     * the delivery sequence. */
    g_test_publish_reservation_fail_once = 1;
    if (m21_device_step() == -1
        && noun_eq(g_gate[0], staged.gate0) && noun_eq(g_gate[1], staged.gate1)
        && noun_eq(g_queue[1], staged.queue1) && g_queue_n[0] == 0
        && g_queue_n[1] == staged.n1 && g_sequence == staged.sequence
        && g_faults == staged.faults + 1u && g_last_error == 4)
        passed = 1;
    g_test_publish_reservation_fail_once = 0;
    return passed && root_restore(&before) ? 0 : -1;
}
