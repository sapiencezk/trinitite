/* M37-A candidate-derived execution core.
 *
 * The core is intentionally a small, profile-specific owner of the admitted
 * NativeExecutionSurface.  It runs the shared ABI-1.9 formula over bounded
 * candidate nouns, authenticates no transport itself, and commits one
 * persistent root only after the corresponding native operation succeeds. */
#include <stdint.h>

#include "candidate_execution_core.h"

#ifdef M37_A

#include "bounded_cue.h"
#include "i2_application_surface.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "runtime_stats.h"
#include "setjmp.h"

#define M37_A_OPS 2000000ULL
#define M37_A_CELLS 128000ULL
#define M37_A_RATE_LIMIT 64ULL
#define M37_A_ROUTE_FIELDS 5u
#define M37_A_ROUTE_CAPACITY 16u
#define M37_A_CAUSE_BUDGET 16u
#define M37_A_WORK_BUDGET 17u

#define CORD_COMMIT 127996156276579ULL
#define CORD_I2_RX_ORIGIN_V1 0x3178723269ULL
#define CORD_I2_INTERNAL_ORIGIN_V1 0x316e693269ULL

static noun g_gate;
static runtime_identity_t g_identity;
static NativeExecutionSurface g_surface;
static noun g_external_tag, g_ei_tag, g_intent_tag, g_graph_intent_tag;
static noun g_pending_event;
static uint64_t g_pending_value;
static candidate_execution_intent_t g_pending_intent;
static uint8_t g_pending_valid, g_intent_pending, g_intent_taken;
static uint8_t g_fifo_payload[CANDIDATE_EXECUTION_FIFO_CAPACITY][M37_A_MAX_PAYLOAD];
static uint32_t g_fifo_length[CANDIDATE_EXECUTION_FIFO_CAPACITY];
static uint64_t g_fifo_sequence[CANDIDATE_EXECUTION_FIFO_CAPACITY];
static uint32_t g_fifo_head, g_fifo_count;
static uint64_t g_next_sequence, g_high_water, g_admitted_high_water, g_last_error;
static uint64_t g_rate_window_start, g_rate_successes;
static uint64_t g_last_output;
static uint8_t g_output_valid, g_active, g_running, g_source, g_native_initialized;
static uint8_t g_hold_processing;
static uint8_t g_allocation_pressure;
static uint64_t g_root_commits, g_publications;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head; *tail = cell->tail;
    return 1;
}

static int direct_is(noun n, uint64_t value)
{
    return noun_is_direct(n) && direct_val(n) == value;
}

static int cons(noun head, noun tail, noun *out)
{
    return alloc_cell_checked(head, tail, out);
}

static int positive_direct(noun n, uint64_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) == 0) return 0;
    if (out) *out = direct_val(n);
    return 1;
}

static int same_descriptor(const uint64_t a[11], const uint64_t b[11])
{
    for (unsigned i = 0; i < 11; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static int build_slam(noun *out)
{
    noun n0, n1, n2, n3, n4, n5, n6;
    if (!out || !cons(direct(0), direct(3), &n0)
        || !cons(direct(6), n0, &n1) || !cons(direct(0), direct(2), &n2)
        || !cons(n1, n2, &n3) || !cons(direct(10), n3, &n4)
        || !cons(direct(2), n4, &n5) || !cons(direct(9), n5, &n6)) return 0;
    *out = n6; return 1;
}

static int product_parts(noun result, noun *candidate, noun *causes)
{
    noun tag, product, effects, rest;
    return take(result, &tag, &product) && direct_is(tag, CORD_COMMIT)
        && take(product, &effects, &rest) && direct_is(effects, 0)
        && take(rest, candidate, causes);
}

static int slam_gate(noun gate, noun event, int rx_origin,
                     noun *candidate, noun *causes)
{
    noun carrier, subject, result, formula;
    if (!build_slam(&formula)
        || !cons(rx_origin ? direct(CORD_I2_RX_ORIGIN_V1)
                             : direct(CORD_I2_INTERNAL_ORIGIN_V1),
                 event, &carrier)
        || !cons(gate, carrier, &subject)) return 0;
    int jump = setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(g_surface.binding.max_ops, g_surface.binding.max_cells);
    result = nock(subject, formula);
    nock_budget_finish();
    return product_parts(result, candidate, causes)
        && runtime_identity_validate_gate(*candidate, &g_identity, 0);
}

static int route_fields(noun cause, uint64_t fields[M37_A_ROUTE_FIELDS], noun *samples)
{
    noun tag, body, value;
    if (!cause || !fields || !samples || !take(cause, &tag, &body)
        || !i2_application_surface_tag_matches(tag, "i2-route-ei", 11)) return 0;
    for (unsigned i = 0; i < M37_A_ROUTE_FIELDS; i++)
        if (!take(body, &value, &body) || !positive_direct(value, &fields[i])) return 0;
    *samples = body;
    return 1;
}

static int root_route_at(uint32_t ordinal, uint64_t fields[5])
{
    uint32_t seen = 0;
    if (!fields) return 0;
    for (uint32_t i = 0; i < g_surface.route_count; i++) {
        /* The external endpoint names the producer input event.  The first
         * derived route is emitted by that producer's output event, so the
         * root reservation is keyed by the candidate-derived instance only. */
        if (g_surface.routes[i][1] != g_surface.ingress_instance) continue;
        if (seen++ == ordinal) {
            for (unsigned j = 0; j < M37_A_ROUTE_FIELDS; j++) fields[j] = g_surface.routes[i][j];
            return 1;
        }
    }
    return 0;
}

static uint32_t outgoing_route_count(uint64_t source_instance, uint64_t source_event)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_surface.route_count; i++)
        if (g_surface.routes[i][1] == source_instance
            && g_surface.routes[i][2] == source_event) count++;
    return count;
}

static int outgoing_route_at(uint64_t source_instance, uint64_t source_event,
                             uint32_t ordinal, uint64_t fields[5])
{
    uint32_t seen = 0;
    if (!fields) return 0;
    for (uint32_t i = 0; i < g_surface.route_count; i++)
        if (g_surface.routes[i][1] == source_instance
            && g_surface.routes[i][2] == source_event) {
            if (seen++ == ordinal) {
                for (unsigned j = 0; j < M37_A_ROUTE_FIELDS; j++) fields[j] = g_surface.routes[i][j];
                return 1;
            }
        }
    return 0;
}

static int route_record_matches(const uint64_t actual[5], const uint64_t expected[5])
{
    if (!actual || !expected) return 0;
    for (unsigned i = 0; i < M37_A_ROUTE_FIELDS; i++)
        if (actual[i] != expected[i]) return 0;
    return 1;
}

static int preflight_worklist(void)
{
    uint32_t root_count = 0;
    uint64_t targets[M37_A_ROUTE_CAPACITY][2];
    if (g_surface.route_count == 0 || g_surface.route_count > CANDIDATE_EXECUTION_ROUTE_CAPACITY)
        return 0;
    for (uint32_t i = 0; i < g_surface.route_count; i++) {
        const uint64_t *edge = g_surface.routes[i];
        if (edge[1] != g_surface.ingress_instance)
            continue;
        if (root_count >= M37_A_ROUTE_CAPACITY) return 0;
        for (uint32_t prior = 0; prior < root_count; prior++)
            if (targets[prior][0] == edge[3] && targets[prior][1] == edge[4]) return 0;
        targets[root_count][0] = edge[3]; targets[root_count][1] = edge[4];
        root_count++;
    }
    return root_count != 0 && root_count <= M37_A_CAUSE_BUDGET;
}

static int drain_causes(noun candidate, noun causes,
                        noun *final_candidate, noun *final_causes)
{
    noun current = candidate, pending = causes, cause, rest;
    noun queue[M37_A_ROUTE_CAPACITY];
    uint32_t head = 0, tail = 0, cause_count = 0, work_count = 1;
    uint32_t final_intent_count = 0;

    while (take(pending, &cause, &rest)) {
        uint64_t fields[M37_A_ROUTE_FIELDS], expected[5]; noun samples;
        if (tail >= M37_A_ROUTE_CAPACITY || cause_count >= M37_A_CAUSE_BUDGET
            || !root_route_at(tail, expected)
            || !route_fields(cause, fields, &samples)
            || !route_record_matches(fields, expected)) return 0;
        for (uint32_t prior = 0; prior < tail; prior++) {
            uint64_t old[M37_A_ROUTE_FIELDS]; noun old_samples;
            if (!route_fields(queue[prior], old, &old_samples)
                || (old[3] == fields[3] && old[4] == fields[4])) return 0;
        }
        queue[tail++] = cause; cause_count++; pending = rest;
    }
    if (!direct_is(pending, 0) || tail == 0) return 0;

    while (head < tail) {
        uint64_t fields[M37_A_ROUTE_FIELDS], expected[5]; noun samples;
        noun next_causes = NOUN_ZERO, next_candidate;
        noun children[M37_A_ROUTE_CAPACITY];
        uint32_t outgoing, child_count = 0, intent_count = 0;
        if (work_count >= M37_A_WORK_BUDGET
            || !route_fields(queue[head], fields, &samples)) return 0;
        outgoing = outgoing_route_count(fields[3], fields[2]);
        if (outgoing > M37_A_ROUTE_CAPACITY
            || tail - head - 1u + outgoing > M37_A_ROUTE_CAPACITY
            || cause_count + outgoing > M37_A_CAUSE_BUDGET) return 0;

        for (uint32_t i = 0; i < outgoing; i++) {
            if (!outgoing_route_at(fields[3], fields[2], i, expected)) return 0;
            for (uint32_t j = head + 1u; j < tail; j++) {
                uint64_t queued[M37_A_ROUTE_FIELDS]; noun queued_samples;
                if (!route_fields(queue[j], queued, &queued_samples)) return 0;
                if (queued[3] == expected[3] && queued[4] == expected[4]) return 0;
            }
            for (uint32_t j = 0; j < i; j++) {
                uint64_t old[5];
                if (!outgoing_route_at(fields[3], fields[2], j, old)
                    || (old[3] == expected[3] && old[4] == expected[4])) return 0;
            }
        }
        if (!slam_gate(current, queue[head], 0, &next_candidate, &next_causes)) return 0;
        noun scan = next_causes, scan_tail, tag, cause_body;
        while (take(scan, &cause, &scan_tail)) {
            if (!take(cause, &tag, &cause_body)) return 0;
            if (noun_eq(tag, g_graph_intent_tag)) intent_count++;
            else if (i2_application_surface_tag_matches(tag, "i2-route-ei", 11)) {
                uint64_t child_fields[M37_A_ROUTE_FIELDS]; noun child_samples;
                if (child_count >= outgoing
                    || !route_fields(cause, child_fields, &child_samples)
                    || !outgoing_route_at(fields[3], fields[2], child_count, expected)
                    || !route_record_matches(child_fields, expected)) return 0;
                children[child_count++] = cause;
            } else return 0;
            scan = scan_tail;
        }
        if (!direct_is(scan, 0) || child_count != outgoing
            || (outgoing == 0 && intent_count > 1)
            || (outgoing != 0 && intent_count != 0)) {
            return 0;
        }
        if (tail - head - 1u + child_count > M37_A_ROUTE_CAPACITY) return 0;
        {
            uint32_t remaining = tail - head - 1u;
            for (uint32_t i = 0; i < remaining; i++) queue[i] = queue[head + 1u + i];
            for (uint32_t i = 0; i < child_count; i++) queue[remaining + i] = children[i];
            head = 0; tail = remaining + child_count;
        }
        cause_count += child_count; work_count++; current = next_candidate;
        if (intent_count) { *final_causes = next_causes; final_intent_count = intent_count; }
    }
    if (final_candidate) *final_candidate = current;
    return final_causes && final_intent_count == 1;
}

static int build_external(uint64_t value, noun *out)
{
    noun typed, variable, samples, body, target;
    if (!out || g_surface.ingress_type != 1 || value > 1) return 0;
    if (!cons(direct(g_surface.ingress_type), direct(value), &typed)
        || !cons(direct(g_surface.ingress_sample), typed, &variable)
        || !cons(variable, NOUN_ZERO, &samples)
        || !cons(direct(g_surface.ingress_event), samples, &body)
        || !cons(direct(g_surface.ingress_instance), body, &target)
        || !cons(cord_from_bytes("i2-ei", 5), target, &body)
        || !cons(cord_from_bytes("i2-external", 11), body, out)) return 0;
    return 1;
}

static int parse_intent_cause(noun cause, const uint64_t expected[11], uint64_t *value)
{
    noun tag, body, item, type, payload;
    uint64_t descriptor[11];
    if (!take(cause, &tag, &body) || !noun_eq(tag, g_graph_intent_tag)
        ) return 0;
    for (unsigned i = 0; i < 11; i++)
        if (!take(body, &item, &body) || !positive_direct(item, &descriptor[i])) return 0;
    if (!take(body, &type, &payload) || !direct_is(type, 1)
        || !noun_is_direct(payload) || direct_val(payload) > 1
        || !same_descriptor(descriptor, expected)) return 0;
    if (value) *value = direct_val(payload);
    return 1;
}

static int parse_intent_list(noun causes, const uint64_t expected[11], uint64_t *value)
{
    noun cause, rest;
    return take(causes, &cause, &rest) && direct_is(rest, 0)
        && parse_intent_cause(cause, expected, value);
}

static int run_graph(uint64_t value, noun *candidate, noun *final_causes)
{
    noun external, root_candidate, root_causes;
    if (!preflight_worklist()) return 0;
    if (!build_external(value, &external)) return 0;
    if (!slam_gate(g_gate, external, 1, &root_candidate, &root_causes)) return 0;
    if (!drain_causes(root_candidate, root_causes, candidate, final_causes)) return 0;
    return 1;
}

static int build_intent_payload(const uint64_t descriptor[11], uint64_t value,
                                candidate_execution_intent_t *out)
{
    noun tail = direct(0), intent;
    const uint8_t *bytes;
    uint64_t length;
    if (!out || value > 1) return 0;
    if (!cons(direct(value), tail, &tail)) return 0;
    for (int i = 10; i >= 0; i--)
        if (!cons(direct(descriptor[i]), tail, &tail)) return 0;
    if (!cons(direct(1), tail, &tail) || !cons(direct(1), tail, &tail)
        || !cons(g_intent_tag, tail, &intent)
        || jam_encode_bytes_checked(intent, &bytes, &length) != 0
        || length == 0 || length > M37_A_MAX_PAYLOAD) return 0;
    for (uint64_t i = 0; i < length; i++) out->payload[i] = bytes[i];
    out->payload_len = (uint32_t)length;
    return 1;
}

static int commit_candidate(noun candidate)
{
    noun staged;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(candidate, &staged)) {
        heap_persist_abort_tx(); return 0;
    }
    g_gate = staged; heap_persist_commit_tx(); g_root_commits++;
    return 1;
}

static int rate_available(uint64_t *window_start, uint64_t *successes)
{
    uint64_t now = runtime_counter_now(), frequency = runtime_counter_freq();
    uint64_t start = g_rate_window_start, count = g_rate_successes;
    if (start == 0 || (frequency != 0 && now - start >= frequency)) {
        start = now; count = 0;
    }
    if (count >= M37_A_RATE_LIMIT) return 0;
    if (window_start) *window_start = start;
    if (successes) *successes = count;
    return 1;
}

static int process_fifo_head(void)
{
    uint32_t at;
    uint64_t value, sequence, window_start, successes;
    noun candidate, causes;
    if (g_fifo_count == 0) return 0;
    at = g_fifo_head;
    sequence = g_fifo_sequence[at];
    /* The wire parser already checked the typed noun.  The first byte is not
     * the value contract; recover it from the bounded Jam noun below. */
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    noun decoded;
    if (cue_bounded_bytes(g_fifo_payload[at], g_fifo_length[at], &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &decoded) != CUE_BOUNDED_OK) {
        if (noun_tx_active()) noun_tx_abort();
        g_last_error = 3; return -1;
    }
    noun tag, body, version, type, item, tail;
    uint64_t descriptor[11];
    if (!take(decoded, &tag, &body) || !noun_eq(tag, g_intent_tag)
        || !take(body, &version, &body) || !direct_is(version, 1)
        || !take(body, &type, &body) || !direct_is(type, 1)) {
        noun_tx_abort(); g_last_error = 3; return -1;
    }
    for (unsigned i = 0; i < 11; i++)
        if (!take(body, &item, &body) || !positive_direct(item, &descriptor[i])) {
            noun_tx_abort(); g_last_error = 3; return -1;
        }
    if (!take(body, &item, &tail) || !direct_is(tail, 0)
        || !noun_is_direct(item) || direct_val(item) > 1
        || !same_descriptor(descriptor, g_surface.binding.peer_descriptor)) {
        noun_tx_abort(); g_last_error = 3; return -1;
    }
    value = direct_val(item); noun_tx_abort();
    if (!rate_available(&window_start, &successes)) { g_last_error = 10; return -1; }
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!run_graph(value, &candidate, &causes)
        || !parse_intent_list(causes, g_surface.publication, &value)) {
        g_last_error = 4; return -1;
    }
    if (!commit_candidate(candidate)) { g_last_error = 5; return -1; }
    g_fifo_head = (g_fifo_head + 1u) % CANDIDATE_EXECUTION_FIFO_CAPACITY;
    g_fifo_count--; g_high_water = sequence; g_last_output = value;
    g_output_valid = 1; g_publications++; g_rate_window_start = window_start;
    g_rate_successes = successes + 1; g_last_error = 0;
    return 1;
}

int candidate_execution_core_prepare(
    const NativeExecutionSurface *surface, noun gate,
    const runtime_identity_t *identity, candidate_execution_prepared_t *out)
{
    if (!surface || !identity || !out || surface->route_count == 0
        || surface->route_count > CANDIDATE_EXECUTION_ROUTE_CAPACITY
        || surface->binding.max_payload != M37_A_MAX_PAYLOAD
        || surface->binding.max_ops != M37_A_OPS
        || surface->binding.max_cells != M37_A_CELLS
        || surface->binding.local_device != (uint64_t)M24_NODE_ID
        || surface->binding.peer_device == surface->binding.local_device
        || !runtime_identity_validate_gate_header(gate, identity, 0)) {
        return -1;
    }
    for (unsigned i = 0; i < 11; i++)
        if (surface->publication[i] == 0 || surface->binding.peer_descriptor[i] == 0)
            return -1;
    out->gate = gate; out->identity = *identity; out->surface = *surface;
    return 0;
}

int candidate_execution_core_activate(const candidate_execution_prepared_t *prepared)
{
    if (!prepared) return -1;
    g_gate = prepared->gate; g_identity = prepared->identity;
    g_surface = prepared->surface;
    g_external_tag = cord_from_bytes("i2-external", 11);
    g_ei_tag = cord_from_bytes("i2-ei", 5);
    g_intent_tag = cord_from_bytes("m37-a-intent-v1", 15);
    g_graph_intent_tag = cord_from_bytes("i2-m25-intent-v1", 16);
    noun route_tag = cord_from_bytes("i2-route-ei", 11);
    if (!noun_is_atom(g_external_tag) || !noun_is_atom(g_ei_tag)
        || !noun_is_atom(g_intent_tag) || !noun_is_atom(g_graph_intent_tag)
        || !noun_is_atom(route_tag)) return -1;
    runtime_identity_set(&g_identity);
    runtime_identity_set_capability_profile(RUNTIME_CAPABILITY_PROFILE_M25);
    g_pending_event = NOUN_ZERO; g_pending_value = 0; g_pending_intent.payload_len = 0;
    g_pending_valid = 0; g_intent_pending = 0; g_intent_taken = 0;
    g_fifo_head = g_fifo_count = 0; g_next_sequence = 1;
    g_high_water = g_admitted_high_water = 0;
    g_last_error = 0; g_last_output = 0; g_output_valid = 0;
    g_rate_window_start = g_rate_successes = 0; g_root_commits = 1; g_publications = 0;
    g_active = 1; g_running = 0; g_native_initialized = 0;
    g_hold_processing = 0;
    g_allocation_pressure = 0;
    g_source = g_surface.binding.local_device == 11;
    return 0;
}

int candidate_execution_core_init(void)
{
    if (!g_active || g_pending_valid || g_fifo_count != 0
        || m37_a_adapter_tx_pending() || m37_a_adapter_init(&g_surface.binding) != 0) return -1;
    g_native_initialized = 1; return 0;
}

int candidate_execution_core_set_running(int running)
{
    if (!g_active || g_pending_valid || g_fifo_count != 0
        || m37_a_adapter_tx_pending() || (running && !g_native_initialized)) return -1;
    g_running = running != 0; return 0;
}

int candidate_execution_core_submit(const candidate_execution_ingress_t *ingress)
{
    if (!ingress || !g_active || !g_running || !g_source || g_pending_valid
        || ingress->type != 1 || ingress->value > 1) return -1;
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!build_external(ingress->value, &g_pending_event)) { g_last_error = 2; return -1; }
    g_pending_value = ingress->value;
    g_pending_valid = 1; return 0;
}

int candidate_execution_core_take_intent(candidate_execution_intent_t *out)
{
    if (!out || !g_intent_pending || g_intent_taken) return -1;
    *out = g_pending_intent; g_intent_taken = 1; return 0;
}

int candidate_execution_core_pump(void)
{
    if (!g_active || !g_running || !g_native_initialized) return 0;
    if (!g_source) {
        if (g_fifo_count != 0 && !g_hold_processing) return process_fifo_head();
        m37_a_datagram_t datagram;
        m37_a_native_status_t status = m37_a_adapter_receive(&g_surface.binding, &datagram);
        if (status == M37_A_NATIVE_NO_PACKET) return 0;
        if (status != M37_A_NATIVE_OK) { g_last_error = 1; return -1; }
        candidate_execution_delivery_t delivery = {
            datagram.payload, datagram.payload_len, datagram.sequence,
        };
        return candidate_execution_core_deliver(&delivery);
    }
    if (!g_pending_valid) return 0;
    uint64_t window_start, successes;
    if (g_next_sequence == UINT64_MAX || !rate_available(&window_start, &successes)) {
        g_last_error = 10; return -1;
    }
    if (g_allocation_pressure) {
        /* Deterministic test pressure is checked before any candidate work;
         * the pending ingress remains available for a later retry. */
        g_last_error = 4; return -1;
    }
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    noun candidate, causes; uint64_t value;
    if (!run_graph(g_pending_value, &candidate, &causes)) {
        g_last_error = 3; return -1;
    }
    if (!parse_intent_list(causes, g_surface.publication, &value)) {
        g_last_error = 3; return -1;
    }
    if (!build_intent_payload(g_surface.publication, value, &g_pending_intent)) {
        g_last_error = 3; return -1;
    }
    g_pending_intent.sequence = g_next_sequence; g_intent_pending = 1; g_intent_taken = 0;
    noun staged;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(candidate, &staged)) {
        heap_persist_abort_tx(); g_intent_pending = 0; g_last_error = 4; return -1;
    }
    candidate_execution_intent_t intent;
    if (candidate_execution_core_take_intent(&intent) != 0) {
        heap_persist_abort_tx(); g_intent_pending = 0; g_last_error = 4; return -1;
    }
    m37_a_native_status_t status = m37_a_adapter_send(
        &g_surface.binding, intent.payload, intent.payload_len, intent.sequence);
    if (status != M37_A_NATIVE_OK) {
        heap_persist_abort_tx(); g_intent_taken = 0; g_last_error = status == M37_A_NATIVE_RING_FULL ? 6 : 5;
        return -1;
    }
    g_gate = staged; g_pending_event = NOUN_ZERO; g_pending_value = 0; g_pending_valid = 0;
    g_intent_pending = 0; g_intent_taken = 0; g_next_sequence++;
    g_rate_window_start = window_start; g_rate_successes = successes + 1;
    g_publications++; g_root_commits++; heap_persist_commit_tx(); g_last_error = 0;
    return 1;
}

int candidate_execution_core_deliver(const candidate_execution_delivery_t *delivery)
{
    if (!delivery || !g_active || !g_running || g_source || delivery->sequence == 0
        || delivery->sequence == UINT64_MAX
        || !delivery->payload || delivery->payload_len == 0
        || delivery->payload_len > M37_A_MAX_PAYLOAD
        || delivery->sequence <= g_admitted_high_water
        || g_fifo_count >= CANDIDATE_EXECUTION_FIFO_CAPACITY) {
        g_last_error = 2; return -1;
    }
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    noun decoded, tag, body, version, type, item, tail;
    uint64_t descriptor[11];
    if (cue_bounded_bytes(delivery->payload, delivery->payload_len, &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &decoded) != CUE_BOUNDED_OK
        || !take(decoded, &tag, &body) || !noun_eq(tag, g_intent_tag)
        || !take(body, &version, &body) || !direct_is(version, 1)
        || !take(body, &type, &body) || !direct_is(type, 1)) {
        if (noun_tx_active()) noun_tx_abort();
        g_last_error = 3; return -1;
    }
    for (unsigned i = 0; i < 11; i++)
        if (!take(body, &item, &body) || !positive_direct(item, &descriptor[i])) {
            noun_tx_abort(); g_last_error = 3; return -1;
        }
    if (!take(body, &item, &tail) || !direct_is(tail, 0)
        || !noun_is_direct(item) || direct_val(item) > 1
        || !same_descriptor(descriptor, g_surface.binding.peer_descriptor)) {
        noun_tx_abort(); g_last_error = 3; return -1;
    }
    noun_tx_abort();
    uint32_t at = (g_fifo_head + g_fifo_count) % CANDIDATE_EXECUTION_FIFO_CAPACITY;
    for (uint32_t i = 0; i < delivery->payload_len; i++) g_fifo_payload[at][i] = delivery->payload[i];
    g_fifo_length[at] = delivery->payload_len; g_fifo_sequence[at] = delivery->sequence;
    g_fifo_count++; g_admitted_high_water = delivery->sequence;
    if (g_hold_processing) return 1;
    return process_fifo_head();
}

uint64_t candidate_execution_core_queue_len(void) { return g_active ? g_fifo_count : UINT64_MAX; }
uint64_t candidate_execution_core_output(void) { return g_output_valid ? g_last_output : UINT64_MAX; }
uint64_t candidate_execution_core_sequence(void) { return g_next_sequence; }
uint64_t candidate_execution_core_high_water(void) { return g_high_water; }
uint64_t candidate_execution_core_error(void) { return g_last_error; }
uint64_t candidate_execution_core_root_commits(void) { return g_root_commits; }
uint64_t candidate_execution_core_publications(void) { return g_publications; }

int candidate_execution_core_test_hold_processing(int enabled)
{
    if (!g_active || !g_running || g_source) return -1;
    g_hold_processing = enabled != 0; return 0;
}

int candidate_execution_core_test_clear_error(void)
{
    if (!g_active) return -1;
    g_last_error = 0; return 0;
}

int candidate_execution_core_test_rate_exhaust(void)
{
    if (!g_active || !g_running || !g_source) return -1;
    g_rate_window_start = runtime_counter_now(); g_rate_successes = M37_A_RATE_LIMIT;
    g_last_error = 10; return 0;
}

int candidate_execution_core_test_rate_reset(void)
{
    if (!g_active || !g_source) return -1;
    g_rate_window_start = g_rate_successes = 0; g_last_error = 0; return 0;
}

int candidate_execution_core_test_allocation_pressure(void)
{
    if (!g_active || !g_running || !g_source) return -1;
    g_allocation_pressure = 1; return 0;
}

int candidate_execution_core_test_allocation_release(void)
{
    if (!g_active || !g_source) return -1;
    g_allocation_pressure = 0; noun_test_copy_fail_after(-1); g_last_error = 0; return 0;
}

#endif
