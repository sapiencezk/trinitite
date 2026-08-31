/* M36-T's bounded native target path.
 *
 * The M29 management seam admits and publishes this module only after the
 * authenticated policy, PILL, and generic runtime identity checks succeed.
 * The implementation below deliberately has one fixed M36 graph projection:
 * BOOL TRIGGER -> UINT16 COUNTER on node 11, then UINT16 THRESHOLD -> BOOL
 * SINK on node 22.  It uses the same M17-derived Nock slam and service
 * transaction vocabulary as the host compiler, but has no name registry,
 * dispatch table, or open-ended ABI.
 */
#include "m36_target_core.h"

#ifdef M36_TYPED

#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "jam.h"
#include "m36_aethernet_native.h"
#include "memory.h"
#include "nock.h"
#include "runtime_stats.h"
#include "setjmp.h"
#include "sha256.h"

#define M36_SOURCE_NODE 11u
#define M36_DESTINATION_NODE 22u
#define M36_SOURCE_RESOURCE 1u
#define M36_DESTINATION_RESOURCE 2u
#define M36_FIFO_CAPACITY 16u
#define M36_HEADER_BYTES 128u
#define M36_MAX_PAYLOAD 512u
#define M36_MAX_DATAGRAM 1200u
#define M36_OPS 2000000ULL
#define M36_CELLS 128000ULL
#define M36_RATE_LIMIT 64u
#define M36_PROFILE 2u
#define M36_WIRE_MAJOR 0u
#define M36_WIRE_MINOR 1u
#define M36_MESSAGE_KIND_DATA 1u
#define M36_KEY_ID 1u
#define M36_EPOCH 1u
#define M36_UINT_TYPE 4u
#define M36_UINT_WIDTH 16u
#define M36_UINT_MAX 65535u
#define M36_COMMIT 127996156276579ULL
#define M36_CORD_I2_RX_ORIGIN_V1 0x3178723269ULL
#define M36_CORD_I2_INTERNAL_ORIGIN_V1 0x316e693269ULL

static const uint8_t M36_KEY[] = "m36-typed-scalar-key-0123456789";
/* The explicit final NUL is part of the HMAC domain and the C terminator is
 * excluded by sizeof-1, matching m36_typed_wire.py exactly. */
static const uint8_t M36_HMAC_DOMAIN[] =
    "1499kernel-aethernet-1-typed-scalar-v1\0";
static const uint8_t M36_SCHEMA[32] = {
    0x6f,0x4f,0x4c,0x8d,0xc7,0x15,0x52,0x23,
    0x6a,0x4b,0x47,0xc4,0x7f,0xa8,0x70,0xf2,
    0x05,0x6d,0x07,0x05,0xaf,0x87,0x91,0xb7,
    0x66,0xf3,0xdb,0xec,0x20,0xd1,0x0b,0x6b,
};
static const uint8_t M36_BINDING_11_22[16] = {
    0x3e,0x18,0xe3,0x92,0x88,0x62,0xec,0xc3,
    0x16,0x9b,0x86,0xe8,0x18,0xd6,0xb8,0xb0,
};

static noun g_gate;
static runtime_identity_t g_identity;
static noun g_external_tag, g_ei_tag, g_route_tag, g_intent_tag;
static noun g_delivery_tag, g_envelope_tag, g_publish_tag, g_service_tag;
static noun g_pending_event;
static uint16_t g_fifo_value[M36_FIFO_CAPACITY];
static uint64_t g_fifo_sequence[M36_FIFO_CAPACITY];
static uint32_t g_fifo_head, g_fifo_count;
static uint64_t g_next_sequence, g_high_water, g_last_indication, g_last_error;
static uint64_t g_rate_window_start, g_rate_successes;
static int g_indication_valid, g_active, g_is_source, g_native_initialized;
static int g_lifecycle_running;
static uint8_t g_initial_jam[JAM_MAX_BYTES];
static uint64_t g_initial_jam_len;

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

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    if (!a || !b) return 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static uint16_t get16(const volatile uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get32(const volatile uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get64(const volatile uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static void put16(volatile uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void put32(volatile uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void put64(volatile uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (56u - 8u * i));
}

static noun build_slam(void)
{
    noun n0, n1, n2, n3, n4, n5, n6;
    if (!cons(direct(0), direct(3), &n0)
        || !cons(direct(6), n0, &n1) || !cons(direct(0), direct(2), &n2)
        || !cons(n1, n2, &n3) || !cons(direct(10), n3, &n4)
        || !cons(direct(2), n4, &n5) || !cons(direct(9), n5, &n6)) return NOUN_ZERO;
    return n6;
}

static int product_parts(noun result, noun *candidate, noun *causes)
{
    noun tag, product, effects, rest;
    return take(result, &tag, &product) && direct_is(tag, M36_COMMIT)
        && take(product, &effects, &rest) && direct_is(effects, 0)
        && take(rest, candidate, causes);
}

static int slam_gate(noun gate, noun event, int rx_origin,
                     noun *candidate, noun *causes)
{
    noun carrier, subject, result, formula = build_slam();
    if (!noun_is_cell(formula)
        || !cons(rx_origin ? direct(M36_CORD_I2_RX_ORIGIN_V1)
                             : direct(M36_CORD_I2_INTERNAL_ORIGIN_V1), event, &carrier)
        || !cons(gate, carrier, &subject)) return 0;
    int jump = setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(M36_OPS, M36_CELLS);
    result = nock(subject, formula);
    nock_budget_finish();
    if (!product_parts(result, candidate, causes)) return 0;
    if (!runtime_identity_validate_gate(*candidate, &g_identity, 0)) return 0;
    return 1;
}

static int route_fields(noun cause, uint64_t fields[5])
{
    noun tag, body, value;
    if (!take(cause, &tag, &body) || !noun_eq(tag, g_route_tag)) return 0;
    for (unsigned i = 0; i < 5; i++)
        if (!take(body, &value, &body) || !noun_is_direct(value)
            || (fields[i] = direct_val(value)) == 0) return 0;
    return 1;
}

static int one_cause(noun causes, noun *cause)
{
    noun rest;
    return cause && take(causes, cause, &rest) && direct_is(rest, 0);
}

static int exact_route(noun cause, uint64_t source_instance,
                       uint64_t source_event, uint64_t target_instance,
                       uint64_t target_event)
{
    uint64_t fields[5];
    return route_fields(cause, fields)
        && fields[0] == 1 && fields[1] == source_instance
        && fields[2] == source_event && fields[3] == target_instance
        && fields[4] == target_event;
}

static int build_external(uint64_t value, noun *out)
{
    noun typed, variable, sample_list, body, target;
    if (!out || value > 1
        || !cons(direct(1), direct(value), &typed)
        || !cons(direct(1), typed, &variable)
        || !cons(variable, NOUN_ZERO, &sample_list)
        || !cons(direct(1), sample_list, &body)
        || !cons(direct(1), body, &target)
        || !cons(g_ei_tag, target, &body)
        || !cons(g_external_tag, body, out)) return 0;
    return 1;
}

static int parse_intent(noun causes, const uint64_t expected[11],
                        uint64_t expected_type, uint64_t *value)
{
    noun cause, rest, tag, body, field, type, payload;
    if (!value || !one_cause(causes, &cause)
        || !take(cause, &tag, &body) || !noun_eq(tag, g_intent_tag)) return 0;
    for (unsigned i = 0; i < 11; i++)
        if (!take(body, &field, &body) || !noun_is_direct(field)
            || direct_val(field) != expected[i]) return 0;
    if (!take(body, &type, &payload) || !direct_is(type, expected_type)
        || !noun_is_direct(payload)) return 0;
    if (expected_type == M36_UINT_TYPE) {
        if (direct_val(payload) > M36_UINT_MAX) return 0;
    } else if (direct_val(payload) > 1) return 0;
    (void)rest;
    *value = direct_val(payload);
    return 1;
}

static int source_graph(noun event, noun *final_gate, uint64_t *value)
{
    static const uint64_t descriptor[11] = {2,2,8,2,4,8,9,5,1,1,4};
    noun candidate, causes, route, next_candidate, next_causes;
    if (!event || !slam_gate(g_gate, event, 1, &candidate, &causes)) return 0;
    if (!one_cause(causes, &route)
        || !exact_route(route, 1, 2, 2, 1)
        || !slam_gate(candidate, route, 0, &next_candidate, &next_causes)
        || !parse_intent(next_causes, descriptor, M36_UINT_TYPE, value)) return 0;
    *final_gate = next_candidate;
    return 1;
}

static int build_service_event(uint64_t instance, uint64_t operation,
                               uint64_t value, noun *out)
{
    return cons(direct(value), NOUN_ZERO, out)
        && cons(direct(operation), *out, out)
        && cons(direct(instance), *out, out)
        && cons(g_service_tag, *out, out);
}

static int service_candidate(noun base_gate, uint64_t instance,
                             uint64_t operation, uint64_t value,
                             noun *out)
{
    noun event, causes, cause;
    if (!build_service_event(instance, operation, value, &event)) return 0;
    if (!slam_gate(base_gate, event, 0, out, &causes)) return 0;
    if (!one_cause(causes, &cause)) return 0;
    if (!noun_eq(cause, event)) return 0;
    return 1;
}

static int build_delivery(uint64_t value, noun *out)
{
    noun typed, event, target_event, instance, service;
    /* The delivery noun follows the retained M25 service-event lowering:
     * [type value], unlike the external ingress sample [id [type value]]. */
    return cons(direct(M36_UINT_TYPE), direct(value), &typed)
        && cons(direct(1), typed, &target_event)
        && cons(direct(1), target_event, &event)
        && cons(direct(5), event, &instance)
        && cons(direct(9), instance, &service)
        && cons(g_delivery_tag, service, out);
}

static int destination_graph(uint64_t value, noun *final_gate, uint64_t *output)
{
    static const uint64_t descriptor[11] = {6,2,8,2,1,8,9,5,1,1,1};
    noun service_state, event, candidate, causes, route, next_candidate, next_causes;
    if (!service_candidate(g_gate, 9, 4, value, &service_state)) return 0;
    if (!build_delivery(value, &event)) return 0;
    if (!slam_gate(service_state, event, 0, &candidate, &causes)) return 0;
    if (!one_cause(causes, &route)) return 0;
    if (!exact_route(route, 5, 2, 6, 1)) return 0;
    if (!slam_gate(candidate, route, 0, &next_candidate, &next_causes)) return 0;
    if (!parse_intent(next_causes, descriptor, 1, output)) return 0;
    *final_gate = next_candidate;
    return 1;
}

static void m36_auth(const uint8_t *unsigned_frame, uint32_t frame_len,
                     uint8_t digest[32])
{
    uint8_t input[sizeof M36_HMAC_DOMAIN - 1u + M36_HEADER_BYTES + M36_MAX_PAYLOAD];
    uint32_t domain_len = (uint32_t)(sizeof M36_HMAC_DOMAIN - 1u);
    for (uint32_t i = 0; i < domain_len; i++) input[i] = M36_HMAC_DOMAIN[i];
    for (uint32_t i = 0; i < frame_len; i++) input[domain_len + i] = unsigned_frame[i];
    hmac_sha256(M36_KEY, sizeof M36_KEY - 1u, input, domain_len + frame_len, digest);
}

static int build_publication(uint64_t value, uint64_t sequence,
                             uint8_t *frame, uint32_t *frame_len)
{
    static const uint64_t descriptor[11] = {2,2,8,2,4,8,9,5,1,1,4};
    noun tail = NOUN_ZERO, publication;
    const uint8_t *payload;
    uint64_t payload_len;
    uint64_t fields[18] = {1,0,M36_UINT_TYPE,M36_UINT_WIDTH,0,M36_UINT_MAX,
                           2,2,8,2,4,8,9,5,1,1,4,0};
    if (!frame || !frame_len || value > M36_UINT_MAX || sequence == 0) return 0;
    fields[1] = 0; /* replaced by the canonical PUBLISH_1 cord below */
    fields[17] = value;
    for (unsigned i = 0; i < 11; i++) fields[6 + i] = descriptor[i];
    for (int i = 17; i >= 0; i--) {
        noun item = i == 1 ? g_publish_tag : direct(fields[i]);
        if (!cons(item, tail, &tail)) return 0;
    }
    if (!cons(g_envelope_tag, tail, &publication)
        || jam_encode_bytes_checked(publication, &payload, &payload_len) != 0
        || payload_len == 0 || payload_len > M36_MAX_PAYLOAD
        || M36_HEADER_BYTES + payload_len > M36_MAX_DATAGRAM) return 0;
    for (uint64_t i = 0; i < payload_len; i++) frame[M36_HEADER_BYTES + i] = payload[i];
    frame[0] = 'A'; frame[1] = 'E'; frame[2] = 'T'; frame[3] = '0';
    frame[4] = M36_WIRE_MAJOR; frame[5] = M36_WIRE_MINOR;
    frame[6] = M36_PROFILE; frame[7] = M36_MESSAGE_KIND_DATA;
    put16(frame + 8, M36_HEADER_BYTES); put16(frame + 10, (uint16_t)payload_len);
    put64(frame + 12, M36_SOURCE_NODE); put64(frame + 20, M36_DESTINATION_NODE);
    for (unsigned i = 0; i < 16; i++) frame[28 + i] = M36_BINDING_11_22[i];
    for (unsigned i = 0; i < 32; i++) frame[44 + i] = M36_SCHEMA[i];
    put32(frame + 76, M36_KEY_ID); put64(frame + 80, M36_EPOCH);
    put64(frame + 88, sequence);
    for (unsigned i = 96; i < M36_HEADER_BYTES; i++) frame[i] = 0;
    uint8_t auth[32];
    m36_auth(frame, M36_HEADER_BYTES + (uint32_t)payload_len, auth);
    for (unsigned i = 0; i < sizeof auth; i++) frame[96 + i] = auth[i];
    *frame_len = M36_HEADER_BYTES + (uint32_t)payload_len;
    return 1;
}

static int parse_frame(const uint8_t *raw, uint32_t len,
                       uint64_t *sequence, uint64_t *value)
{
    static const uint64_t descriptor[11] = {2,2,8,2,4,8,9,5,1,1,4};
    if (!raw || len < M36_HEADER_BYTES || len > M36_MAX_DATAGRAM
        || raw[0] != 'A' || raw[1] != 'E' || raw[2] != 'T' || raw[3] != '0'
        || raw[4] != M36_WIRE_MAJOR || raw[5] != M36_WIRE_MINOR
        || raw[6] != M36_PROFILE || raw[7] != M36_MESSAGE_KIND_DATA
        || get16(raw + 8) != M36_HEADER_BYTES || !get16(raw + 10)
        || get16(raw + 10) > M36_MAX_PAYLOAD
        || len != M36_HEADER_BYTES + get16(raw + 10)
        || get64(raw + 12) != M36_SOURCE_NODE
        || get64(raw + 20) != M36_DESTINATION_NODE
        || !equal_bytes(raw + 28, M36_BINDING_11_22, 16)
        || !equal_bytes(raw + 44, M36_SCHEMA, 32)
        || get32(raw + 76) != M36_KEY_ID || get64(raw + 80) != M36_EPOCH
        || !get64(raw + 88)) return 0;
    uint8_t unsigned_frame[M36_HEADER_BYTES + M36_MAX_PAYLOAD];
    for (uint32_t i = 0; i < len; i++) unsigned_frame[i] = raw[i];
    for (unsigned i = 96; i < M36_HEADER_BYTES; i++) unsigned_frame[i] = 0;
    uint8_t auth[32];
    m36_auth(unsigned_frame, len, auth);
    if (!equal_bytes(auth, raw + 96, 32)) return 0;

    uint16_t payload_len = get16(raw + 10);
    noun publication;
    if (cue_bounded_bytes(raw + M36_HEADER_BYTES, payload_len, &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &publication) != CUE_BOUNDED_OK) return 0;
    noun tag, rest, field;
    int valid = take(publication, &tag, &rest)
        && noun_eq(tag, g_envelope_tag);
    noun fields[18];
    for (unsigned i = 0; valid && i < 18; i++)
        valid = take(rest, &field, &rest) && (fields[i] = field, 1);
    if (valid) valid = direct_is(rest, 0)
        && direct_is(fields[0], 1) && noun_eq(fields[1], g_publish_tag)
        && direct_is(fields[2], M36_UINT_TYPE)
        && direct_is(fields[3], M36_UINT_WIDTH)
        && direct_is(fields[4], 0) && direct_is(fields[5], M36_UINT_MAX);
    for (unsigned i = 0; valid && i < 11; i++)
        valid = direct_is(fields[6 + i], descriptor[i]);
    if (valid) valid = noun_is_direct(fields[17])
        && direct_val(fields[17]) <= M36_UINT_MAX;
    const uint8_t *canonical;
    uint64_t canonical_len;
    if (valid && (jam_encode_bytes_identity(publication, &canonical, &canonical_len) != 0
                  || canonical_len != payload_len
                  || !equal_bytes(canonical, raw + M36_HEADER_BYTES, payload_len)))
        valid = 0;
    if (valid) { *sequence = get64(raw + 88); *value = direct_val(fields[17]); }
    noun_tx_abort();
    return valid;
}

static int resource_id(noun gate, uint64_t *out)
{
    noun battery, sample, zero, state, tag, rest, header, versions, rid;
    return out && take(gate, &battery, &sample) && take(sample, &zero, &state)
        && take(state, &tag, &rest) && take(rest, &header, &rest)
        && take(header, &versions, &rest) && take(rest, &rid, &rest)
        && noun_is_direct(rid) && (*out = direct_val(rid), 1);
}

static void init_tags(void)
{
    g_external_tag = cord_from_bytes("i2-external", 11);
    g_ei_tag = cord_from_bytes("i2-ei", 5);
    g_route_tag = cord_from_bytes("i2-route-ei", 11);
    g_intent_tag = cord_from_bytes("i2-m25-intent-v1", 16);
    g_delivery_tag = cord_from_bytes("i2-m25-delivery-v1", 18);
    g_envelope_tag = cord_from_bytes("m36-t-envelope-v1", 17);
    g_publish_tag = cord_from_bytes("PUBLISH_1", 9);
    g_service_tag = cord_from_bytes("i2-m25-service-v1", 17);
}

static int m36_step(void)
{
    if (!g_active || !g_lifecycle_running) return 0;
    if (g_is_source && g_pending_event != NOUN_ZERO) {
        noun candidate, confirmed, staged;
        uint64_t value;
        uint8_t frame[M36_HEADER_BYTES + M36_MAX_PAYLOAD];
        uint32_t frame_len;
        heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
        if (g_next_sequence == UINT64_MAX
            || !source_graph(g_pending_event, &candidate, &value)) {
            g_last_error = 3; return -1;
        }
        if (!service_candidate(candidate, 8, 3, g_next_sequence, &confirmed)
            || !build_publication(value, g_next_sequence, frame, &frame_len)) {
            g_last_error = 3; return -1;
        }
        uint64_t now = runtime_counter_now();
        uint64_t start = g_rate_window_start;
        uint64_t count = g_rate_successes;
        uint64_t frequency = runtime_counter_freq();
        if (!start || (frequency && now - start >= frequency)) { start = now; count = 0; }
        if (count >= M36_RATE_LIMIT) { g_last_error = 10; return -1; }
        heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
        if (!noun_copy_checked(confirmed, &staged)) {
            heap_persist_abort_tx(); g_last_error = 4; return -1;
        }
        m36_native_status_t sent = m36_native_send(frame, frame_len);
        if (sent != M36_NATIVE_OK) {
            heap_persist_abort_tx(); g_last_error = 5; return -1;
        }
        g_gate = staged; g_pending_event = NOUN_ZERO; g_next_sequence++;
        g_rate_window_start = start; g_rate_successes = count + 1;
        heap_persist_commit_tx(); g_last_error = 0; return 1;
    }
    if (g_fifo_count == 0) return 0;
    uint32_t at = g_fifo_head;
    uint64_t sequence = g_fifo_sequence[at], value = g_fifo_value[at];
    noun next_gate, staged;
    uint64_t output;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (sequence <= g_high_water
        || !destination_graph(value, &next_gate, &output)) {
        g_last_error = 6; return -1;
    }
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(next_gate, &staged)) {
        heap_persist_abort_tx(); g_last_error = 7; return -1;
    }
    g_gate = staged;
    g_fifo_head = (g_fifo_head + 1u) % M36_FIFO_CAPACITY;
    g_fifo_count--; g_high_water = sequence;
    g_last_indication = output; g_indication_valid = 1;
    heap_persist_commit_tx(); g_last_error = 0; return 1;
}

int m36_target_init(void)
{
    noun service_state, staged;
    uint64_t service = g_is_source ? 8u : 9u;
    if (!g_active || g_native_initialized || m36_native_init() != 0) return -1;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!service_candidate(g_gate, service, 1, 0, &service_state)) return -1;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(service_state, &staged)) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = staged; heap_persist_commit_tx();
    g_native_initialized = 1; return 0;
}

int m36_target_restart_source(void)
{
    noun staged;
    if (!g_active || !g_is_source || g_pending_event != NOUN_ZERO
        || g_fifo_count != 0) return -1;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(g_initial_jam, g_initial_jam_len, &cue_i2_limits,
                          HEAP_MODE_PERSIST, &staged) != CUE_BOUNDED_OK) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = staged; noun_tx_commit(); heap_persist_commit_tx();
    return 0;
}

int m36_target_input(uint64_t a, uint64_t b)
{
    noun event;
    if (!g_active || !g_is_source || !g_lifecycle_running
        || g_pending_event != NOUN_ZERO || b != 0 || a > 1) return -1;
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!build_external(a, &event)) return -1;
    g_pending_event = event; return 0;
}

static int m36_poll(void)
{
    m36_native_datagram_t datagram;
    uint64_t sequence, value;
    m36_native_status_t status = m36_native_receive(&datagram);
    if (status == M36_NATIVE_NO_PACKET) return 0;
    if (status != M36_NATIVE_OK
        || !parse_frame(datagram.payload, datagram.payload_len, &sequence, &value)) {
        g_last_error = 1; return -1;
    }
    if (sequence <= g_high_water || g_fifo_count >= M36_FIFO_CAPACITY) {
        g_last_error = 2; return -1;
    }
    uint32_t at = (g_fifo_head + g_fifo_count) % M36_FIFO_CAPACITY;
    g_fifo_value[at] = (uint16_t)value; g_fifo_sequence[at] = sequence;
    g_fifo_count++; g_last_error = 0; return 1;
}

int m36_target_service_tick(void)
{
    if (!g_active || !g_native_initialized || !g_lifecycle_running) return 0;
    if (!g_is_source) {
        int received = m36_poll();
        if (received < 0) return received;
    }
    return m36_step();
}

uint64_t m36_target_queue_len(void) { return g_active ? g_fifo_count : UINT64_MAX; }
uint64_t m36_target_sink_value(void) { return g_indication_valid ? g_last_indication : UINT64_MAX; }
uint64_t m36_target_next_sequence(void) { return g_next_sequence; }
uint64_t m36_target_high_water(void) { return g_high_water; }
uint64_t m36_target_last_error(void) { return g_last_error; }

int m36_target_set_running(int running)
{
    if (!g_active || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || m36_native_tx_pending()) return -1;
    if (running && !g_native_initialized) return -1;
    g_lifecycle_running = running != 0; return 0;
}

int m36_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out)
{
    uint64_t rid;
    if (!out || !identity || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25
        || (M24_NODE_ID != M36_SOURCE_NODE && M24_NODE_ID != M36_DESTINATION_NODE)
        || identity->runtime_abi[0] != 1 || identity->runtime_abi[1] != 9
        || !runtime_identity_validate_gate(gate, identity, 0)
        || !resource_id(gate, &rid)) return -1;
    if ((M24_NODE_ID == M36_SOURCE_NODE && rid != M36_SOURCE_RESOURCE)
        || (M24_NODE_ID == M36_DESTINATION_NODE && rid != M36_DESTINATION_RESOURCE)) return -1;
    *out = gate; return 0;
}

void m36_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile)
{
    const uint8_t *encoded;
    uint64_t encoded_len;
    init_tags();
    g_gate = gate; g_identity = *identity;
    runtime_identity_set(identity);
    runtime_identity_set_capability_profile(capability_profile);
    g_is_source = M24_NODE_ID == M36_SOURCE_NODE;
    g_active = 1; g_native_initialized = 0; g_lifecycle_running = 0;
    g_pending_event = NOUN_ZERO; g_fifo_head = g_fifo_count = 0;
    g_next_sequence = 1; g_high_water = 0; g_last_indication = 0;
    g_last_error = 0; g_indication_valid = 0;
    g_rate_window_start = g_rate_successes = 0;
    g_initial_jam_len = 0;
    if (jam_encode_bytes_checked(gate, &encoded, &encoded_len) == 0
        && encoded_len > 0 && encoded_len <= sizeof g_initial_jam) {
        for (uint64_t i = 0; i < encoded_len; i++) g_initial_jam[i] = encoded[i];
        g_initial_jam_len = encoded_len;
    }
}

int m36_target_identity_matches(const runtime_identity_t *identity)
{
    return identity && runtime_identity_equal(&g_identity, identity);
}

int m36_target_native_ready(void)
{
    return g_active && g_native_initialized;
}

#else

int m36_target_init(void) { return -1; }
int m36_target_restart_source(void) { return -1; }
int m36_target_input(uint64_t a, uint64_t b) { (void)a; (void)b; return -1; }
int m36_target_service_tick(void) { return -1; }
uint64_t m36_target_queue_len(void) { return UINT64_MAX; }
uint64_t m36_target_sink_value(void) { return UINT64_MAX; }
uint64_t m36_target_next_sequence(void) { return 0; }
uint64_t m36_target_high_water(void) { return 0; }
uint64_t m36_target_last_error(void) { return 0; }
int m36_target_set_running(int running) { (void)running; return -1; }
int m36_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out)
{
    (void)gate; (void)identity; (void)capability_profile; (void)out; return -1;
}
void m36_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile)
{
    (void)gate; (void)identity; (void)capability_profile;
}
int m36_target_identity_matches(const runtime_identity_t *identity)
{ (void)identity; return 0; }
int m36_target_native_ready(void) { return 0; }

#endif
