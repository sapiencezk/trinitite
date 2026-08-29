/* The M25 target-side resource/service/provider path.
 *
 * This module has exactly one local admitted resource per image.  A source
 * image accepts one external BOOL event, runs its PILL gate through Nock,
 * classifies the compiler-produced M25 intent, and sends one bounded frame.
 * A target image authenticates the frame, advances its private FIFO/session
 * root, and the device service loop runs the SUBSCRIBE delivery through Nock.
 * It does not call earlier provider controls or interpret application behavior. */
#include <stddef.h>
#include <stdint.h>

#include "m25_target_core.h"

#ifdef M25_TARGET

#include "bounded_cue.h"
#include "jam.h"
#include "m25_aethernet_native.h"
#include "i2_application_surface.h"
#include "m25_plan_record.h"
#include "memory.h"
#include "nock.h"
#include "setjmp.h"
#include "sha256.h"
#ifdef M26_DUPLEX
#include "runtime_stats.h"
#endif

#define M25_FIFO_CAPACITY 16u
#define M25_HEADER_BYTES 128u
#define M25_MAX_PAYLOAD 512u
#define M25_MAX_DATAGRAM 1200u
#ifdef M26_DUPLEX
#define M26_RATE_LIMIT 64u
#endif
#define M25_OPS 2000000ULL
#define M25_CELLS 128000ULL
#define M25_CHECKPOINT_BYTES JAM_MAX_BYTES
#define M25_PROFILE 1u
#define M25_WIRE_MAJOR 0u
#define M25_WIRE_MINOR 1u
#define M25_MESSAGE_KIND_DATA 1u
#define CORD_COMMIT 127996156276579ULL
#define CORD_I2_RX_ORIGIN_V1 0x3178723269ULL
#define CORD_I2_INTERNAL_ORIGIN_V1 0x316e693269ULL

#ifdef M26_DUPLEX
static const uint8_t M25_PSK[] = "m26-development-key-0123456789";
#else
static const uint8_t M25_PSK[] = "m25-development-key-0123456789";
#endif

static noun g_gate;
static runtime_identity_t g_identity;
static noun g_external_tag, g_ei_tag, g_intent_tag, g_delivery_tag, g_service_tag;
static i2_application_service_surface_t g_surface;
static noun g_envelope_tag, g_publish_tag;
static noun g_pending_event;
static uint8_t g_fifo_value[M25_FIFO_CAPACITY];
static uint64_t g_fifo_sequence[M25_FIFO_CAPACITY];
static uint32_t g_fifo_head, g_fifo_count;
static uint64_t g_next_sequence, g_high_water, g_last_indication, g_last_error;
#ifdef M26_DUPLEX
static uint64_t g_rate_window_start, g_rate_successes;
#endif
static int g_indication_valid, g_active, g_is_source, g_native_initialized;
/* M27 owns the lifecycle fence around the unchanged M26 data service.  The
 * historical M25/M26 paths remain running by default; only the M27 build
 * toggles this narrow gate. */
#ifdef M26_DUPLEX
static int g_lifecycle_running;
#endif
static uint8_t g_checkpoint[M25_CHECKPOINT_BYTES];
static uint64_t g_checkpoint_len;
static int g_checkpoint_valid;
static uint8_t g_initial_jam[M25_CHECKPOINT_BYTES];
static uint64_t g_initial_jam_len;
#ifdef M26_DUPLEX
static uint8_t g_candidate_jam[M25_CHECKPOINT_BYTES];
static uint64_t g_candidate_jam_len;
static i2_application_service_surface_t g_candidate_surface;
#endif
static uint64_t g_test_cnf_failure;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head; *tail = c->tail;
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

static uint16_t get16(const volatile uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
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

static int equal_bytes(const volatile uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
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
    return take(result, &tag, &product) && direct_is(tag, CORD_COMMIT)
        && take(product, &effects, &rest) && direct_is(effects, 0)
        && take(rest, candidate, causes);
}

static int slam_gate(noun gate, noun event, int rx_origin,
                     noun *candidate, noun *causes)
{
    noun carrier, subject, result, formula = build_slam();
    if (!noun_is_cell(formula)
        || !cons(rx_origin ? direct(CORD_I2_RX_ORIGIN_V1)
                             : direct(CORD_I2_INTERNAL_ORIGIN_V1), event, &carrier)
        || !cons(gate, carrier, &subject)) return 0;
    int jump = setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(M25_OPS, M25_CELLS);
    result = nock(subject, formula);
    nock_budget_finish();
    return product_parts(result, candidate, causes)
        && runtime_identity_validate_gate(*candidate, &g_identity, 0);
}

static int slam(noun event, noun *candidate, noun *causes)
{
    return slam_gate(g_gate, event, g_is_source, candidate, causes);
}

#define I2_GRAPH_WORKLIST_CAPACITY 3u
#define I2_GRAPH_CAUSE_BUDGET 4u
#define I2_GRAPH_WORK_BUDGET 5u

static int route_fields(noun cause, uint64_t fields[5], noun *samples)
{
    noun tag, body, value;
    if (!cause || !fields || !samples || !take(cause, &tag, &body)
        || !i2_application_surface_tag_matches(tag, "i2-route-ei", 11)) return 0;
    for (unsigned i = 0; i < 5; i++)
        if (!take(body, &value, &body) || !noun_is_direct(value)
            || (fields[i] = direct_val(value)) == 0) return 0;
    *samples = body;
    return 1;
}

static int root_route_at(uint32_t ordinal, const i2_event_edge_t **edge)
{
    uint32_t seen = 0;
    if (!edge) return 0;
    for (uint32_t i = 0; i < g_surface.event_edge_count; i++)
        if (g_surface.event_edges[i].source_instance == g_surface.ingress.instance) {
            if (seen++ == ordinal) { *edge = &g_surface.event_edges[i]; return 1; }
        }
    return 0;
}

static int route_record_matches(const uint64_t fields[5],
                                const i2_event_edge_t *edge)
{
    return fields && edge && fields[0] == edge->ordinal
        && fields[1] == edge->source_instance && fields[2] == edge->source_event
        && fields[3] == edge->target_instance && fields[4] == edge->target_event;
}

static uint32_t outgoing_route_count(uint64_t source_instance, uint64_t source_event)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_surface.event_edge_count; i++)
        if (g_surface.event_edges[i].source_instance == source_instance
            && g_surface.event_edges[i].source_event == source_event) count++;
    return count;
}

static int outgoing_route_at(uint64_t source_instance, uint64_t source_event,
                             uint32_t ordinal,
                             const i2_event_edge_t **edge)
{
    uint32_t seen = 0;
    if (!edge) return 0;
    for (uint32_t i = 0; i < g_surface.event_edge_count; i++)
        if (g_surface.event_edges[i].source_instance == source_instance
            && g_surface.event_edges[i].source_event == source_event) {
            if (seen++ == ordinal) { *edge = &g_surface.event_edges[i]; return 1; }
        }
    return 0;
}

static int preflight_application_worklist(void)
{
    uint32_t root_count = 0;
    uint64_t root_targets[I2_GRAPH_WORKLIST_CAPACITY * 2u];
    for (uint32_t i = 0; i < g_surface.event_edge_count; i++) {
        const i2_event_edge_t *edge = &g_surface.event_edges[i];
        if (edge->source_instance != g_surface.ingress.instance) continue;
        if (root_count >= I2_GRAPH_WORKLIST_CAPACITY) return 0;
        for (uint32_t prior = 0; prior < root_count; prior++)
            if (root_targets[prior] == edge->target_instance
                && root_targets[I2_GRAPH_WORKLIST_CAPACITY + prior] == edge->target_event) return 0;
        root_targets[root_count] = edge->target_instance;
        root_targets[I2_GRAPH_WORKLIST_CAPACITY + root_count] = edge->target_event;
        root_count++;
    }
    return root_count != 0 && root_count <= I2_GRAPH_CAUSE_BUDGET;
}

static int queued_destination(noun cause, uint64_t instance, uint64_t event)
{
    uint64_t fields[5]; noun samples;
    return route_fields(cause, fields, &samples)
        && fields[3] == instance && fields[4] == event;
}

static int drain_application_causes(noun candidate, noun causes,
                                    noun *final_candidate, noun *final_causes)
{
    noun current = candidate, pending = causes, cause, rest, tag;
    noun queue[I2_GRAPH_WORKLIST_CAPACITY];
    uint32_t head = 0, tail = 0, cause_count = 0, work_count = 1;
    uint32_t final_intent_count = 0;
    uint64_t root_instance = g_surface.ingress.instance;
    while (take(pending, &cause, &rest)) {
        uint64_t fields[5]; noun samples;
        const i2_event_edge_t *root_edge;
        if (tail >= I2_GRAPH_WORKLIST_CAPACITY || cause_count >= I2_GRAPH_CAUSE_BUDGET
            || !root_route_at(tail, &root_edge)
            || !route_fields(cause, fields, &samples)
            || !route_record_matches(fields, root_edge)
            || root_edge->source_instance != root_instance) return 0;
        for (uint32_t prior = 0; prior < tail; prior++)
            if (queued_destination(queue[prior], fields[3], fields[4])) return 0;
        queue[tail++] = cause; cause_count++;
        pending = rest;
    }
    if (!direct_is(pending, 0) || tail == 0) return 0;
    while (head < tail) {
        uint64_t fields[5]; noun samples, next_causes = NOUN_ZERO;
        const i2_event_edge_t *expected;
        noun children[I2_GRAPH_WORKLIST_CAPACITY];
        uint32_t outgoing, child_count = 0, intent_count = 0;
        noun next_candidate;
        if (work_count >= I2_GRAPH_WORK_BUDGET
            || !route_fields(queue[head], fields, &samples)) return 0;
        outgoing = outgoing_route_count(fields[3], fields[2]);
        if (tail - head - 1u + outgoing > I2_GRAPH_WORKLIST_CAPACITY
            || cause_count + outgoing > I2_GRAPH_CAUSE_BUDGET) return 0;
        for (uint32_t i = 0; i < outgoing; i++) {
            const i2_event_edge_t *edge;
            if (!outgoing_route_at(fields[3], fields[2], i, &edge)) return 0;
            for (uint32_t j = head + 1u; j < tail; j++) {
                uint64_t queued_fields[5]; noun queued_samples;
                if (!route_fields(queue[j], queued_fields, &queued_samples)) return 0;
                if (queued_fields[3] == edge->target_instance
                    && queued_fields[4] == edge->target_event) return 0;
            }
            for (uint32_t j = 0; j < i; j++) {
                const i2_event_edge_t *old_edge;
                if (!outgoing_route_at(fields[3], fields[2], j, &old_edge)
                    || (old_edge->target_instance == edge->target_instance
                        && old_edge->target_event == edge->target_event)) return 0;
            }
        }
        if (!slam_gate(current, queue[head], 0, &next_candidate, &next_causes)) return 0;
        noun scan = next_causes, scan_tail, cause_body;
        while (take(scan, &cause, &scan_tail)) {
            if (!take(cause, &tag, &cause_body)) return 0;
            if (noun_eq(tag, g_intent_tag)) intent_count++;
            else if (i2_application_surface_tag_matches(tag, "i2-route-ei", 11)) {
                uint64_t child_fields[5]; noun child_samples;
                if (child_count >= outgoing || !route_fields(cause, child_fields, &child_samples)
                    || !outgoing_route_at(fields[3], fields[2], child_count, &expected)
                    || !route_record_matches(child_fields, expected)) return 0;
                children[child_count] = cause; child_count++;
            } else return 0;
            scan = scan_tail;
        }
        if (!direct_is(scan, 0) || child_count != outgoing
            || (outgoing == 0 && intent_count > 1)
            || (outgoing != 0 && intent_count != 0)) return 0;
        if (tail - head - 1u + child_count > I2_GRAPH_WORKLIST_CAPACITY) return 0;
        {
            uint32_t remaining = tail - head - 1u;
            for (uint32_t i = 0; i < remaining; i++) queue[i] = queue[head + 1u + i];
            for (uint32_t i = 0; i < child_count; i++) queue[remaining + i] = children[i];
            head = 0; tail = remaining + child_count;
        }
        cause_count += child_count; work_count++;
        if (intent_count) {
            *final_causes = next_causes;
            final_intent_count = intent_count;
        }
        current = next_candidate;
    }
    *final_candidate = current;
    return final_intent_count == 1 && *final_causes != NOUN_ZERO;
}

static int build_external(uint64_t a, uint64_t b, noun *out)
{
    noun list = NOUN_ZERO, typed, variable, body, target;
    if (!g_surface.ingress.sample_count
        || g_surface.ingress.sample_count > I2_SURFACE_MAX_INGRESS_SAMPLES
        || a > 1 || (g_surface.ingress.sample_count > 1 && b > 1)) return 0;
    for (uint32_t i = g_surface.ingress.sample_count; i > 0; i--) {
        uint64_t value = i == 1 ? a : b;
        if (!cons(direct(g_surface.ingress.sample_type[i - 1]), direct(value), &typed)
            || !cons(direct(g_surface.ingress.sample_id[i - 1]), typed, &variable)
            || !cons(variable, list, &list)) return 0;
    }
    if (!cons(direct(g_surface.ingress.event), list, &body)
        || !cons(direct(g_surface.ingress.instance), body, &target)
        || !cons(g_ei_tag, target, &body) || !cons(g_external_tag, body, out)) return 0;
    return 1;
}

#ifdef M26_DUPLEX
static int surface_remote_target_valid(const i2_application_service_surface_t *surface)
{
    const i2_publication_attachment_t *publication;
    if (!surface || surface->publication_count == 0) return 0;
    publication = &surface->publications[0];
    return publication->target_instance == m25_admitted_plan.target_application_instance
        && publication->target_event == m25_admitted_plan.target_event
        && publication->target_data == m25_admitted_plan.target_data
        && publication->target_type == 1;
}
#endif

static int resource_id(noun gate, uint64_t *out)
{
    noun battery, sample, zero, state, tag, rest, header, dynamic;
    noun versions, rid;
    return take(gate, &battery, &sample) && take(sample, &zero, &state)
        && take(state, &tag, &rest) && take(rest, &header, &dynamic)
        && take(header, &versions, &rest) && take(rest, &rid, &rest)
        && noun_is_direct(rid) && (*out = direct_val(rid), 1);
}

static int parse_intent(noun causes, uint64_t *value)
{
    noun cause, rest, tag, body, fields[11], value_type, value_payload;
    if (!take(causes, &cause, &rest) || !direct_is(rest, 0)
        || !take(cause, &tag, &body) || !noun_eq(tag, g_intent_tag)) return 0;
    for (unsigned i = 0; i < 11; i++)
        if (!take(body, &fields[i], &body)) return 0;
    if (!take(body, &value_type, &value_payload)
        || !direct_is(value_type, 1) || !noun_is_direct(value_payload)
        || direct_val(value_payload) > 1
        || !noun_is_direct(fields[1]) || !noun_is_direct(fields[2])
        || !noun_is_direct(fields[3])
        || !noun_is_direct(fields[4]) || !noun_is_direct(fields[5])
        || !noun_is_direct(fields[6]) || !noun_is_direct(fields[7])
        || !noun_is_direct(fields[8]) || !noun_is_direct(fields[9])
        || !noun_is_direct(fields[10])
        || !i2_application_surface_publication_matches(
            &g_surface, direct_val(fields[0]), direct_val(fields[1]),
            direct_val(fields[2]), direct_val(fields[3]), direct_val(fields[4]),
            direct_val(fields[5]), direct_val(fields[6]), direct_val(fields[7]),
            direct_val(fields[8]), direct_val(fields[9]), direct_val(fields[10]))) return 0;
    *value = direct_val(value_payload);
    return 1;
}

static int build_publication(uint64_t value, uint64_t sequence,
                             uint8_t *frame, uint32_t *frame_len)
{
    noun tail, type, event, version, publication;
    const uint8_t *payload; uint64_t payload_len;
    if (!cons(direct(value), NOUN_ZERO, &tail) || !cons(direct(1), tail, &type)
        || !cons(g_publish_tag, type, &event) || !cons(direct(1), event, &version)
        || !cons(g_envelope_tag, version, &publication)
        || jam_encode_bytes_checked(publication, &payload, &payload_len) != 0
        || payload_len == 0 || payload_len > M25_MAX_PAYLOAD
        || M25_HEADER_BYTES + payload_len > M25_MAX_DATAGRAM) return 0;
    for (uint64_t i = 0; i < payload_len; i++) frame[M25_HEADER_BYTES + i] = payload[i];
    frame[0]='A'; frame[1]='E'; frame[2]='T'; frame[3]='0';
    frame[4]=M25_WIRE_MAJOR; frame[5]=M25_WIRE_MINOR; frame[6]=M25_PROFILE;
    frame[7]=M25_MESSAGE_KIND_DATA; put16(frame + 8, M25_HEADER_BYTES);
    put16(frame + 10, (uint16_t)payload_len);
    put32(frame + 12, 0); put32(frame + 16, m25_admitted_plan.source_device_id);
    put32(frame + 20, 0); put32(frame + 24, m25_admitted_plan.target_device_id);
    for (unsigned i = 0; i < sizeof m25_admitted_plan.binding_id; i++) frame[28+i] = m25_admitted_plan.binding_id[i];
    for (unsigned i = 0; i < sizeof m25_admitted_plan.schema_digest; i++) frame[44+i] = m25_admitted_plan.schema_digest[i];
    put32(frame + 76, m25_admitted_plan.key_id); put64(frame + 80, m25_admitted_plan.epoch);
    put64(frame + 88, sequence);
    for (unsigned i = 96; i < 128; i++) frame[i] = 0;
    uint8_t auth[32]; hmac_sha256(M25_PSK, sizeof M25_PSK - 1u,
                                  frame, M25_HEADER_BYTES + payload_len, auth);
    for (unsigned i = 0; i < sizeof auth; i++) frame[96+i] = auth[i];
    *frame_len = M25_HEADER_BYTES + (uint32_t)payload_len;
    return 1;
}

static int parse_frame(const uint8_t *raw, uint32_t len, uint64_t *sequence,
                       uint64_t *value)
{
    if (!raw || len < M25_HEADER_BYTES || len > M25_MAX_DATAGRAM
        || raw[0]!='A' || raw[1]!='E' || raw[2]!='T' || raw[3]!='0'
        || raw[4] != M25_WIRE_MAJOR || raw[5] != M25_WIRE_MINOR
        || raw[6] != M25_PROFILE || raw[7] != M25_MESSAGE_KIND_DATA
        || get16(raw + 8) != M25_HEADER_BYTES
        || get16(raw + 10) == 0
        || get16(raw + 10) > M25_MAX_PAYLOAD
        || len != M25_HEADER_BYTES + get16(raw + 10)) return 0;
#ifdef M26_DUPLEX
    if (get64(raw + 12) != m25_admitted_plan.target_device_id) return 0;
    if (get64(raw + 20) != m25_admitted_plan.source_device_id) return 0;
    if (!equal_bytes(raw + 28, m25_admitted_plan.reverse_binding_id,
                     sizeof m25_admitted_plan.reverse_binding_id)) return 0;
    if (!equal_bytes(raw + 44, m25_admitted_plan.reverse_schema_digest,
                     sizeof m25_admitted_plan.reverse_schema_digest)) return 0;
#else
    if (get64(raw + 12) != m25_admitted_plan.source_device_id) return 0;
    if (get64(raw + 20) != m25_admitted_plan.target_device_id) return 0;
    if (!equal_bytes(raw + 28, m25_admitted_plan.binding_id, sizeof m25_admitted_plan.binding_id)) return 0;
    if (!equal_bytes(raw + 44, m25_admitted_plan.schema_digest, sizeof m25_admitted_plan.schema_digest)) return 0;
#endif
    if (get32(raw + 76) != m25_admitted_plan.key_id) return 0;
    if (get64(raw + 80) != m25_admitted_plan.epoch) return 0;
    if (get64(raw + 88) == 0) return 0;
    uint8_t input[M25_HEADER_BYTES + M25_MAX_PAYLOAD];
    for (uint32_t i = 0; i < len; i++) input[i] = raw[i];
    for (unsigned i = 96; i < 128; i++) input[i] = 0;
    uint8_t auth[32];
    hmac_sha256(M25_PSK, sizeof M25_PSK - 1u, input, len, auth);
    if (!equal_bytes(auth, raw + 96, sizeof auth)) return 0;
    uint16_t payload_len = get16(raw + 10);
    noun publication;
    if (cue_bounded_bytes(raw + M25_HEADER_BYTES, payload_len, &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &publication) != CUE_BOUNDED_OK) return 0;
    noun tag, rest, version, event, type, tail, sample = NOUN_ZERO;
    int valid = take(publication, &tag, &rest) && noun_eq(tag, g_envelope_tag)
        && take(rest, &version, &rest) && direct_is(version, 1)
        && take(rest, &event, &rest) && noun_eq(event, g_publish_tag)
        && take(rest, &type, &rest) && direct_is(type, 1)
        && take(rest, &sample, &tail) && direct_is(tail, 0)
        && noun_is_direct(sample) && direct_val(sample) <= 1;
    if (valid) { *sequence = get64(raw + 88); *value = direct_val(sample); }
    noun_tx_abort();
    return valid;
}

static int build_delivery(uint64_t value, noun *out)
{
    noun type_value, variable, target_event, target_instance, service;
    const i2_publication_attachment_t *publication = &g_surface.publications[0];
    if (g_surface.publication_count == 0
        || !cons(direct(publication->target_type), direct(value), &type_value)
        || !cons(direct(publication->target_data), type_value, &variable)
        || !cons(direct(publication->target_event), variable, &target_event)
        || !cons(direct(publication->target_instance), target_event, &target_instance)
        || !cons(direct(publication->target_service), target_instance, &service)
        || !cons(g_delivery_tag, service, out)) return 0;
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
    noun event, causes, cause, rest;
    if (!build_service_event(instance, operation, value, &event)
        || !slam_gate(base_gate, event, 0, out, &causes)
        || !take(causes, &cause, &rest)
        || !noun_eq(cause, event) || !direct_is(rest, 0)) return 0;
    return 1;
}

int m25_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile)
{
    uint64_t rid;
    i2_application_service_surface_t surface;
    if (!identity || !m25_plan_record_validate()
        || identity->runtime_abi[0] != 1 || identity->runtime_abi[1] != 9
        || identity->host_abi[0] != 1 || identity->host_abi[1] != 3
        || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25) {
        return -1;
    }
    if (!runtime_identity_validate_gate(gate, identity, 0)) {
        return -1;
    }
    if (!i2_application_surface_from_gate(gate, &surface)
#ifdef M26_DUPLEX
        || !surface_remote_target_valid(&surface)
#endif
    ) return -1;
    if (!resource_id(gate, &rid)
        || (rid != m25_admitted_plan.source_resource_id
            && rid != m25_admitted_plan.target_resource_id)) {
        return -1;
    }
    noun tags[7] = {
        cord_from_bytes("i2-external", 11), cord_from_bytes("i2-ei", 5),
        cord_from_bytes("i2-m25-intent-v1", 16), cord_from_bytes("i2-m25-delivery-v1", 18),
        cord_from_bytes("m25-publication-envelope-v1", 27), cord_from_bytes("M25-PUBLISH-1", 13),
        cord_from_bytes("i2-m25-service-v1", 17),
    };
    g_external_tag=tags[0]; g_ei_tag=tags[1]; g_intent_tag=tags[2];
    g_delivery_tag=tags[3]; g_envelope_tag=tags[4]; g_publish_tag=tags[5];
    g_service_tag=tags[6];
    if (!noun_is_atom(g_intent_tag) || !noun_is_atom(g_delivery_tag)
        || !noun_is_atom(g_envelope_tag) || !noun_is_atom(g_service_tag)) {
        return -1;
    }
    noun copy;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(gate, &copy)) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = copy; g_surface = surface; heap_persist_commit_tx();
    if (noun_tx_active()) noun_tx_commit();
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    const uint8_t *initial_bytes; uint64_t initial_len;
    if (jam_encode_bytes_checked(g_gate, &initial_bytes, &initial_len) != 0
        || initial_len == 0 || initial_len > sizeof g_initial_jam) return -1;
    for (uint64_t i = 0; i < initial_len; i++) g_initial_jam[i] = initial_bytes[i];
    g_initial_jam_len = initial_len;
    g_identity = *identity; runtime_identity_set(identity);
    runtime_identity_set_capability_profile(capability_profile);
    g_pending_event = NOUN_ZERO; g_fifo_head = g_fifo_count = 0;
    g_next_sequence = 1; g_high_water = 0; g_last_indication = 0;
#ifdef M26_DUPLEX
    g_rate_window_start = 0; g_rate_successes = 0;
#endif
    g_last_error = 0; g_indication_valid = 0; g_active = 1;
#ifdef M26_DUPLEX
    g_is_source = 1;
    g_lifecycle_running = 1;
#else
    g_is_source = rid == m25_admitted_plan.source_resource_id;
#endif
    g_native_initialized = 0;
    g_test_cnf_failure = 0;
    g_checkpoint_len = 0; g_checkpoint_valid = 0;
    return 0;
}

int m25_target_active(void) { return g_active; }

int m25_target_init(void)
{
    if (!g_active || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || m25_native_tx_pending()) return -1;
    if (m25_native_init() != 0) return -1;
    noun staged, persisted;
    uint64_t instance = g_is_source ? g_surface.publications[0].source_service
                                    : g_surface.publications[0].target_service;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!service_candidate(g_gate, instance, 1, 0, &staged)) return -1;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(staged, &persisted)) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = persisted; heap_persist_commit_tx();
    g_native_initialized = 1;
#ifdef M26_DUPLEX
    /* Every M26 resource owns both local service instances.  The second INIT
     * is staged from the first committed candidate before native RX/TX is
     * enabled; no provider-side shortcut can initialize the seam. */
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!service_candidate(g_gate, g_surface.publications[0].target_service,
                           1, 0, &staged)) return -1;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(staged, &persisted)) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = persisted; heap_persist_commit_tx();
#endif
    return 0;
}

int m25_target_restart_source(void)
{
    noun staged;
#ifdef M26_DUPLEX
    if (!g_active || g_pending_event != NOUN_ZERO) return -1;
#else
    if (!g_active || !g_is_source || g_pending_event != NOUN_ZERO) return -1;
#endif
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(g_initial_jam, g_initial_jam_len, &cue_i2_limits,
                          HEAP_MODE_PERSIST, &staged) != CUE_BOUNDED_OK) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = staged; noun_tx_commit(); heap_persist_commit_tx();
    return 0;
}

int m25_target_input(uint64_t a, uint64_t b)
{
    noun event;
#ifndef M26_DUPLEX
    if (!g_active || !g_is_source || g_pending_event != NOUN_ZERO) return -1;
#else
    if (!g_active || !g_lifecycle_running || g_pending_event != NOUN_ZERO) return -1;
#endif
    /* The bounded pending event is owned by the current persistent arena.
     * The later authoritative step flips to the other arena for the gate
     * candidate; keeping this event out of that flip preserves retry safety
     * when native TX is pending or fails. */
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!build_external(a, b, &event)) return -1;
    g_pending_event = event;
    return 0;
}

int m25_target_poll(void)
{
    m25_native_datagram_t datagram;
    uint64_t sequence, value;
#ifndef M26_DUPLEX
    if (!g_active || g_is_source) return -1;
#else
    if (!g_active) return -1;
#endif
    m25_native_status_t status = m25_native_receive(&datagram);
    if (status == M25_NATIVE_NO_PACKET) return 0;
    if (status != M25_NATIVE_OK || !parse_frame(datagram.payload, datagram.payload_len,
                                                &sequence, &value)) {
        g_last_error = 1; return -1;
    }
    if (sequence <= g_high_water || g_fifo_count >= M25_FIFO_CAPACITY) {
        g_last_error = 2; return -1;
    }
    uint32_t at = (g_fifo_head + g_fifo_count) % M25_FIFO_CAPACITY;
    g_fifo_value[at] = (uint8_t)value; g_fifo_sequence[at] = sequence;
    g_fifo_count++; g_high_water = sequence; g_last_error = 0;
    return 1;
}

int m25_target_step(void)
{
    if (!g_active) return -1;
    if (g_is_source && g_pending_event != NOUN_ZERO) {
        /* UINT64_MAX is a terminal fence: never serialize a sequence that
         * would wrap to zero after the coherent send commit. */
        if (g_next_sequence == UINT64_MAX) { g_last_error = 8; return -1; }
        heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
        noun candidate, causes, final_causes; uint64_t value;
        uint8_t frame[M25_HEADER_BYTES + M25_MAX_PAYLOAD]; uint32_t frame_len;
        /* Static candidate-derived fan-out reservation is checked before the
         * live root is slammed.  The root, queue, and publication remain
         * untouched on every refusal below. */
        if (!preflight_application_worklist()
            || !slam(g_pending_event, &candidate, &causes)
            || !drain_application_causes(candidate, causes, &candidate, &final_causes)
            || !parse_intent(final_causes, &value)
            || !build_publication(value, g_next_sequence, frame, &frame_len)) {
            g_last_error = 3; return -1;
        }
#ifdef M26_DUPLEX
        /* The native target has one statically admitted outbound direction.
         * Rate accounting is a private candidate: a Nock/product/copy/native
         * failure cannot consume the window or alter checkpoint state. */
        uint64_t rate_now = runtime_counter_now();
        uint64_t rate_start = g_rate_window_start;
        uint64_t rate_count = g_rate_successes;
        uint64_t rate_freq = runtime_counter_freq();
        if (rate_start == 0 || (rate_freq != 0 && rate_now - rate_start >= rate_freq)) {
            rate_start = rate_now; rate_count = 0;
        }
        if (rate_count >= M26_RATE_LIMIT) { g_last_error = 10; return -1; }
#endif
        /* CNF is a second authoritative service transaction.  Build its
         * application/service candidate and reserve the persistent copy
         * before native TX becomes externally visible.  The send-success
         * suffix below is assignment-only: no Nock, copy, or allocation can
         * remain after a frame has been accepted by the native adapter. */
        noun confirmed, staged;
        if (g_test_cnf_failure == 1) { g_last_error = 9; return -1; }
        if (!service_candidate(candidate, g_surface.publications[0].source_service,
                               3, g_next_sequence, &confirmed)) {
            g_last_error = 9; return -1;
        }
        if (g_test_cnf_failure == 2) { g_last_error = 9; return -1; }
        heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
        if (g_test_cnf_failure == 3) {
            heap_persist_abort_tx(); g_last_error = 4; return -1;
        }
        if (!noun_copy_checked(confirmed, &staged)) { heap_persist_abort_tx(); g_last_error = 4; return -1; }
        m25_native_status_t status = m25_native_send(frame, frame_len);
        if (status != M25_NATIVE_OK) { heap_persist_abort_tx(); g_last_error = 5; return -1; }
        /* No fallible work follows native completion. */
        g_gate = staged; g_pending_event = NOUN_ZERO; g_next_sequence++;
#ifdef M26_DUPLEX
        g_rate_window_start = rate_start; g_rate_successes = rate_count + 1;
#endif
        heap_persist_commit_tx(); g_last_error = 0; return 1;
    }
    if (g_fifo_count == 0) return 0;
    uint32_t at = g_fifo_head; uint64_t value = g_fifo_value[at];
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    noun event, candidate, causes, indicated;
#ifdef M26_DUPLEX
    /* The typed SUBSCRIBE IND is the authoritative service transition before
     * the application delivery.  Keep the same order as the host endpoint:
     * both candidates are private until the final persistent copy commits. */
    noun service_state, final_causes;
    uint64_t effect_value;
    if (!service_candidate(g_gate, g_surface.publications[0].target_service,
                           4, value, &service_state)
        || !build_delivery(value, &event)
        || !slam_gate(service_state, event, 0, &candidate, &causes)
        || !drain_application_causes(candidate, causes, &candidate, &final_causes)
        || !parse_intent(final_causes, &effect_value)) {
        g_last_error = 6; return -1;
    }
    (void)effect_value;
#else
    if (!build_delivery(value, &event) || !slam(event, &candidate, &causes)
        || !direct_is(causes, 0)) { g_last_error = 6; return -1; }
#endif
#ifndef M26_DUPLEX
    if (!service_candidate(candidate, m25_admitted_plan.subscribe_instance,
                           4, value, &indicated)) { g_last_error = 6; return -1; }
#else
    indicated = candidate;
#endif
    noun staged;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(indicated, &staged)) { heap_persist_abort_tx(); g_last_error = 7; return -1; }
    g_gate = staged; g_fifo_head = (g_fifo_head + 1u) % M25_FIFO_CAPACITY;
    g_fifo_count--; g_last_indication = value; g_indication_valid = 1;
    heap_persist_commit_tx(); g_last_error = 0; return 1;
}

int m25_target_service_tick(void)
{
    if (!g_active || !g_native_initialized) return 0;
#ifdef M26_DUPLEX
    if (!g_lifecycle_running) return 0;
#endif
#if defined(M26_DUPLEX)
    {
        int received = m25_target_poll();
        if (received < 0 && received != -1) return received;
    }
#else
    if (!g_is_source) {
        int received = m25_target_poll();
        if (received < 0) return received;
    }
#endif
    return m25_target_step();
}

uint64_t m25_target_queue_len(void) { return g_active ? g_fifo_count : UINT64_MAX; }
uint64_t m25_target_sink_value(void) { return g_indication_valid ? g_last_indication : UINT64_MAX; }
uint64_t m25_target_next_sequence(void) { return g_next_sequence; }
uint64_t m25_target_high_water(void) { return g_high_water; }
uint64_t m25_target_last_error(void) { return g_last_error; }

int m25_target_test_cnf_failure(uint64_t kind)
{
    if (!g_active || !g_is_source || kind < 1 || kind > 3) return -1;
    g_test_cnf_failure = kind;
    return 0;
}

int m25_target_test_cnf_release(void)
{
    if (!g_active || !g_is_source) return -1;
    g_test_cnf_failure = 0;
    return 0;
}

static int checkpoint_noun(noun *out)
{
    noun tail = NOUN_ZERO;
#ifdef M26_DUPLEX
    noun values[7];
#else
    noun values[5];
#endif
    values[0] = g_gate; values[1] = direct(g_next_sequence);
    values[2] = direct(g_high_water); values[3] = direct(g_last_indication);
    values[4] = direct(g_indication_valid ? 1 : 0);
#ifdef M26_DUPLEX
    values[5] = direct(g_rate_window_start);
    values[6] = direct(g_rate_successes);
    for (int i = 6; i >= 0; i--) if (!cons(values[i], tail, &tail)) return 0;
#else
    for (int i = 4; i >= 0; i--) if (!cons(values[i], tail, &tail)) return 0;
#endif
#ifdef M26_DUPLEX
    return cons(cord_from_bytes("m26-checkpoint-v1", 17), tail, out);
#else
    return cons(cord_from_bytes("m25-checkpoint-v2", 17), tail, out);
#endif
}

int m25_target_checkpoint_capture(void)
{
    if (!g_active || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || g_next_sequence == UINT64_MAX || m25_native_tx_pending()) return -1;
    noun checkpoint; const uint8_t *bytes; uint64_t length;
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!checkpoint_noun(&checkpoint)
        || jam_encode_bytes_checked(checkpoint, &bytes, &length) != 0
        || length == 0 || length > M25_CHECKPOINT_BYTES) return -1;
    for (uint64_t i = 0; i < length; i++) g_checkpoint[i] = bytes[i];
    g_checkpoint_len = length; g_checkpoint_valid = 1; return 0;
}

int m25_target_checkpoint_restore(void)
{
    if (!g_active || !g_checkpoint_valid || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || m25_native_tx_pending()) return -1;
    noun checkpoint, tag, rest, staged;
#ifdef M26_DUPLEX
    noun values[7];
#else
    noun values[5];
#endif
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(g_checkpoint, g_checkpoint_len, &cue_i2_limits,
                          HEAP_MODE_PERSIST, &checkpoint) != CUE_BOUNDED_OK
        || !take(checkpoint, &tag, &rest)
#ifdef M26_DUPLEX
        || !noun_eq(tag, cord_from_bytes("m26-checkpoint-v1", 17))) goto reject;
#else
        || !noun_eq(tag, cord_from_bytes("m25-checkpoint-v2", 17))) goto reject;
#endif
#ifdef M26_DUPLEX
    for (unsigned i = 0; i < 7; i++) if (!take(rest, &values[i], &rest)) goto reject;
#else
    for (unsigned i = 0; i < 5; i++) if (!take(rest, &values[i], &rest)) goto reject;
#endif
    if (!direct_is(rest, 0) || !noun_is_direct(values[1]) || !noun_is_direct(values[2])
        || !noun_is_direct(values[3]) || !noun_is_direct(values[4])
        || direct_val(values[1]) == 0
        || direct_val(values[1]) == UINT64_MAX
        || direct_val(values[4]) > 1
        || !runtime_identity_validate_gate(values[0], &g_identity, 0)
        || !noun_copy_checked(values[0], &staged)) goto reject;
#ifdef M26_DUPLEX
    if (!noun_is_direct(values[5]) || !noun_is_direct(values[6])
        || direct_val(values[5]) == UINT64_MAX || direct_val(values[6]) > M26_RATE_LIMIT
        || (direct_val(values[5]) == 0 && direct_val(values[6]) != 0)) goto reject;
#endif
    g_gate = staged; g_next_sequence = direct_val(values[1]);
    g_high_water = direct_val(values[2]); g_last_indication = direct_val(values[3]);
    g_indication_valid = direct_val(values[4]) != 0;
#ifdef M26_DUPLEX
    g_rate_window_start = direct_val(values[5]); g_rate_successes = direct_val(values[6]);
#endif
    noun_tx_commit(); heap_persist_commit_tx(); return 0;
reject:
    if (noun_tx_active()) noun_tx_abort();
    heap_persist_abort_tx();
    return -1;
}

#ifdef M26_DUPLEX

int m25_target_set_running(int running)
{
    if (!g_active || (g_pending_event != NOUN_ZERO) || g_fifo_count != 0
        || m25_native_tx_pending()) return -1;
    if (!running) {
        g_lifecycle_running = 0;
        return 0;
    }
    if (!g_native_initialized) return -1;
    g_lifecycle_running = 1;
    return 0;
}

int m25_target_native_ready(void)
{
    return g_active && g_native_initialized;
}

int m25_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out)
{
    if (!out || !g_active || g_lifecycle_running
        || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || m25_native_tx_pending() || !identity
        || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25
        || identity->runtime_abi[0] != 1 || identity->runtime_abi[1] != 9
        || !runtime_identity_validate_gate(gate, identity, 0)) return -1;
    if (!i2_application_surface_from_gate(gate, &g_candidate_surface)
        || !surface_remote_target_valid(&g_candidate_surface)) return -1;
    const uint8_t *encoded;
    uint64_t encoded_len;
    if (jam_encode_bytes_checked(gate, &encoded, &encoded_len) != 0
        || encoded_len == 0 || encoded_len > sizeof g_initial_jam) return -1;
    /* The gate itself was cued in the caller's persistent transaction.  The
     * byte-for-byte jam copy is prepared before the transaction can publish,
     * so START can rebuild the service root without a fallible post-commit
     * operation. */
    for (uint64_t i = 0; i < encoded_len; i++) g_candidate_jam[i] = encoded[i];
    g_candidate_jam_len = encoded_len;
    *out = gate;
    return 0;
}

void m25_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile)
{
    g_gate = gate;
    g_surface = g_candidate_surface;
    for (uint64_t i = 0; i < g_candidate_jam_len; i++)
        g_initial_jam[i] = g_candidate_jam[i];
    g_initial_jam_len = g_candidate_jam_len;
    g_identity = *identity;
    runtime_identity_set(identity);
    runtime_identity_set_capability_profile(capability_profile);
    g_native_initialized = 0;
    g_lifecycle_running = 0;
}

int m25_target_identity_matches(const runtime_identity_t *identity)
{
    return identity && runtime_identity_equal(&g_identity, identity);
}

#endif

#else

int m25_target_boot(noun gate, const runtime_identity_t *identity, uint8_t capability_profile)
{ (void)gate; (void)identity; (void)capability_profile; return -1; }
int m25_target_active(void) { return 0; }
int m25_target_init(void) { return -1; }
int m25_target_restart_source(void) { return -1; }
int m25_target_input(uint64_t a, uint64_t b) { (void)a; (void)b; return -1; }
int m25_target_poll(void) { return -1; }
int m25_target_step(void) { return -1; }
int m25_target_service_tick(void) { return -1; }
uint64_t m25_target_queue_len(void) { return UINT64_MAX; }
uint64_t m25_target_sink_value(void) { return UINT64_MAX; }
uint64_t m25_target_next_sequence(void) { return 0; }
uint64_t m25_target_high_water(void) { return 0; }
uint64_t m25_target_last_error(void) { return 0; }
int m25_target_test_cnf_failure(uint64_t kind) { (void)kind; return -1; }
int m25_target_test_cnf_release(void) { return -1; }
int m25_target_checkpoint_capture(void) { return -1; }
int m25_target_checkpoint_restore(void) { return -1; }

#endif
