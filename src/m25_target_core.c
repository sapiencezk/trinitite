/* The M25 target-side resource/service/provider path.
 *
 * This module has exactly one local admitted resource per image.  A source
 * image accepts one external BOOL event, runs its PILL gate through Nock,
 * classifies the compiler-produced M25 intent, and sends one bounded frame.
 * A target image authenticates the frame, advances its private FIFO/session
 * root, and on the later M25STEP runs the SUBSCRIBE delivery through Nock.
 * It does not call M21/M23/M24 provider controls or interpret M16 behavior. */
#include <stddef.h>
#include <stdint.h>

#include "m25_target_core.h"

#ifdef M25_TARGET

#include "bounded_cue.h"
#include "jam.h"
#include "m25_aethernet_native.h"
#include "memory.h"
#include "nock.h"
#include "setjmp.h"
#include "sha256.h"

#define M25_SOURCE_DEVICE 11u
#define M25_TARGET_DEVICE 22u
#define M25_SOURCE_RESOURCE 1u
#define M25_TARGET_RESOURCE 2u
#define M25_SERVICE_PUBLISH 8u
#define M25_SERVICE_SUBSCRIBE 9u
#define M25_SOURCE_INSTANCE 5u
#define M25_TARGET_INSTANCE 6u
#define M25_FIFO_CAPACITY 16u
#define M25_HEADER_BYTES 128u
#define M25_MAX_PAYLOAD 512u
#define M25_MAX_DATAGRAM 1200u
#define M25_OPS 2000000ULL
#define M25_CELLS 128000ULL
#define M25_CHECKPOINT_BYTES JAM_MAX_BYTES
#define M25_PLAN_EPOCH 1u
#define M25_KEY_ID 1u
#define M25_PROFILE 1u
#define M25_WIRE_MAJOR 0u
#define M25_WIRE_MINOR 1u
#define M25_MESSAGE_KIND_DATA 1u
#define CORD_COMMIT 127996156276579ULL
#define CORD_I2_RX_ORIGIN_V1 0x3178723269ULL
#define CORD_I2_INTERNAL_ORIGIN_V1 0x316e693269ULL

static const uint8_t M25_PSK[] = "m25-development-key-0123456789";
static const uint8_t M25_BINDING[16] = {
    0xba,0x59,0xa8,0x09,0x5c,0x82,0x51,0x8f,0x5b,0x67,0xdf,0x9d,0x2d,0x1f,0xcc,0x06
};
static const uint8_t M25_SCHEMA[32] = {
    0x73,0x2d,0x9c,0xb1,0x71,0x79,0x81,0x30,0xe8,0x32,0xdb,0x68,0x2a,0x4a,0x2c,0xc4,
    0x5c,0x44,0x1c,0x5f,0xf9,0xfe,0xaf,0x69,0x5f,0xa9,0x5d,0x96,0x7d,0x60,0x85,0x55
};

static noun g_gate;
static runtime_identity_t g_identity;
static noun g_external_tag, g_ei_tag, g_intent_tag, g_delivery_tag;
static noun g_envelope_tag, g_publish_tag;
static noun g_pending_event;
static uint8_t g_fifo_value[M25_FIFO_CAPACITY];
static uint64_t g_fifo_sequence[M25_FIFO_CAPACITY];
static uint32_t g_fifo_head, g_fifo_count;
static uint64_t g_next_sequence, g_high_water, g_last_indication, g_last_error;
static int g_indication_valid, g_active, g_is_source;
static uint8_t g_checkpoint[M25_CHECKPOINT_BYTES];
static uint64_t g_checkpoint_len;
static int g_checkpoint_valid;
static uint8_t g_initial_jam[M25_CHECKPOINT_BYTES];
static uint64_t g_initial_jam_len;

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

static int slam(noun event, noun *candidate, noun *causes)
{
    noun carrier, subject, result, formula = build_slam();
    if (!noun_is_cell(formula)
        || !cons(g_is_source ? direct(CORD_I2_RX_ORIGIN_V1)
                             : direct(CORD_I2_INTERNAL_ORIGIN_V1), event, &carrier)
        || !cons(g_gate, carrier, &subject)) return 0;
    int jump = setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(M25_OPS, M25_CELLS);
    result = nock(subject, formula);
    nock_budget_finish();
    return product_parts(result, candidate, causes)
        && runtime_identity_validate_gate(*candidate, &g_identity, 0);
}

static int build_external(uint64_t a, uint64_t b, noun *out)
{
    noun va, vb, sa, sb, list, ei, body;
    if (a > 1 || b > 1 || !cons(direct(1), direct(a), &va)
        || !cons(direct(1), direct(b), &vb) || !cons(direct(1), va, &sa)
        || !cons(direct(2), vb, &sb) || !cons(sb, NOUN_ZERO, &list)
        || !cons(sa, list, &ei) || !cons(direct(1), ei, &body)
        || !cons(direct(M25_SOURCE_INSTANCE), body, &ei)
        || !cons(g_ei_tag, ei, &body) || !cons(g_external_tag, body, out)) return 0;
    return 1;
}

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
    noun cause, rest, tag, body, fields[10], value_type, value_payload;
    if (!take(causes, &cause, &rest) || !direct_is(rest, 0)
        || !take(cause, &tag, &body) || !noun_eq(tag, g_intent_tag)) return 0;
    for (unsigned i = 0; i < 10; i++)
        if (!take(body, &fields[i], &body)) return 0;
    if (!take(body, &value_type, &value_payload)
        || !direct_is(value_type, 1) || !noun_is_direct(value_payload)
        || direct_val(value_payload) > 1
        || !direct_is(fields[0], M25_SOURCE_INSTANCE)
        || !(direct_is(fields[1], 2) || direct_is(fields[1], 3))
        || !(direct_is(fields[2], 8) || direct_is(fields[2], 9))
        || !direct_is(fields[3], direct_val(fields[1]) == 2 ? 3 : 4)
        || !direct_is(fields[4], 1) || !direct_is(fields[5], M25_SERVICE_SUBSCRIBE)
        || !direct_is(fields[6], M25_TARGET_INSTANCE) || !direct_is(fields[7], 1)
        || !direct_is(fields[8], 1) || !direct_is(fields[9], 1)) return 0;
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
    put32(frame + 12, 0); put32(frame + 16, M25_SOURCE_DEVICE);
    put32(frame + 20, 0); put32(frame + 24, M25_TARGET_DEVICE);
    for (unsigned i = 0; i < sizeof M25_BINDING; i++) frame[28+i] = M25_BINDING[i];
    for (unsigned i = 0; i < sizeof M25_SCHEMA; i++) frame[44+i] = M25_SCHEMA[i];
    put32(frame + 76, M25_KEY_ID); put64(frame + 80, M25_PLAN_EPOCH);
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
    if (get64(raw + 12) != M25_SOURCE_DEVICE) return 0;
    if (get64(raw + 20) != M25_TARGET_DEVICE) return 0;
    if (!equal_bytes(raw + 28, M25_BINDING, sizeof M25_BINDING)) return 0;
    if (!equal_bytes(raw + 44, M25_SCHEMA, sizeof M25_SCHEMA)) return 0;
    if (get32(raw + 76) != M25_KEY_ID) return 0;
    if (get64(raw + 80) != M25_PLAN_EPOCH) return 0;
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
    if (!cons(direct(1), direct(value), &type_value)
        || !cons(direct(1), type_value, &variable)
        || !cons(direct(1), variable, &target_event)
        || !cons(direct(M25_TARGET_INSTANCE), target_event, &target_instance)
        || !cons(direct(M25_SERVICE_SUBSCRIBE), target_instance, &service)
        || !cons(g_delivery_tag, service, out)) return 0;
    return 1;
}

int m25_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile)
{
    uint64_t rid;
    if (!identity || identity->runtime_abi[0] != 1 || identity->runtime_abi[1] != 9
        || identity->host_abi[0] != 1 || identity->host_abi[1] != 3
        || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25) {
        return -1;
    }
    if (!runtime_identity_validate_gate(gate, identity, 0)) {
        return -1;
    }
    if (!resource_id(gate, &rid)
        || (rid != M25_SOURCE_RESOURCE && rid != M25_TARGET_RESOURCE)) {
        return -1;
    }
    noun tags[6] = {
        cord_from_bytes("i2-external", 11), cord_from_bytes("i2-ei", 5),
        cord_from_bytes("i2-m25-intent-v1", 16), cord_from_bytes("i2-m25-delivery-v1", 18),
        cord_from_bytes("m25-publication-envelope-v1", 27), cord_from_bytes("M25-PUBLISH-1", 13),
    };
    g_external_tag=tags[0]; g_ei_tag=tags[1]; g_intent_tag=tags[2];
    g_delivery_tag=tags[3]; g_envelope_tag=tags[4]; g_publish_tag=tags[5];
    if (!noun_is_atom(g_intent_tag) || !noun_is_atom(g_delivery_tag)
        || !noun_is_atom(g_envelope_tag)) return -1;
    noun copy;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(gate, &copy)) {
        heap_persist_abort_tx(); return -1;
    }
    g_gate = copy; heap_persist_commit_tx();
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
    g_last_error = 0; g_indication_valid = 0; g_active = 1;
    g_is_source = rid == M25_SOURCE_RESOURCE;
    g_checkpoint_len = 0; g_checkpoint_valid = 0;
    return 0;
}

int m25_target_active(void) { return g_active; }

int m25_target_init(void)
{
    if (!g_active || g_pending_event != NOUN_ZERO || g_fifo_count != 0
        || m25_native_tx_pending()) return -1;
    if (m25_native_init() != 0) return -1;
    return 0;
}

int m25_target_restart_source(void)
{
    noun staged;
    if (!g_active || !g_is_source || g_pending_event != NOUN_ZERO) return -1;
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
    if (!g_active || !g_is_source || g_pending_event != NOUN_ZERO) return -1;
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
    if (!g_active || g_is_source) return -1;
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
    if (g_is_source) {
        if (g_pending_event == NOUN_ZERO) return 0;
        /* UINT64_MAX is a terminal fence: never serialize a sequence that
         * would wrap to zero after the coherent send commit. */
        if (g_next_sequence == UINT64_MAX) { g_last_error = 8; return -1; }
        heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
        noun candidate, causes; uint64_t value;
        uint8_t frame[M25_HEADER_BYTES + M25_MAX_PAYLOAD]; uint32_t frame_len;
        if (!slam(g_pending_event, &candidate, &causes)
            || !parse_intent(causes, &value)
            || !build_publication(value, g_next_sequence, frame, &frame_len)) {
            g_last_error = 3; return -1;
        }
        noun staged;
        heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
        if (!noun_copy_checked(candidate, &staged)) { heap_persist_abort_tx(); g_last_error = 4; return -1; }
        m25_native_status_t status = m25_native_send(frame, frame_len);
        if (status != M25_NATIVE_OK) { heap_persist_abort_tx(); g_last_error = 5; return -1; }
        g_gate = staged; g_pending_event = NOUN_ZERO; g_next_sequence++;
        heap_persist_commit_tx(); g_last_error = 0; return 1;
    }
    if (g_fifo_count == 0) return 0;
    uint32_t at = g_fifo_head; uint64_t value = g_fifo_value[at];
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    noun event, candidate, causes;
    if (!build_delivery(value, &event) || !slam(event, &candidate, &causes)
        || !direct_is(causes, 0)) { g_last_error = 6; return -1; }
    noun staged;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(candidate, &staged)) { heap_persist_abort_tx(); g_last_error = 7; return -1; }
    g_gate = staged; g_fifo_head = (g_fifo_head + 1u) % M25_FIFO_CAPACITY;
    g_fifo_count--; g_last_indication = value; g_indication_valid = 1;
    heap_persist_commit_tx(); g_last_error = 0; return 1;
}

uint64_t m25_target_queue_len(void) { return g_active ? g_fifo_count : UINT64_MAX; }
uint64_t m25_target_sink_value(void) { return g_indication_valid ? g_last_indication : UINT64_MAX; }
uint64_t m25_target_next_sequence(void) { return g_next_sequence; }
uint64_t m25_target_high_water(void) { return g_high_water; }
uint64_t m25_target_last_error(void) { return g_last_error; }

static int checkpoint_noun(noun *out)
{
    noun tail = NOUN_ZERO, values[5];
    values[0] = g_gate; values[1] = direct(g_next_sequence);
    values[2] = direct(g_high_water); values[3] = direct(g_last_indication);
    values[4] = direct(g_indication_valid ? 1 : 0);
    for (int i = 4; i >= 0; i--) if (!cons(values[i], tail, &tail)) return 0;
    return cons(cord_from_bytes("m25-checkpoint-v2", 17), tail, out);
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
    noun checkpoint, tag, rest, values[5], staged;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(g_checkpoint, g_checkpoint_len, &cue_i2_limits,
                          HEAP_MODE_PERSIST, &checkpoint) != CUE_BOUNDED_OK
        || !take(checkpoint, &tag, &rest)
        || !noun_eq(tag, cord_from_bytes("m25-checkpoint-v2", 17))) goto reject;
    for (unsigned i = 0; i < 5; i++) if (!take(rest, &values[i], &rest)) goto reject;
    if (!direct_is(rest, 0) || !noun_is_direct(values[1]) || !noun_is_direct(values[2])
        || !noun_is_direct(values[3]) || !noun_is_direct(values[4])
        || direct_val(values[1]) == 0
        || direct_val(values[1]) == UINT64_MAX
        || direct_val(values[4]) > 1
        || !runtime_identity_validate_gate(values[0], &g_identity, 0)
        || !noun_copy_checked(values[0], &staged)) goto reject;
    g_gate = staged; g_next_sequence = direct_val(values[1]);
    g_high_water = direct_val(values[2]); g_last_indication = direct_val(values[3]);
    g_indication_valid = direct_val(values[4]) != 0;
    noun_tx_commit(); heap_persist_commit_tx(); return 0;
reject:
    if (noun_tx_active()) noun_tx_abort();
    heap_persist_abort_tx();
    return -1;
}

#else

int m25_target_boot(noun gate, const runtime_identity_t *identity, uint8_t capability_profile)
{ (void)gate; (void)identity; (void)capability_profile; return -1; }
int m25_target_active(void) { return 0; }
int m25_target_init(void) { return -1; }
int m25_target_restart_source(void) { return -1; }
int m25_target_input(uint64_t a, uint64_t b) { (void)a; (void)b; return -1; }
int m25_target_poll(void) { return -1; }
int m25_target_step(void) { return -1; }
uint64_t m25_target_queue_len(void) { return UINT64_MAX; }
uint64_t m25_target_sink_value(void) { return UINT64_MAX; }
uint64_t m25_target_next_sequence(void) { return 0; }
uint64_t m25_target_high_water(void) { return 0; }
uint64_t m25_target_last_error(void) { return 0; }
int m25_target_checkpoint_capture(void) { return -1; }
int m25_target_checkpoint_restore(void) { return -1; }

#endif
