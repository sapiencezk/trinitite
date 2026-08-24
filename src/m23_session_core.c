#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_ingress.h"
#include "jam.h"
#include "m23_session_core.h"
#include "memory.h"
#include "uart.h"
#ifdef M24_NATIVE
#include "aethernet_native.h"
#include "sha256.h"
#endif

#define M23_FIFO_CAP 16u
#define M23_RATE_CAP 64u
#define M23_VERSION 1u
#define M23_WIRE_MAJOR 0u
#define M23_WIRE_MINOR 1u
#define M23_PROFILE 0u
#define M23_MESSAGE_KIND 1u
#define M23_SENDER_DEVICE 11u
#define M23_RECEIVER_DEVICE 22u
#define M23_KEY_ID 7u
/* These fixed values are image/deployment authority for the one proof
 * session.  No framed noun supplies an epoch, floor, or policy. */
#define M23_INITIAL_FLOOR 2u
#define M23_INITIAL_EPOCH 3u
#define M23_U64_MAX UINT64_MAX
#define M23_CHECKPOINT_MAGIC 0x4d323353ULL

#ifdef M24_NATIVE
#define M24_WIRE_HEADER_LEN 128u
#define M24_WIRE_MAX_DATAGRAM 1200u
#define M24_WIRE_MAX_PAYLOAD 512u
#define M24_AUTH_TAG_LEN 32u
static const uint8_t M24_PSK[] = "m22-test-psk-0123456789abcdef";
static const uint8_t M24_TRUE_PAYLOAD[39] = {
    0x01,0x68,0x83,0xab,0x13,0x63,0x4b,0x1b,0x0b,0xa3,0x4b,0x7b,0x73,
    0x6b,0x29,0x73,0xb3,0x2b,0x63,0x7b,0x83,0x2b,0x6b,0xb1,0x8b,0xe3,
    0x00,0x1a,0x50,0x55,0x42,0x4c,0x49,0x53,0x48,0x5f,0x71,0x1c,0x0b
};
static const uint8_t M24_FALSE_PAYLOAD[39] = {
    0x01,0x68,0x83,0xab,0x13,0x63,0x4b,0x1b,0x0b,0xa3,0x4b,0x7b,0x73,
    0x6b,0x29,0x73,0xb3,0x2b,0x63,0x7b,0x83,0x2b,0x6b,0xb1,0x8b,0xe3,
    0x00,0x1a,0x50,0x55,0x42,0x4c,0x49,0x53,0x48,0x5f,0x71,0x9c,0x02
};
#endif

static const uint8_t M23_BINDING[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t M23_SCHEMA[32] = {
    0x0f, 0xc5, 0x52, 0x05, 0x48, 0x83, 0x82, 0x8d,
    0x4e, 0x52, 0xeb, 0x5b, 0x86, 0x48, 0xc2, 0x3e,
    0xad, 0xda, 0xb8, 0x60, 0x54, 0xd4, 0x19, 0xdb,
    0x2a, 0x25, 0x55, 0x2f, 0x29, 0xa6, 0x93, 0xf9
};

static const uint64_t g_adapter_issuer = 0x4d32334154544553ULL;
static const m23_adapter_attestation_t g_attestation = {
    .magic = 0x4d32334155544831ULL,
    .issuer = &g_adapter_issuer,
    .profile = 0x4d3233u,
    .authenticated = 1u
};

static noun g_product_tag;
static noun g_publication_tag;
static noun g_publish_event_tag;
static noun g_raw_carrier_tag;
static noun g_bare_ei_tag;
/* One bounded target session root.  Candidate copies are published only
 * after admission has completed; diagnostics remain outside this root. */
typedef struct {
    noun queue_value[M23_FIFO_CAP];
    uint64_t queue_sequence[M23_FIFO_CAP];
    uint32_t queue_head;
    uint32_t queue_count;
    uint64_t high_water;
    int high_water_valid;
    uint64_t epoch;
    uint64_t next_sequence;
    uint64_t authority_floor;
    uint64_t outbound_rate_count;
    uint64_t outbound_rate_deadline;
    uint64_t state;
} m23_session_root_t;

static m23_session_root_t g_root;
#define g_queue_value (g_root.queue_value)
#define g_queue_sequence (g_root.queue_sequence)
#define g_queue_head (g_root.queue_head)
#define g_queue_count (g_root.queue_count)
#define g_high_water (g_root.high_water)
#define g_high_water_valid (g_root.high_water_valid)
#define g_epoch (g_root.epoch)
#define g_next_sequence (g_root.next_sequence)
#define g_authority_floor (g_root.authority_floor)
#define g_outbound_rate_count (g_root.outbound_rate_count)
#define g_outbound_rate_deadline (g_root.outbound_rate_deadline)
#define g_state (g_root.state)
static uint64_t g_last_indication;
static uint64_t g_last_indication_sequence;
/* Bounded codec/work accounting is not session state and never participates
 * in a candidate root publication.  In particular, a replay or malformed
 * frame cannot mutate the durable session root merely by being inspected. */
static uint64_t g_ingress_work_count;
static uint64_t g_last_error;
static int g_indication_valid;
static int g_active;
static int g_checkpoint_valid;
static uint64_t g_checkpoint_magic;
static uint64_t g_checkpoint_version;
static uint64_t g_checkpoint_profile;
static uint64_t g_checkpoint_local_device;
static uint64_t g_checkpoint_peer_device;
static uint64_t g_checkpoint_key_id;
static uint8_t g_checkpoint_binding[16];
static uint8_t g_checkpoint_schema[32];
static uint64_t g_checkpoint_epoch;
static uint64_t g_checkpoint_high_water;
static uint64_t g_checkpoint_next_sequence;
static uint64_t g_checkpoint_rate_count;
static uint64_t g_checkpoint_rate_remaining;
static uint64_t g_checkpoint_state;
static uint64_t g_checkpoint_wire_major;
static uint64_t g_checkpoint_wire_minor;
static uint64_t g_checkpoint_message_kind;

static const cue_bounded_limits_t M23_CUE_LIMITS = {
    .max_input_bytes = 512,
    .max_depth = 64,
    .max_nodes = 128,
    .max_cells = 64,
    .max_backrefs = 64,
    .max_cache_entries = 64,
    .max_atom_bytes = 64,
    .max_total_atom_bytes = 512,
    .max_work = 4096
};

static void reject(uint64_t error);

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail)
        return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head;
    *tail = cell->tail;
    return 1;
}

static int direct_is(noun n, uint64_t value)
{
    return noun_is_direct(n) && direct_val(n) == value;
}

static int atom_is_bytes(noun n, const uint8_t *expected, size_t len)
{
    uint8_t actual[32];
    if (len > sizeof actual || !noun_atom_read_fixed(n, actual, len))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (actual[i] != expected[i])
            return 0;
    return 1;
}

static int admit_sequence_value(uint64_t sequence, uint64_t epoch, uint64_t value)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_UNARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    if (g_state == M23_STATE_EXHAUSTED || g_state == M23_STATE_CLOSED) {
        reject(g_state == M23_STATE_EXHAUSTED ? M23_ERR_SEQUENCE_EXHAUSTED : M23_ERR_CLOSED);
        return -1;
    }
    if (epoch != g_epoch) { reject(M23_ERR_STALE_EPOCH); return -1; }
    if (g_high_water_valid && sequence <= g_high_water) { reject(M23_ERR_REPLAY); return -1; }
    if (g_queue_count >= M23_FIFO_CAP) { reject(M23_ERR_FIFO_FULL); return -1; }
    m23_session_root_t candidate = g_root;
    uint32_t slot = (candidate.queue_head + candidate.queue_count) % M23_FIFO_CAP;
    candidate.queue_value[slot] = value;
    candidate.queue_sequence[slot] = sequence;
    candidate.queue_count++;
    candidate.high_water = sequence;
    candidate.high_water_valid = 1;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

static int noun_u64(noun n, uint64_t *out)
{
    uint8_t bytes[sizeof(uint64_t)];
    uint64_t value = 0;
    if (!out || !noun_atom_read_fixed(n, bytes, sizeof bytes))
        return 0;
    for (size_t i = 0; i < sizeof bytes; i++)
        value |= ((uint64_t)bytes[i]) << (8u * i);
    *out = value;
    return 1;
}

static int attestation_valid(const m23_adapter_attestation_t *attestation)
{
    return attestation == &g_attestation
        && attestation->magic == g_attestation.magic
        && attestation->issuer == &g_adapter_issuer
        && attestation->profile == g_attestation.profile
        && attestation->authenticated == 1u;
}

static void reject(uint64_t error) { g_last_error = error; }

static uint64_t target_counter_now(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static uint64_t target_counter_freq(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value ? value : 54000000ULL;
}

static int parse_publication(noun publication, uint64_t *value)
{
    noun tag, rest, version, event, type, sample, tail;
    if (!take(publication, &tag, &rest)) {
        reject(M23_ERR_PUBLICATION_SHAPE); return 0;
    }
    if (!noun_eq(tag, g_publication_tag)) {
        reject(M23_ERR_PUBLICATION_TAG); return 0;
    }
    if (!take(rest, &version, &rest) || !direct_is(version, M23_VERSION)) {
        reject(M23_ERR_PUBLICATION_VERSION); return 0;
    }
    if (!take(rest, &event, &rest) || !noun_eq(event, g_publish_event_tag)) {
        reject(M23_ERR_PUBLICATION_EVENT); return 0;
    }
    if (!take(rest, &type, &rest) || !direct_is(type, 1u)) {
        reject(M23_ERR_PUBLICATION_TYPE); return 0;
    }
    if (!take(rest, &sample, &tail) || !direct_is(tail, 0)
        || !noun_is_direct(sample) || direct_val(sample) > 1u) {
        reject(M23_ERR_PUBLICATION_VALUE); return 0;
    }
    *value = direct_val(sample);
    return 1;
}

static int parse_product(noun product, uint64_t *sequence, uint64_t *epoch,
                         uint64_t *value)
{
    noun tag, rest, field, publication;
    if (noun_is_cell(product) && take(product, &tag, &field)) {
        if (noun_eq(tag, g_raw_carrier_tag)) {
            reject(M23_ERR_RAW_M21_CARRIER); return 0;
        }
        if (noun_eq(tag, g_bare_ei_tag)) {
            reject(M23_ERR_BARE_INTERNAL_EI); return 0;
        }
    }
    if (!take(product, &tag, &rest) || !noun_eq(tag, g_product_tag)) {
        reject(M23_ERR_PRODUCT_TAG); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_VERSION)) {
        reject(M23_ERR_VERSION); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_PROFILE)) {
        reject(M23_ERR_PROFILE); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_MESSAGE_KIND)) {
        reject(M23_ERR_MESSAGE_KIND); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_SENDER_DEVICE)) {
        reject(M23_ERR_SENDER); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_RECEIVER_DEVICE)) {
        reject(M23_ERR_RECEIVER); return 0;
    }
    if (!take(rest, &field, &rest) || !atom_is_bytes(field, M23_BINDING, sizeof M23_BINDING)) {
        reject(M23_ERR_BINDING); return 0;
    }
    if (!take(rest, &field, &rest) || !atom_is_bytes(field, M23_SCHEMA, sizeof M23_SCHEMA)) {
        reject(M23_ERR_SCHEMA); return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M23_KEY_ID)) {
        reject(M23_ERR_KEY_ID); return 0;
    }
    if (!take(rest, epoch, &rest) || !noun_u64(*epoch, epoch)
        || *epoch == 0) {
        reject(M23_ERR_EPOCH); return 0;
    }
    if (!take(rest, sequence, &publication) || !noun_u64(*sequence, sequence)
        || *sequence == 0) {
        reject(M23_ERR_SEQUENCE_ZERO); return 0;
    }
    return parse_publication(publication, value);
}

int m23_provider_core_init(void)
{
#ifdef M24_NATIVE
    /* A native descriptor may already be visible to the device.  Resetting
     * the session here would discard its identity and let a late completion
     * commit against a different root. */
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    m23_session_root_t initial = {0};
    g_product_tag = cord_from_bytes("aethernet-0-adapter-product-v1", 30);
    g_publication_tag = cord_from_bytes("publication-envelope-v1", 23);
    g_publish_event_tag = cord_from_bytes("PUBLISH_1", 9);
    g_raw_carrier_tag = cord_from_bytes("i2-inter-resource-v1", 20);
    g_bare_ei_tag = cord_from_bytes("i2-ei", 5);
    initial.authority_floor = M23_INITIAL_FLOOR;
    initial.state = M23_STATE_UNARMED;
    g_root = initial;
    g_ingress_work_count = 0;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    g_last_indication = 0;
    g_last_indication_sequence = 0;
    g_last_error = M23_ERR_NONE;
    g_indication_valid = 0;
    g_checkpoint_valid = 0;
    g_active = noun_is_atom(g_product_tag) && noun_is_atom(g_publication_tag)
        && noun_is_atom(g_publish_event_tag) && noun_is_atom(g_raw_carrier_tag)
        && noun_is_atom(g_bare_ei_tag);
    i2_rx_init();
    return g_active ? 0 : -1;
}

int m23_provider_core_arm(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state != M23_STATE_UNARMED) { reject(M23_ERR_EPOCH_NOT_NEWER); return -1; }
    uint64_t epoch = g_authority_floor == M23_INITIAL_FLOOR
        ? M23_INITIAL_EPOCH : g_authority_floor + 1u;
    if (epoch == 0 || epoch <= g_authority_floor) {
        reject(M23_ERR_EPOCH_NOT_NEWER); return -1;
    }
    m23_session_root_t candidate = g_root;
    candidate.epoch = epoch;
    candidate.next_sequence = 1;
    candidate.high_water = 0;
    candidate.high_water_valid = 0;
    g_ingress_work_count = 0;
    candidate.outbound_rate_count = 0;
    candidate.outbound_rate_deadline = 0;
    candidate.state = M23_STATE_ARMED;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_cold(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    m23_session_root_t candidate = g_root;
    candidate.authority_floor = g_epoch;
    candidate.state = M23_STATE_UNARMED;
    candidate.epoch = 0;
    candidate.next_sequence = 0;
    candidate.high_water = 0;
    candidate.high_water_valid = 0;
    candidate.queue_head = 0;
    candidate.queue_count = 0;
    g_ingress_work_count = 0;
    candidate.outbound_rate_count = 0;
    candidate.outbound_rate_deadline = 0;
    g_root = candidate;
    /* A cold/unclean restart has no usable clean checkpoint. */
    g_checkpoint_valid = 0;
    g_checkpoint_magic = 0;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_restart_clean(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    if (g_state != M23_STATE_ARMED || g_queue_count != 0 || !g_checkpoint_valid) {
        reject(M23_ERR_CHECKPOINT_BUSY); return -1;
    }
    m23_session_root_t candidate = g_root;
    candidate.authority_floor = g_epoch;
    candidate.state = M23_STATE_UNARMED;
    candidate.epoch = 0;
    candidate.next_sequence = 0;
    candidate.high_water = 0;
    candidate.high_water_valid = 0;
    candidate.queue_head = 0;
    candidate.queue_count = 0;
    g_ingress_work_count = 0;
    candidate.outbound_rate_count = 0;
    candidate.outbound_rate_deadline = 0;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

static int admit_attested_framed_product(noun product,
                                         const m23_adapter_attestation_t *attestation)
{
    uint64_t sequence, epoch, value;
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_UNARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    if (g_state == M23_STATE_EXHAUSTED || g_state == M23_STATE_CLOSED) {
        reject(g_state == M23_STATE_EXHAUSTED ? M23_ERR_SEQUENCE_EXHAUSTED : M23_ERR_CLOSED);
        return -1;
    }
    if (!attestation_valid(attestation)) { reject(M23_ERR_ADAPTER_ATTESTATION); return -1; }
    if (!parse_product(product, &sequence, &epoch, &value)) return -1;
    /* The admission helper is the one M23 root linearization point. */
    return admit_sequence_value(sequence, epoch, value);
}

static uint64_t target_counter_deadline(void)
{
    uint64_t now = target_counter_now();
    uint64_t freq = target_counter_freq();
    return now > UINT64_MAX - freq ? UINT64_MAX : now + freq;
}

static uint64_t target_counter_remaining(uint64_t deadline, uint64_t now)
{
    return deadline > now ? deadline - now : 0;
}

int m23_provider_core_receive_framed(void)
{
    uint64_t rejects_before;
    noun product;
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    rejects_before = i2_rx_reject_total();
    uint64_t now = target_counter_now();
    uint64_t deadline = target_counter_deadline();
    uint64_t idle_since = 0;
    int saw_input = 0;
    for (;;) {
        now = target_counter_now();
        if (now >= deadline) break;
        if (uart_rx_ready()) {
            saw_input = 1;
            idle_since = 0;
            if (i2_rx_poll(32)) break;
        } else if (saw_input) {
            if (idle_since == 0) idle_since = now;
            if (now >= idle_since && now - idle_since >= target_counter_freq() / 4u)
                break;
        }
        if (i2_rx_reject_total() != rejects_before) {
            reject(M23_ERR_FRAME_LENGTH); return -1;
        }
    }
    i2_rx_check_timeout(UINT64_MAX);
    if (i2_rx_reject_total() != rejects_before) { reject(M23_ERR_FRAME_LENGTH); return -1; }
    if (!i2_rx_ready()) { reject(M23_ERR_NO_FRAME); return -1; }
    if (i2_rx_payload_len() > M23_CUE_LIMITS.max_input_bytes) {
        i2_rx_discard_ready(); reject(M23_ERR_FRAME_LENGTH); return -1;
    }
    /* Lifecycle refusal precedes Cue and all session admission work.  A
     * remote DATA frame cannot make an unarmed target spend codec budget or
     * alter its session root. */
    if (g_state != M23_STATE_ARMED) {
        i2_rx_discard_ready();
        reject(g_state == M23_STATE_UNARMED ? M23_ERR_SESSION_UNARMED
            : g_state == M23_STATE_EXHAUSTED ? M23_ERR_SEQUENCE_EXHAUSTED
            : M23_ERR_CLOSED);
        return -1;
    }
    if (g_ingress_work_count >= M23_RATE_CAP) {
        i2_rx_discard_ready(); reject(M23_ERR_INGRESS_WORK_LIMIT); return -1;
    }
    g_ingress_work_count++;
    if (!i2_rx_take_limited(&product, &M23_CUE_LIMITS)) {
        reject(M23_ERR_CUE); return -1;
    }
    int result = admit_attested_framed_product(product, &g_attestation);
    if (noun_tx_active()) noun_tx_abort();
    return result;
}

int m23_provider_core_step(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state != M23_STATE_ARMED) { reject(M23_ERR_CLOSED); return -1; }
    if (g_queue_count == 0) return 0;
    m23_session_root_t candidate = g_root;
    uint32_t slot = candidate.queue_head;
    g_last_indication = g_queue_value[slot];
    g_last_indication_sequence = g_queue_sequence[slot];
    g_indication_valid = 1;
    candidate.queue_head = (candidate.queue_head + 1u) % M23_FIFO_CAP;
    candidate.queue_count--;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 1;
}

int m23_provider_core_rotate(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    if (g_state != M23_STATE_ARMED || g_queue_count != 0) {
        reject(g_queue_count ? M23_ERR_CHECKPOINT_BUSY : M23_ERR_EPOCH_NOT_NEWER);
        return -1;
    }
    uint64_t next_epoch = g_epoch + 1u;
    if (next_epoch == 0 || next_epoch <= g_epoch) { reject(M23_ERR_EPOCH_NOT_NEWER); return -1; }
    m23_session_root_t candidate = g_root;
    candidate.authority_floor = g_epoch;
    candidate.epoch = next_epoch;
    candidate.next_sequence = 1;
    candidate.high_water = 0;
    candidate.high_water_valid = 0;
    g_ingress_work_count = 0;
    candidate.outbound_rate_count = 0;
    candidate.outbound_rate_deadline = 0;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_checkpoint_save(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    if (g_state != M23_STATE_ARMED || g_queue_count != 0) {
        reject(M23_ERR_CHECKPOINT_BUSY); return -1;
    }
    g_checkpoint_epoch = g_epoch;
    g_checkpoint_magic = M23_CHECKPOINT_MAGIC;
    g_checkpoint_version = M23_VERSION;
    g_checkpoint_profile = M23_PROFILE;
    g_checkpoint_local_device = M23_RECEIVER_DEVICE;
    g_checkpoint_peer_device = M23_SENDER_DEVICE;
    g_checkpoint_key_id = M23_KEY_ID;
    for (size_t i = 0; i < sizeof M23_BINDING; i++)
        g_checkpoint_binding[i] = M23_BINDING[i];
    for (size_t i = 0; i < sizeof M23_SCHEMA; i++)
        g_checkpoint_schema[i] = M23_SCHEMA[i];
    g_checkpoint_high_water = g_high_water;
    g_checkpoint_next_sequence = g_next_sequence;
    g_checkpoint_state = g_state;
    g_checkpoint_wire_major = M23_WIRE_MAJOR;
    g_checkpoint_wire_minor = M23_WIRE_MINOR;
    g_checkpoint_message_kind = M23_MESSAGE_KIND;
    uint64_t checkpoint_now = target_counter_now();
    g_checkpoint_rate_remaining = target_counter_remaining(
        g_outbound_rate_deadline, checkpoint_now);
    g_checkpoint_rate_count = g_checkpoint_rate_remaining == 0
        ? 0 : g_outbound_rate_count;
    g_checkpoint_valid = 1;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_checkpoint_restore(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    if (g_state != M23_STATE_UNARMED || !g_checkpoint_valid
        || g_checkpoint_magic != M23_CHECKPOINT_MAGIC
        || g_checkpoint_version != M23_VERSION
        || g_checkpoint_profile != M23_PROFILE
        || g_checkpoint_local_device != M23_RECEIVER_DEVICE
        || g_checkpoint_peer_device != M23_SENDER_DEVICE
        || g_checkpoint_key_id != M23_KEY_ID
        || g_checkpoint_state != M23_STATE_ARMED
        || g_checkpoint_wire_major != M23_WIRE_MAJOR
        || g_checkpoint_wire_minor != M23_WIRE_MINOR
        || g_checkpoint_message_kind != M23_MESSAGE_KIND
        || g_checkpoint_epoch == 0 || g_checkpoint_next_sequence == 0
        /* A checkpoint captured before a local rotation is stale.  Clean
         * restore may equal the retained floor (the checkpoint's own epoch),
         * but it must never move authority backwards. */
        || g_checkpoint_epoch < g_authority_floor
        || g_checkpoint_rate_count > M23_RATE_CAP
        || (g_checkpoint_rate_count == 0 && g_checkpoint_rate_remaining != 0)
        || g_checkpoint_rate_remaining > target_counter_freq()) {
        reject(M23_ERR_CHECKPOINT_INVALID); return -1;
    }
    for (size_t i = 0; i < sizeof M23_BINDING; i++)
        if (g_checkpoint_binding[i] != M23_BINDING[i]) {
            reject(M23_ERR_CHECKPOINT_INVALID); return -1;
        }
    for (size_t i = 0; i < sizeof M23_SCHEMA; i++)
        if (g_checkpoint_schema[i] != M23_SCHEMA[i]) {
            reject(M23_ERR_CHECKPOINT_INVALID); return -1;
        }
    m23_session_root_t candidate = g_root;
    candidate.epoch = g_checkpoint_epoch;
    candidate.high_water = g_checkpoint_high_water;
    candidate.high_water_valid = g_checkpoint_high_water != 0;
    candidate.next_sequence = g_checkpoint_next_sequence;
    candidate.outbound_rate_count = g_checkpoint_rate_count;
    uint64_t now = target_counter_now();
    candidate.outbound_rate_deadline = g_checkpoint_rate_remaining == 0
        ? 0 : (now > UINT64_MAX - g_checkpoint_rate_remaining
            ? UINT64_MAX : now + g_checkpoint_rate_remaining);
    /* An ARMED checkpoint with next==UINT64_MAX still permits that final
     * sequence.  EXHAUSTED is entered only by the successful send itself. */
    candidate.state = M23_STATE_ARMED;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

#ifdef M23_TEST_CONTROLS
int m23_provider_core_checkpoint_tamper(void)
{
    if (!g_checkpoint_valid) { reject(M23_ERR_CHECKPOINT_INVALID); return -1; }
    g_checkpoint_version = M23_VERSION + 1u;
    return 0;
}
#endif

#ifdef M24_NATIVE
static uint16_t native_be16(const uint8_t *p)
{
    volatile const uint8_t *q = (volatile const uint8_t *)p;
    return ((uint16_t)q[0] << 8) | q[1];
}

static uint32_t native_be32(const uint8_t *p)
{
    volatile const uint8_t *q = (volatile const uint8_t *)p;
    return ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16)
        | ((uint32_t)q[2] << 8) | q[3];
}

static uint64_t native_be64(const uint8_t *p)
{
    volatile const uint8_t *q = (volatile const uint8_t *)p;
    uint64_t value = 0;
    for (uint32_t i = 0; i < 8; i++) value = (value << 8) | q[i];
    return value;
}

static void native_put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void native_put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void native_put64(uint8_t *p, uint64_t value)
{
    for (uint32_t i = 0; i < 8; i++) p[7u - i] = (uint8_t)(value >> (8u * i));
}

static int native_bytes_equal(const uint8_t *left, const uint8_t *right, uint32_t len)
{
    volatile const uint8_t *q = (volatile const uint8_t *)left;
    uint8_t different = 0;
    for (uint32_t i = 0; i < len; i++) different |= q[i] ^ right[i];
    return different == 0;
}

static int native_make_wire(uint8_t *wire, uint32_t *wire_len,
                            uint64_t epoch, uint64_t sequence, uint64_t value)
{
    const uint8_t *payload = value ? M24_TRUE_PAYLOAD : M24_FALSE_PAYLOAD;
    if (!wire || !wire_len || value > 1 || M24_WIRE_HEADER_LEN + sizeof M24_TRUE_PAYLOAD > M24_WIRE_MAX_DATAGRAM)
        return 0;
    for (uint32_t i = 0; i < M24_WIRE_HEADER_LEN + sizeof M24_TRUE_PAYLOAD; i++) wire[i] = 0;
    wire[0] = 'A'; wire[1] = 'E'; wire[2] = 'T'; wire[3] = '0';
    wire[4] = M23_WIRE_MAJOR; wire[5] = M23_WIRE_MINOR;
    wire[6] = M23_PROFILE; wire[7] = M23_MESSAGE_KIND;
    native_put16(wire + 8, M24_WIRE_HEADER_LEN);
    native_put16(wire + 10, sizeof M24_TRUE_PAYLOAD);
    native_put64(wire + 12, M23_SENDER_DEVICE);
    native_put64(wire + 20, M23_RECEIVER_DEVICE);
    for (uint32_t i = 0; i < sizeof M23_BINDING; i++) wire[28 + i] = M23_BINDING[i];
    for (uint32_t i = 0; i < sizeof M23_SCHEMA; i++) wire[44 + i] = M23_SCHEMA[i];
    native_put32(wire + 76, M23_KEY_ID);
    native_put64(wire + 80, epoch); native_put64(wire + 88, sequence);
    for (uint32_t i = 0; i < sizeof M24_TRUE_PAYLOAD; i++) wire[M24_WIRE_HEADER_LEN + i] = payload[i];
    uint8_t auth_input[M24_WIRE_HEADER_LEN + sizeof M24_TRUE_PAYLOAD];
    uint8_t digest[M24_AUTH_TAG_LEN];
    for (uint32_t i = 0; i < sizeof auth_input; i++) auth_input[i] = wire[i];
    for (uint32_t i = 96; i < 128; i++) auth_input[i] = 0;
    hmac_sha256(M24_PSK, sizeof M24_PSK - 1u, auth_input, sizeof auth_input, digest);
    for (uint32_t i = 0; i < M24_AUTH_TAG_LEN; i++) wire[96 + i] = digest[i];
    *wire_len = M24_WIRE_HEADER_LEN + sizeof M24_TRUE_PAYLOAD;
    return 1;
}

static uint64_t native_transport_error(m24_native_status_t status)
{
    switch (status) {
    case M24_NATIVE_NO_PACKET: return M23_ERR_NATIVE_NO_PACKET;
    case M24_NATIVE_MALFORMED_ETHERNET: return M23_ERR_NATIVE_ETHERNET;
    case M24_NATIVE_MALFORMED_IPV6: return M23_ERR_NATIVE_IPV6;
    case M24_NATIVE_ENDPOINT: return M23_ERR_NATIVE_ENDPOINT;
    case M24_NATIVE_CHECKSUM: return M23_ERR_NATIVE_CHECKSUM;
    case M24_NATIVE_RING_FULL: return M23_ERR_NATIVE_RING_FULL;
    default: return M23_ERR_NATIVE_DEVICE;
    }
}

int m23_provider_core_native_init(void)
{
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    int result = m23_provider_core_init();
    if (result != 0) return result;
    if (m24_native_init() != 0) { reject(M23_ERR_NATIVE_DEVICE); return -1; }
    return 0;
}

int m23_provider_core_receive_native(void)
{
    m24_native_datagram_t datagram;
    m24_native_status_t transport = M24_NATIVE_NO_PACKET;
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state != M23_STATE_ARMED) {
        reject(g_state == M23_STATE_UNARMED ? M23_ERR_SESSION_UNARMED
            : g_state == M23_STATE_EXHAUSTED ? M23_ERR_SEQUENCE_EXHAUSTED : M23_ERR_CLOSED);
        return -1;
    }
    if (g_ingress_work_count >= M23_RATE_CAP) {
        reject(M23_ERR_INGRESS_WORK_LIMIT); return -1;
    }
    for (uint32_t i = 0; i < 64u; i++) {
        transport = m24_native_receive(&datagram);
        if (transport != M24_NATIVE_NO_PACKET) break;
    }
    if (transport != M24_NATIVE_OK) { reject(native_transport_error(transport)); return -1; }
    const uint8_t *wire = datagram.payload;
    uint32_t wire_len = datagram.payload_len;
    if (!wire || wire_len < M24_WIRE_HEADER_LEN || wire_len > M24_WIRE_MAX_DATAGRAM) {
        reject(M23_ERR_NATIVE_ETHERNET); return -1;
    }
    uint16_t header_len = native_be16(wire + 8), payload_len = native_be16(wire + 10);
    if (wire[0] != 'A' || wire[1] != 'E' || wire[2] != 'T' || wire[3] != '0'
        || wire[4] != M23_WIRE_MAJOR || wire[5] != M23_WIRE_MINOR
        || wire[6] != M23_PROFILE || wire[7] != M23_MESSAGE_KIND
        || header_len != M24_WIRE_HEADER_LEN || payload_len == 0
        || payload_len > M24_WIRE_MAX_PAYLOAD || wire_len != header_len + payload_len) {
        reject(M23_ERR_NATIVE_ETHERNET); return -1;
    }
    if (native_be64(wire + 12) != M23_SENDER_DEVICE
        || native_be64(wire + 20) != M23_RECEIVER_DEVICE
        || !native_bytes_equal(wire + 28, M23_BINDING, sizeof M23_BINDING)
        || !native_bytes_equal(wire + 44, M23_SCHEMA, sizeof M23_SCHEMA)
        || native_be32(wire + 76) != M23_KEY_ID
        || native_be64(wire + 80) == 0 || native_be64(wire + 88) == 0) {
        reject(M23_ERR_NATIVE_ENDPOINT); return -1;
    }
    uint8_t auth_input[M24_WIRE_HEADER_LEN + M24_WIRE_MAX_PAYLOAD];
    uint8_t expected[M24_AUTH_TAG_LEN];
    for (uint32_t i = 0; i < wire_len; i++) auth_input[i] = wire[i];
    for (uint32_t i = 96; i < 128; i++) auth_input[i] = 0;
    hmac_sha256(M24_PSK, sizeof M24_PSK - 1u, auth_input, wire_len, expected);
    if (!native_bytes_equal(wire + 96, expected, M24_AUTH_TAG_LEN)) {
        reject(M23_ERR_NATIVE_AUTHENTICATION); return -1;
    }
    noun publication;
    cue_bounded_status_t cue_status = cue_bounded_bytes(
        wire + M24_WIRE_HEADER_LEN, payload_len, &M23_CUE_LIMITS,
        HEAP_MODE_SCRATCH, &publication);
    if (cue_status != CUE_BOUNDED_OK) {
        reject(M23_ERR_NATIVE_CANONICAL); return -1;
    }
    const uint8_t *canonical; uint64_t canonical_len;
    if (jam_encode_bytes_checked(publication, &canonical, &canonical_len) != 0
        || canonical_len != payload_len
        || !native_bytes_equal(canonical, wire + M24_WIRE_HEADER_LEN, payload_len)) {
        if (noun_tx_active()) noun_tx_abort();
        reject(M23_ERR_NATIVE_CANONICAL); return -1;
    }
    uint64_t value, sequence = native_be64(wire + 88), epoch = native_be64(wire + 80);
    if (!parse_publication(publication, &value)) {
        if (noun_tx_active()) noun_tx_abort();
        return -1;
    }
    int result = admit_sequence_value(sequence, epoch, value);
    if (result == 0) g_ingress_work_count++;
    if (noun_tx_active()) noun_tx_abort();
    return result;
}

int m23_provider_core_publish_native(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_UNARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    if (g_state == M23_STATE_EXHAUSTED) { reject(M23_ERR_SEQUENCE_EXHAUSTED); return -1; }
    if (g_state == M23_STATE_CLOSED) { reject(M23_ERR_CLOSED); return -1; }
    uint64_t now = target_counter_now();
    m23_session_root_t candidate = g_root;
    if (candidate.outbound_rate_deadline == 0 || now >= candidate.outbound_rate_deadline) {
        candidate.outbound_rate_count = 0;
        candidate.outbound_rate_deadline = target_counter_deadline();
    }
    if (candidate.outbound_rate_count >= M23_RATE_CAP) {
        reject(M23_ERR_OUTBOUND_RATE_LIMIT); return -1;
    }
    if (candidate.next_sequence == 0) { reject(M23_ERR_SEQUENCE_EXHAUSTED); return -1; }
    uint8_t wire[M24_WIRE_MAX_DATAGRAM]; uint32_t wire_len;
    if (!native_make_wire(wire, &wire_len, candidate.epoch, candidate.next_sequence, 1)) {
        reject(M23_ERR_NATIVE_ETHERNET); return -1;
    }
    m24_native_status_t status = m24_native_send(wire, wire_len);
    if (status != M24_NATIVE_OK) {
        reject(native_transport_error(status)); return -1;
    }
    if (candidate.next_sequence == UINT64_MAX) candidate.state = M23_STATE_EXHAUSTED;
    else candidate.next_sequence++;
    candidate.outbound_rate_count++;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}
#endif

int m23_provider_core_complete_egress(void)
{
    /* This is a synthetic post-transport egress-completion operation for the
     * framed provider-core proof; it is not target networking. */
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_UNARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    if (g_state == M23_STATE_EXHAUSTED) { reject(M23_ERR_SEQUENCE_EXHAUSTED); return -1; }
    if (g_state == M23_STATE_CLOSED) { reject(M23_ERR_CLOSED); return -1; }
    uint64_t now = target_counter_now();
    m23_session_root_t candidate = g_root;
    if (candidate.outbound_rate_deadline == 0 || now >= candidate.outbound_rate_deadline) {
        candidate.outbound_rate_count = 0;
        candidate.outbound_rate_deadline = target_counter_deadline();
    }
    if (candidate.outbound_rate_count >= M23_RATE_CAP) {
        reject(M23_ERR_OUTBOUND_RATE_LIMIT); return -1;
    }
    if (candidate.next_sequence == UINT64_MAX) {
        candidate.state = M23_STATE_EXHAUSTED;
    } else {
        candidate.next_sequence++;
    }
    candidate.outbound_rate_count++;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

#ifdef M23_TEST_CONTROLS
static int m23_root_equal(const m23_session_root_t *left,
                          const m23_session_root_t *right)
{
    if (left->queue_head != right->queue_head
        || left->queue_count != right->queue_count
        || left->high_water != right->high_water
        || left->high_water_valid != right->high_water_valid
        || left->epoch != right->epoch
        || left->next_sequence != right->next_sequence
        || left->authority_floor != right->authority_floor
        || left->outbound_rate_count != right->outbound_rate_count
        || left->outbound_rate_deadline != right->outbound_rate_deadline
        || left->state != right->state) return 0;
    for (size_t i = 0; i < M23_FIFO_CAP; i++) {
        if (left->queue_value[i] != right->queue_value[i]
            || left->queue_sequence[i] != right->queue_sequence[i]) return 0;
    }
    return 1;
}

int m23_provider_core_test_outbound_burst(void)
{
    if (!g_active || g_state != M23_STATE_ARMED) {
        reject(M23_ERR_SESSION_UNARMED); return -1;
    }
    for (uint64_t i = 0; i < M23_RATE_CAP; i++) {
        if (m23_provider_core_complete_egress() != 0) return -1;
    }
    m23_session_root_t before = g_root;
    if (m23_provider_core_complete_egress() == 0
        || g_last_error != M23_ERR_OUTBOUND_RATE_LIMIT
        || !m23_root_equal(&before, &g_root)) return -1;
    return 0;
}

#ifdef M24_NATIVE
int m23_provider_core_test_native_rate_burst(void)
{
    if (!g_active || g_state != M23_STATE_ARMED) {
        reject(M23_ERR_SESSION_UNARMED); return -1;
    }
    /* Compact test control: every iteration still uses the real native
     * frame build, virtio submission, used completion, and root commit. */
    for (uint64_t i = g_outbound_rate_count; i < M23_RATE_CAP; i++) {
        if (m23_provider_core_publish_native() != 0) return -1;
    }
    return 0;
}
#endif

int m23_provider_core_set_next_max_minus_one(void)
{
    if (g_state != M23_STATE_ARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    m23_session_root_t candidate = g_root;
    candidate.next_sequence = UINT64_MAX - 1u;
    candidate.outbound_rate_count = 0;
    candidate.outbound_rate_deadline = 0;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}
#endif

int m23_provider_core_close(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
#ifdef M24_NATIVE
    if (m24_native_tx_pending()) { reject(M23_ERR_NATIVE_RING_FULL); return -1; }
#endif
    if (g_state == M23_STATE_CLOSED) return 0;
    m23_session_root_t candidate = g_root;
    candidate.state = M23_STATE_CLOSED;
    g_root = candidate;
    g_last_error = M23_ERR_NONE;
    return 0;
}

uint64_t m23_provider_core_queue_len(void) { return g_queue_count; }
uint64_t m23_provider_core_high_water(void) { return g_high_water_valid ? g_high_water : 0; }
uint64_t m23_provider_core_next_sequence(void) { return g_next_sequence; }
uint64_t m23_provider_core_epoch(void) { return g_epoch; }
uint64_t m23_provider_core_state(void) { return g_state; }
uint64_t m23_provider_core_indication(void)
{
    return g_indication_valid ? g_last_indication : UINT64_MAX;
}
uint64_t m23_provider_core_indication_sequence(void)
{
    return g_indication_valid ? g_last_indication_sequence : UINT64_MAX;
}
uint64_t m23_provider_core_last_error(void) { return g_last_error; }
uint64_t m23_provider_core_cue_calls(void) { return i2_rx_cue_calls(); }
uint64_t m23_provider_core_outbound_rate_count(void) { return g_outbound_rate_count; }
