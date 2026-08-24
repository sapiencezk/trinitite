#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_ingress.h"
#include "m23_session_core.h"
#include "memory.h"
#include "uart.h"

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
#define M23_INITIAL_FLOOR 2u
#define M23_INITIAL_EPOCH 3u
#define M23_ROTATED_EPOCH 4u
#define M23_U64_MAX UINT64_MAX
#define M23_CHECKPOINT_MAGIC 0x4d323353ULL

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
    uint64_t ingress_rate_count;
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
#define g_ingress_rate_count (g_root.ingress_rate_count)
#define g_outbound_rate_count (g_root.outbound_rate_count)
#define g_outbound_rate_deadline (g_root.outbound_rate_deadline)
#define g_state (g_root.state)
static uint64_t g_last_indication;
static uint64_t g_last_indication_sequence;
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
    if (!take(rest, epoch, &rest) || !noun_is_direct(*epoch)
        || direct_val(*epoch) == 0) {
        reject(M23_ERR_EPOCH); return 0;
    }
    if (!take(rest, sequence, &publication) || !noun_is_direct(*sequence)
        || direct_val(*sequence) == 0) {
        reject(M23_ERR_SEQUENCE_ZERO); return 0;
    }
    *epoch = direct_val(*epoch);
    *sequence = direct_val(*sequence);
    return parse_publication(publication, value);
}

int m23_provider_core_init(void)
{
    g_product_tag = cord_from_bytes("aethernet-0-adapter-product-v1", 30);
    g_publication_tag = cord_from_bytes("publication-envelope-v1", 23);
    g_publish_event_tag = cord_from_bytes("PUBLISH_1", 9);
    g_raw_carrier_tag = cord_from_bytes("i2-inter-resource-v1", 20);
    g_bare_ei_tag = cord_from_bytes("i2-ei", 5);
    g_queue_head = 0;
    g_queue_count = 0;
    g_high_water = 0;
    g_high_water_valid = 0;
    g_epoch = 0;
    g_next_sequence = 0;
    g_authority_floor = M23_INITIAL_FLOOR;
    g_ingress_rate_count = 0;
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
    g_state = M23_STATE_UNARMED;
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
    g_epoch = epoch;
    g_next_sequence = 1;
    g_high_water = 0;
    g_high_water_valid = 0;
    g_ingress_rate_count = 0;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    g_state = M23_STATE_ARMED;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_cold(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    g_authority_floor = g_epoch;
    g_state = M23_STATE_UNARMED;
    g_epoch = 0;
    g_next_sequence = 0;
    g_high_water = 0;
    g_high_water_valid = 0;
    g_queue_head = 0;
    g_queue_count = 0;
    g_ingress_rate_count = 0;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    /* A cold/unclean restart has no usable clean checkpoint. */
    g_checkpoint_valid = 0;
    g_checkpoint_magic = 0;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_restart_clean(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state != M23_STATE_ARMED || g_queue_count != 0 || !g_checkpoint_valid) {
        reject(M23_ERR_CHECKPOINT_BUSY); return -1;
    }
    g_authority_floor = g_epoch;
    g_state = M23_STATE_UNARMED;
    g_epoch = 0;
    g_next_sequence = 0;
    g_high_water = 0;
    g_high_water_valid = 0;
    g_queue_head = 0;
    g_queue_count = 0;
    g_ingress_rate_count = 0;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_admit(noun product,
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
    if (epoch != g_epoch) { reject(M23_ERR_STALE_EPOCH); return -1; }
    if (g_high_water_valid && sequence <= g_high_water) { reject(M23_ERR_REPLAY); return -1; }
    if (g_queue_count >= M23_FIFO_CAP) { reject(M23_ERR_FIFO_FULL); return -1; }
    /* The reservation boundary is intentionally absent in M23's target
     * positive path; all checks still precede this single root publication. */
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
    if (g_ingress_rate_count >= M23_RATE_CAP) {
        i2_rx_discard_ready(); reject(M23_ERR_FRAME_RATE); return -1;
    }
    g_ingress_rate_count++;
    if (!i2_rx_take_limited(&product, &M23_CUE_LIMITS)) {
        reject(M23_ERR_CUE); return -1;
    }
    int result = m23_provider_core_admit(product, &g_attestation);
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
    if (g_state != M23_STATE_ARMED || g_queue_count != 0) {
        reject(g_queue_count ? M23_ERR_CHECKPOINT_BUSY : M23_ERR_EPOCH_NOT_NEWER);
        return -1;
    }
    uint64_t next_epoch = g_epoch + 1u;
    if (next_epoch == 0 || next_epoch <= g_epoch) { reject(M23_ERR_EPOCH_NOT_NEWER); return -1; }
    g_authority_floor = g_epoch;
    g_epoch = next_epoch;
    g_next_sequence = 1;
    g_high_water = 0;
    g_high_water_valid = 0;
    g_ingress_rate_count = 0;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    g_last_error = M23_ERR_NONE;
    return 0;
}

int m23_provider_core_checkpoint_save(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
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
    g_epoch = g_checkpoint_epoch;
    g_high_water = g_checkpoint_high_water;
    g_high_water_valid = g_checkpoint_high_water != 0;
    g_next_sequence = g_checkpoint_next_sequence;
    g_outbound_rate_count = g_checkpoint_rate_count;
    uint64_t now = target_counter_now();
    g_outbound_rate_deadline = g_checkpoint_rate_remaining == 0
        ? 0 : (now > UINT64_MAX - g_checkpoint_rate_remaining
            ? UINT64_MAX : now + g_checkpoint_rate_remaining);
    /* An ARMED checkpoint with next==UINT64_MAX still permits that final
     * sequence.  EXHAUSTED is entered only by the successful send itself. */
    g_state = M23_STATE_ARMED;
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

int m23_provider_core_publish(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_UNARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    if (g_state == M23_STATE_EXHAUSTED) { reject(M23_ERR_SEQUENCE_EXHAUSTED); return -1; }
    if (g_state == M23_STATE_CLOSED) { reject(M23_ERR_CLOSED); return -1; }
    uint64_t now = target_counter_now();
    if (g_outbound_rate_deadline == 0 || now >= g_outbound_rate_deadline) {
        g_outbound_rate_count = 0;
        g_outbound_rate_deadline = target_counter_deadline();
    }
    if (g_outbound_rate_count >= M23_RATE_CAP) {
        reject(M23_ERR_FRAME_RATE); return -1;
    }
    m23_session_root_t candidate = g_root;
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
int m23_provider_core_set_next_max_minus_one(void)
{
    if (g_state != M23_STATE_ARMED) { reject(M23_ERR_SESSION_UNARMED); return -1; }
    g_next_sequence = UINT64_MAX - 1u;
    g_outbound_rate_count = 0;
    g_outbound_rate_deadline = 0;
    g_last_error = M23_ERR_NONE;
    return 0;
}
#endif

int m23_provider_core_close(void)
{
    if (!g_active) { reject(M23_ERR_NOT_INITIALIZED); return -1; }
    if (g_state == M23_STATE_CLOSED) return 0;
    g_state = M23_STATE_CLOSED;
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
