#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "i2_ingress.h"
#include "m22_provider_core.h"
#include "memory.h"
#include "uart.h"

#define M22_FIFO_CAP 16u
#define M22_RATE_CAP 64u
#define M22_TARGET_VERSION 1u
#define M22_TARGET_PROFILE 0u
#define M22_TARGET_MESSAGE_KIND 1u
#define M22_SENDER_DEVICE 11u
#define M22_RECEIVER_DEVICE 22u
#define M22_KEY_ID 7u
#define M22_SENDER_EPOCH 3u

static const uint8_t M22_BINDING[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static const uint8_t M22_SCHEMA[32] = {
    0x0f, 0xc5, 0x52, 0x05, 0x48, 0x83, 0x82, 0x8d,
    0x4e, 0x52, 0xeb, 0x5b, 0x86, 0x48, 0xc2, 0x3e,
    0xad, 0xda, 0xb8, 0x60, 0x54, 0xd4, 0x19, 0xdb,
    0x2a, 0x25, 0x55, 0x2f, 0x29, 0xa6, 0x93, 0xf9
};

/* A deliberately separate, image-owned issuer marker. */
static const uint64_t g_adapter_issuer = 0x4d32324154544553ULL;
static const m22_adapter_attestation_t g_framed_attestation = {
    .magic = 0x4d32324155544831ULL,
    .issuer = &g_adapter_issuer,
    .profile = 0x4d3232u,
    .authenticated = 1u
};

static noun g_product_tag;
static noun g_publication_tag;
static noun g_publish_event_tag;
static noun g_raw_carrier_tag;
static noun g_bare_ei_tag;
static noun g_queue_value[M22_FIFO_CAP];
static uint64_t g_queue_sequence[M22_FIFO_CAP];
static uint32_t g_queue_head;
static uint32_t g_queue_count;
static uint64_t g_high_water;
static uint64_t g_rate_count;
static uint64_t g_last_indication;
static uint64_t g_last_indication_sequence;
static uint64_t g_last_error;
static int g_indication_valid;
static int g_active;
static int g_reservation_fail_once;

static const cue_bounded_limits_t M22_CUE_LIMITS = {
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
    if (len > sizeof actual)
        return 0;
    if (!noun_atom_read_fixed(n, actual, len))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (actual[i] != expected[i])
            return 0;
    return 1;
}

static int attestation_valid(const m22_adapter_attestation_t *attestation)
{
    return attestation == &g_framed_attestation
        && attestation->magic == g_framed_attestation.magic
        && attestation->issuer == &g_adapter_issuer
        && attestation->profile == g_framed_attestation.profile
        && attestation->authenticated == 1u;
}

static void reject(uint64_t error)
{
    g_last_error = error;
}

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

static uint64_t framed_reject_error(void)
{
    switch (i2_rx_last_reason()) {
    case I2_RX_REASON_VERSION: return M22_ERR_FRAME_VERSION;
    case I2_RX_REASON_HEADER: return M22_ERR_FRAME_HEADER;
    case I2_RX_REASON_LENGTH: return M22_ERR_FRAME_LENGTH;
    case I2_RX_REASON_DIGEST: return M22_ERR_FRAME_DIGEST;
    case I2_RX_REASON_TIMEOUT: return M22_ERR_FRAME_TIMEOUT;
    case I2_RX_REASON_CUE: return M22_ERR_CUE;
    default: return M22_ERR_CUE;
    }
}

static int parse_publication(noun publication, uint64_t *value)
{
    noun tag, rest, version, event, type, sample, tail;
    if (!take(publication, &tag, &rest)) {
        reject(M22_ERR_PUBLICATION_SHAPE);
        return 0;
    }
    if (!noun_eq(tag, g_publication_tag)) {
        reject(M22_ERR_PUBLICATION_TAG);
        return 0;
    }
    if (!take(rest, &version, &rest) || !direct_is(version, M22_TARGET_VERSION)) {
        reject(M22_ERR_PUBLICATION_VERSION);
        return 0;
    }
    if (!take(rest, &event, &rest) || !noun_eq(event, g_publish_event_tag)) {
        reject(M22_ERR_PUBLICATION_EVENT);
        return 0;
    }
    if (!take(rest, &type, &rest) || !direct_is(type, 1u)) {
        reject(M22_ERR_PUBLICATION_TYPE);
        return 0;
    }
    if (!take(rest, &sample, &tail) || !direct_is(tail, 0)
        || !noun_is_direct(sample) || direct_val(sample) > 1u) {
        reject(M22_ERR_PUBLICATION_VALUE);
        return 0;
    }
    *value = direct_val(sample);
    return 1;
}

static int parse_product(noun product, uint64_t *sequence, uint64_t *value)
{
    noun tag, rest, field, publication;
    if (noun_is_cell(product) && take(product, &tag, &field)) {
        if (noun_eq(tag, g_raw_carrier_tag)) {
            reject(M22_ERR_RAW_M21_CARRIER);
            return 0;
        }
        if (noun_eq(tag, g_bare_ei_tag)) {
            reject(M22_ERR_BARE_INTERNAL_EI);
            return 0;
        }
    }
    if (!take(product, &tag, &rest) || !noun_eq(tag, g_product_tag)) {
        reject(M22_ERR_PRODUCT_TAG);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_TARGET_VERSION)) {
        reject(M22_ERR_VERSION);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_TARGET_PROFILE)) {
        reject(M22_ERR_PROFILE);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_TARGET_MESSAGE_KIND)) {
        reject(M22_ERR_MESSAGE_KIND);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_SENDER_DEVICE)) {
        reject(M22_ERR_SENDER);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_RECEIVER_DEVICE)) {
        reject(M22_ERR_RECEIVER);
        return 0;
    }
    if (!take(rest, &field, &rest) || !atom_is_bytes(field, M22_BINDING, sizeof M22_BINDING)) {
        reject(M22_ERR_BINDING);
        return 0;
    }
    if (!take(rest, &field, &rest) || !atom_is_bytes(field, M22_SCHEMA, sizeof M22_SCHEMA)) {
        reject(M22_ERR_SCHEMA);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_KEY_ID)) {
        reject(M22_ERR_KEY_ID);
        return 0;
    }
    if (!take(rest, &field, &rest) || !direct_is(field, M22_SENDER_EPOCH)) {
        reject(M22_ERR_EPOCH);
        return 0;
    }
    if (!take(rest, sequence, &publication) || !noun_is_direct(*sequence)
        || direct_val(*sequence) == 0) {
        reject(M22_ERR_SEQUENCE_ZERO);
        return 0;
    }
    return parse_publication(publication, value);
}

int m22_provider_core_init(void)
{
    g_product_tag = cord_from_bytes("aethernet-0-adapter-product-v1", 30);
    g_publication_tag = cord_from_bytes("publication-envelope-v1", 23);
    g_publish_event_tag = cord_from_bytes("PUBLISH_1", 9);
    g_raw_carrier_tag = cord_from_bytes("i2-inter-resource-v1", 20);
    g_bare_ei_tag = cord_from_bytes("i2-ei", 5);
    g_queue_head = 0;
    g_queue_count = 0;
    g_high_water = 0;
    g_rate_count = 0;
    g_last_indication = 0;
    g_last_indication_sequence = 0;
    g_last_error = M22_ERR_NONE;
    g_indication_valid = 0;
    g_reservation_fail_once = 0;
    g_active = noun_is_atom(g_product_tag) && noun_is_atom(g_publication_tag)
        && noun_is_atom(g_publish_event_tag) && noun_is_atom(g_raw_carrier_tag)
        && noun_is_atom(g_bare_ei_tag);
    i2_rx_init();
    return g_active ? 0 : -1;
}

int m22_provider_core_admit(noun product,
                            const m22_adapter_attestation_t *attestation)
{
    uint64_t sequence, value;
    if (!g_active) {
        reject(M22_ERR_NOT_INITIALIZED);
        return -1;
    }
    if (!attestation_valid(attestation)) {
        reject(M22_ERR_ADAPTER_ATTESTATION);
        return -1;
    }
    if (!parse_product(product, &sequence, &value))
        return -1;
    if (sequence <= g_high_water) {
        reject(M22_ERR_REPLAY);
        return -1;
    }
    if (g_queue_count >= M22_FIFO_CAP) {
        reject(M22_ERR_FIFO_FULL);
        return -1;
    }
    if (g_reservation_fail_once) {
        g_reservation_fail_once = 0;
        reject(M22_ERR_RESERVATION);
        return -1;
    }
    /* All validation and capacity checks precede this single root mutation. */
    uint32_t slot = (g_queue_head + g_queue_count) % M22_FIFO_CAP;
    g_queue_value[slot] = value;
    g_queue_sequence[slot] = sequence;
    g_queue_count++;
    g_high_water = sequence;
    g_last_error = M22_ERR_NONE;
    return 0;
}

int m22_provider_core_receive_framed(void)
{
    uint64_t rejects_before;
    noun product;
    if (!g_active) {
        reject(M22_ERR_NOT_INITIALIZED);
        return -1;
    }
    rejects_before = i2_rx_reject_total();
    /* The UART transport is asynchronous even in QEMU.  Use a real bounded
     * time wait, then a shorter post-byte idle grace for a malformed frame;
     * the target provider never blocks on a socket. */
    int saw_input = 0;
    uint64_t now = target_counter_now();
    uint64_t frequency = target_counter_freq();
    uint64_t deadline = now > UINT64_MAX - frequency ? UINT64_MAX : now + frequency;
    uint64_t idle_since = 0;
    for (;;) {
        now = target_counter_now();
        if (now >= deadline)
            break;
        if (uart_rx_ready()) {
            saw_input = 1;
            idle_since = 0;
            if (i2_rx_poll(32))
                break;
        } else if (saw_input) {
            if (idle_since == 0)
                idle_since = now;
            if (now >= idle_since && now - idle_since >= frequency / 4u)
                break;
        }
        if (i2_rx_reject_total() != rejects_before) {
            reject(framed_reject_error());
            return -1;
        }
    }
    /* The idle/deadline exit is also the terminal poll for a partial frame.
     * Force the ingress deadline check so the M22 seam reports and clears a
     * truncated frame rather than leaving scanner state resident. */
    i2_rx_check_timeout(UINT64_MAX);
    if (i2_rx_reject_total() != rejects_before) {
        reject(framed_reject_error());
        return -1;
    }
    if (!i2_rx_ready()) {
        reject(M22_ERR_NO_FRAME);
        return -1;
    }
    if (i2_rx_payload_len() > M22_CUE_LIMITS.max_input_bytes) {
        i2_rx_discard_ready();
        reject(M22_ERR_FRAME_LENGTH);
        return -1;
    }
    /* This bounded per-initialized-test-epoch budget is before Cue.  The
     * framed target seam has no wall-clock network provider; the host UDP
     * adapter owns the live one-second rate window. */
    if (g_rate_count >= M22_RATE_CAP) {
        i2_rx_discard_ready();
        reject(M22_ERR_FRAME_RATE);
        return -1;
    }
    g_rate_count++;
    if (!i2_rx_take_limited(&product, &M22_CUE_LIMITS)) {
        reject(M22_ERR_CUE);
        return -1;
    }
    int result = m22_provider_core_admit(product, &g_framed_attestation);
    if (noun_tx_active())
        noun_tx_abort();
    return result;
}

int m22_provider_core_unattested_probe(void)
{
    noun before_value = g_last_indication;
    uint64_t before_queue = g_queue_count;
    uint64_t before_hwm = g_high_water;
    int result = m22_provider_core_admit(NOUN_ZERO, 0);
    return result == -1 && g_last_error == M22_ERR_ADAPTER_ATTESTATION
        && before_value == g_last_indication
        && before_queue == g_queue_count && before_hwm == g_high_water
        ? 0 : -1;
}

int m22_provider_core_step(void)
{
    if (!g_active) {
        reject(M22_ERR_NOT_INITIALIZED);
        return -1;
    }
    if (g_queue_count == 0)
        return 0;
    uint32_t slot = g_queue_head;
    g_last_indication = g_queue_value[slot];
    g_last_indication_sequence = g_queue_sequence[slot];
    g_indication_valid = 1;
    g_queue_head = (g_queue_head + 1u) % M22_FIFO_CAP;
    g_queue_count--;
    g_last_error = M22_ERR_NONE;
    return 1;
}

int m22_provider_core_checkpoint(void)
{
    if (!g_active) {
        reject(M22_ERR_NOT_INITIALIZED);
        return -1;
    }
    if (g_queue_count != 0) {
        reject(M22_ERR_CHECKPOINT_BUSY);
        return -1;
    }
    /* In-process quiescence only; no restart/power-loss replay claim. */
    g_last_error = M22_ERR_NONE;
    return 0;
}

void m22_provider_core_reservation_fault_once(void)
{
    g_reservation_fail_once = 1;
}

uint64_t m22_provider_core_queue_len(void) { return g_queue_count; }
uint64_t m22_provider_core_high_water(void) { return g_high_water; }
uint64_t m22_provider_core_indication(void)
{
    return g_indication_valid ? g_last_indication : UINT64_MAX;
}
uint64_t m22_provider_core_indication_sequence(void)
{
    return g_indication_valid ? g_last_indication_sequence : UINT64_MAX;
}
uint64_t m22_provider_core_last_error(void) { return g_last_error; }
uint64_t m22_provider_core_cue_calls(void) { return i2_rx_cue_calls(); }
