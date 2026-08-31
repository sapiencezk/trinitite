/* M37-A's narrow authenticated transport adapter.
 *
 * This layer owns only the Aethernet/1 header, authentication, endpoint
 * binding, and the retained qemu-virt UDP/IPv6 ownership.  It deliberately
 * returns an opaque Jam byte string to candidate_execution_core. */
#include <stddef.h>
#include <stdint.h>

#include "m37_a_adapter.h"

#ifdef M37_A

#include "m25_aethernet_native.h"
#include "sha256.h"

#define M37_A_HEADER_BYTES 128u
#define M37_A_MAX_DATAGRAM 1200u
#define M37_A_AUTH_BYTES 32u
#define M37_A_KEY_ID 3u
#define M37_A_EPOCH 1ULL
#define M37_A_PROFILE 3u
#define M37_A_WIRE_MAJOR 0u
#define M37_A_WIRE_MINOR 2u
#define M37_A_MESSAGE_KIND 1u

static const uint8_t M37_A_KEY[] =
    "m37-a-candidate-execution-key-0123456789";
static const uint8_t M37_A_DOMAIN[] =
    "1499kernel-aethernet-1-candidate-execution-v1\0";
static const uint8_t M37_A_SCHEMA[32] = {
    0x1c,0x23,0xe8,0x41,0x4c,0x1b,0x98,0x53,
    0x0d,0x58,0x45,0x3c,0x1a,0x90,0xc3,0x39,
    0x28,0xa4,0x5b,0xec,0x9b,0xd7,0xff,0xd1,
    0x05,0x54,0xd3,0x3b,0x22,0x3e,0x30,0x98,
};

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

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void put32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static void put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (56u - 8u * i));
}

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t different = 0;
    for (size_t i = 0; i < len; i++) different |= a[i] ^ b[i];
    return different == 0;
}

static int binding_endpoints_valid(const m37_a_transport_binding_t *binding)
{
    if (!binding || binding->local_device == 0 || binding->peer_device == 0
        || binding->local_device == binding->peer_device
        || binding->local_device != (uint64_t)M24_NODE_ID) return 0;
    if (binding->local_device == 11 && binding->peer_device == 22)
        return binding->local_port == 25911 && binding->peer_port == 25922;
    if (binding->local_device == 22 && binding->peer_device == 11)
        return binding->local_port == 25922 && binding->peer_port == 25911;
    return 0;
}

static void frame_auth(const uint8_t *frame, uint32_t frame_len, uint8_t out[32])
{
    uint8_t input[sizeof M37_A_DOMAIN + M37_A_HEADER_BYTES + M37_A_MAX_PAYLOAD];
    uint32_t domain_len = (uint32_t)(sizeof M37_A_DOMAIN - 1u);
    for (uint32_t i = 0; i < domain_len; i++) input[i] = M37_A_DOMAIN[i];
    for (uint32_t i = 0; i < frame_len; i++) {
        input[domain_len + i] = frame[i];
        if (i >= 96u && i < 128u)
            input[domain_len + i] = 0;
    }
    hmac_sha256(M37_A_KEY, sizeof M37_A_KEY - 1u, input,
                domain_len + frame_len, out);
}

int m37_a_adapter_init(const m37_a_transport_binding_t *binding)
{
    if (!binding_endpoints_valid(binding)
        || binding->profile != M37_A_PROFILE
        || binding->wire_major != M37_A_WIRE_MAJOR
        || binding->wire_minor != M37_A_WIRE_MINOR
        || binding->key_id != M37_A_KEY_ID || binding->epoch != M37_A_EPOCH
        || binding->max_payload != M37_A_MAX_PAYLOAD
        || binding->max_ops != 2000000ULL || binding->max_cells != 128000ULL
        || !equal_bytes(binding->schema_digest, M37_A_SCHEMA, sizeof M37_A_SCHEMA))
        return -1;
    return m25_native_init();
}

m37_a_native_status_t m37_a_adapter_send(
    const m37_a_transport_binding_t *binding, const uint8_t *payload,
    uint32_t payload_len, uint64_t sequence)
{
    uint8_t frame[M37_A_HEADER_BYTES + M37_A_MAX_PAYLOAD];
    uint8_t auth[M37_A_AUTH_BYTES];
    if (!binding_endpoints_valid(binding) || !payload || payload_len == 0
        || payload_len > M37_A_MAX_PAYLOAD || sequence == 0
        || sequence == UINT64_MAX
        || M37_A_HEADER_BYTES + payload_len > M37_A_MAX_DATAGRAM)
        return M37_A_NATIVE_MALFORMED;
    frame[0] = 'A'; frame[1] = 'E'; frame[2] = 'T'; frame[3] = '0';
    frame[4] = M37_A_WIRE_MAJOR; frame[5] = M37_A_WIRE_MINOR;
    frame[6] = M37_A_PROFILE; frame[7] = M37_A_MESSAGE_KIND;
    put16(frame + 8, M37_A_HEADER_BYTES); put16(frame + 10, payload_len);
    put64(frame + 12, binding->local_device);
    put64(frame + 20, binding->peer_device);
    for (unsigned i = 0; i < M37_A_BINDING_BYTES; i++) frame[28 + i] = binding->outbound_binding[i];
    for (unsigned i = 0; i < M37_A_SCHEMA_BYTES; i++) frame[44 + i] = binding->schema_digest[i];
    put32(frame + 76, (uint32_t)binding->key_id);
    put64(frame + 80, binding->epoch); put64(frame + 88, sequence);
    for (unsigned i = 96; i < M37_A_HEADER_BYTES; i++) frame[i] = 0;
    for (uint32_t i = 0; i < payload_len; i++) frame[M37_A_HEADER_BYTES + i] = payload[i];
    frame_auth(frame, M37_A_HEADER_BYTES + payload_len, auth);
    for (unsigned i = 0; i < M37_A_AUTH_BYTES; i++) frame[96 + i] = auth[i];

    switch (m25_native_send(frame, M37_A_HEADER_BYTES + payload_len)) {
    case M25_NATIVE_OK: return M37_A_NATIVE_OK;
    case M25_NATIVE_RING_FULL: return M37_A_NATIVE_RING_FULL;
    case M25_NATIVE_ENDPOINT: return M37_A_NATIVE_ENDPOINT;
    case M25_NATIVE_CHECKSUM: return M37_A_NATIVE_CHECKSUM;
    case M25_NATIVE_MALFORMED: return M37_A_NATIVE_MALFORMED;
    default: return M37_A_NATIVE_DEVICE;
    }
}

m37_a_native_status_t m37_a_adapter_receive(
    const m37_a_transport_binding_t *binding, m37_a_datagram_t *out)
{
    m25_native_datagram_t datagram;
    m25_native_status_t status;
    uint8_t input[M37_A_HEADER_BYTES + M37_A_MAX_PAYLOAD];
    uint8_t auth[M37_A_AUTH_BYTES];
    uint16_t payload_len;
    if (!binding_endpoints_valid(binding) || !out) return M37_A_NATIVE_MALFORMED;
    status = m25_native_receive(&datagram);
    if (status == M25_NATIVE_NO_PACKET) return M37_A_NATIVE_NO_PACKET;
    if (status != M25_NATIVE_OK) {
        if (status == M25_NATIVE_ENDPOINT) return M37_A_NATIVE_ENDPOINT;
        if (status == M25_NATIVE_CHECKSUM) return M37_A_NATIVE_CHECKSUM;
        if (status == M25_NATIVE_MALFORMED) return M37_A_NATIVE_MALFORMED;
        return M37_A_NATIVE_DEVICE;
    }
    if (!datagram.payload || datagram.payload_len < M37_A_HEADER_BYTES
        || datagram.payload_len > M37_A_MAX_DATAGRAM) return M37_A_NATIVE_MALFORMED;
    const uint8_t *frame = datagram.payload;
    if (frame[0] != 'A' || frame[1] != 'E' || frame[2] != 'T' || frame[3] != '0'
        || frame[4] != M37_A_WIRE_MAJOR || frame[5] != M37_A_WIRE_MINOR
        || frame[6] != M37_A_PROFILE || frame[7] != M37_A_MESSAGE_KIND
        || get16(frame + 8) != M37_A_HEADER_BYTES
        || (payload_len = get16(frame + 10)) == 0
        || payload_len > M37_A_MAX_PAYLOAD
        || datagram.payload_len != M37_A_HEADER_BYTES + payload_len) {
        return M37_A_NATIVE_MALFORMED;
    }
    if (get64(frame + 12) != binding->peer_device) {
        return M37_A_NATIVE_ENDPOINT;
    }
    if (get64(frame + 20) != binding->local_device) {
        return M37_A_NATIVE_ENDPOINT;
    }
    if (!equal_bytes(frame + 28, binding->inbound_binding, M37_A_BINDING_BYTES)) {
        return M37_A_NATIVE_ENDPOINT;
    }
    if (!equal_bytes(frame + 44, binding->schema_digest, M37_A_SCHEMA_BYTES)) {
        return M37_A_NATIVE_ENDPOINT;
    }
    uint32_t frame_key_id = get32(frame + 76);
    if (frame_key_id != binding->key_id) {
        return M37_A_NATIVE_ENDPOINT;
    }
    if (get64(frame + 80) != binding->epoch) {
        return M37_A_NATIVE_ENDPOINT;
    }
    if (get64(frame + 88) == 0 || get64(frame + 88) == UINT64_MAX) {
        return M37_A_NATIVE_ENDPOINT;
    }
    for (uint32_t i = 0; i < datagram.payload_len; i++) input[i] = frame[i];
    for (unsigned i = 96; i < M37_A_HEADER_BYTES; i++) input[i] = 0;
    frame_auth(input, datagram.payload_len, auth);
    if (!equal_bytes(auth, frame + 96, M37_A_AUTH_BYTES)) {
        return M37_A_NATIVE_CHECKSUM;
    }
    out->payload = frame + M37_A_HEADER_BYTES;
    out->payload_len = payload_len;
    out->sequence = get64(frame + 88);
    return M37_A_NATIVE_OK;
}

int m37_a_adapter_tx_pending(void)
{
    return m25_native_tx_pending();
}

#else

int m37_a_adapter_init(const m37_a_transport_binding_t *binding) { (void)binding; return -1; }
m37_a_native_status_t m37_a_adapter_send(const m37_a_transport_binding_t *binding,
                                         const uint8_t *payload, uint32_t payload_len,
                                         uint64_t sequence)
{ (void)binding; (void)payload; (void)payload_len; (void)sequence; return M37_A_NATIVE_DEVICE; }
m37_a_native_status_t m37_a_adapter_receive(const m37_a_transport_binding_t *binding,
                                            m37_a_datagram_t *out)
{ (void)binding; (void)out; return M37_A_NATIVE_DEVICE; }
int m37_a_adapter_tx_pending(void) { return 0; }

#endif
