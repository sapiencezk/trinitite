#pragma once

#include <stdint.h>

#define M37_A_MAX_PAYLOAD 512u
#define M37_A_BINDING_BYTES 16u
#define M37_A_SCHEMA_BYTES 32u
#define M37_A_DOMAIN_BYTES 32u

typedef struct {
    uint64_t local_device;
    uint64_t peer_device;
    uint64_t profile;
    uint64_t wire_major;
    uint64_t wire_minor;
    uint64_t key_id;
    uint64_t epoch;
    uint64_t local_port;
    uint64_t peer_port;
    uint64_t max_payload;
    uint64_t max_ops;
    uint64_t max_cells;
    uint8_t outbound_binding[M37_A_BINDING_BYTES];
    uint8_t inbound_binding[M37_A_BINDING_BYTES];
    uint8_t schema_digest[M37_A_SCHEMA_BYTES];
    uint8_t domain_digest[M37_A_DOMAIN_BYTES];
    uint64_t peer_descriptor[11];
} m37_a_transport_binding_t;

typedef enum {
    M37_A_NATIVE_OK = 0,
    M37_A_NATIVE_NO_PACKET = 1,
    M37_A_NATIVE_MALFORMED = 2,
    M37_A_NATIVE_ENDPOINT = 3,
    M37_A_NATIVE_CHECKSUM = 4,
    M37_A_NATIVE_DEVICE = 5,
    M37_A_NATIVE_RING_FULL = 6,
} m37_a_native_status_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
    uint64_t sequence;
} m37_a_datagram_t;

int m37_a_adapter_init(const m37_a_transport_binding_t *binding);
m37_a_native_status_t m37_a_adapter_send(
    const m37_a_transport_binding_t *binding, const uint8_t *payload,
    uint32_t payload_len, uint64_t sequence);
m37_a_native_status_t m37_a_adapter_receive(
    const m37_a_transport_binding_t *binding, m37_a_datagram_t *out);
int m37_a_adapter_tx_pending(void);
