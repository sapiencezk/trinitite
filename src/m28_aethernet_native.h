#pragma once

#include <stdint.h>

typedef enum {
    M28_NATIVE_OK = 0,
    M28_NATIVE_NO_PACKET = 1,
    M28_NATIVE_MALFORMED = 2,
    M28_NATIVE_CHECKSUM = 4,
    M28_NATIVE_DEVICE = 5,
    M28_NATIVE_RING_FULL = 6
} m28_native_status_t;

typedef struct {
    const uint8_t *header;
    const uint8_t *payload;
    uint32_t payload_len;
} m28_native_datagram_t;

int m28_native_init(void);
m28_native_status_t m28_native_receive(m28_native_datagram_t *out);
m28_native_status_t m28_native_send(const uint8_t *payload, uint32_t payload_len);
