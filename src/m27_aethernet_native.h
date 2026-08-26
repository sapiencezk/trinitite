#pragma once

#include <stdint.h>

typedef enum {
    M27_NATIVE_OK = 0,
    M27_NATIVE_NO_PACKET = 1,
    M27_NATIVE_MALFORMED = 2,
    M27_NATIVE_ENDPOINT = 3,
    M27_NATIVE_CHECKSUM = 4,
    M27_NATIVE_DEVICE = 5,
    M27_NATIVE_RING_FULL = 6
} m27_native_status_t;

typedef struct {
    const uint8_t *header;
    const uint8_t *payload;
    uint32_t payload_len;
} m27_native_datagram_t;

int m27_native_init(void);
m27_native_status_t m27_native_receive(m27_native_datagram_t *out);
m27_native_status_t m27_native_send(const uint8_t *payload, uint32_t payload_len);
