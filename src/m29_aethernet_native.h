#pragma once

#include <stdint.h>

typedef enum {
    M29_NATIVE_OK = 0,
    M29_NATIVE_NO_PACKET = 1,
    M29_NATIVE_MALFORMED = 2,
    M29_NATIVE_CHECKSUM = 4,
    M29_NATIVE_DEVICE = 5,
    M29_NATIVE_RING_FULL = 6
} m29_native_status_t;

typedef struct {
    const uint8_t *header;
    const uint8_t *payload;
    uint32_t payload_len;
} m29_native_datagram_t;

int m29_native_init(void);
m29_native_status_t m29_native_receive(m29_native_datagram_t *out);
m29_native_status_t m29_native_send(const uint8_t *payload, uint32_t payload_len);
