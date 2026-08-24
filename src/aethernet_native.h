#pragma once

#include <stdint.h>

typedef enum {
    M24_NATIVE_OK = 0,
    M24_NATIVE_NO_PACKET = 1,
    M24_NATIVE_MALFORMED_ETHERNET = 2,
    M24_NATIVE_MALFORMED_IPV6 = 3,
    M24_NATIVE_ENDPOINT = 4,
    M24_NATIVE_CHECKSUM = 5,
    M24_NATIVE_DEVICE = 6,
    M24_NATIVE_RING_FULL = 7
} m24_native_status_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
} m24_native_datagram_t;

int m24_native_init(void);
m24_native_status_t m24_native_receive(m24_native_datagram_t *out);
m24_native_status_t m24_native_send(const uint8_t *payload, uint32_t payload_len);
int m24_native_tx_pending(void);
uint64_t m24_native_rx_packets(void);
uint64_t m24_native_tx_packets(void);
uint64_t m24_native_last_error(void);
