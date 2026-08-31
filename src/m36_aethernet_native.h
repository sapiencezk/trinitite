#pragma once

#include <stdint.h>

/* M36 owns a distinct semantic endpoint.  The qemu-virt Ethernet/IPv6/UDP
 * driver is deliberately shared as a platform seam with the predecessor;
 * profile admission and frame contents remain M36-owned. */
typedef enum {
    M36_NATIVE_OK = 0,
    M36_NATIVE_NO_PACKET = 1,
    M36_NATIVE_MALFORMED = 2,
    M36_NATIVE_ENDPOINT = 3,
    M36_NATIVE_CHECKSUM = 4,
    M36_NATIVE_DEVICE = 5,
    M36_NATIVE_RING_FULL = 6
} m36_native_status_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
} m36_native_datagram_t;

int m36_native_init(void);
m36_native_status_t m36_native_receive(m36_native_datagram_t *out);
m36_native_status_t m36_native_send(const uint8_t *payload, uint32_t payload_len);
int m36_native_tx_pending(void);
