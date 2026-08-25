#pragma once

#include <stdint.h>

typedef enum {
    M25_NATIVE_OK = 0,
    M25_NATIVE_NO_PACKET = 1,
    M25_NATIVE_MALFORMED = 2,
    M25_NATIVE_ENDPOINT = 3,
    M25_NATIVE_CHECKSUM = 4,
    M25_NATIVE_DEVICE = 5,
    M25_NATIVE_RING_FULL = 6
} m25_native_status_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
} m25_native_datagram_t;

int m25_native_init(void);
m25_native_status_t m25_native_receive(m25_native_datagram_t *out);
m25_native_status_t m25_native_send(const uint8_t *payload, uint32_t payload_len);
int m25_native_tx_pending(void);
/* Bounded qualification controls.  They model a deterministic native TX
 * refusal without changing the admitted application/session state. */
void m25_native_test_hold_tx(void);
void m25_native_test_release_tx(void);
