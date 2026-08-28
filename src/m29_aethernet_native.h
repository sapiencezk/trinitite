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
/* Whether the most recent send call advanced the bounded TX avail index. */
int m29_native_last_send_submitted(void);
/* -1 is a driver error, 0 is an in-flight descriptor, and 1 is available
 * for a new bounded response submission. */
int m29_native_tx_complete(void);
#ifdef M32_TEST_CONTROLS
int m29_native_test_fail_tx_once(void);
int m29_native_test_fail_tx_persistent(void);
uint64_t m29_native_test_rx_packets(void);
uint64_t m29_native_test_rx_errors(void);
uint64_t m29_native_test_rx_last_status(void);
uint64_t m29_native_test_tx_submit_attempts(void);
uint64_t m29_native_test_tx_submit_failures(void);
uint64_t m29_native_test_tx_last_status(void);
uint64_t m29_native_test_tx_completion_calls(void);
uint64_t m29_native_test_tx_last_completion(void);
#endif
