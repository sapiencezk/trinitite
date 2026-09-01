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
#ifdef M37_A_R
int m25_native_prepare_platform(void);
int m25_native_configure_endpoint(const uint8_t *local_mac,
                                   const uint8_t *peer_mac,
                                   const uint8_t *local_ip,
                                   const uint8_t *peer_ip,
                                   uint64_t local_port, uint64_t peer_port);
#ifdef M37_IEC_SERVICE
/* M37 Service-only native seam.  submit() records an exact frame intent;
 * poll_completion() accepts only the matching completed descriptor. */
m25_native_status_t m25_native_submit(const uint8_t *payload, uint32_t payload_len);
m25_native_status_t m25_native_poll_completion(const uint8_t *payload, uint32_t payload_len);
#endif
#endif
/* M27's management demultiplexer receives from the same virtio RX ring. It
 * hands an already-captured data frame back to this adapter without touching
 * the M26 data session. */
void m25_native_accept_frame(const uint8_t *frame, uint32_t frame_len);
void m25_native_set_shared_demux(int enabled);
/* Bounded qualification controls.  They model a deterministic native TX
 * refusal without changing the admitted application/session state. */
void m25_native_test_hold_tx(void);
void m25_native_test_release_tx(void);
#ifdef M37_A_R
/* Test only: submit one frame to virtio, then suppress completion.  This
 * models the real lost-completion window rather than pre-submit ring-full. */
void m25_native_test_lost_completion(void);
void m25_native_test_release_lost_completion(void);
void m25_native_test_delayed_completion(void);
void m25_native_test_release_delayed_completion(void);
#endif
