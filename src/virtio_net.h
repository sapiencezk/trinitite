#pragma once

#include <stdint.h>

typedef enum {
    VIRTIO_NET_OK = 0,
    VIRTIO_NET_NO_PACKET = 1,
    VIRTIO_NET_RING_FULL = 2,
    VIRTIO_NET_DEVICE_FAILURE = 3,
    VIRTIO_NET_MALFORMED = 4,
    VIRTIO_NET_NOT_READY = 5
} virtio_net_status_t;

int virtio_net_init(void);
int virtio_net_config_mac(uint8_t out[6]);
virtio_net_status_t virtio_net_receive(uint8_t *out, uint32_t out_cap,
                                       uint32_t *out_len);
virtio_net_status_t virtio_net_send(const uint8_t *frame, uint32_t len);
int virtio_net_tx_complete(void);
uint64_t virtio_net_rx_packets(void);
uint64_t virtio_net_tx_packets(void);
uint64_t virtio_net_last_error(void);
uint64_t virtio_net_debug_reg(uint32_t offset);
uint64_t virtio_net_debug_status(void);
uint64_t virtio_net_debug_queue_ready(uint32_t queue);
uint64_t virtio_net_debug_tx_used(void);
uint64_t virtio_net_debug_tx_avail(void);
uint64_t virtio_net_debug_tx_packets(void);
#ifdef M23_TEST_CONTROLS
int virtio_net_test_hold_tx(void);
int virtio_net_test_release_tx(void);
int virtio_net_test_corrupt_rx_used(void);
int virtio_net_test_overadvance_rx_used(void);
int virtio_net_test_corrupt_tx_used(void);
int virtio_net_test_overlong_tx_used(void);
#endif
