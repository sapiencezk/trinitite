#include <stdint.h>

#include "aethernet_native.h"
#include "platform.h"
#include "virtio_net.h"

#define ETH_HEADER_BYTES 14u
#define IPV6_HEADER_BYTES 40u
#define UDP_HEADER_BYTES 8u
#define NATIVE_MAX_UDP_PAYLOAD 1200u
#define NATIVE_FRAME_BYTES (ETH_HEADER_BYTES + IPV6_HEADER_BYTES + UDP_HEADER_BYTES + NATIVE_MAX_UDP_PAYLOAD)
#define AETHERNET_UDP_PORT 14990u

#if defined(M24_NODE_ID) && M24_NODE_ID == 11
static const uint8_t LOCAL_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};
static const uint8_t PEER_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x16};
static const uint8_t LOCAL_IP[16] = {0xfd,0x00,0x14,0x99,0x00,0x24,0,0,0,0,0,0,0,0,0,0x0b};
static const uint8_t PEER_IP[16] = {0xfd,0x00,0x14,0x99,0x00,0x24,0,0,0,0,0,0,0,0,0,0x16};
#else
static const uint8_t LOCAL_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x16};
static const uint8_t PEER_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0b};
static const uint8_t LOCAL_IP[16] = {0xfd,0x00,0x14,0x99,0x00,0x24,0,0,0,0,0,0,0,0,0,0x16};
static const uint8_t PEER_IP[16] = {0xfd,0x00,0x14,0x99,0x00,0x24,0,0,0,0,0,0,0,0,0,0x0b};
#endif

static uint8_t g_rx_frame[NATIVE_FRAME_BYTES] __attribute__((aligned(16)));
static uint8_t g_tx_frame[NATIVE_FRAME_BYTES] __attribute__((aligned(16)));
static uint8_t g_pending_payload[NATIVE_MAX_UDP_PAYLOAD];
static uint32_t g_pending_payload_len;
static uint64_t g_last_error;
static int g_pending_tx;

static uint16_t be16(const volatile uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void put16(volatile uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

static void put32(volatile uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static int same_bytes(const volatile uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t diff = 0; for (uint32_t i = 0; i < len; i++) diff |= a[i] ^ b[i]; return diff == 0;
}

static uint32_t add_words(uint32_t sum, const volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i + 1u < len; i += 2u) sum += ((uint32_t)p[i] << 8) | p[i + 1u];
    if (len & 1u) sum += (uint32_t)p[len - 1u] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

static uint16_t udp_checksum(const volatile uint8_t *ip,
                             const volatile uint8_t *udp, uint32_t udp_len)
{
    uint32_t sum = 0;
    sum = add_words(sum, ip + 8, 32);
    uint8_t length[4]; put32(length, udp_len); sum = add_words(sum, length, 4);
    uint8_t next[4] = {0, 0, 0, 17}; sum = add_words(sum, next, 4);
    sum = add_words(sum, udp, udp_len);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

int m24_native_init(void)
{
    uint8_t mac[6];
    g_last_error = 0; g_pending_tx = 0; g_pending_payload_len = 0;
    if (virtio_net_init() != 0 || virtio_net_config_mac(mac) != 0
        || !same_bytes(mac, LOCAL_MAC, 6)) { g_last_error = 1; return -1; }
    return 0;
}

m24_native_status_t m24_native_receive(m24_native_datagram_t *out)
{
    uint32_t frame_len = 0;
    if (!out) return M24_NATIVE_MALFORMED_ETHERNET;
    virtio_net_status_t got = virtio_net_receive(g_rx_frame, sizeof g_rx_frame, &frame_len);
    if (got == VIRTIO_NET_NO_PACKET) return M24_NATIVE_NO_PACKET;
    if (got != VIRTIO_NET_OK) { g_last_error = got; return M24_NATIVE_DEVICE; }
    if (frame_len < ETH_HEADER_BYTES + IPV6_HEADER_BYTES + UDP_HEADER_BYTES
        || frame_len > sizeof g_rx_frame) { g_last_error = 2; return M24_NATIVE_MALFORMED_ETHERNET; }
    volatile const uint8_t *eth = g_rx_frame, *ip = eth + ETH_HEADER_BYTES;
    if (be16(eth + 12) != 0x86ddu || !same_bytes(eth, LOCAL_MAC, 6)
        || !same_bytes(eth + 6, PEER_MAC, 6)) { g_last_error = 3; return M24_NATIVE_ENDPOINT; }
    if ((ip[0] >> 4) != 6 || ip[6] != 17 || ip[7] != 64
        || !same_bytes(ip + 8, PEER_IP, 16) || !same_bytes(ip + 24, LOCAL_IP, 16)) {
        g_last_error = 4; return M24_NATIVE_MALFORMED_IPV6;
    }
    uint32_t udp_len = be16(ip + 4);
    if (udp_len < UDP_HEADER_BYTES || udp_len > NATIVE_MAX_UDP_PAYLOAD + UDP_HEADER_BYTES
        || frame_len != ETH_HEADER_BYTES + IPV6_HEADER_BYTES + udp_len) {
        g_last_error = 5; return M24_NATIVE_MALFORMED_IPV6;
    }
    volatile const uint8_t *udp = ip + IPV6_HEADER_BYTES;
    if (be16(udp) != AETHERNET_UDP_PORT || be16(udp + 2) != AETHERNET_UDP_PORT) {
        g_last_error = 6; return M24_NATIVE_ENDPOINT;
    }
    if (be16(udp + 6) == 0 || udp_checksum(ip, udp, udp_len) != 0) {
        g_last_error = 6; return M24_NATIVE_CHECKSUM;
    }
    out->payload = (const uint8_t *)(udp + UDP_HEADER_BYTES);
    out->payload_len = udp_len - UDP_HEADER_BYTES;
    return M24_NATIVE_OK;
}

m24_native_status_t m24_native_send(const uint8_t *payload, uint32_t payload_len)
{
    if (!payload || payload_len == 0 || payload_len > NATIVE_MAX_UDP_PAYLOAD) return M24_NATIVE_MALFORMED_ETHERNET;
    if (g_pending_tx) {
        int complete = virtio_net_tx_complete();
        if (complete == 1) {
            int same = payload_len == g_pending_payload_len;
            for (uint32_t i = 0; same && i < payload_len; i++)
                same = payload[i] == g_pending_payload[i];
            g_pending_tx = 0; g_pending_payload_len = 0;
            if (!same) { g_last_error = 9; return M24_NATIVE_DEVICE; }
            g_last_error = 0; return M24_NATIVE_OK;
        }
        g_last_error = complete < 0 ? 8 : VIRTIO_NET_RING_FULL;
        return M24_NATIVE_RING_FULL;
    }
    volatile uint8_t *eth = g_tx_frame, *ip = eth + ETH_HEADER_BYTES;
    volatile uint8_t *udp = ip + IPV6_HEADER_BYTES;
    for (uint32_t i = 0; i < 6; i++) { eth[i] = PEER_MAC[i]; eth[6 + i] = LOCAL_MAC[i]; }
    put16(eth + 12, 0x86ddu);
    ip[0] = 0x60; ip[1] = 0; ip[2] = 0; ip[3] = 0;
    put16(ip + 4, UDP_HEADER_BYTES + payload_len); ip[6] = 17; ip[7] = 64;
    for (uint32_t i = 0; i < 16; i++) { ip[8 + i] = LOCAL_IP[i]; ip[24 + i] = PEER_IP[i]; }
    put16(udp, AETHERNET_UDP_PORT); put16(udp + 2, AETHERNET_UDP_PORT);
    put16(udp + 4, UDP_HEADER_BYTES + payload_len); put16(udp + 6, 0);
    for (uint32_t i = 0; i < payload_len; i++) udp[UDP_HEADER_BYTES + i] = payload[i];
    put16(udp + 6, udp_checksum(ip, udp, UDP_HEADER_BYTES + payload_len));
    virtio_net_status_t status = virtio_net_send(g_tx_frame, ETH_HEADER_BYTES + IPV6_HEADER_BYTES + UDP_HEADER_BYTES + payload_len);
    if (status == VIRTIO_NET_OK) return M24_NATIVE_OK;
    if (virtio_net_tx_complete() == 1) return M24_NATIVE_OK;
    if (status == VIRTIO_NET_DEVICE_FAILURE || status == VIRTIO_NET_RING_FULL) {
        g_pending_tx = 1;
        g_pending_payload_len = payload_len;
        for (uint32_t i = 0; i < payload_len; i++) g_pending_payload[i] = payload[i];
    }
    g_last_error = status;
    return status == VIRTIO_NET_RING_FULL ? M24_NATIVE_RING_FULL : M24_NATIVE_DEVICE;
}

int m24_native_tx_pending(void) { return g_pending_tx; }

uint64_t m24_native_rx_packets(void) { return virtio_net_rx_packets(); }
uint64_t m24_native_tx_packets(void) { return virtio_net_tx_packets(); }
uint64_t m24_native_last_error(void) { return g_last_error; }
