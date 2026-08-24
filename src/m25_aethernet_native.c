/* M25's fixed qemu-virt Aethernet/0 endpoint projection.  This is a bounded
 * sibling of the frozen M24 native adapter: the port and profile are M25
 * plan facts, while virtio ownership and IPv6/UDP framing remain the named
 * qemu-virt platform contract. */
#include <stdint.h>

#include "m25_aethernet_native.h"
#include "platform.h"
#include "virtio_net.h"

#define ETH_BYTES 14u
#define IPV6_BYTES 40u
#define UDP_BYTES 8u
#define MAX_PAYLOAD 1200u
#define FRAME_BYTES (ETH_BYTES + IPV6_BYTES + UDP_BYTES + MAX_PAYLOAD)

#if defined(M24_NODE_ID) && M24_NODE_ID == 11
#define LOCAL_PORT 25911u
#define PEER_PORT 25922u
static const uint8_t LOCAL_MAC[6] = {2,0,0,0,0,0x0b};
static const uint8_t PEER_MAC[6] = {2,0,0,0,0,0x16};
static const uint8_t LOCAL_IP[16] = {0xfd,0,0x00,0x14,0x99,0x24,0,0,0,0,0,0,0,0,0,0x0b};
static const uint8_t PEER_IP[16] = {0xfd,0,0x00,0x14,0x99,0x24,0,0,0,0,0,0,0,0,0,0x16};
#else
#define LOCAL_PORT 25922u
#define PEER_PORT 25911u
static const uint8_t LOCAL_MAC[6] = {2,0,0,0,0,0x16};
static const uint8_t PEER_MAC[6] = {2,0,0,0,0,0x0b};
static const uint8_t LOCAL_IP[16] = {0xfd,0,0x00,0x14,0x99,0x24,0,0,0,0,0,0,0,0,0,0x16};
static const uint8_t PEER_IP[16] = {0xfd,0,0x00,0x14,0x99,0x24,0,0,0,0,0,0,0,0,0,0x0b};
#endif

static uint8_t g_rx[FRAME_BYTES] __attribute__((aligned(16)));
static uint8_t g_tx[FRAME_BYTES] __attribute__((aligned(16)));
static uint8_t g_pending[MAX_PAYLOAD];
static uint32_t g_pending_len;
static int g_pending_tx;

static uint16_t be16(const volatile uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static void put16(volatile uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8); p[1] = (uint8_t)value;
}

static void put32(volatile uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24); p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8); p[3] = (uint8_t)value;
}

static int same(const volatile uint8_t *a, const uint8_t *b, uint32_t len)
{
    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static uint32_t add_words(uint32_t sum, const volatile uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i + 1u < len; i += 2u)
        sum += ((uint32_t)p[i] << 8) | p[i + 1u];
    if (len & 1u) sum += (uint32_t)p[len - 1u] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

static uint16_t checksum(const volatile uint8_t *ip,
                         const volatile uint8_t *udp, uint32_t udp_len)
{
    uint32_t sum = add_words(0, ip + 8, 32);
    uint8_t length[4]; put32(length, udp_len); sum = add_words(sum, length, 4);
    uint8_t next[4] = {0,0,0,17}; sum = add_words(sum, next, 4);
    sum = add_words(sum, udp, udp_len);
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

int m25_native_init(void)
{
    uint8_t mac[6];
    g_pending_tx = 0; g_pending_len = 0;
    return virtio_net_init() != 0 || virtio_net_config_mac(mac) != 0
        || !same(mac, LOCAL_MAC, 6) ? -1 : 0;
}

m25_native_status_t m25_native_receive(m25_native_datagram_t *out)
{
    uint32_t frame_len = 0;
    if (!out) return M25_NATIVE_MALFORMED;
    virtio_net_status_t got = virtio_net_receive(g_rx, sizeof g_rx, &frame_len);
    if (got == VIRTIO_NET_NO_PACKET) return M25_NATIVE_NO_PACKET;
    if (got != VIRTIO_NET_OK || frame_len < ETH_BYTES + IPV6_BYTES + UDP_BYTES
        || frame_len > sizeof g_rx) return M25_NATIVE_DEVICE;
    volatile const uint8_t *eth = g_rx, *ip = eth + ETH_BYTES;
    if (be16(eth + 12) != 0x86ddu || !same(eth, LOCAL_MAC, 6)
        || !same(eth + 6, PEER_MAC, 6)) return M25_NATIVE_ENDPOINT;
    if ((ip[0] >> 4) != 6 || ip[6] != 17 || ip[7] != 64
        || !same(ip + 8, PEER_IP, 16) || !same(ip + 24, LOCAL_IP, 16))
        return M25_NATIVE_ENDPOINT;
    uint32_t udp_len = be16(ip + 4);
    if (udp_len < UDP_BYTES || udp_len > UDP_BYTES + MAX_PAYLOAD
        || frame_len != ETH_BYTES + IPV6_BYTES + udp_len) return M25_NATIVE_MALFORMED;
    volatile const uint8_t *udp = ip + IPV6_BYTES;
    if (be16(udp) != PEER_PORT || be16(udp + 2) != LOCAL_PORT
        || be16(udp + 6) == 0 || checksum(ip, udp, udp_len) != 0)
        return M25_NATIVE_CHECKSUM;
    out->payload = (const uint8_t *)(udp + UDP_BYTES);
    out->payload_len = udp_len - UDP_BYTES;
    return M25_NATIVE_OK;
}

m25_native_status_t m25_native_send(const uint8_t *payload, uint32_t payload_len)
{
    if (!payload || payload_len == 0 || payload_len > MAX_PAYLOAD) return M25_NATIVE_MALFORMED;
    if (g_pending_tx) {
        int complete = virtio_net_tx_complete();
        if (complete == 1) {
            int equal = payload_len == g_pending_len;
            for (uint32_t i = 0; equal && i < payload_len; i++) equal = payload[i] == g_pending[i];
            g_pending_tx = 0; g_pending_len = 0;
            return equal ? M25_NATIVE_OK : M25_NATIVE_DEVICE;
        }
        return M25_NATIVE_RING_FULL;
    }
    volatile uint8_t *eth = g_tx, *ip = eth + ETH_BYTES, *udp = ip + IPV6_BYTES;
    for (uint32_t i = 0; i < 6; i++) { eth[i] = PEER_MAC[i]; eth[6+i] = LOCAL_MAC[i]; }
    put16(eth + 12, 0x86ddu);
    ip[0] = 0x60; ip[1] = ip[2] = ip[3] = 0;
    put16(ip + 4, UDP_BYTES + payload_len); ip[6] = 17; ip[7] = 64;
    for (uint32_t i = 0; i < 16; i++) { ip[8+i] = LOCAL_IP[i]; ip[24+i] = PEER_IP[i]; }
    put16(udp, LOCAL_PORT); put16(udp + 2, PEER_PORT);
    put16(udp + 4, UDP_BYTES + payload_len); put16(udp + 6, 0);
    for (uint32_t i = 0; i < payload_len; i++) udp[UDP_BYTES+i] = payload[i];
    put16(udp + 6, checksum(ip, udp, UDP_BYTES + payload_len));
    virtio_net_status_t status = virtio_net_send(g_tx, ETH_BYTES + IPV6_BYTES + UDP_BYTES + payload_len);
    if (status == VIRTIO_NET_OK || virtio_net_tx_complete() == 1) return M25_NATIVE_OK;
    if (status == VIRTIO_NET_RING_FULL || status == VIRTIO_NET_DEVICE_FAILURE) {
        g_pending_tx = 1; g_pending_len = payload_len;
        for (uint32_t i = 0; i < payload_len; i++) g_pending[i] = payload[i];
        return M25_NATIVE_RING_FULL;
    }
    return M25_NATIVE_DEVICE;
}

int m25_native_tx_pending(void) { return g_pending_tx; }
