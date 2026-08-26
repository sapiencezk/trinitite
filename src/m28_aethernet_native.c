#include <stdint.h>

#include "m25_aethernet_native.h"
#include "m28_aethernet_native.h"
#include "platform.h"
#include "virtio_net.h"

#define ETH_BYTES 14u
#define IPV6_BYTES 40u
#define UDP_BYTES 8u
#define HEADER_BYTES 128u
#define MAX_PAYLOAD 512u
#define MAX_FRAME_PAYLOAD (HEADER_BYTES + MAX_PAYLOAD)
#define FRAME_BYTES (ETH_BYTES + IPV6_BYTES + UDP_BYTES + MAX_FRAME_PAYLOAD)
#define MANAGER_PORT 25933u
#define TARGET_PORT 25927u

#if M24_NODE_ID == 11
static const uint8_t LOCAL_MAC[6] = {2,0,0,0,0,0x0b};
static const uint8_t LOCAL_IP[16] = {0xfd,0,0x14,0x99,0x27,0,0,0,0,0,0,0,0,0,0,0x0b};
#else
static const uint8_t LOCAL_MAC[6] = {2,0,0,0,0,0x16};
static const uint8_t LOCAL_IP[16] = {0xfd,0,0x14,0x99,0x27,0,0,0,0,0,0,0,0,0,0,0x16};
#endif
static const uint8_t MANAGER_MAC[6] = {2,0,0,0,0,0x21};
static const uint8_t MANAGER_IP[16] = {0xfd,0,0x14,0x99,0x27,0,0,0,0,0,0,0,0,0,0,0x21};

static uint8_t g_rx[FRAME_BYTES] __attribute__((aligned(16)));
static uint8_t g_tx[FRAME_BYTES] __attribute__((aligned(16)));
static int g_initialized;

static uint16_t be16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static void put16(uint8_t *p, uint16_t v) { volatile uint8_t *out=p; out[0] = (uint8_t)(v >> 8); out[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { volatile uint8_t *out=p; out[0]=v>>24; out[1]=v>>16; out[2]=v>>8; out[3]=v; }
static int same(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint8_t d = 0; for (uint32_t i=0; i<n; i++) d |= a[i] ^ b[i]; return d == 0;
}
static uint32_t add_words(uint32_t sum, const uint8_t *p, uint32_t n)
{
    for (uint32_t i=0; i+1<n; i+=2) sum += ((uint32_t)p[i]<<8) | p[i+1];
    if (n & 1u) sum += (uint32_t)p[n-1] << 8;
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}
static uint16_t checksum(const uint8_t *ip, const uint8_t *udp, uint32_t n)
{
    uint32_t sum=add_words(0,ip+8,32); uint8_t l[4]; put32(l,n);
    sum=add_words(sum,l,4); { uint8_t next[4]={0,0,0,17}; sum=add_words(sum,next,4); }
    sum=add_words(sum,udp,n); while(sum>>16) sum=(sum&0xffffu)+(sum>>16); return (uint16_t)~sum;
}

int m28_native_init(void)
{
    uint8_t mac[6]; g_initialized=0;
    if (virtio_net_config_mac(mac) != 0 || !same(mac, LOCAL_MAC, 6)) return -1;
    m25_native_set_shared_demux(1); g_initialized=1; return 0;
}

m28_native_status_t m28_native_receive(m28_native_datagram_t *out)
{
    uint32_t length=0; if (!out || !g_initialized) return M28_NATIVE_MALFORMED;
    virtio_net_status_t got=virtio_net_receive(g_rx,sizeof g_rx,&length);
    if (got==VIRTIO_NET_NO_PACKET) return M28_NATIVE_NO_PACKET;
    if (got!=VIRTIO_NET_OK || length<ETH_BYTES+IPV6_BYTES+UDP_BYTES || length>sizeof g_rx) return M28_NATIVE_DEVICE;
    const uint8_t *eth=g_rx,*ip=eth+ETH_BYTES;
    if (be16(eth+12)!=0x86ddu || !same(eth,LOCAL_MAC,6) || !same(eth+6,MANAGER_MAC,6)
        || (ip[0]>>4)!=6 || ip[6]!=17 || ip[7]!=64 || !same(ip+8,MANAGER_IP,16)
        || !same(ip+24,LOCAL_IP,16)) { m25_native_accept_frame(g_rx,length); return M28_NATIVE_NO_PACKET; }
    uint32_t udp_len=be16(ip+4); const uint8_t *udp=ip+IPV6_BYTES;
    if (udp_len<UDP_BYTES+HEADER_BYTES || udp_len>UDP_BYTES+MAX_FRAME_PAYLOAD
        || length!=ETH_BYTES+IPV6_BYTES+udp_len || be16(udp)!=MANAGER_PORT
        || be16(udp+2)!=TARGET_PORT || be16(udp+6)==0 || checksum(ip,udp,udp_len)!=0) return M28_NATIVE_CHECKSUM;
    out->header=udp+UDP_BYTES; out->payload=udp+UDP_BYTES+HEADER_BYTES;
    out->payload_len=udp_len-UDP_BYTES-HEADER_BYTES;
    return out->payload_len ? M28_NATIVE_OK : M28_NATIVE_MALFORMED;
}

m28_native_status_t m28_native_send(const uint8_t *payload, uint32_t payload_len)
{
    if (!payload || !payload_len || payload_len>MAX_FRAME_PAYLOAD || !g_initialized) return M28_NATIVE_MALFORMED;
    uint8_t *eth=g_tx,*ip=eth+ETH_BYTES,*udp=ip+IPV6_BYTES;
    volatile uint8_t *vip=ip;
    for(unsigned i=0;i<6;i++){eth[i]=MANAGER_MAC[i];eth[6+i]=LOCAL_MAC[i];} put16(eth+12,0x86ddu);
    vip[0]=0x60;vip[1]=vip[2]=vip[3]=0;put16(ip+4,UDP_BYTES+payload_len);vip[6]=17;vip[7]=64;
    for(unsigned i=0;i<16;i++){ip[8+i]=LOCAL_IP[i];ip[24+i]=MANAGER_IP[i];}
    put16(udp,TARGET_PORT);put16(udp+2,MANAGER_PORT);put16(udp+4,UDP_BYTES+payload_len);put16(udp+6,0);
    for(uint32_t i=0;i<payload_len;i++) udp[UDP_BYTES+i]=payload[i];
    put16(udp+6,checksum(ip,udp,UDP_BYTES+payload_len));
    virtio_net_status_t status=virtio_net_send(g_tx,ETH_BYTES+IPV6_BYTES+UDP_BYTES+payload_len);
    return status==VIRTIO_NET_OK?M28_NATIVE_OK:(status==VIRTIO_NET_RING_FULL?M28_NATIVE_RING_FULL:M28_NATIVE_DEVICE);
}
