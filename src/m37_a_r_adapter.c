/* M37-A-R adapter.  Header and payload semantics are exactly M36-T; the
 * candidate binding supplies the endpoint/channel identity consumed here. */
#include <stddef.h>
#include <stdint.h>

#include "m37_a_r_adapter.h"

#ifdef M37_A_R

#include "m36_aethernet_native.h"
#include "m25_aethernet_native.h"
#include "sha256.h"

#define HEADER_BYTES 128u
#define MAX_DATAGRAM 1200u
#define AUTH_BYTES 32u
#define PROFILE 2u
#define WIRE_MAJOR 0u
#define WIRE_MINOR 1u
#define MESSAGE_KIND 1u
#define KEY_ID 1u
#define EPOCH 1ULL

static const uint8_t KEY[] = "m36-typed-scalar-key-0123456789";
static const uint8_t DOMAIN[] = "1499kernel-aethernet-1-typed-scalar-v1\0";
static const uint8_t SCHEMA[32] = {
    0x6f,0x4f,0x4c,0x8d,0xc7,0x15,0x52,0x23,
    0x6a,0x4b,0x47,0xc4,0x7f,0xa8,0x70,0xf2,
    0x05,0x6d,0x07,0x05,0xaf,0x87,0x91,0xb7,
    0x66,0xf3,0xdb,0xec,0x20,0xd1,0x0b,0x6b,
};
static const uint8_t DOMAIN_DIGEST[32] = {
    0xf0,0xac,0x6a,0xcd,0x72,0x4c,0x19,0xa0,
    0x28,0x61,0x7d,0x26,0x1c,0x4c,0xcf,0x82,
    0x0c,0x32,0x82,0x4e,0x9b,0x80,0x55,0xa8,
    0x9f,0x26,0x8d,0x84,0xc3,0xae,0xb6,0x61,
};

static uint16_t get16(const volatile uint8_t *p)
{ return ((uint16_t)p[0] << 8) | p[1]; }
static uint32_t get32(const volatile uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint64_t get64(const volatile uint8_t *p)
{ uint64_t n=0; for (unsigned i=0;i<8;i++) n=(n<<8)|p[i]; return n; }
static void put16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static void put32(uint8_t *p, uint32_t n) { p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n; }
static void put64(uint8_t *p, uint64_t n) { for (unsigned i=0;i<8;i++) p[i]=(uint8_t)(n>>(56u-8u*i)); }
static int same(const uint8_t *a, const uint8_t *b, size_t n)
{ uint8_t d=0; for (size_t i=0;i<n;i++) d|=a[i]^b[i]; return d==0; }

static int endpoints(const m37_a_r_transport_binding_t *b)
{
    if (!b || b->local_device != (uint64_t)M24_NODE_ID
        || !b->peer_device || b->peer_device == b->local_device
        || (b->role != 1 && b->role != 2) || !b->channel
        || !b->local_port || b->local_port > 65535u
        || !b->peer_port || b->peer_port > 65535u) return 0;
    if (same(b->local_mac, b->peer_mac, 6)
        || same(b->local_ip, b->peer_ip, 16)) return 0;
    return 1;
}

static void auth(const uint8_t *frame, uint32_t length, uint8_t out[32])
{
    uint8_t input[sizeof DOMAIN + HEADER_BYTES + M37_A_R_MAX_PAYLOAD];
    uint32_t domain_length=(uint32_t)(sizeof DOMAIN-1u);
    for (uint32_t i=0;i<domain_length;i++) input[i]=DOMAIN[i];
    for (uint32_t i=0;i<length;i++) input[domain_length+i]=(i>=96u&&i<128u)?0:frame[i];
    hmac_sha256(KEY,sizeof KEY-1u,input,domain_length+length,out);
}

int m37_a_r_adapter_init(const m37_a_r_transport_binding_t *b)
{
    if (!endpoints(b) || b->profile != PROFILE || b->wire_major != WIRE_MAJOR
        || b->wire_minor != WIRE_MINOR || b->key_id != KEY_ID
        || b->epoch != EPOCH || b->max_payload != M37_A_R_MAX_PAYLOAD
        || b->max_ops != 2000000ULL || b->max_cells != 128000ULL
        || !same(b->schema_digest,SCHEMA,32) || !same(b->domain_digest,DOMAIN_DIGEST,32)
        || m25_native_configure_endpoint(b->local_mac, b->peer_mac,
                                          b->local_ip, b->peer_ip,
                                          b->local_port, b->peer_port) != 0) return -1;
    return m36_native_init();
}

m37_a_r_native_status_t m37_a_r_adapter_send(
    const m37_a_r_transport_binding_t *b, const uint8_t *payload,
    uint32_t payload_len, uint64_t sequence)
{
    uint8_t frame[HEADER_BYTES+M37_A_R_MAX_PAYLOAD], tag[AUTH_BYTES];
    if (!endpoints(b) || !payload || !payload_len || payload_len>M37_A_R_MAX_PAYLOAD
        || sequence==0 || sequence==UINT64_MAX || HEADER_BYTES+payload_len>MAX_DATAGRAM)
        return M37_A_R_NATIVE_MALFORMED;
    frame[0]='A';frame[1]='E';frame[2]='T';frame[3]='0'; frame[4]=WIRE_MAJOR;
    frame[5]=WIRE_MINOR;frame[6]=PROFILE;frame[7]=MESSAGE_KIND; put16(frame+8,HEADER_BYTES);put16(frame+10,payload_len);
    put64(frame+12,b->local_device);put64(frame+20,b->peer_device);
    for(unsigned i=0;i<16;i++)frame[28+i]=b->outbound_binding[i];
    for(unsigned i=0;i<32;i++)frame[44+i]=b->schema_digest[i];
    put32(frame+76,(uint32_t)b->key_id);put64(frame+80,b->epoch);put64(frame+88,sequence);
    for(unsigned i=96;i<HEADER_BYTES;i++)frame[i]=0;
    for(uint32_t i=0;i<payload_len;i++)frame[HEADER_BYTES+i]=payload[i];
    auth(frame,HEADER_BYTES+payload_len,tag);for(unsigned i=0;i<32;i++)frame[96+i]=tag[i];
    switch(m36_native_send(frame,HEADER_BYTES+payload_len)) {
    case M36_NATIVE_OK:return M37_A_R_NATIVE_OK;
    case M36_NATIVE_RING_FULL:return M37_A_R_NATIVE_RING_FULL;
    case M36_NATIVE_ENDPOINT:return M37_A_R_NATIVE_ENDPOINT;
    case M36_NATIVE_CHECKSUM:return M37_A_R_NATIVE_CHECKSUM;
    case M36_NATIVE_MALFORMED:return M37_A_R_NATIVE_MALFORMED;
    default:return M37_A_R_NATIVE_DEVICE;
    }
}

#ifdef M37_IEC_SERVICE
static m37_a_r_native_status_t map_native(m25_native_status_t status)
{
    switch (status) {
    case M25_NATIVE_OK: return M37_A_R_NATIVE_OK;
    case M25_NATIVE_RING_FULL: return M37_A_R_NATIVE_RING_FULL;
    case M25_NATIVE_MALFORMED: return M37_A_R_NATIVE_MALFORMED;
    case M25_NATIVE_ENDPOINT: return M37_A_R_NATIVE_ENDPOINT;
    case M25_NATIVE_CHECKSUM: return M37_A_R_NATIVE_CHECKSUM;
    default: return M37_A_R_NATIVE_DEVICE;
    }
}

static int build_service_frame(const m37_a_r_transport_binding_t *b,
                               const uint8_t *payload, uint32_t payload_len,
                               uint64_t sequence, uint8_t frame[HEADER_BYTES + M37_A_R_MAX_PAYLOAD],
                               uint32_t *frame_len)
{
    uint8_t tag[AUTH_BYTES];
    if (!endpoints(b) || !payload || !payload_len || payload_len > M37_A_R_MAX_PAYLOAD
        || sequence == 0 || sequence == UINT64_MAX
        || HEADER_BYTES + payload_len > MAX_DATAGRAM || !frame || !frame_len)
        return 0;
    frame[0]='A'; frame[1]='E'; frame[2]='T'; frame[3]='0'; frame[4]=WIRE_MAJOR;
    frame[5]=WIRE_MINOR; frame[6]=PROFILE; frame[7]=MESSAGE_KIND;
    put16(frame+8,HEADER_BYTES); put16(frame+10,payload_len);
    put64(frame+12,b->local_device); put64(frame+20,b->peer_device);
    for (unsigned i=0;i<16;i++) frame[28+i]=b->outbound_binding[i];
    for (unsigned i=0;i<32;i++) frame[44+i]=b->schema_digest[i];
    put32(frame+76,(uint32_t)b->key_id); put64(frame+80,b->epoch);
    put64(frame+88,sequence);
    for (unsigned i=96;i<HEADER_BYTES;i++) frame[i]=0;
    for (uint32_t i=0;i<payload_len;i++) frame[HEADER_BYTES+i]=payload[i];
    auth(frame,HEADER_BYTES+payload_len,tag);
    for (unsigned i=0;i<AUTH_BYTES;i++) frame[96+i]=tag[i];
    *frame_len=HEADER_BYTES+payload_len;
    return 1;
}

m37_a_r_native_status_t m37_a_r_adapter_submit(
    const m37_a_r_transport_binding_t *b, const uint8_t *payload,
    uint32_t payload_len, uint64_t sequence)
{
    uint8_t frame[HEADER_BYTES+M37_A_R_MAX_PAYLOAD]; uint32_t frame_len;
    if (!build_service_frame(b,payload,payload_len,sequence,frame,&frame_len))
        return M37_A_R_NATIVE_MALFORMED;
    return map_native(m25_native_submit(frame,frame_len));
}

m37_a_r_native_status_t m37_a_r_adapter_poll_completion(
    const m37_a_r_transport_binding_t *b, const uint8_t *payload,
    uint32_t payload_len, uint64_t sequence)
{
    uint8_t frame[HEADER_BYTES+M37_A_R_MAX_PAYLOAD]; uint32_t frame_len;
    if (!build_service_frame(b,payload,payload_len,sequence,frame,&frame_len))
        return M37_A_R_NATIVE_MALFORMED;
    return map_native(m25_native_poll_completion(frame,frame_len));
}
#endif

m37_a_r_native_status_t m37_a_r_adapter_receive(
    const m37_a_r_transport_binding_t *b, m37_a_r_datagram_t *out)
{
    m36_native_datagram_t d; uint8_t expected[32], copy[HEADER_BYTES+M37_A_R_MAX_PAYLOAD];
    if (!endpoints(b)||!out)return M37_A_R_NATIVE_MALFORMED;
    m36_native_status_t status=m36_native_receive(&d);
    if(status==M36_NATIVE_NO_PACKET)return M37_A_R_NATIVE_NO_PACKET;
    if(status!=M36_NATIVE_OK)return status==M36_NATIVE_ENDPOINT?M37_A_R_NATIVE_ENDPOINT:M37_A_R_NATIVE_DEVICE;
    if(!d.payload||d.payload_len<HEADER_BYTES||d.payload_len>MAX_DATAGRAM)return M37_A_R_NATIVE_MALFORMED;
    const volatile uint8_t *f=d.payload; uint16_t n=get16(f+10);
    if(f[0]!='A'||f[1]!='E'||f[2]!='T'||f[3]!='0'||f[4]!=WIRE_MAJOR||f[5]!=WIRE_MINOR
       ||f[6]!=PROFILE||f[7]!=MESSAGE_KIND||get16(f+8)!=HEADER_BYTES||!n
       ||n>M37_A_R_MAX_PAYLOAD||d.payload_len!=HEADER_BYTES+n)return M37_A_R_NATIVE_MALFORMED;
    if(get64(f+12)!=b->peer_device||get64(f+20)!=b->local_device
       ||!same((const uint8_t *)(f+28),b->inbound_binding,16)
       ||!same((const uint8_t *)(f+44),b->schema_digest,32)
       ||get32(f+76)!=b->key_id||get64(f+80)!=b->epoch
       ||get64(f+88)==0||get64(f+88)==UINT64_MAX)return M37_A_R_NATIVE_ENDPOINT;
    for(uint32_t i=0;i<d.payload_len;i++)copy[i]=f[i];
    for(unsigned i=96;i<128;i++)copy[i]=0;
    auth(copy,d.payload_len,expected);
    if(!same(expected,(const uint8_t *)(f+96),32))return M37_A_R_NATIVE_CHECKSUM;
    out->payload=(const uint8_t *)(f+HEADER_BYTES);out->payload_len=n;out->sequence=get64(f+88);return M37_A_R_NATIVE_OK;
}

int m37_a_r_adapter_tx_pending(void){return m36_native_tx_pending();}
int m37_a_r_adapter_recover(void){return m36_native_init();}
void m37_a_r_adapter_test_lost_completion(void){m25_native_test_lost_completion();}
void m37_a_r_adapter_test_release_lost_completion(void){m25_native_test_release_lost_completion();}
void m37_a_r_adapter_test_delayed_completion(void){m25_native_test_delayed_completion();}
void m37_a_r_adapter_test_release_delayed_completion(void){m25_native_test_release_delayed_completion();}

#else
int m37_a_r_adapter_init(const m37_a_r_transport_binding_t *b){(void)b;return -1;}
m37_a_r_native_status_t m37_a_r_adapter_send(const m37_a_r_transport_binding_t*b,const uint8_t*p,uint32_t n,uint64_t s){(void)b;(void)p;(void)n;(void)s;return M37_A_R_NATIVE_DEVICE;}
m37_a_r_native_status_t m37_a_r_adapter_receive(const m37_a_r_transport_binding_t*b,m37_a_r_datagram_t*o){(void)b;(void)o;return M37_A_R_NATIVE_DEVICE;}
int m37_a_r_adapter_tx_pending(void){return 0;} int m37_a_r_adapter_recover(void){return -1;}
void m37_a_r_adapter_test_lost_completion(void){} void m37_a_r_adapter_test_release_lost_completion(void){}
void m37_a_r_adapter_test_delayed_completion(void){} void m37_a_r_adapter_test_release_delayed_completion(void){}
#endif
