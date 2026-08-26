/* M28's finite manifest-driven management seam.
 *
 * The authority below is metadata only: target identity, limits, and hashes.
 * Successor bytes are staged from authenticated management frames and handed
 * to the already-generic M26 gate validator/executor.  There is no program,
 * route, instance, or hash dispatch for application behavior here. */
#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "i2_admission_policy.h"
#include "jam.h"
#include "m26_target_core.h"
#include "m28_aethernet_native.h"
#include "m28_target_core.h"
#include "memory.h"
#include "noun.h"
#include "runtime_identity.h"
#include "setjmp.h"
#include "sha256.h"

#define M28_STAGE_BYTES 32768u
#define M28_CHUNK_BYTES 384u
#define M28_MAX_CHUNKS 86u
#define M28_MAX_PAYLOAD 512u
#define M28_HEADER_BYTES 128u
#define M28_CACHE_ENTRIES 96u
#define M28_LEASE_SECONDS 5u
#define M28_RATE_LIMIT 64u
#define M28_OPS 2000000ULL
#define M28_CELLS 128000ULL

#define M28_WIRE_MAJOR 0u
#define M28_WIRE_MINOR 1u
#define M28_PROFILE 2u
#define M28_KIND_REQUEST 2u
#define M28_KIND_RESPONSE 3u
#define M28_KEY_ID 2u
#define M28_EPOCH 1u
#define M28_MANAGER 33u
#define M28_TARGET M24_NODE_ID

static const uint8_t M28_PSK[] = "m27-management-development-key-0123456789";
static const uint8_t M28_BINDING[16] = {
    0x8a,0x75,0xfd,0x90,0xf0,0x28,0xc7,0x0a,0xfc,0xd4,0x41,0x92,0x3a,0x7b,0xa7,0x43,
};
static const uint8_t M28_SCHEMA[32] = {
    0x5e,0x29,0x02,0x6d,0x3e,0x60,0x86,0x1b,0xe1,0x0d,0xf2,0x26,0xa3,0x5f,0xa5,0xf5,
    0xac,0x17,0x40,0xa6,0xef,0x90,0x34,0xd0,0x6f,0x02,0xc3,0x20,0x58,0x72,0xb2,0x3b,
};
static const uint8_t M28_MANIFEST[32] = {
    0x8c,0x39,0x09,0xd6,0x80,0x16,0x8e,0x45,0x27,0x30,0x58,0xcc,0xf6,0xc4,0x6d,0xf9,
    0xda,0xa7,0x78,0x51,0x99,0x7f,0x4f,0x81,0x48,0xe3,0x78,0xda,0xc2,0x4e,0xd4,0xf1,
};
/* All hash atoms use the PILL/runtime canonical little-endian byte order. */
static const uint8_t M28_A_PROGRAM[32] = {
    0x77,0x0b,0x73,0x7b,0x49,0x4c,0xbb,0xdc,0x14,0x1c,0xa1,0x4d,0x2e,0xf4,0xd1,0xcc,
    0xa0,0xef,0xaa,0x2f,0xc1,0x16,0xba,0x2c,0xb0,0x91,0x44,0x52,0x75,0xc8,0x67,0x45,
};
static const uint8_t M28_A_ANCHOR[32] = {
    0x96,0x9c,0x64,0x82,0xa8,0xa0,0xa2,0x22,0x29,0x41,0x83,0xc4,0xee,0xce,0x6f,0xc8,
    0x0c,0xe8,0x93,0x98,0x7e,0x74,0x38,0x64,0x18,0x5e,0x66,0x41,0xcc,0x1e,0x52,0xed,
};
static const uint8_t M28_B_PROGRAM[32] = {
    0x07,0x0e,0xc6,0x3b,0xa6,0x4e,0x9d,0x09,0xed,0xb2,0xd0,0xff,0xf3,0x34,0x97,0x1d,
    0x67,0x65,0x51,0xa7,0x66,0x05,0x1b,0x4b,0x9e,0x18,0xc4,0x5d,0x92,0x81,0x50,0xe7,
};
static const uint8_t M28_B_ANCHOR[32] = {
    0x1f,0x6e,0xa9,0x98,0x27,0x2f,0xcd,0x5d,0x3f,0xc9,0x54,0x14,0x2a,0x5d,0x66,0x87,
    0x99,0x43,0xba,0x19,0x5f,0xbb,0xc3,0xc3,0xb6,0xae,0xc6,0xa0,0x50,0x49,0x7d,0x4d,
};
static const uint8_t M28_C_PROGRAM[32] = {
    0x63,0x04,0x13,0x16,0x66,0x4a,0x07,0x2c,0x6a,0xa9,0x18,0x6f,0xde,0xa6,0xec,0xc9,
    0x95,0xe3,0x50,0x64,0xd3,0xd7,0x1b,0xcc,0x6f,0x8f,0x96,0xfe,0x8c,0xb2,0xa2,0x4f,
};
static const uint8_t M28_C_ANCHOR[32] = {
    0x34,0xf7,0x79,0x8d,0x40,0x00,0x0c,0xff,0x61,0xea,0x3b,0x5c,0x67,0x32,0x5f,0x72,
    0x97,0x9a,0x65,0xaa,0xcb,0x8d,0xd8,0xab,0x15,0x18,0x11,0x11,0x4b,0x73,0xfd,0x8c,
};
static const uint8_t M28_B_PILL[32] = {
    0x14,0x68,0x74,0x24,0xb5,0x57,0xca,0xb0,0x2f,0x23,0xdd,0xc0,0x5b,0x01,0x29,0xac,
    0x56,0xed,0x37,0x77,0x9b,0xef,0x9d,0x40,0x2f,0x1a,0x38,0x7a,0x05,0xc3,0x56,0xc7,
};
static const uint8_t M28_B_BLAKE3[32] = {
    0xee,0x9e,0xd9,0xdf,0x7b,0xe5,0x8f,0xb3,0x07,0x08,0xe9,0x02,0x73,0xf5,0x07,0x50,
    0x16,0x66,0x2c,0xb4,0xad,0x73,0x73,0xce,0xb3,0x23,0x67,0xf5,0x9d,0x55,0xa7,0xdf,
};
static const uint8_t M28_C_PILL[32] = {
    0x80,0xce,0x1f,0xe0,0x80,0xd4,0xb2,0x4e,0xd8,0x1d,0x69,0xea,0x80,0xf7,0x10,0x5e,
    0xf2,0x03,0xbd,0x52,0x42,0x4f,0x90,0x3c,0x03,0xec,0x9b,0x12,0xb5,0x7a,0x9b,0xda,
};
static const uint8_t M28_C_BLAKE3[32] = {
    0xad,0x2f,0x95,0xe2,0xfb,0xaa,0x59,0x2b,0x3c,0x7e,0xa7,0xa6,0x31,0x51,0xe7,0x47,
    0xd0,0xa5,0x63,0x6f,0x60,0x00,0x85,0x68,0x5b,0xc4,0xc4,0x95,0x98,0x4f,0x07,0x76,
};
static const uint8_t M28_B_AUTHORITY[32] = {
    0x06,0x59,0x6e,0xaf,0x8a,0xfa,0x16,0x5d,0x15,0xf3,0xce,0x32,0x3b,0xa5,0x89,0x1a,
    0x01,0xe4,0x4d,0x37,0x67,0x06,0x71,0x70,0x15,0xbe,0xd0,0xd5,0x45,0x88,0xd9,0x72,
};
static const uint8_t M28_C_AUTHORITY[32] = {
    0xe4,0x89,0xbd,0x5d,0xe4,0x23,0x0f,0x67,0x58,0x00,0x47,0x3a,0x74,0x68,0xbb,0x18,
    0xf1,0xb1,0xd5,0x4d,0x11,0xe1,0xe6,0x8a,0xe3,0x55,0xec,0x00,0xb1,0x0c,0x0a,0x8b,
};
static const uint8_t M28_LIMITS[32] = {
    0x98,0x8e,0x70,0x63,0x12,0x2b,0xfe,0x48,0x49,0xad,0xc9,0xdd,0xe1,0x24,0xc9,0x36,
    0x45,0x2f,0x1f,0x6a,0x51,0xa3,0xdf,0xb2,0xd0,0x87,0x3a,0x25,0x21,0xe1,0x58,0x3b,
};
static const uint8_t M28_C_LIMITS[32] = {
    0x98,0x8e,0x70,0x63,0x12,0x2b,0xfe,0x48,0x49,0xad,0xc9,0xdd,0xe1,0x24,0xc9,0x36,
    0x45,0x2f,0x1f,0x6a,0x51,0xa3,0xdf,0xb2,0xd0,0x87,0x3a,0x25,0x21,0xe1,0x58,0x3b,
};
static const uint8_t M28_C_SOURCE[32] = {
    0x7e,0x05,0x90,0x43,0xed,0x8c,0xef,0x33,0x90,0x62,0xd3,0x90,0x3c,0x0d,0x23,0xeb,
    0x0a,0xd5,0x01,0x65,0x8a,0x5c,0x00,0x6a,0x0b,0x9d,0x95,0x87,0x4b,0x86,0x9f,0x21,
};
static const uint8_t M28_B_SOURCE[32] = {
    0xe4,0x85,0xef,0x3f,0x26,0x30,0xd2,0x73,0x1c,0x3c,0xf1,0x1f,0xd4,0xc7,0xce,0xbd,
    0x4a,0x90,0x96,0xbc,0x1b,0xe0,0x53,0x2c,0x75,0xea,0xed,0xf5,0xb0,0xae,0xdc,0x18,
};
typedef struct {
    uint64_t manager_id, device_id, resource_id, slot;
    uint64_t transition_id, installation_id, pill_bytes;
    const uint8_t *program, *anchor, *pill, *pill_blake3;
    const uint8_t *authority, *limits, *source;
    uint8_t is_m28;
} m28_authority_t;

/* This is the compiled, hash-only projection of the exact two-entry
 * DeploymentManifest.  It is metadata, not executable successor content. */
static const m28_authority_t M28_AUTHORITY[2] = {
    {33, 22, 2, 2, 1, 2801, 22206, M28_B_PROGRAM, M28_B_ANCHOR,
     M28_B_PILL, M28_B_BLAKE3, M28_B_AUTHORITY, M28_LIMITS, M28_B_SOURCE, 0},
    {33, 11, 1, 1, 2, 2802, 22499, M28_C_PROGRAM, M28_C_ANCHOR,
     M28_C_PILL, M28_C_BLAKE3, M28_C_AUTHORITY, M28_C_LIMITS, M28_C_SOURCE, 1},
};

static const m28_authority_t *local_authority(void)
{
    const m28_authority_t *found = 0;
    unsigned matches = 0;
    for (unsigned i = 0; i < 2; i++) {
        const m28_authority_t *entry = &M28_AUTHORITY[i];
        if (entry->manager_id == M28_MANAGER && entry->device_id == M28_TARGET
            && entry->resource_id != 0 && entry->slot != 0) {
            found = entry;
            matches++;
        }
    }
    return matches == 1 ? found : 0;
}

typedef enum { M28_RUNNING=1, M28_STOPPED=2, M28_IDLE=3 } m28_lifecycle_t;
typedef enum { M28_DONE=1, M28_REJECTED=2, M28_FAILED=3 } m28_result_t;
typedef enum { M28_STATUS=1, M28_STOP, M28_BEGIN, M28_CHUNK, M28_SEAL, M28_ACTIVATE, M28_CANCEL, M28_START } m28_op_t;
typedef struct {
    uint64_t sequence, operation, transition, installation, total, offset;
    uint32_t data_len; uint8_t data[M28_CHUNK_BYTES]; uint8_t pill[32]; uint8_t authority[32]; uint8_t manifest[32]; m28_op_t op;
} m28_request_t;
typedef struct { int used; uint64_t operation; uint8_t digest[32]; uint16_t len; uint8_t payload[M28_MAX_PAYLOAD]; } m28_cache_t;

static uint8_t g_stage[M28_STAGE_BYTES] __attribute__((aligned(16)));
static int g_stage_open,g_stage_sealed,g_selected,g_terminal,g_initialized,g_response_pending;
static uint64_t g_transition,g_installation,g_total,g_received,g_chunks,g_lease;
static m28_lifecycle_t g_lifecycle;
static noun g_management_tag;
static runtime_identity_t g_identity;
static uint8_t g_stage_pill_sha256[32];
static uint64_t g_generation,g_sequence_high,g_operation_high,g_response_sequence,g_terminal_installation;
static uint64_t g_rate_start,g_rate_count;
static m28_cache_t g_cache[M28_CACHE_ENTRIES];
static uint8_t g_checkpoint_valid,g_checkpoint_selected,g_checkpoint_terminal;
static m28_lifecycle_t g_checkpoint_lifecycle; static uint64_t g_checkpoint_generation,g_checkpoint_installation;
static uint64_t g_checkpoint_sequence_high,g_checkpoint_operation_high;
static uint64_t g_checkpoint_response_sequence,g_checkpoint_rate_start,g_checkpoint_rate_count;
static m28_cache_t g_checkpoint_cache[M28_CACHE_ENTRIES];

static int take(noun n,noun *h,noun *t){if(!noun_is_cell(n)||!h||!t)return 0;cell_t*c=(cell_t*)(uintptr_t)cell_ptr(n);*h=c->head;*t=c->tail;return 1;}
static int direct_is(noun n,uint64_t v){return noun_is_direct(n)&&direct_val(n)==v;}
static int pair(noun a,noun b,noun*out){return out&&alloc_cell_checked(a,b,out);}
static int equal_bytes(const uint8_t*a,const uint8_t*b,size_t n){uint8_t d=0;for(size_t i=0;i<n;i++)d|=a[i]^b[i];return d==0;}
static uint64_t now(void){uint64_t v;__asm__ volatile("mrs %0, cntvct_el0":"=r"(v));return v;}
static uint64_t freq(void){uint64_t v;__asm__ volatile("mrs %0, cntfrq_el0":"=r"(v));return v?v:54000000ULL;}
static int accept_sequence(uint64_t sequence)
{
    if(sequence==0||sequence==UINT64_MAX||sequence<=g_sequence_high)return 0;
    uint64_t current=now(),clock=freq();
    if(g_rate_start==0||current-g_rate_start>=clock){g_rate_start=current;g_rate_count=0;}
    if(g_rate_count>=M28_RATE_LIMIT)return 0;
    g_rate_count++;g_sequence_high=sequence;return 1;
}
static int cord_is(noun n,const char*s){char b[32];size_t l=0;while(s[l]&&l+1<sizeof b)l++;return s[l]==0&&cord_to_cstr(n,b,sizeof b)==l&&equal_bytes((const uint8_t*)b,(const uint8_t*)s,l);}
static int atom_bytes(noun n,uint8_t*out,size_t max,size_t len){return out&&len&&len<=max&&noun_atom_read_fixed(n,out,len);}

static int gate_resource_id(noun gate,uint64_t*out)
{
    noun battery,sample,zero,state,tag,rest,header,dynamic,versions,rid;
    return out&&take(gate,&battery,&sample)&&take(sample,&zero,&state)
        &&take(state,&tag,&rest)&&take(rest,&header,&dynamic)
        &&take(header,&versions,&rest)&&take(rest,&rid,&rest)
        &&noun_is_direct(rid)&&(*out=direct_val(rid),1);
}

static int decode_request(const uint8_t*h,const uint8_t*p,uint32_t len,m28_request_t*out)
{
    if(!h||!p||!out||!len||len>M28_MAX_PAYLOAD||h[0]!='A'||h[1]!='E'||h[2]!='T'||h[3]!='0'||h[4]!=M28_WIRE_MAJOR||h[5]!=M28_WIRE_MINOR||h[6]!=M28_PROFILE||h[7]!=M28_KIND_REQUEST||((uint16_t)h[8]<<8|h[9])!=M28_HEADER_BYTES||((uint16_t)h[10]<<8|h[11])!=len)return 0;
    uint64_t manager=0,target=0;for(unsigned i=0;i<8;i++){manager=(manager<<8)|h[12+i];target=(target<<8)|h[20+i];}
    if(manager!=M28_MANAGER||target!=M28_TARGET||!equal_bytes(h+28,M28_BINDING,16)||!equal_bytes(h+44,M28_SCHEMA,32)||h[76]||h[77]||h[78]||h[79]!=M28_KEY_ID||h[80]||h[81]||h[82]||h[83]||h[84]||h[85]||h[86]||h[87]!=M28_EPOCH)return 0;
    uint64_t seq=0;for(unsigned i=0;i<8;i++)seq=(seq<<8)|h[88+i];if(!seq||seq==UINT64_MAX)return 0;
    uint8_t in[M28_HEADER_BYTES+M28_MAX_PAYLOAD],auth[32];for(unsigned i=0;i<M28_HEADER_BYTES;i++)in[i]=i>=96?0:h[i];for(uint32_t i=0;i<len;i++)in[M28_HEADER_BYTES+i]=p[i];hmac_sha256(M28_PSK,sizeof M28_PSK-1,in,M28_HEADER_BYTES+len,auth);if(!equal_bytes(auth,h+96,32))return 0;
    noun root;if(cue_bounded_bytes(p,len,&cue_i2_limits,HEAP_MODE_SCRATCH,&root)!=CUE_BOUNDED_OK)return 0;const uint8_t*canonical;uint64_t n;if(jam_encode_bytes_identity(root,&canonical,&n)||n!=len||!equal_bytes(canonical,p,len))return 0;
    noun tag,rest,version,operation,body,op,payload;if(!take(root,&tag,&rest)||!cord_is(tag,"aethernet-management-m28")||!take(rest,&version,&rest)||!direct_is(version,1)||!take(rest,&operation,&body)||!noun_is_direct(operation)||!direct_val(operation)||!take(body,&op,&payload))return 0;
    out->sequence=seq;out->operation=direct_val(operation);out->transition=out->installation=out->total=out->offset=out->data_len=0;for(unsigned i=0;i<32;i++)out->manifest[i]=0;out->op=0;
    if(cord_is(op,"status")&&payload==NOUN_ZERO)out->op=M28_STATUS;
    else if(cord_is(op,"resource-stop")&&payload==NOUN_ZERO)out->op=M28_STOP;
    else if(cord_is(op,"resource-start")&&payload==NOUN_ZERO)out->op=M28_START;
    else if(cord_is(op,"install-begin")){noun a,b,c,d,e,f;if(!take(payload,&a,&b)||!take(b,&c,&b)||!take(b,&d,&b)||!take(b,&e,&b)||!take(b,&f,&b)||!take(b,&b,&payload)||payload!=NOUN_ZERO||!noun_is_direct(a)||!noun_is_direct(c)||!noun_is_direct(d)||!atom_bytes(e,out->pill,32,32)||!atom_bytes(f,out->authority,32,32)||!atom_bytes(b,out->manifest,32,32))return 0;out->transition=direct_val(a);out->installation=direct_val(c);out->total=direct_val(d);out->op=M28_BEGIN;}
    else if(cord_is(op,"install-chunk")){noun a,b,c,d,e,z;if(!take(payload,&a,&b)||!take(b,&c,&b)||!take(b,&d,&b)||!take(b,&e,&z)||!take(z,&z,&payload)||payload!=NOUN_ZERO||!noun_is_direct(a)||!noun_is_direct(c)||!noun_is_direct(d)||!noun_is_direct(e)||direct_val(e)==0||direct_val(e)>M28_CHUNK_BYTES||!atom_bytes(z,out->data,sizeof out->data,direct_val(e)))return 0;out->transition=direct_val(a);out->installation=direct_val(c);out->offset=direct_val(d);out->data_len=(uint32_t)direct_val(e);out->op=M28_CHUNK;}
    else if(cord_is(op,"install-seal")||cord_is(op,"install-activate")||cord_is(op,"install-cancel")){noun a,b;if(!take(payload,&a,&b)||!noun_is_direct(a)||!noun_is_direct(b)||!direct_val(a)||!direct_val(b))return 0;out->transition=direct_val(a);out->installation=direct_val(b);out->op=cord_is(op,"install-seal")?M28_SEAL:cord_is(op,"install-activate")?M28_ACTIVATE:M28_CANCEL;}
    else return 0;
    return 1;
}

static int status_body(noun*out){noun v[8],tail;v[0]=direct(g_lifecycle);v[1]=direct(g_selected?1:0);v[2]=direct(g_generation);v[3]=direct(g_lifecycle!=M28_RUNNING);v[4]=direct(g_stage_open?g_installation:g_terminal_installation);v[5]=direct(g_stage_open?g_received:0);v[6]=direct(g_stage_open?g_chunks:0);v[7]=direct(g_terminal?1:0);tail=v[7];for(int i=6;i>=0;i--)if(!pair(v[i],tail,&tail))return 0;*out=tail;return 1;}
static int response_payload(uint64_t id,m28_result_t result,noun body,uint8_t*out,uint16_t*length)
{
    if(!noun_tx_begin(HEAP_MODE_SCRATCH))return 0;
    noun r,t,tag,ver,req,op;
    tag=g_management_tag;
    op=cord_from_bytes(result==M28_DONE?"done":result==M28_FAILED?"failed":"rejected",
                       result==M28_DONE?4:result==M28_FAILED?6:8);
    if(!pair(op,body,&t)||!pair(direct(id),t,&req)||!pair(direct(1),req,&ver)||!pair(tag,ver,&r)){
        noun_tx_abort();return 0;
    }
    const uint8_t*b;uint64_t n;
    if(jam_encode_bytes_identity(r,&b,&n)||!n||n>M28_MAX_PAYLOAD){
        noun_tx_abort();return 0;
    }
    for(uint64_t i=0;i<n;i++)out[i]=b[i];
    noun_tx_abort();*length=(uint16_t)n;return 1;
}

static int response_frame(const uint8_t *payload, uint16_t payload_len,
                          uint8_t out[M28_HEADER_BYTES + M28_MAX_PAYLOAD],
                          uint32_t *length)
{
    if (!payload || !length || payload_len > M28_MAX_PAYLOAD) return 0;
    for (unsigned i=0;i<M28_HEADER_BYTES;i++) out[i]=0;
    out[0]='A';out[1]='E';out[2]='T';out[3]='0';
    out[4]=M28_WIRE_MAJOR;out[5]=M28_WIRE_MINOR;out[6]=M28_PROFILE;out[7]=M28_KIND_RESPONSE;
    out[8]=0;out[9]=M28_HEADER_BYTES;out[10]=(uint8_t)(payload_len>>8);out[11]=(uint8_t)payload_len;
    for(unsigned i=0;i<8;i++){
        out[12+i]=(uint8_t)((uint64_t)M28_TARGET>>(56u-i*8u));
        out[20+i]=(uint8_t)((uint64_t)M28_MANAGER>>(56u-i*8u));
    }
    for(unsigned i=0;i<16;i++)out[28+i]=M28_BINDING[i];
    for(unsigned i=0;i<32;i++)out[44+i]=M28_SCHEMA[i];
    out[79]=M28_KEY_ID;out[87]=M28_EPOCH;
    for(unsigned i=0;i<8;i++)out[88+i]=(uint8_t)(g_response_sequence>>(56u-i*8u));
    for(unsigned i=0;i<payload_len;i++)out[M28_HEADER_BYTES+i]=payload[i];
    uint8_t auth[32];
    hmac_sha256(M28_PSK,sizeof M28_PSK-1u,out,M28_HEADER_BYTES+payload_len,auth);
    for(unsigned i=0;i<32;i++)out[96+i]=auth[i];
    *length=M28_HEADER_BYTES+payload_len;return 1;
}
static int cache_find(uint64_t id,const uint8_t*d){for(unsigned i=0;i<M28_CACHE_ENTRIES;i++)if(g_cache[i].used&&g_cache[i].operation==id)return equal_bytes(g_cache[i].digest,d,32)?(int)i:-2;return -1;}
static int cache_put(uint64_t id,const uint8_t*d,const uint8_t*p,uint16_t n){for(unsigned i=0;i<M28_CACHE_ENTRIES;i++)if(!g_cache[i].used){g_cache[i].used=1;g_cache[i].operation=id;for(unsigned j=0;j<32;j++)g_cache[i].digest[j]=d[j];g_cache[i].len=n;for(unsigned j=0;j<n;j++)g_cache[i].payload[j]=p[j];return 1;}return 0;}
static int cache_free(void){for(unsigned i=0;i<M28_CACHE_ENTRIES;i++)if(!g_cache[i].used)return 1;return 0;}
static int validate_program_projection(noun gate,
                                       const runtime_identity_t *identity,
                                       const m28_authority_t *authority)
{
    noun ignored, state, tag, rest, program_n, dynamic;
    noun tables, exports, services;
    if(!take(gate,&ignored,&rest) || !take(rest,&ignored,&state)
       || !take(state,&tag,&rest)
       || !direct_is(tag,0x65746174732d3269ULL)) return 0;
    if(!take(rest,&ignored,&rest) || !take(rest,&program_n,&dynamic)
       || !take(program_n,&tag,&rest)) return 0;
    if(!authority || !identity || !runtime_identity_validate_gate(gate,identity,0)
       || !equal_bytes(identity->package_hash,authority->anchor,32)
       || !equal_bytes(identity->program_hash,authority->program,32)) return 0;
    if(!take(rest,&ignored,&tables) || !take(tables,&ignored,&tables)
       || !take(tables,&ignored,&tables) || !take(tables,&ignored,&tables)
       || !take(tables,&exports,&services)) return 0;
    if(authority->is_m28){
        if(!noun_eq(tag,cord_from_bytes("i2-m28-program",14))
           || !atom_bytes(exports,(uint8_t *)authority->source,32,32)) return 0;
    }else if(!noun_eq(tag,cord_from_bytes("i2-m27-program",14))) return 0;
    return 1;
}

static int activate_install(const m28_request_t*r,uint8_t*reserved,uint16_t*reserved_len)
{
    const m28_authority_t *authority=local_authority();
    if(!g_stage_open||!g_stage_sealed
       ||!authority||r->transition!=authority->transition_id
       ||r->installation!=g_installation||g_lifecycle!=M28_STOPPED
       ||g_selected||g_terminal||g_received!=g_total)return 0;
    noun body;if(!status_body(&body)||!response_payload(r->operation,M28_DONE,body,reserved,reserved_len))return 0;
    noun candidate,prepared;runtime_identity_t identity;uint8_t capability;
    pill_i2_status_t candidate_status=pill_i2_validate_buffer(g_stage,g_total,HEAP_MODE_PERSIST,&candidate,&identity,&capability);
    if(candidate_status!=PILL_I2_OK)goto reject;
    if(capability!=RUNTIME_CAPABILITY_PROFILE_M25||identity.generation!=2||identity.runtime_abi[0]!=1||identity.runtime_abi[1]!=9||identity.formula_abi[0]!=1||identity.formula_abi[1]!=9)goto reject;
    uint8_t got_sha[32],got_b3[32],got_limits[32];sha256_hash(g_stage,g_total,got_sha);blake3_hash(g_stage,g_total,got_b3);
    if(g_total!=authority->pill_bytes||!equal_bytes(got_sha,authority->pill,32)||!equal_bytes(got_b3,authority->pill_blake3,32)||!equal_bytes(g_stage_pill_sha256,authority->pill,32)||!equal_bytes(r->authority,authority->authority,32)||!equal_bytes(identity.program_hash,authority->program,32)||!equal_bytes(identity.package_hash,authority->anchor,32)||!equal_bytes(identity.battery_hash,(const uint8_t[]){0x57,0x42,0x2c,0x15,0xa7,0x72,0xc6,0x11,0x44,0x3e,0x5a,0x28,0x40,0x68,0x94,0xf7,0xa4,0x5a,0xcf,0x2f,0x21,0xea,0x38,0x3e,0x68,0x8f,0x06,0x03,0x67,0x67,0xc2,0x20},32)||!i2_admission_limits_hash(candidate,got_limits)||!equal_bytes(got_limits,authority->limits,32))goto reject;
    if(!validate_program_projection(candidate,&identity,authority))goto reject;
    if(m26_target_prepare_gate(candidate,&identity,capability,&prepared)!=0)goto reject;
    noun_tx_commit();heap_persist_commit_tx();
    m26_target_publish_gate(prepared,&identity,capability);
    g_selected=1;g_generation=2;g_lifecycle=M28_IDLE;g_terminal=1;
    g_terminal_installation=r->installation;g_stage_open=g_stage_sealed=0;
    g_received=g_chunks=g_total=0;return 1;
reject:
    if(noun_tx_active())noun_tx_abort();
    return 0;
}

static int execute(const m28_request_t*r,uint8_t*out,uint16_t*length)
{
    m28_result_t result=M28_REJECTED;noun body=NOUN_ZERO;
    if(r->op==M28_STATUS){if(!status_body(&body))return 0;result=M28_DONE;}
    else if(r->op==M28_STOP){if(g_lifecycle==M28_RUNNING&&!g_stage_open&&m26_target_set_running(0)==0){g_lifecycle=M28_STOPPED;result=M28_DONE;}if(result==M28_DONE&&!status_body(&body))return 0;}
    else if(r->op==M28_BEGIN){
        const m28_authority_t *authority=local_authority();
        if(authority&&g_lifecycle==M28_STOPPED&&!g_stage_open&&!g_terminal&&r->transition==authority->transition_id&&r->installation==authority->installation_id&&r->total==authority->pill_bytes&&equal_bytes(r->pill,authority->pill,32)&&equal_bytes(r->authority,authority->authority,32)&&equal_bytes(r->manifest,M28_MANIFEST,32)){g_transition=r->transition;g_installation=r->installation;g_total=r->total;g_received=g_chunks=0;for(unsigned i=0;i<32;i++)g_stage_pill_sha256[i]=r->pill[i];g_stage_open=1;g_stage_sealed=0;g_lease=now()+freq()*M28_LEASE_SECONDS;result=M28_DONE;}
    } else if(r->op==M28_CHUNK){if(g_lifecycle==M28_STOPPED&&g_stage_open&&!g_stage_sealed&&r->transition==g_transition&&r->installation==g_installation&&r->data_len&&r->offset<=g_received&&r->offset+r->data_len<=g_total){if(r->offset<g_received){if(r->offset+r->data_len<=g_received&&equal_bytes(g_stage+r->offset,r->data,r->data_len))result=M28_DONE;}else if(r->offset==g_received&&g_chunks<M28_MAX_CHUNKS){for(uint32_t i=0;i<r->data_len;i++)g_stage[g_received+i]=r->data[i];g_received+=r->data_len;g_chunks++;g_lease=now()+freq()*M28_LEASE_SECONDS;result=M28_DONE;}}
    } else if(r->op==M28_SEAL){
        uint8_t sha[32],b3[32];
        const m28_authority_t *authority=local_authority();
        if(g_lifecycle==M28_STOPPED&&g_stage_open&&!g_stage_sealed
           &&authority&&r->transition==g_transition&&r->installation==g_installation
           &&g_received==g_total){
            sha256_hash(g_stage,g_total,sha);blake3_hash(g_stage,g_total,b3);
            if(equal_bytes(sha,authority->pill,32)&&equal_bytes(b3,authority->pill_blake3,32)){g_stage_sealed=1;result=M28_DONE;}
        }
    }
    else if(r->op==M28_ACTIVATE){if(activate_install(r,out,length))return 1;}
    else if(r->op==M28_CANCEL){if(g_lifecycle==M28_STOPPED&&g_stage_open&&r->transition==g_transition&&r->installation==g_installation){g_stage_open=g_stage_sealed=0;g_received=g_chunks=g_total=0;result=M28_DONE;}}
    else if(r->op==M28_START){if(g_selected&&(g_lifecycle==M28_IDLE||g_lifecycle==M28_STOPPED)&&!g_stage_open&&m26_target_init()==0&&m28_native_init()==0&&m26_target_set_running(1)==0){g_lifecycle=M28_RUNNING;result=M28_DONE;if(!status_body(&body))return 0;}}
    if(!response_payload(r->operation,result,body,out,length))return 0;
    return 1;
}

int m28_target_boot(noun gate,const runtime_identity_t*identity,uint8_t capability)
{
    const m28_authority_t *authority=local_authority();
    uint64_t rid=0;
    if(!authority||!gate_resource_id(gate,&rid)||rid!=authority->resource_id
       ||!identity||capability!=RUNTIME_CAPABILITY_PROFILE_M25||identity->generation!=1
       ||!equal_bytes(identity->program_hash,M28_A_PROGRAM,32)
       ||!equal_bytes(identity->package_hash,M28_A_ANCHOR,32))return -1;
    (void)gate;g_identity=*identity;g_management_tag=cord_from_bytes("aethernet-management-m28",24);if(!noun_is_atom(g_management_tag))return -1;for(unsigned i=0;i<M28_CACHE_ENTRIES;i++)g_cache[i].used=0;g_lifecycle=M28_RUNNING;g_selected=0;g_terminal=0;g_generation=1;g_terminal_installation=0;g_sequence_high=0;g_operation_high=0;g_response_sequence=1;g_rate_start=g_rate_count=0;g_stage_open=g_stage_sealed=0;g_initialized=0;g_response_pending=0;g_checkpoint_valid=0;return 0;
}

int m28_target_service_tick(void)
{
    if(!g_initialized){
        if(!m26_target_native_ready())return 0;
        if(m28_native_init()!=0)return 0;
        g_initialized=1;
    }
    if(g_stage_open&&g_lease&&now()>=g_lease){
        g_stage_open=g_stage_sealed=0;g_received=g_chunks=g_total=0;
        for(unsigned i=0;i<32;i++)g_stage_pill_sha256[i]=0;
    }
    m28_native_datagram_t d;
    m28_native_status_t native=m28_native_receive(&d);
    if(native!=M28_NATIVE_OK)return 0;
    uint8_t digest[32];
    sha256_hash(d.payload,d.payload_len,digest);
    m28_request_t r;
    if(!decode_request(d.header,d.payload,d.payload_len,&r))return 0;
    if(noun_tx_active())noun_tx_abort();
    if(!accept_sequence(r.sequence))return 0;
    int found=cache_find(r.operation,digest);
    uint8_t response[M28_MAX_PAYLOAD];uint16_t n=0;
    if(found>=0){
        for(unsigned i=0;i<g_cache[found].len;i++)response[i]=g_cache[found].payload[i];
        n=g_cache[found].len;
    }else if(found==-2){
        if(!response_payload(r.operation,M28_REJECTED,NOUN_ZERO,response,&n))return 0;
    }else{
        if(g_response_pending||r.operation==0||r.operation==UINT64_MAX||r.operation<=g_operation_high)return 0;
        if(!cache_free()||!execute(&r,response,&n))return 0;
        if(!cache_put(r.operation,digest,response,n))return 0;
        g_operation_high=r.operation;
    }
    if(g_response_sequence==UINT64_MAX)return 0;
    uint8_t frame[M28_HEADER_BYTES+M28_MAX_PAYLOAD];uint32_t frame_len=0;
    if(!response_frame(response,n,frame,&frame_len))return 0;
    if(m28_native_send(frame,frame_len)!=M28_NATIVE_OK){g_response_pending=1;return 0;}
    g_response_sequence++;g_response_pending=0;return 1;
}

int m28_target_checkpoint_capture(void)
{
    if(g_stage_open||g_response_pending||g_checkpoint_valid||m26_target_checkpoint_capture()!=0)return -1;
    g_checkpoint_selected=g_selected;g_checkpoint_terminal=g_terminal;
    g_checkpoint_lifecycle=g_lifecycle;g_checkpoint_generation=g_generation;
    g_checkpoint_installation=g_terminal_installation;
    g_checkpoint_sequence_high=g_sequence_high;
    g_checkpoint_operation_high=g_operation_high;
    g_checkpoint_response_sequence=g_response_sequence;
    g_checkpoint_rate_start=g_rate_start;g_checkpoint_rate_count=g_rate_count;
    for(unsigned i=0;i<M28_CACHE_ENTRIES;i++){
        g_checkpoint_cache[i]=g_cache[i];
    }
    g_checkpoint_valid=1;return 0;
}
int m28_target_checkpoint_restore(void)
{
    if(!g_checkpoint_valid||g_stage_open||g_response_pending||m26_target_checkpoint_restore()!=0)return -1;
    g_selected=g_checkpoint_selected;g_terminal=g_checkpoint_terminal;
    g_lifecycle=g_checkpoint_lifecycle;g_generation=g_checkpoint_generation;
    g_terminal_installation=g_checkpoint_installation;
    g_sequence_high=g_checkpoint_sequence_high;
    g_operation_high=g_checkpoint_operation_high;
    g_response_sequence=g_checkpoint_response_sequence;
    g_rate_start=g_checkpoint_rate_start;
    g_rate_count=g_checkpoint_rate_count;
    for(unsigned i=0;i<M28_CACHE_ENTRIES;i++){
        g_cache[i]=g_checkpoint_cache[i];
    }
    if(g_lifecycle==M28_RUNNING){if(m26_target_init()!=0||m28_native_init()!=0||m26_target_set_running(1)!=0)return -1;}
    return 0;
}
uint64_t m28_target_selected(void){return g_selected?1:0;} uint64_t m28_target_generation(void){return g_generation;} uint64_t m28_target_terminal(void){return g_terminal?1:0;}
