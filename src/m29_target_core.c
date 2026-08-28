/* M29's bounded authenticated commissioning seam.
 *
 * The bootstrap image carries only the transport and capability envelope plus
 * the retained local predecessor identity.  The successor identities and
 * authorization facts arrive together in one authenticated CommissioningPolicyV1
 * and are checked against the generic PILL/gate validator before one clean
 * local publication boundary.  No successor program, route, source, or PILL
 * identity is resident here. */
#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "i2_admission_policy.h"
#include "jam.h"
#include "m26_target_core.h"
#include "m29_aethernet_native.h"
#include "m29_target_core.h"
#include "memory.h"
#include "noun.h"
#include "runtime_identity.h"
#include "setjmp.h"
#include "sha256.h"

#define M29_STAGE_BYTES 32768u
#define M29_CHUNK_BYTES 384u
#define M29_MAX_CHUNKS 86u
#define M29_MAX_PAYLOAD 512u
#define M29_HEADER_BYTES 128u
#define M29_CACHE_ENTRIES 96u
#define M29_LEASE_SECONDS 5u
#define M29_RATE_LIMIT 64u
#define M29_OPS 2000000ULL
#define M29_CELLS 128000ULL
#define M29_RESPONSE_ATTEMPTS 3u

#define M29_WIRE_MAJOR 0u
#define M29_WIRE_MINOR 1u
#define M29_PROFILE 2u
#define M29_KIND_REQUEST 2u
#define M29_KIND_RESPONSE 3u
#define M29_KEY_ID 2u
#define M29_EPOCH 1u
#define M29_MANAGER 33u
#define M29_TARGET M24_NODE_ID

static const uint8_t M29_PSK[] = "m27-management-development-key-0123456789";
static const uint8_t M29_BINDING[16] = {
    0x8a,0x75,0xfd,0x90,0xf0,0x28,0xc7,0x0a,0xfc,0xd4,0x41,0x92,0x3a,0x7b,0xa7,0x43,
};
static const uint8_t M29_SCHEMA[32] = {
    0x5e,0x29,0x02,0x6d,0x3e,0x60,0x86,0x1b,0xe1,0x0d,0xf2,0x26,0xa3,0x5f,0xa5,0xf5,
    0xac,0x17,0x40,0xa6,0xef,0x90,0x34,0xd0,0x6f,0x02,0xc3,0x20,0x58,0x72,0xb2,0x3b,
};
/* All hash atoms use the PILL/runtime canonical little-endian byte order. */
static const uint8_t M29_PREDECESSOR_PROGRAM[32] = {
    0x77,0x0b,0x73,0x7b,0x49,0x4c,0xbb,0xdc,0x14,0x1c,0xa1,0x4d,0x2e,0xf4,0xd1,0xcc,
    0xa0,0xef,0xaa,0x2f,0xc1,0x16,0xba,0x2c,0xb0,0x91,0x44,0x52,0x75,0xc8,0x67,0x45,
};
static const uint8_t M29_PREDECESSOR_ANCHOR[32] = {
    0x96,0x9c,0x64,0x82,0xa8,0xa0,0xa2,0x22,0x29,0x41,0x83,0xc4,0xee,0xce,0x6f,0xc8,
    0x0c,0xe8,0x93,0x98,0x7e,0x74,0x38,0x64,0x18,0x5e,0x66,0x41,0xcc,0x1e,0x52,0xed,
};
static const uint8_t M29_FORMULA_ID[32] = {
    0x0d,0x8f,0x97,0x0d,0x15,0xd7,0x69,0x89,0x79,0xe2,0xdf,0xe0,0xce,0x2a,0xdd,0x41,
    0x40,0x40,0xed,0x48,0x60,0xde,0xd3,0x17,0x3e,0xb8,0xf3,0xa1,0x32,0x57,0x7c,0xb0,
};
static const uint8_t M29_DATA_PLAN_ID[32] = {
    0x41,0x2e,0xe3,0xf4,0x29,0x32,0xdb,0x66,0xbd,0x56,0x9c,0x99,0xe2,0x88,0x4a,0x28,
    0x47,0xd7,0x66,0xb0,0x44,0x25,0x51,0xad,0x19,0xf7,0xa0,0x4a,0xb0,0x14,0xd5,0x50,
};
typedef enum { M29_RUNNING=1, M29_STOPPED=2, M29_IDLE=3 } m29_lifecycle_t;
typedef enum { M29_DONE=1, M29_REJECTED=2, M29_FAILED=3 } m29_result_t;
typedef enum { M29_STATUS=1, M29_STOP, M29_BEGIN, M29_CHUNK, M29_SEAL, M29_ACTIVATE, M29_CANCEL, M29_START } m29_op_t;
typedef struct {
    uint64_t sequence, operation, installation, total, policy_bytes, pill_bytes, offset;
    uint32_t data_len; uint8_t data[M29_CHUNK_BYTES];
    uint8_t policy_sha256[32]; uint8_t pill_sha256[32]; m29_op_t op;
} m29_request_t;
typedef struct { int used; uint64_t operation; uint8_t digest[32]; uint16_t len; uint8_t payload[M29_MAX_PAYLOAD]; } m29_cache_t;
typedef enum { M29_PENDING_NONE=0, M29_PENDING_UNSENT=1, M29_PENDING_IN_FLIGHT=2 } m29_pending_tx_t;
typedef struct {
    int used; uint64_t operation; uint8_t digest[32]; uint16_t len;
    uint8_t payload[M29_MAX_PAYLOAD]; uint64_t response_sequence;
    uint8_t attempts; m29_pending_tx_t tx_state;
} m29_pending_response_t;

static uint8_t g_stage[M29_STAGE_BYTES] __attribute__((aligned(16)));
static int g_stage_open,g_stage_sealed,g_selected,g_terminal,g_initialized;
static uint64_t g_installation,g_total,g_policy_bytes,g_pill_bytes,g_received,g_chunks,g_lease;
static m29_lifecycle_t g_lifecycle;
static noun g_management_tag;
static runtime_identity_t g_identity;
static uint8_t g_stage_policy_sha256[32], g_stage_pill_sha256[32];
static uint64_t g_generation,g_sequence_high,g_operation_high,g_response_sequence,g_terminal_installation;
static uint64_t g_rate_start,g_rate_count;
static m29_cache_t g_cache[M29_CACHE_ENTRIES];
static m29_pending_response_t g_pending;
static uint8_t g_checkpoint_valid,g_checkpoint_selected,g_checkpoint_terminal;
static m29_lifecycle_t g_checkpoint_lifecycle; static uint64_t g_checkpoint_generation,g_checkpoint_installation;
static uint64_t g_checkpoint_sequence_high,g_checkpoint_operation_high;
static uint64_t g_checkpoint_response_sequence,g_checkpoint_rate_start,g_checkpoint_rate_count;
static m29_cache_t g_checkpoint_cache[M29_CACHE_ENTRIES];
static uint8_t g_checkpoint_replay_digest[32];
static uint8_t g_active_policy_digest[32], g_active_program_identity[32];
static uint8_t g_checkpoint_policy_digest[32], g_checkpoint_program_identity[32];
#ifdef M32_TEST_CONTROLS
static uint64_t g_diag_management_rx, g_diag_decode_ok, g_diag_decode_failures;
static uint64_t g_diag_accepted, g_diag_refused;
static uint64_t g_diag_last_sequence, g_diag_last_operation, g_diag_last_offset;
static uint8_t g_diag_last_digest[32];
static uint64_t g_diag_cache_hits, g_diag_cache_misses, g_diag_cache_conflicts;
static uint64_t g_diag_cache_presence, g_diag_execute_count, g_diag_pending_replays;
static uint64_t g_diag_pending_refusals;
static uint64_t g_diag_lease_start, g_diag_lease_expiry;
static uint64_t g_diag_lease_expired;
#endif

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
    if(g_rate_count>=M29_RATE_LIMIT)return 0;
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

static int decode_request(const uint8_t*h,const uint8_t*p,uint32_t len,m29_request_t*out)
{
    if(!h||!p||!out||!len||len>M29_MAX_PAYLOAD||h[0]!='A'||h[1]!='E'||h[2]!='T'||h[3]!='0'||h[4]!=M29_WIRE_MAJOR||h[5]!=M29_WIRE_MINOR||h[6]!=M29_PROFILE||h[7]!=M29_KIND_REQUEST||((uint16_t)h[8]<<8|h[9])!=M29_HEADER_BYTES||((uint16_t)h[10]<<8|h[11])!=len)return 0;
    uint64_t manager=0,target=0;for(unsigned i=0;i<8;i++){manager=(manager<<8)|h[12+i];target=(target<<8)|h[20+i];}
    if(manager!=M29_MANAGER||target!=M29_TARGET||!equal_bytes(h+28,M29_BINDING,16)||!equal_bytes(h+44,M29_SCHEMA,32)||h[76]||h[77]||h[78]||h[79]!=M29_KEY_ID||h[80]||h[81]||h[82]||h[83]||h[84]||h[85]||h[86]||h[87]!=M29_EPOCH)return 0;
    uint64_t seq=0;for(unsigned i=0;i<8;i++)seq=(seq<<8)|h[88+i];if(!seq||seq==UINT64_MAX)return 0;
    uint8_t in[M29_HEADER_BYTES+M29_MAX_PAYLOAD],auth[32];for(unsigned i=0;i<M29_HEADER_BYTES;i++)in[i]=i>=96?0:h[i];for(uint32_t i=0;i<len;i++)in[M29_HEADER_BYTES+i]=p[i];hmac_sha256(M29_PSK,sizeof M29_PSK-1,in,M29_HEADER_BYTES+len,auth);if(!equal_bytes(auth,h+96,32))return 0;
    noun root;if(cue_bounded_bytes(p,len,&cue_i2_limits,HEAP_MODE_SCRATCH,&root)!=CUE_BOUNDED_OK)return 0;const uint8_t*canonical;uint64_t n;if(jam_encode_bytes_identity(root,&canonical,&n)||n!=len||!equal_bytes(canonical,p,len))return 0;
    noun tag,rest,version,operation,body,op,payload;if(!take(root,&tag,&rest)||!cord_is(tag,"aethernet-management-m29")||!take(rest,&version,&rest)||!direct_is(version,1)||!take(rest,&operation,&body)||!noun_is_direct(operation)||!direct_val(operation)||!take(body,&op,&payload))return 0;
    out->sequence=seq;out->operation=direct_val(operation);out->installation=out->total=out->policy_bytes=out->pill_bytes=out->offset=out->data_len=0;for(unsigned i=0;i<32;i++){out->policy_sha256[i]=0;out->pill_sha256[i]=0;}out->op=0;
    if(cord_is(op,"status")&&payload==NOUN_ZERO)out->op=M29_STATUS;
    else if(cord_is(op,"resource-stop")&&payload==NOUN_ZERO)out->op=M29_STOP;
    else if(cord_is(op,"resource-start")&&payload==NOUN_ZERO)out->op=M29_START;
    else if(cord_is(op,"install-begin")){noun a,b,c,d,e,f,g;if(!take(payload,&a,&b)||!take(b,&c,&b)||!take(b,&d,&b)||!take(b,&e,&b)||!take(b,&f,&b)||!take(b,&g,&payload)||payload!=NOUN_ZERO||!noun_is_direct(a)||!noun_is_direct(c)||!noun_is_direct(d)||!noun_is_direct(e)||!atom_bytes(f,out->policy_sha256,32,32)||!atom_bytes(g,out->pill_sha256,32,32))return 0;out->installation=direct_val(a);out->total=direct_val(c);out->policy_bytes=direct_val(d);out->pill_bytes=direct_val(e);out->op=M29_BEGIN;}
    else if(cord_is(op,"install-chunk")){noun a,b,c,d,e,z;if(!take(payload,&a,&b)||!take(b,&c,&b)||!take(b,&d,&e)||!take(e,&z,&payload)||payload!=NOUN_ZERO||!noun_is_direct(a)||!noun_is_direct(c)||!noun_is_direct(d)||direct_val(d)==0||direct_val(d)>M29_CHUNK_BYTES||!atom_bytes(z,out->data,sizeof out->data,direct_val(d)))return 0;out->installation=direct_val(a);out->offset=direct_val(c);out->data_len=(uint32_t)direct_val(d);out->op=M29_CHUNK;}
    else if(cord_is(op,"install-seal")||cord_is(op,"install-activate")||cord_is(op,"install-cancel")){noun a,b;if(!take(payload,&a,&b)||!noun_is_direct(a)||!direct_is(b,0)||!direct_val(a))return 0;out->installation=direct_val(a);out->op=cord_is(op,"install-seal")?M29_SEAL:cord_is(op,"install-activate")?M29_ACTIVATE:M29_CANCEL;}
    else return 0;
    return 1;
}

static int status_body(noun*out){noun v[8],tail;v[0]=direct(g_lifecycle);v[1]=direct(g_selected?1:0);v[2]=direct(g_generation);v[3]=direct(g_lifecycle!=M29_RUNNING);v[4]=direct(g_stage_open?g_installation:g_terminal_installation);v[5]=direct(g_stage_open?g_received:0);v[6]=direct(g_stage_open?g_chunks:0);v[7]=direct(g_terminal?1:0);tail=v[7];for(int i=6;i>=0;i--)if(!pair(v[i],tail,&tail))return 0;*out=tail;return 1;}
static int response_payload(uint64_t id,m29_result_t result,noun body,uint8_t*out,uint16_t*length)
{
    if(!noun_tx_begin(HEAP_MODE_SCRATCH))return 0;
    noun r,t,tag,ver,req,op;
    tag=g_management_tag;
    op=cord_from_bytes(result==M29_DONE?"done":result==M29_FAILED?"failed":"rejected",
                       result==M29_DONE?4:result==M29_FAILED?6:8);
    if(!pair(op,body,&t)||!pair(direct(id),t,&req)||!pair(direct(1),req,&ver)||!pair(tag,ver,&r)){
        noun_tx_abort();return 0;
    }
    const uint8_t*b;uint64_t n;
    if(jam_encode_bytes_identity(r,&b,&n)||!n||n>M29_MAX_PAYLOAD){
        noun_tx_abort();return 0;
    }
    for(uint64_t i=0;i<n;i++)out[i]=b[i];
    noun_tx_abort();*length=(uint16_t)n;return 1;
}

static int response_frame(const uint8_t *payload, uint16_t payload_len,
                          uint8_t out[M29_HEADER_BYTES + M29_MAX_PAYLOAD],
                          uint32_t *length, uint64_t response_sequence)
{
    if (!payload || !length || payload_len > M29_MAX_PAYLOAD) return 0;
    for (unsigned i=0;i<M29_HEADER_BYTES;i++) out[i]=0;
    out[0]='A';out[1]='E';out[2]='T';out[3]='0';
    out[4]=M29_WIRE_MAJOR;out[5]=M29_WIRE_MINOR;out[6]=M29_PROFILE;out[7]=M29_KIND_RESPONSE;
    out[8]=0;out[9]=M29_HEADER_BYTES;out[10]=(uint8_t)(payload_len>>8);out[11]=(uint8_t)payload_len;
    for(unsigned i=0;i<8;i++){
        out[12+i]=(uint8_t)((uint64_t)M29_TARGET>>(56u-i*8u));
        out[20+i]=(uint8_t)((uint64_t)M29_MANAGER>>(56u-i*8u));
    }
    for(unsigned i=0;i<16;i++)out[28+i]=M29_BINDING[i];
    for(unsigned i=0;i<32;i++)out[44+i]=M29_SCHEMA[i];
    out[79]=M29_KEY_ID;out[87]=M29_EPOCH;
    for(unsigned i=0;i<8;i++)out[88+i]=(uint8_t)(response_sequence>>(56u-i*8u));
    for(unsigned i=0;i<payload_len;i++)out[M29_HEADER_BYTES+i]=payload[i];
    uint8_t auth[32];
    hmac_sha256(M29_PSK,sizeof M29_PSK-1u,out,M29_HEADER_BYTES+payload_len,auth);
    for(unsigned i=0;i<32;i++)out[96+i]=auth[i];
    *length=M29_HEADER_BYTES+payload_len;return 1;
}
static int cache_find(uint64_t id,const uint8_t*d){for(unsigned i=0;i<M29_CACHE_ENTRIES;i++)if(g_cache[i].used&&g_cache[i].operation==id)return equal_bytes(g_cache[i].digest,d,32)?(int)i:-2;return -1;}
static int cache_put(uint64_t id,const uint8_t*d,const uint8_t*p,uint16_t n){for(unsigned i=0;i<M29_CACHE_ENTRIES;i++)if(!g_cache[i].used){g_cache[i].used=1;g_cache[i].operation=id;for(unsigned j=0;j<32;j++)g_cache[i].digest[j]=d[j];g_cache[i].len=n;for(unsigned j=0;j<n;j++)g_cache[i].payload[j]=p[j];return 1;}return 0;}
static int cache_free(void){for(unsigned i=0;i<M29_CACHE_ENTRIES;i++)if(!g_cache[i].used)return 1;return 0;}

static int checkpoint_cache_response_valid(const m29_cache_t *entry)
{
    if (!entry || entry->used != 1 || entry->operation == 0
        || entry->operation >= (1ULL << 63) || entry->len == 0
        || entry->len > M29_MAX_PAYLOAD) return 0;
    noun root,tag,rest,version,operation,result,body;
    int ok = cue_bounded_bytes(entry->payload,entry->len,&cue_i2_limits,
                               HEAP_MODE_SCRATCH,&root) == CUE_BOUNDED_OK;
    const uint8_t *canonical = 0; uint64_t canonical_len = 0;
    if (ok) ok = jam_encode_bytes_identity(root,&canonical,&canonical_len) == 0
        && canonical_len == entry->len
        && equal_bytes(canonical,entry->payload,entry->len);
    if (ok) ok = take(root,&tag,&rest) && cord_is(tag,"aethernet-management-m29")
        && take(rest,&version,&rest) && direct_is(version,1)
        && take(rest,&operation,&rest) && noun_is_direct(operation)
        && direct_val(operation) == entry->operation
        && take(rest,&result,&body)
        && (cord_is(result,"done") || cord_is(result,"rejected")
            || cord_is(result,"failed"));
    if (noun_tx_active()) noun_tx_abort();
    return ok;
}

static void hash_u64(sha256_ctx_t *ctx,uint64_t value)
{
    uint8_t bytes[8];
    for (unsigned i=0;i<8;i++) bytes[i]=(uint8_t)(value>>(8u*i));
    sha256_update(ctx,bytes,sizeof bytes);
}

static void checkpoint_replay_hash(uint8_t out[32])
{
    sha256_ctx_t ctx; sha256_init(&ctx);
    static const uint8_t domain[] = "M29-checkpoint-replay-v1";
    sha256_update(&ctx,domain,sizeof domain-1u);
    hash_u64(&ctx,g_checkpoint_selected); hash_u64(&ctx,g_checkpoint_terminal);
    hash_u64(&ctx,g_checkpoint_lifecycle); hash_u64(&ctx,g_checkpoint_generation);
    hash_u64(&ctx,g_checkpoint_installation);
    hash_u64(&ctx,g_checkpoint_sequence_high);
    hash_u64(&ctx,g_checkpoint_operation_high);
    hash_u64(&ctx,g_checkpoint_response_sequence);
    hash_u64(&ctx,g_checkpoint_rate_start);
    hash_u64(&ctx,g_checkpoint_rate_count);
    for (unsigned i=0;i<M29_CACHE_ENTRIES;i++) {
        const m29_cache_t *entry=&g_checkpoint_cache[i];
        hash_u64(&ctx,(uint64_t)entry->used); hash_u64(&ctx,entry->operation);
        sha256_update(&ctx,entry->digest,sizeof entry->digest);
        hash_u64(&ctx,entry->len);
        sha256_update(&ctx,entry->payload,entry->len);
    }
    sha256_final(&ctx,out);
}

static int checkpoint_replay_valid(void)
{
    if (g_checkpoint_selected > 1u
        || (g_checkpoint_lifecycle != M29_RUNNING
            && g_checkpoint_lifecycle != M29_STOPPED
            && g_checkpoint_lifecycle != M29_IDLE)
        || (g_checkpoint_selected == 0
            ? (g_checkpoint_generation != 1 || g_checkpoint_terminal != 0)
            : (g_checkpoint_generation != 2 || g_checkpoint_terminal != 1))
        || g_checkpoint_sequence_high == UINT64_MAX
        || g_checkpoint_operation_high == UINT64_MAX
        || g_checkpoint_response_sequence == 0
        || g_checkpoint_response_sequence == UINT64_MAX
        || g_checkpoint_rate_count > M29_RATE_LIMIT
        || (g_checkpoint_rate_start == 0 && g_checkpoint_rate_count != 0)) return 0;
    unsigned used=0; uint64_t previous=0,maximum=0;
    for (unsigned i=0;i<M29_CACHE_ENTRIES;i++) {
        const m29_cache_t *entry=&g_checkpoint_cache[i];
        if (entry->used == 0) continue;
        if (entry->used != 1 || entry->operation <= previous
            || !checkpoint_cache_response_valid(entry)) return 0;
        previous=entry->operation; maximum=entry->operation; used++;
    }
    if (maximum > g_checkpoint_operation_high
        || g_checkpoint_sequence_high < used
        || g_checkpoint_response_sequence < (uint64_t)used + 1u) return 0;
    uint8_t digest[32]; checkpoint_replay_hash(digest);
    return equal_bytes(digest,g_checkpoint_replay_digest,sizeof digest);
}

typedef struct {
    uint8_t policy_id[32], policy_digest[32], predecessor[32];
    uint8_t successor_program[32], successor_package[32];
    uint8_t successor_binding[32], successor_source[32], successor_limits[32];
    uint8_t pill_sha256[32], pill_blake3[32], battery[32], formula[32], data_plan[32];
    uint64_t generation, manager, device, resource, slot, schema;
    uint64_t predecessor_generation, pill_bytes, installation, operation;
    uint16_t runtime_major, runtime_minor;
} m29_policy_t;

static int policy_u(noun n, uint64_t *out)
{
    return out && noun_is_direct(n) && (*out = direct_val(n), 1);
}

static int policy_hash(noun n, uint8_t out[32])
{
    return atom_bytes(n, out, 32, 32);
}

static int parse_policy(const uint8_t *bytes, uint64_t len, m29_policy_t *out)
{
    noun root, tag, rest, version, count, fields, tail, values[24];
    uint64_t runtime_major, runtime_minor;
    if (!bytes || !out || len == 0 || len > 8192u
        || cue_bounded_bytes(bytes, len, &cue_i2_limits, HEAP_MODE_SCRATCH, &root)
            != CUE_BOUNDED_OK)
        return 0;
    const uint8_t *canonical; uint64_t canonical_len;
    if (jam_encode_bytes_identity(root, &canonical, &canonical_len)
        || canonical_len != len || !equal_bytes(canonical, bytes, len)
        || !take(root, &tag, &rest) || !cord_is(tag, "CommissioningPolicyV1")
        || !take(rest, &version, &rest) || !direct_is(version, 1)
        || !take(rest, &count, &rest) || !direct_is(count, 1)
        || !take(rest, &fields, &tail) || tail != NOUN_ZERO)
        goto reject;
    for (unsigned i = 0; i < 24; i++)
        if (!take(fields, &values[i], &fields)) goto reject;
    if (fields != NOUN_ZERO) goto reject;

    noun body = NOUN_ZERO;
    for (int i = 23; i >= 0; i--) {
        if (i == 1) continue;
        if (!pair(values[i], body, &body)) goto reject;
    }
    if (jam_encode_bytes_identity(body, &canonical, &canonical_len)) goto reject;
    uint8_t digest[32]; sha256_hash(canonical, canonical_len, digest);
    if (!policy_hash(values[0], out->policy_id)
        || !policy_hash(values[1], out->policy_digest)
        || !equal_bytes(out->policy_digest, digest, 32)
        || !policy_u(values[2], &out->generation)
        || !policy_u(values[3], &out->manager)
        || !policy_u(values[4], &out->device)
        || !policy_u(values[5], &out->resource)
        || !policy_u(values[6], &out->slot)
        || !policy_u(values[7], &out->schema)
        || !policy_hash(values[8], out->predecessor)
        || !policy_u(values[9], &out->predecessor_generation)
        || !policy_hash(values[10], out->successor_program)
        || !policy_hash(values[11], out->successor_package)
        || !policy_hash(values[12], out->successor_binding)
        || !policy_hash(values[13], out->successor_source)
        || !policy_hash(values[14], out->successor_limits)
        || !policy_u(values[15], &out->pill_bytes)
        || !policy_hash(values[16], out->pill_sha256)
        || !policy_hash(values[17], out->pill_blake3)
        || !policy_hash(values[18], out->battery)
        || !policy_hash(values[19], out->formula)
        || !take(values[20], &version, &rest)
        || !policy_u(version, &runtime_major)
        || !policy_u(rest, &runtime_minor)
        || runtime_major > UINT16_MAX || runtime_minor > UINT16_MAX
        || !policy_hash(values[21], out->data_plan)
        || !policy_u(values[22], &out->installation)
        || !policy_u(values[23], &out->operation))
        goto reject;
    out->runtime_major = (uint16_t)runtime_major;
    out->runtime_minor = (uint16_t)runtime_minor;
    noun_tx_abort();
    return 1;
reject:
    noun_tx_abort();
    return 0;
}

static int policy_bootstrap_valid(const m29_policy_t *p)
{
    return p && p->generation == 2 && p->manager == M29_MANAGER
        && p->device == M29_TARGET && p->resource == 1 && p->slot == 1
        && p->schema == 1 && p->predecessor_generation == 1
        && p->pill_bytes > 0 && p->pill_bytes <= M29_STAGE_BYTES
        && p->runtime_major == 1 && p->runtime_minor == 9
        && p->installation > 0 && p->operation > 0
        && equal_bytes(p->predecessor, g_identity.program_hash, 32)
        && equal_bytes(p->battery, g_identity.battery_hash, 32)
        && equal_bytes(p->formula, M29_FORMULA_ID, 32)
        && equal_bytes(p->data_plan, M29_DATA_PLAN_ID, 32);
}

static int validate_program_projection(noun gate,
                                       const runtime_identity_t *identity,
                                       const m29_policy_t *policy)
{
    noun ignored, state, tag, rest, program_n, dynamic;
    noun tables, exports, services;
    uint8_t actual_source[32];
    if(!take(gate,&ignored,&rest) || !take(rest,&ignored,&state)
       || !take(state,&tag,&rest)
       || !direct_is(tag,0x65746174732d3269ULL)) return 0;
    if(!take(rest,&ignored,&rest) || !take(rest,&program_n,&dynamic)
       || !take(program_n,&tag,&rest)) return 0;
    if(!policy || !identity || !runtime_identity_validate_gate(gate,identity,0)
       || !equal_bytes(identity->package_hash,policy->successor_package,32)
       || !equal_bytes(identity->program_hash,policy->successor_program,32)
       || !equal_bytes(identity->battery_hash,policy->battery,32)) return 0;
    if(!take(rest,&ignored,&tables) || !take(tables,&ignored,&tables)
       || !take(tables,&ignored,&tables) || !take(tables,&ignored,&tables)
       || !take(tables,&exports,&services)) return 0;
    return cord_is(tag, "i2-resource-program-v1")
        && atom_bytes(exports, actual_source, 32, 32)
        && equal_bytes(actual_source, policy->successor_source, 32)
        && noun_is_cell(services);
}

static int activate_install(const m29_request_t*r,uint8_t*reserved,uint16_t*reserved_len)
{
    if(!g_stage_open||!g_stage_sealed||r->installation!=g_installation
       ||g_lifecycle!=M29_STOPPED||g_selected||g_terminal
       ||g_received!=g_total||g_policy_bytes+g_pill_bytes!=g_total
       ||g_policy_bytes==0||g_pill_bytes==0)return 0;
    /* Reserve the management result before any candidate cueing begins.  The
     * candidate validator leaves its own noun transaction live until the
     * clean local publication boundary, so result serialization belongs
     * before that transaction. */
    if(!response_payload(r->operation,M29_DONE,NOUN_ZERO,reserved,reserved_len))return 0;

    m29_policy_t policy;
    if(!parse_policy(g_stage,g_policy_bytes,&policy)
       ||!policy_bootstrap_valid(&policy)
       ||policy.installation!=r->installation
       ||policy.operation==0
       ||policy.pill_bytes!=g_pill_bytes)goto reject;
    uint8_t policy_sha[32], pill_sha[32], pill_b3[32];
    sha256_hash(g_stage,g_policy_bytes,policy_sha);
    sha256_hash(g_stage+g_policy_bytes,g_pill_bytes,pill_sha);
    blake3_hash(g_stage+g_policy_bytes,g_pill_bytes,pill_b3);
    if(!equal_bytes(policy_sha,g_stage_policy_sha256,32)
       ||!equal_bytes(pill_sha,g_stage_pill_sha256,32)
       ||!equal_bytes(pill_sha,policy.pill_sha256,32)
       ||!equal_bytes(pill_b3,policy.pill_blake3,32))goto reject;

    noun candidate,prepared;
    runtime_identity_t identity;uint8_t capability;
    uint8_t got_limits[32], capability_binding[32];
    pill_i2_status_t candidate_status = pill_i2_validate_buffer(
        g_stage+g_policy_bytes,g_pill_bytes,HEAP_MODE_PERSIST,
        &candidate,&identity,&capability);
    if(candidate_status!=PILL_I2_OK)goto reject;
    if(capability!=RUNTIME_CAPABILITY_PROFILE_M25)goto reject;
    if(identity.generation!=2)goto reject;
    if(identity.runtime_abi[0]!=1||identity.runtime_abi[1]!=9)goto reject;
    if(identity.formula_abi[0]!=1||identity.formula_abi[1]!=9)goto reject;
    if(!equal_bytes(identity.program_hash,policy.successor_program,32))goto reject;
    if(!equal_bytes(identity.package_hash,policy.successor_package,32))goto reject;
    if(!equal_bytes(identity.battery_hash,policy.battery,32))goto reject;
    if(!i2_admission_limits_hash(candidate,got_limits)
       ||!equal_bytes(got_limits,policy.successor_limits,32))goto reject;
    if(!i2_candidate_binding_digest(candidate,policy.resource,policy.generation,
                                    identity.package_hash,identity.battery_hash,
                                    capability_binding)
       ||!equal_bytes(capability_binding,policy.successor_binding,32))goto reject;
    if(!validate_program_projection(candidate,&identity,&policy))goto reject;
    if(m26_target_prepare_gate(candidate,&identity,capability,&prepared)!=0)goto reject;
    /* No fallible operation follows this local publication boundary. */
    noun_tx_commit();heap_persist_commit_tx();
    m26_target_publish_gate(prepared,&identity,capability);
    g_selected=1;g_generation=2;g_lifecycle=M29_IDLE;g_terminal=1;
    g_terminal_installation=r->installation;
    for(unsigned i=0;i<32;i++){
        g_active_policy_digest[i]=policy.policy_digest[i];
        g_active_program_identity[i]=identity.program_hash[i];
    }
    g_stage_open=g_stage_sealed=0;
    g_received=g_chunks=g_total=g_policy_bytes=g_pill_bytes=0;
    return 1;
reject:
    if(noun_tx_active())noun_tx_abort();
    return response_payload(r->operation,M29_REJECTED,NOUN_ZERO,reserved,reserved_len);
}

static int execute(const m29_request_t*r,uint8_t*out,uint16_t*length)
{
    m29_result_t result=M29_REJECTED;noun body=NOUN_ZERO;
    if(r->op==M29_STATUS){if(!status_body(&body))return 0;result=M29_DONE;}
    else if(r->op==M29_STOP){if(g_lifecycle==M29_RUNNING&&!g_stage_open&&m26_target_set_running(0)==0){g_lifecycle=M29_STOPPED;result=M29_DONE;}if(result==M29_DONE&&!status_body(&body))return 0;}
    else if(r->op==M29_BEGIN){
        if(g_lifecycle==M29_STOPPED&&!g_stage_open&&!g_terminal
           &&r->installation>0&&r->total>0&&r->total<=M29_STAGE_BYTES
           &&r->policy_bytes>0&&r->policy_bytes<=8192
           &&r->pill_bytes>0&&r->policy_bytes+r->pill_bytes==r->total){
            g_installation=r->installation;g_total=r->total;
            g_policy_bytes=r->policy_bytes;g_pill_bytes=r->pill_bytes;
            g_received=g_chunks=0;
            for(unsigned i=0;i<32;i++){
                g_stage_policy_sha256[i]=r->policy_sha256[i];
                g_stage_pill_sha256[i]=r->pill_sha256[i];
            }
            g_stage_open=1;g_stage_sealed=0;
            uint64_t lease_start=now();
            g_lease=lease_start+freq()*M29_LEASE_SECONDS;
#ifdef M32_TEST_CONTROLS
            g_diag_lease_start=lease_start; g_diag_lease_expiry=g_lease;
            g_diag_lease_expired=0;
#endif
            result=M29_DONE;
        }
    } else if(r->op==M29_CHUNK){
        if(g_lifecycle==M29_STOPPED&&g_stage_open&&!g_stage_sealed
           &&r->installation==g_installation&&r->data_len
           &&r->offset<=g_received&&r->offset+r->data_len<=g_total){
            if(r->offset<g_received){
                if(r->offset+r->data_len<=g_received
                   &&equal_bytes(g_stage+r->offset,r->data,r->data_len))result=M29_DONE;
            }else if(r->offset==g_received&&g_chunks<M29_MAX_CHUNKS){
                for(uint32_t i=0;i<r->data_len;i++)g_stage[g_received+i]=r->data[i];
                g_received+=r->data_len;g_chunks++;
                uint64_t lease_start=now();
                g_lease=lease_start+freq()*M29_LEASE_SECONDS;
#ifdef M32_TEST_CONTROLS
                g_diag_lease_start=lease_start; g_diag_lease_expiry=g_lease;
                g_diag_lease_expired=0;
#endif
                result=M29_DONE;
            }
        }
    } else if(r->op==M29_SEAL){
        uint8_t policy_sha[32],pill_sha[32];
        if(g_lifecycle==M29_STOPPED&&g_stage_open&&!g_stage_sealed
           &&r->installation==g_installation
           &&g_received==g_total){
            sha256_hash(g_stage,g_policy_bytes,policy_sha);
            sha256_hash(g_stage+g_policy_bytes,g_pill_bytes,pill_sha);
            m29_policy_t policy;
            if(equal_bytes(policy_sha,g_stage_policy_sha256,32)
               &&equal_bytes(pill_sha,g_stage_pill_sha256,32)
               &&parse_policy(g_stage,g_policy_bytes,&policy)
               &&policy.installation==g_installation
               &&policy.pill_bytes==g_pill_bytes){
                g_stage_sealed=1;result=M29_DONE;
            }
        }
    }
    else if(r->op==M29_ACTIVATE){if(activate_install(r,out,length))return 1;}
    else if(r->op==M29_CANCEL){if(g_lifecycle==M29_STOPPED&&g_stage_open&&r->installation==g_installation){g_stage_open=g_stage_sealed=0;g_received=g_chunks=g_total=g_policy_bytes=g_pill_bytes=0;result=M29_DONE;}}
    else if(r->op==M29_START){if(g_selected&&(g_lifecycle==M29_IDLE||g_lifecycle==M29_STOPPED)&&!g_stage_open&&m26_target_init()==0&&m29_native_init()==0&&m26_target_set_running(1)==0){g_lifecycle=M29_RUNNING;result=M29_DONE;if(!status_body(&body))return 0;}}
    if(!response_payload(r->operation,result,body,out,length))return 0;
    return 1;
}

int m29_target_boot(noun gate,const runtime_identity_t*identity,uint8_t capability)
{
    uint64_t rid=0;
    if(!gate_resource_id(gate,&rid)||rid!=1
       ||!identity||capability!=RUNTIME_CAPABILITY_PROFILE_M25||identity->generation!=1
       ||!equal_bytes(identity->program_hash,M29_PREDECESSOR_PROGRAM,32)
       ||!equal_bytes(identity->package_hash,M29_PREDECESSOR_ANCHOR,32))return -1;
    (void)gate;g_identity=*identity;g_management_tag=cord_from_bytes("aethernet-management-m29",24);if(!noun_is_atom(g_management_tag))return -1;for(unsigned i=0;i<M29_CACHE_ENTRIES;i++)g_cache[i].used=0;g_pending.used=0;g_lifecycle=M29_RUNNING;g_selected=0;g_terminal=0;g_generation=1;g_terminal_installation=0;g_sequence_high=0;g_operation_high=0;g_response_sequence=1;g_rate_start=g_rate_count=0;g_stage_open=g_stage_sealed=0;g_initialized=0;g_checkpoint_valid=0;
#ifdef M32_TEST_CONTROLS
    g_diag_management_rx=g_diag_decode_ok=g_diag_decode_failures=0;
    g_diag_accepted=g_diag_refused=0;
    g_diag_last_sequence=g_diag_last_operation=g_diag_last_offset=0;
    for (unsigned i=0;i<32;i++) g_diag_last_digest[i]=0;
    g_diag_cache_hits=g_diag_cache_misses=g_diag_cache_conflicts=0;
    g_diag_cache_presence=g_diag_execute_count=g_diag_pending_replays=0;
    g_diag_pending_refusals=0;
    g_diag_lease_start=g_diag_lease_expiry=g_diag_lease_expired=0;
#endif
    return 0;
}

static m29_pending_tx_t pending_tx_state(void)
{
    int completion=m29_native_tx_complete();
    return completion==0?M29_PENDING_IN_FLIGHT:M29_PENDING_UNSENT;
}

static int pending_store(uint64_t operation,const uint8_t digest[32],
                         const uint8_t *payload,uint16_t length)
{
    if(g_pending.used||!digest||!payload||!length||length>M29_MAX_PAYLOAD
       ||g_response_sequence==UINT64_MAX)return 0;
    /* virtio_net_send may report a bounded poll failure after the descriptor
     * has already reached the used ring.  A completion observed here is an
     * authenticated local proof that the retained response was submitted;
     * keeping a stale slot in that case would fence the next mutation even
     * after the host has correlated this response.  If the host did not see
     * it, the normal exact cache replay remains available. */
    int submitted=m29_native_last_send_submitted();
    int completion=m29_native_tx_complete();
    if(submitted && completion>0){
        g_response_sequence++;
        return 1;
    }
    g_pending.used=1;g_pending.operation=operation;g_pending.len=length;
    g_pending.response_sequence=g_response_sequence;g_pending.attempts=1;
    g_pending.tx_state=(!submitted||completion<0)?M29_PENDING_UNSENT:M29_PENDING_IN_FLIGHT;
    for(unsigned i=0;i<32;i++)g_pending.digest[i]=digest[i];
    for(unsigned i=0;i<length;i++)g_pending.payload[i]=payload[i];
    return 1;
}

static int pending_retry(const m29_request_t *r,const uint8_t digest[32])
{
    if(!r||!digest||!g_pending.used||r->operation!=g_pending.operation
       ||!equal_bytes(digest,g_pending.digest,32))return 0;
    if(g_pending.attempts>=M29_RESPONSE_ATTEMPTS)return 0;
    g_pending.attempts++;
    int completion=m29_native_tx_complete();
    if(completion==0){g_pending.tx_state=M29_PENDING_IN_FLIGHT;return 0;}
    if(completion<0){g_pending.tx_state=M29_PENDING_UNSENT;return 0;}
    g_pending.tx_state=M29_PENDING_UNSENT;
    uint8_t frame[M29_HEADER_BYTES+M29_MAX_PAYLOAD];uint32_t frame_len=0;
    if(!response_frame(g_pending.payload,g_pending.len,frame,&frame_len,
                       g_pending.response_sequence))return 0;
    if(m29_native_send(frame,frame_len)!=M29_NATIVE_OK){
        g_pending.tx_state=pending_tx_state();return 0;
    }
    g_response_sequence++;g_pending.used=0;return 1;
}

static void pending_poll_completion(void)
{
    /* An unsent frame has no descriptor to poll.  Treating an available TX
     * ring as completion for that state would silently clear a persistent
     * submit failure before the bounded exact replay gets its attempt. */
    if(!g_pending.used||g_pending.tx_state!=M29_PENDING_IN_FLIGHT)return;
    int completion=m29_native_tx_complete();
    if(completion>0){
        /* Completion proves the retained frame was submitted.  A lost
         * host-visible frame is repaired by the normal cache replay; no
         * background retransmission is introduced here. */
        g_response_sequence++;g_pending.used=0;
    }else if(completion<0){
        g_pending.tx_state=M29_PENDING_UNSENT;
    }else{
        g_pending.tx_state=M29_PENDING_IN_FLIGHT;
    }
}

int m29_target_service_tick(void)
{
    if(!g_initialized){
        if(!m26_target_native_ready())return 0;
        if(m29_native_init()!=0)return 0;
        g_initialized=1;
    }
    if(g_stage_open&&g_lease&&now()>=g_lease){
#ifdef M32_TEST_CONTROLS
        g_diag_lease_expired=1;
#endif
        g_stage_open=g_stage_sealed=0;g_received=g_chunks=g_total=g_policy_bytes=g_pill_bytes=0;
        for(unsigned i=0;i<32;i++){g_stage_policy_sha256[i]=0;g_stage_pill_sha256[i]=0;}
    }
    pending_poll_completion();
    m29_native_datagram_t d;
    m29_native_status_t native=m29_native_receive(&d);
    if(native!=M29_NATIVE_OK)return 0;
#ifdef M32_TEST_CONTROLS
    g_diag_management_rx++;
#endif
    uint8_t digest[32];
    sha256_hash(d.payload,d.payload_len,digest);
    m29_request_t r;
    if(!decode_request(d.header,d.payload,d.payload_len,&r)){
#ifdef M32_TEST_CONTROLS
        g_diag_decode_failures++;
#endif
        return 0;
    }
#ifdef M32_TEST_CONTROLS
    g_diag_decode_ok++;
    g_diag_last_sequence=r.sequence; g_diag_last_operation=r.operation;
    g_diag_last_offset=r.offset;
    for (unsigned i=0;i<32;i++) g_diag_last_digest[i]=digest[i];
#endif
    if(noun_tx_active())noun_tx_abort();
    if(g_pending.used){
        if(r.operation!=g_pending.operation){
#ifdef M32_TEST_CONTROLS
            g_diag_pending_refusals++;
#endif
            return 0;
        }
        if(!equal_bytes(digest,g_pending.digest,32)){
#ifdef M32_TEST_CONTROLS
            g_diag_pending_refusals++;
#endif
            return 0;
        }
        if(g_pending.attempts>=M29_RESPONSE_ATTEMPTS)return 0;
        if(!accept_sequence(r.sequence)){
#ifdef M32_TEST_CONTROLS
            g_diag_refused++;
#endif
            return 0;
        }
#ifdef M32_TEST_CONTROLS
        g_diag_accepted++; g_diag_pending_replays++; g_diag_cache_presence=1;
#endif
        return pending_retry(&r,digest);
    }
    if(!accept_sequence(r.sequence)){
#ifdef M32_TEST_CONTROLS
        g_diag_refused++;
#endif
        return 0;
    }
#ifdef M32_TEST_CONTROLS
    g_diag_accepted++;
#endif
    if(g_response_sequence==UINT64_MAX)return 0;
    int found=cache_find(r.operation,digest);
#ifdef M32_TEST_CONTROLS
    if (found>=0) { g_diag_cache_hits++; g_diag_cache_presence=1; }
    else if (found==-2) { g_diag_cache_conflicts++; g_diag_cache_presence=2; }
    else { g_diag_cache_misses++; g_diag_cache_presence=0; }
#endif
    uint8_t response[M29_MAX_PAYLOAD];uint16_t n=0;
    if(found>=0){
        for(unsigned i=0;i<g_cache[found].len;i++)response[i]=g_cache[found].payload[i];
        n=g_cache[found].len;
    }else if(found==-2){
        if(!response_payload(r.operation,M29_REJECTED,NOUN_ZERO,response,&n))return 0;
    }else{
        if(r.operation==0||r.operation==UINT64_MAX||r.operation<=g_operation_high)return 0;
#ifdef M32_TEST_CONTROLS
        g_diag_execute_count++;
#endif
        if(!cache_free()||!execute(&r,response,&n))return 0;
        if(!cache_put(r.operation,digest,response,n))return 0;
        g_operation_high=r.operation;
    }
    uint8_t frame[M29_HEADER_BYTES+M29_MAX_PAYLOAD];uint32_t frame_len=0;
    if(!response_frame(response,n,frame,&frame_len,g_response_sequence))return 0;
    if(m29_native_send(frame,frame_len)!=M29_NATIVE_OK){
        if(!pending_store(r.operation,digest,response,n))return 0;
        return 0;
    }
    g_response_sequence++;return 1;
}

int m29_target_checkpoint_capture(void)
{
    /* The supported M29 checkpoint profile is already-quiescent STOPPED.
     * RUNNING capture would create a checkpoint whose restore requires a
     * fallible provider/native reinitialization suffix without rollback. */
    if(g_lifecycle!=M29_STOPPED||g_stage_open||g_pending.used
       ||g_checkpoint_valid||m26_target_checkpoint_capture()!=0)return -1;
    g_checkpoint_selected=g_selected;g_checkpoint_terminal=g_terminal;
    g_checkpoint_lifecycle=g_lifecycle;g_checkpoint_generation=g_generation;
    g_checkpoint_installation=g_terminal_installation;
    g_checkpoint_sequence_high=g_sequence_high;
    g_checkpoint_operation_high=g_operation_high;
    g_checkpoint_response_sequence=g_response_sequence;
    g_checkpoint_rate_start=g_rate_start;g_checkpoint_rate_count=g_rate_count;
    for(unsigned i=0;i<32;i++){
        g_checkpoint_policy_digest[i]=g_active_policy_digest[i];
        g_checkpoint_program_identity[i]=g_active_program_identity[i];
    }
    for(unsigned i=0;i<M29_CACHE_ENTRIES;i++){
        g_checkpoint_cache[i]=g_cache[i];
    }
    checkpoint_replay_hash(g_checkpoint_replay_digest);
    g_checkpoint_valid=1;return 0;
}
int m29_target_checkpoint_restore(void)
{
    /* Validate the complete bounded replay record before touching the M26
     * provider or any M29 publication state.  The digest detects mutation of
     * the fixed checkpoint copy; this is an in-memory integrity fence, not a
     * crash/power-loss durability claim. */
    /* Refuse RUNNING restore before the underlying M26 provider restore or
     * any M29 publication assignment.  The later reinitialization path is
     * therefore unreachable in the supported STOPPED-only profile. */
    if(!g_checkpoint_valid||g_lifecycle!=M29_STOPPED||g_stage_open
       ||g_pending.used||!checkpoint_replay_valid())return -1;
    if(m26_target_checkpoint_restore()!=0)return -1;
    g_selected=g_checkpoint_selected;g_terminal=g_checkpoint_terminal;
    g_lifecycle=g_checkpoint_lifecycle;g_generation=g_checkpoint_generation;
    g_terminal_installation=g_checkpoint_installation;
    g_sequence_high=g_checkpoint_sequence_high;
    g_operation_high=g_checkpoint_operation_high;
    g_response_sequence=g_checkpoint_response_sequence;
    g_rate_start=g_checkpoint_rate_start;
    g_rate_count=g_checkpoint_rate_count;
    for(unsigned i=0;i<32;i++){
        g_active_policy_digest[i]=g_checkpoint_policy_digest[i];
        g_active_program_identity[i]=g_checkpoint_program_identity[i];
    }
    for(unsigned i=0;i<M29_CACHE_ENTRIES;i++){
        g_cache[i]=g_checkpoint_cache[i];
    }
    return 0;
}
#ifdef M29_TEST_CONTROLS
int m29_target_test_checkpoint_tamper(void)
{
    /* The separate replay digest remains untouched: this is the compiled
     * target witness for detecting a single cached-field mutation. */
    if(!g_checkpoint_valid||!g_checkpoint_cache[0].used)return -1;
    g_checkpoint_cache[0].digest[0]^=1u;
    return 0;
}
#endif
uint64_t m29_target_selected(void){return g_selected?1:0;} uint64_t m29_target_generation(void){return g_generation;} uint64_t m29_target_terminal(void){return g_terminal?1:0;}
uint64_t m29_target_pending(void){return g_pending.used?1:0;}
uint64_t m29_target_pending_attempts(void){return g_pending.used?g_pending.attempts:0;}
uint64_t m29_target_pending_tx_state(void){return g_pending.used?(uint64_t)g_pending.tx_state:0;}
uint64_t m29_target_response_sequence(void){return g_response_sequence;}
#ifdef M32_TEST_CONTROLS
static uint64_t diag_digest_part(const uint8_t digest[32], uint64_t index)
{
    if (!digest || index >= 4) return UINT64_MAX;
    uint64_t value=0;
    for (unsigned i=0;i<8;i++) value|=(uint64_t)digest[index*8u+i]<<(8u*i);
    return value;
}

static uint64_t diag_cache_used(void)
{
    uint64_t used=0;
    for (unsigned i=0;i<M29_CACHE_ENTRIES;i++) if (g_cache[i].used) used++;
    return used;
}

uint64_t m29_target_diag_management_rx(void){return g_diag_management_rx;}
uint64_t m29_target_diag_decode_ok(void){return g_diag_decode_ok;}
uint64_t m29_target_diag_decode_failures(void){return g_diag_decode_failures;}
uint64_t m29_target_diag_accepted(void){return g_diag_accepted;}
uint64_t m29_target_diag_refused(void){return g_diag_refused;}
uint64_t m29_target_diag_last_sequence(void){return g_diag_last_sequence;}
uint64_t m29_target_diag_last_operation(void){return g_diag_last_operation;}
uint64_t m29_target_diag_last_offset(void){return g_diag_last_offset;}
uint64_t m29_target_diag_last_digest(uint64_t index){return diag_digest_part(g_diag_last_digest,index);}
uint64_t m29_target_diag_cache_hits(void){return g_diag_cache_hits;}
uint64_t m29_target_diag_cache_misses(void){return g_diag_cache_misses;}
uint64_t m29_target_diag_cache_conflicts(void){return g_diag_cache_conflicts;}
uint64_t m29_target_diag_cache_presence(void){return g_diag_cache_presence;}
uint64_t m29_target_diag_cache_used(void){return diag_cache_used();}
uint64_t m29_target_diag_execute_count(void){return g_diag_execute_count;}
uint64_t m29_target_diag_pending_replays(void){return g_diag_pending_replays;}
uint64_t m29_target_diag_pending_refusals(void){return g_diag_pending_refusals;}
uint64_t m29_target_diag_pending_operation(void){return g_pending.used?g_pending.operation:0;}
uint64_t m29_target_diag_pending_digest(uint64_t index)
{
    return g_pending.used?diag_digest_part(g_pending.digest,index):0;
}
uint64_t m29_target_diag_stage_open(void){return g_stage_open?1:0;}
uint64_t m29_target_diag_stage_sealed(void){return g_stage_sealed?1:0;}
uint64_t m29_target_diag_stage_received(void){return g_received;}
uint64_t m29_target_diag_stage_chunks(void){return g_chunks;}
uint64_t m29_target_diag_lease_start(void){return g_diag_lease_start;}
uint64_t m29_target_diag_lease_remaining(void)
{
    if (!g_stage_open || !g_lease) return 0;
    uint64_t current=now();
    return current>=g_lease?0:g_lease-current;
}
uint64_t m29_target_diag_lease_expired(void){return g_diag_lease_expired;}
uint64_t m29_target_diag_operation_high(void){return g_operation_high;}
#endif
