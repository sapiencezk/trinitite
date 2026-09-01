/* Native owner for the exact M37 IEC Service profile.
 *
 * This module consumes only the closed candidate formula and its numeric
 * envelopes.  It does not inspect FB type names, XML, IEC spellings, or a
 * Python/host state machine.  The existing M37-A-R adapter remains the sole
 * authenticated UINT16 transport boundary.
 */
#include <stdint.h>

#include "m37_service_target_core.h"

#ifdef M37_IEC_SERVICE

#include "bounded_cue.h"
#include "i2_application_surface.h"
#include "jam.h"
#include "m25_aethernet_native.h"
#include "m34_local_allocation.h"
#include "m37_a_r_adapter.h"
#include "nock.h"
#include "setjmp.h"
#include "sha256.h"

#define PROFILE 2ULL
#define WIRE_MAJOR 0ULL
#define WIRE_MINOR 1ULL
#define KEY_ID 1ULL
#define EPOCH 1ULL
#define MAX_PAYLOAD 512ULL
#define MAX_OPS 2000000ULL
#define MAX_CELLS 128000ULL
#define UINT16_MAX_VALUE 65535ULL
#define RECOVERY_ATTEMPTS 4u
#define OUTPUT_CAPACITY 1u
#define PHASE_NEW 0ULL
#define PHASE_READY 1ULL
#define PHASE_REQUEST_PENDING 2ULL
#define PHASE_INDICATION_PENDING 3ULL
#define PHASE_RELEASED 4ULL
#define EVENT_INIT 1ULL
#define EVENT_REQ 2ULL
#define EVENT_RSP 3ULL
#define EVENT_INITO 4ULL
#define EVENT_CNF 5ULL
#define EVENT_IND 6ULL
#define CAUSE_COMPLETE 4ULL
#define CAUSE_DELIVER 5ULL
#define CAUSE_PROVIDER_RELEASE 6ULL
#define TYPE_UINT16 4ULL
#define STATUS_OK 0ULL
#define STATUS_INVALID 1ULL
#define STATUS_PROVIDER 2ULL
#define ROLE_PUBLISHER 1ULL
#define ROLE_SUBSCRIBER 2ULL

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
static const uint8_t SERVICE_PLAN_ID[32] = {
    0x53,0x4f,0x47,0xcc,0x2e,0xdd,0xe4,0x45,
    0x3f,0x47,0x38,0xb4,0x6a,0xbc,0x43,0x0d,
    0x7a,0x96,0x08,0x76,0x02,0x71,0xff,0x6f,
    0x9c,0x22,0x25,0x20,0x87,0x80,0x69,0x44,
};
static const uint64_t PUBLISHER_LOCAL_DESCRIPTOR[11] =
    {2,2,8,2,4,8,9,5,1,1,4};
static const uint64_t SUBSCRIBER_LOCAL_DESCRIPTOR[11] =
    {6,2,8,2,1,8,9,5,1,1,1};

typedef struct {
    noun gate;
    m37_a_r_transport_binding_t binding;
    noun plan;
    noun initial_state;
    noun formula;
} m37_service_prepared_t;

typedef struct {
    uint8_t payload[MAX_PAYLOAD];
    uint32_t payload_len;
    uint64_t sequence;
    uint64_t token;
    uint64_t value;
    noun state;
} m37_service_pending_t;

static m37_service_prepared_t g_prepared;
static uint8_t g_prepared_valid;
static m37_a_r_transport_binding_t g_binding;
static noun g_state, g_formula, g_plan;
static uint8_t g_active, g_running, g_source, g_initialized, g_plan_bound;
static uint8_t g_provider_pending, g_pending_valid;
static uint8_t g_retry_attempts, g_terminal_fence, g_recovery_paused;
static m37_service_pending_t g_pending;
static uint64_t g_output[5];
static uint8_t g_output_valid;
static uint64_t g_last_error, g_root_commits, g_publications, g_rx_high;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head; *tail = c->tail; return 1;
}
static int direct_is(noun n, uint64_t value)
{ return noun_is_direct(n) && direct_val(n) == value; }
static int cons(noun a, noun b, noun *out)
{ return alloc_cell_checked(a, b, out); }
static int fixed(noun n, uint8_t *out, unsigned length)
{ return out && noun_atom_read_fixed(n, out, length); }
static int same_bytes(const uint8_t *a, const uint8_t *b, unsigned n)
{ for (unsigned i=0;i<n;i++) if (a[i] != b[i]) return 0; return 1; }
static int positive_direct(noun n, uint64_t *out)
{ if (!noun_is_direct(n) || !direct_val(n)) return 0; if (out) *out=direct_val(n); return 1; }

static int state_values(noun state, uint64_t values[6])
{
    noun cur = state, item;
    for (unsigned i=0;i<6;i++) {
        if (!take(cur, &item, &cur) || !noun_is_direct(item)) return 0;
        values[i] = direct_val(item);
    }
    return direct_is(cur, 0);
}

static int parse_binding(noun binding, m37_a_r_transport_binding_t *out,
                         noun *plan, noun *initial_state)
{
    noun tag, rest, item;
    uint64_t fields[14];
    uint8_t bytes[8][32];
    if (!out || !take(binding, &tag, &rest)
        || !i2_application_surface_tag_matches(
            tag, "m37-iec-service-binding-v1", 26)) return 0;
    for (unsigned i=0;i<14;i++)
        if (!take(rest,&item,&rest) || !noun_is_direct(item)) return 0;
        else fields[i]=direct_val(item);
    out->local_device=fields[0]; out->peer_device=fields[1]; out->role=fields[2];
    out->channel=fields[3]; out->local_port=fields[4]; out->peer_port=fields[5];
    out->profile=fields[6]; out->wire_major=fields[7]; out->wire_minor=fields[8];
    out->key_id=fields[9]; out->epoch=fields[10]; out->max_payload=fields[11];
    out->max_ops=fields[12]; out->max_cells=fields[13];
    for (unsigned i=0;i<4;i++)
        if (!take(rest,&item,&rest) || !fixed(item,bytes[i],i<2?16:32)) return 0;
    if (!take(rest,&item,&rest) || !fixed(item,bytes[4],6)
        || !take(rest,&item,&rest) || !fixed(item,bytes[5],6)
        || !take(rest,&item,&rest) || !fixed(item,bytes[6],16)
        || !take(rest,&item,&rest) || !fixed(item,bytes[7],16)) return 0;
    for (unsigned i=0;i<11;i++)
        if (!take(rest,&item,&rest) || !noun_is_direct(item)) return 0;
        else out->peer_descriptor[i]=direct_val(item);
    uint8_t plan_id[32];
    if (!take(rest,&item,&rest)) return 0;
    if (!fixed(item,plan_id,32) || !same_bytes(plan_id,SERVICE_PLAN_ID,32)) return 0;
    if (!take(rest,plan,&rest) || !noun_is_cell(*plan)
        || jam_size_checked(*plan,16384u,&(uint64_t){0}) != 0) return 0;
    if (!take(rest,initial_state,&rest) || !noun_is_cell(*initial_state)
        || !direct_is(rest,0)) return 0;
    for (unsigned i=0;i<16;i++) out->outbound_binding[i]=bytes[0][i],out->inbound_binding[i]=bytes[1][i];
    for (unsigned i=0;i<32;i++) out->schema_digest[i]=bytes[2][i],out->domain_digest[i]=bytes[3][i];
    for (unsigned i=0;i<6;i++) out->local_mac[i]=bytes[4][i],out->peer_mac[i]=bytes[5][i];
    for (unsigned i=0;i<16;i++) out->local_ip[i]=bytes[6][i],out->peer_ip[i]=bytes[7][i];
    return 1;
}

static int binding_valid(const m37_a_r_transport_binding_t *b, noun plan,
                         noun initial_state)
{
    uint64_t values[6];
    if (!b || b->local_device!=(uint64_t)M24_NODE_ID || !b->peer_device
        || b->peer_device==b->local_device || (b->role!=1 && b->role!=2)
        || !b->channel || b->profile!=PROFILE || b->wire_major!=WIRE_MAJOR
        || b->wire_minor!=WIRE_MINOR || b->key_id!=KEY_ID || b->epoch!=EPOCH
        || b->max_payload!=MAX_PAYLOAD || b->max_ops!=MAX_OPS || b->max_cells!=MAX_CELLS
        || !same_bytes(b->schema_digest,SCHEMA,32)
        || !same_bytes(b->domain_digest,DOMAIN_DIGEST,32)
        || !b->local_port || b->local_port>65535u || !b->peer_port || b->peer_port>65535u
        || !noun_is_cell(plan) || !state_values(initial_state,values)
        || values[0]!=b->role || values[1]!=PHASE_NEW || values[2] || values[3]
        || values[4] || values[5] || !b->peer_descriptor[0]) return 0;
    const uint64_t *peer_descriptor = b->role == ROLE_PUBLISHER
        ? SUBSCRIBER_LOCAL_DESCRIPTOR : PUBLISHER_LOCAL_DESCRIPTOR;
    for (unsigned i=0;i<11;i++)
        if (b->peer_descriptor[i] != peer_descriptor[i]) return 0;
    if (!same_bytes(b->local_mac,b->peer_mac,6)
        && !same_bytes(b->local_ip,b->peer_ip,16)) return 1;
    return 0;
}

static int parse_service_gate(noun gate, m37_service_prepared_t *out)
{
    noun battery, sample, zero, state, tag, rest, header, dynamic, instances;
    noun program, base, tables, routes, specs, owners, exports, services;
    noun source_hash, binding;
    if (!out || !take(gate,&battery,&sample) || !take(sample,&zero,&state)
        || !direct_is(zero,0) || !take(state,&tag,&rest)
        || !i2_application_surface_tag_matches(tag,"i2-state",8)
        || !take(rest,&header,&rest) || !take(rest,&program,&dynamic)
        || !take(dynamic,&instances,&out->formula) || !noun_is_cell(instances)
        || !noun_is_cell(out->formula) || !take(program,&tag,&rest)
        || !i2_application_surface_tag_matches(tag,"i2-resource-program-v1",22)
        || !take(rest,&base,&tables) || !take(tables,&routes,&tables)
        || !take(tables,&specs,&tables) || !take(tables,&owners,&tables)
        || !take(tables,&exports,&services) || !noun_is_cell(services)
        || !take(exports,&source_hash,&binding) || !noun_is_atom(source_hash)
        || !parse_binding(binding,&out->binding,&out->plan,&out->initial_state)
        || !binding_valid(&out->binding,out->plan,out->initial_state)) return 0;
    (void)battery; (void)header; (void)routes; (void)specs; (void)owners; (void)source_hash; (void)base;
    return 1;
}

static int build_event(uint64_t kind,uint64_t qi,uint64_t token,uint64_t value,
                       uint64_t status,noun *out)
{
    noun tail=direct(0), item;
    if (!out || kind<1 || kind>CAUSE_PROVIDER_RELEASE || qi>1 || status>STATUS_PROVIDER
        || value>UINT16_MAX_VALUE || token>= (1ULL<<62)) return 0;
    if (!cons(direct(status),tail,&tail) || !cons(direct(value),tail,&tail)
        || !cons(direct(token),tail,&tail) || !cons(direct(qi),tail,&tail)
        || !cons(direct(kind),tail,&item)) return 0;
    *out=item; return 1;
}

static int build_wire(uint64_t value, uint64_t sequence, uint8_t *payload,
                      uint32_t *payload_len)
{
    noun tail=direct(0), intent; const uint8_t *bytes; uint64_t length;
    const uint64_t *descriptor = g_binding.role == ROLE_PUBLISHER
        ? PUBLISHER_LOCAL_DESCRIPTOR : SUBSCRIBER_LOCAL_DESCRIPTOR;
    if (!payload || !payload_len || value>UINT16_MAX_VALUE || !sequence) return 0;
    if (!cons(direct(value),tail,&tail)) return 0;
    for (int i=10;i>=0;i--) if (!cons(direct(descriptor[i]),tail,&tail)) return 0;
    if (!cons(direct(UINT16_MAX_VALUE),tail,&tail) || !cons(direct(0),tail,&tail)
        || !cons(direct(16),tail,&tail) || !cons(direct(TYPE_UINT16),tail,&tail)
        || !cons(cord_from_bytes("PUBLISH_1",9),tail,&tail) || !cons(direct(1),tail,&tail)
        || !cons(cord_from_bytes("m36-t-envelope-v1",17),tail,&intent)
        || jam_encode_bytes_checked(intent,&bytes,&length) != 0
        || !length || length>MAX_PAYLOAD) return 0;
    for (uint64_t i=0;i<length;i++) payload[i]=bytes[i];
    *payload_len=(uint32_t)length; return 1;
}

static int parse_wire(const uint8_t *payload,uint32_t length,uint64_t *value)
{
    noun decoded,tag,body,item,tail,publish; uint64_t descriptor[11],fields[6];
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!payload || !length || cue_bounded_bytes(payload,length,&cue_i2_limits,
            HEAP_MODE_SCRATCH,&decoded)!=CUE_BOUNDED_OK || !take(decoded,&tag,&body)
        || !i2_application_surface_tag_matches(tag,"m36-t-envelope-v1",17)
        || !take(body,&item,&body) || !noun_is_direct(item) || (fields[0]=direct_val(item))!=1
        || !take(body,&publish,&body) || !i2_application_surface_tag_matches(publish,"PUBLISH_1",9)) goto bad;
    for (unsigned i=2;i<6;i++) if (!take(body,&item,&body)||!noun_is_direct(item)) goto bad; else fields[i]=direct_val(item);
    if (fields[2]!=TYPE_UINT16 || fields[3]!=16 || fields[4]!=0 || fields[5]!=UINT16_MAX_VALUE) goto bad;
    for (unsigned i=0;i<11;i++) if (!take(body,&item,&body)||!positive_direct(item,&descriptor[i])) goto bad;
    if (!take(body,&item,&tail)||!direct_is(tail,0)||!noun_is_direct(item)
        ||direct_val(item)>UINT16_MAX_VALUE) goto bad;
    for (unsigned i=0;i<11;i++) if (descriptor[i]!=g_binding.peer_descriptor[i]) goto bad;
    if (value) *value=direct_val(item);
    return 1;
bad:
    g_last_error=3; return 0;
}

static int run_step(noun event,noun state,noun *next_state,noun *causes)
{
    noun subject,result,tag,body;
    if (!cons(event,state,&subject)) return 0;
    int jump=setjmp(nock_abort);
    if (jump) { nock_budget_finish(); return 0; }
    nock_budget_set_limits(MAX_OPS,MAX_CELLS);
    result=nock(subject,g_formula); nock_budget_finish();
    if (!take(result,&tag,&body)) return 0;
    if (noun_eq(tag,cord_from_bytes("i2-m37-service-reject-v1",24))) { g_last_error=2; return 0; }
    if (!noun_eq(tag,cord_from_bytes("i2-m37-service-commit-v1",24)) || !take(body,next_state,causes)) return 0;
    uint64_t values[6];
    if (!state_values(*next_state,values) || values[0]!=g_binding.role
        || values[1]>PHASE_RELEASED || values[2]>=(1ULL<<62)
        || values[3]>=(1ULL<<62) || values[4]>UINT16_MAX_VALUE
        || values[5]>STATUS_PROVIDER) return 0;
    return 1;
}

static int parse_product_causes(noun causes, uint64_t *intent_token,
                                uint64_t *intent_value, uint64_t output[5],
                                uint8_t *has_intent, uint8_t *has_output)
{
    noun cause, rest, tag, body, item;
    if (!has_intent || !has_output) return 0;
    *has_intent=*has_output=0;
    while (take(causes,&cause,&rest)) {
        if (*has_intent || *has_output || !take(cause,&tag,&body)) return 0;
        if (noun_eq(tag,cord_from_bytes("i2-m37-provider-intent-v1",25))) {
            uint64_t values[3];
            for (unsigned i=0;i<3;i++) if (!take(body,&item,&body)||!noun_is_direct(item)) return 0; else values[i]=direct_val(item);
            if (!direct_is(body,0) || values[0]!=ROLE_PUBLISHER || !values[1]
                || values[1]>=(1ULL<<62) || values[2]>UINT16_MAX_VALUE) return 0;
            *intent_token=values[1]; *intent_value=values[2]; *has_intent=1;
        } else {
            uint64_t values[5]; noun cur=cause;
            /* Outputs are bare five-field nouns in the closed product; the
             * first field is checked below as the visible IEC event kind. */
            for (unsigned i=0;i<5;i++) if (!take(cur,&item,&cur)||!noun_is_direct(item)) return 0; else values[i]=direct_val(item);
            if (!direct_is(cur,0) || values[0] < EVENT_INITO || values[0] > EVENT_IND
                || values[1]>1 || values[2]>=(1ULL<<62)
                || values[3]>UINT16_MAX_VALUE || values[4]>STATUS_PROVIDER
                || (values[0] != EVENT_INITO && !values[2])
                || (values[0] != EVENT_INITO
                    && values[0] != (g_binding.role == ROLE_PUBLISHER ? EVENT_CNF : EVENT_IND))
                || (values[0] == EVENT_INITO && (values[2] || values[3]))) return 0;
            for (unsigned i=0;i<5;i++) output[i]=values[i];
            *has_output=1;
        }
        causes=rest;
    }
    return direct_is(causes,0);
}

static int commit_state(noun next_state, const uint64_t output[5], uint8_t has_output)
{
    noun staged;
    if (has_output && g_output_valid) { g_last_error=7; return 0; }
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(next_state,&staged)) { heap_persist_abort_tx(); g_last_error=4; return 0; }
    g_state=staged;
    if (has_output) for (unsigned i=0;i<5;i++) g_output[i]=output[i];
    g_output_valid=has_output; g_root_commits++; g_publications+=has_output;
    heap_persist_commit_tx(); g_last_error=0; return 1;
}

static int retain_provider_transaction(noun next_state,uint64_t token,uint64_t value)
{
    m37_service_pending_t pending; noun staged; uint32_t length=0;
    if (!build_wire(value,token,pending.payload,&length)) { g_last_error=4; return 0; }
    pending.payload_len=length; pending.sequence=token; pending.token=token; pending.value=value;
    heap_persist_begin_tx(); heap_set_mode(HEAP_MODE_PERSIST);
    if (!noun_copy_checked(next_state,&staged)) { heap_persist_abort_tx(); g_last_error=4; return 0; }
    pending.state=staged;
    m37_a_r_native_status_t status=m37_a_r_adapter_send(&g_binding,pending.payload,length,token);
    g_pending=pending;
    if (status!=M37_A_R_NATIVE_OK) {
        g_pending_valid=1; g_provider_pending=0; g_retry_attempts=1;
        g_last_error=(status==M37_A_R_NATIVE_RING_FULL)?6:5;
        heap_persist_commit_tx(); return 0;
    }
    g_state=staged; g_provider_pending=1; g_pending_valid=0; g_retry_attempts=0;
    g_root_commits++; g_last_error=0; heap_persist_commit_tx(); return 1;
}

static int retry_provider_transaction(void)
{
    if (!g_pending_valid) return 0;
    if (g_retry_attempts>=RECOVERY_ATTEMPTS) {
        if (m37_a_r_adapter_recover()!=0) return -1;
        g_pending_valid=0; g_retry_attempts=0; g_terminal_fence=1; g_last_error=9; return -1;
    }
    m37_a_r_native_status_t status=m37_a_r_adapter_send(
        &g_binding,g_pending.payload,g_pending.payload_len,g_pending.sequence);
    if (status!=M37_A_R_NATIVE_OK) {
        g_retry_attempts++; g_last_error=(status==M37_A_R_NATIVE_RING_FULL)?6:5; return -1;
    }
    g_state=g_pending.state; g_provider_pending=1; g_pending_valid=0; g_retry_attempts=0;
    g_root_commits++; g_last_error=0; return 1;
}

int m37_service_target_boot(noun gate,const runtime_identity_t *identity,uint8_t capability)
{
    if (!identity || capability!=RUNTIME_CAPABILITY_PROFILE_M25
        || identity->runtime_abi[0]!=1 || identity->runtime_abi[1]!=9
        || identity->host_abi[0]!=1 || identity->host_abi[1]!=3
        || !runtime_identity_validate_gate(gate,identity,0)
        || !m34_local_allocation_predecessor_matches(identity)) return -1;
    return 0;
}

int m37_service_target_prepare_gate(noun gate,const runtime_identity_t *identity,
                                    uint8_t capability,noun *out)
{
    if (!out || capability!=RUNTIME_CAPABILITY_PROFILE_M25
        || !runtime_identity_validate_gate_header(gate,identity,0)
        || !parse_service_gate(gate,&g_prepared)) { g_prepared_valid=0; return -1; }
    g_prepared.gate=gate;
    g_prepared_valid=1; *out=gate; return 0;
}

void m37_service_target_publish_gate(noun gate,const runtime_identity_t *identity,
                                     uint8_t capability)
{
    (void)identity; (void)capability;
    if (!g_prepared_valid || !gate || gate != g_prepared.gate) return;
    g_binding=g_prepared.binding; g_plan=g_prepared.plan; g_formula=g_prepared.formula;
    g_state=g_prepared.initial_state; g_active=1; g_running=0; g_source=g_binding.role==ROLE_PUBLISHER;
    g_initialized=0; g_plan_bound=1; g_provider_pending=0; g_pending_valid=0;
    g_retry_attempts=0; g_output_valid=0; g_last_error=0; g_root_commits=1; g_publications=0;
    g_rx_high=0; g_terminal_fence=0; g_prepared_valid=0;
    g_recovery_paused=0;
}

int m37_service_target_init(void)
{
    if (!g_active || g_terminal_fence || g_pending_valid || g_provider_pending
        || m37_a_r_adapter_tx_pending() || m37_a_r_adapter_init(&g_binding)!=0) return -1;
    g_initialized=1; return 0;
}

int m37_service_target_set_running(int running)
{
    if (!g_active || g_pending_valid || g_provider_pending
        || (running && (!g_initialized || g_terminal_fence))) return -1;
    g_running=running!=0; return 0;
}

int m37_service_target_input(uint64_t kind,uint64_t qi,uint64_t token,
                             uint64_t value,uint64_t status)
{
    noun event,next_state,causes; uint64_t intent_token=0,intent_value=0,output[5];
    uint8_t has_intent=0,has_output=0;
    if (!g_active || !g_running || g_terminal_fence || g_pending_valid || g_output_valid
        || !build_event(kind,qi,token,value,status,&event)) { g_last_error=2; return -1; }
    if ((kind==CAUSE_COMPLETE && (!g_provider_pending || token!=g_pending.token))
        || (kind==EVENT_INIT && qi==0 && g_provider_pending)) { g_last_error=8; return -1; }
    heap_scratch_reset(); heap_set_mode(HEAP_MODE_SCRATCH);
    if (!run_step(event,g_state,&next_state,&causes)
        || !parse_product_causes(causes,&intent_token,&intent_value,output,
                                 &has_intent,&has_output)) { if (!g_last_error) g_last_error=2; return -1; }
    if (has_intent) {
        if (g_provider_pending || has_output) { g_last_error=8; return -1; }
        return retain_provider_transaction(next_state,intent_token,intent_value)?0:-1;
    }
    if (!commit_state(next_state,output,has_output)) return -1;
    if (kind==CAUSE_COMPLETE) g_provider_pending=0;
    return has_output ? 1 : 0;
}

int m37_service_target_tick(void)
{
    if (!g_active || !g_running || !g_initialized) return 0;
    if (g_terminal_fence) return -1;
    if (g_pending_valid) return g_recovery_paused ? 0 : retry_provider_transaction();
    if (g_source) return 0;
    m37_a_r_datagram_t datagram; m37_a_r_native_status_t status;
    status=m37_a_r_adapter_receive(&g_binding,&datagram);
    if (status==M37_A_R_NATIVE_NO_PACKET) return 0;
    if (status!=M37_A_R_NATIVE_OK) { g_last_error=1; return -1; }
    if (datagram.sequence<=g_rx_high || datagram.sequence==UINT64_MAX) { g_last_error=2; return -1; }
    uint64_t value;
    if (!parse_wire(datagram.payload,datagram.payload_len,&value)) return -1;
    int result=m37_service_target_input(CAUSE_DELIVER,1,datagram.sequence,value,STATUS_OK);
    if (result>=0) g_rx_high=datagram.sequence;
    return result;
}

int m37_service_target_recover_tx(void)
{
    while (g_pending_valid && !g_terminal_fence) {
        if (retry_provider_transaction()<0 && g_retry_attempts>=RECOVERY_ATTEMPTS) break;
    }
    return g_terminal_fence ? -1 : 0;
}

uint64_t m37_service_target_output_field(uint64_t field)
{ return g_output_valid && field<5 ? g_output[field] : UINT64_MAX; }
uint64_t m37_service_target_output_valid(void){return g_output_valid?1:0;}
void m37_service_target_output_pop(void){g_output_valid=0;}
uint64_t m37_service_target_phase(void){uint64_t v[6];return state_values(g_state,v)?v[1]:UINT64_MAX;}
uint64_t m37_service_target_sequence(void){uint64_t v[6];return state_values(g_state,v)?v[2]:UINT64_MAX;}
uint64_t m37_service_target_pending(void){uint64_t v[6];return g_pending_valid||g_provider_pending||(!state_values(g_state,v)?0:v[3]!=0);}
uint64_t m37_service_target_intent_valid(void){return g_provider_pending?1:0;}
uint64_t m37_service_target_intent_token(void){return g_provider_pending?g_pending.token:UINT64_MAX;}
uint64_t m37_service_target_intent_value(void){return g_provider_pending?g_pending.value:UINT64_MAX;}
uint64_t m37_service_target_plan_bound(void){return g_plan_bound?1:0;}
uint64_t m37_service_target_error(void){return g_last_error;}
uint64_t m37_service_target_root_commits(void){return g_root_commits;}
uint64_t m37_service_target_publications(void){return g_publications;}
uint64_t m37_service_target_terminal_fence(void){return g_terminal_fence?1:0;}

void m37_service_target_test_pre_submit_failure(void)
{m25_native_test_hold_tx();g_recovery_paused=1;}
void m37_service_target_test_release_pre_submit(void)
{m25_native_test_release_tx();g_recovery_paused=0;}
void m37_service_target_test_lost_completion(void)
{m37_a_r_adapter_test_lost_completion();g_recovery_paused=1;}
void m37_service_target_test_release_lost_completion(void)
{m37_a_r_adapter_test_release_lost_completion();g_recovery_paused=0;}
void m37_service_target_test_delayed_completion(void)
{m37_a_r_adapter_test_delayed_completion();g_recovery_paused=1;}
void m37_service_target_test_release_delayed_completion(void)
{m37_a_r_adapter_test_release_delayed_completion();g_recovery_paused=0;}
int m37_service_target_test_exhaust_pending(void)
{ if (!g_pending_valid) return -1; g_retry_attempts=RECOVERY_ATTEMPTS; return 0; }

#else
int m37_service_target_boot(noun n,const runtime_identity_t*i,uint8_t c){(void)n;(void)i;(void)c;return -1;}
int m37_service_target_prepare_gate(noun n,const runtime_identity_t*i,uint8_t c,noun*o){(void)n;(void)i;(void)c;(void)o;return -1;}
void m37_service_target_publish_gate(noun n,const runtime_identity_t*i,uint8_t c){(void)n;(void)i;(void)c;}
int m37_service_target_init(void){return -1;} int m37_service_target_set_running(int r){(void)r;return -1;}
int m37_service_target_input(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e){(void)a;(void)b;(void)c;(void)d;(void)e;return -1;}
int m37_service_target_tick(void){return 0;} int m37_service_target_recover_tx(void){return -1;}
uint64_t m37_service_target_output_field(uint64_t f){(void)f;return UINT64_MAX;}uint64_t m37_service_target_output_valid(void){return 0;}void m37_service_target_output_pop(void){}
uint64_t m37_service_target_phase(void){return UINT64_MAX;}uint64_t m37_service_target_sequence(void){return UINT64_MAX;}uint64_t m37_service_target_pending(void){return 0;}uint64_t m37_service_target_intent_valid(void){return 0;}uint64_t m37_service_target_intent_token(void){return UINT64_MAX;}uint64_t m37_service_target_intent_value(void){return UINT64_MAX;}uint64_t m37_service_target_plan_bound(void){return 0;}uint64_t m37_service_target_error(void){return 0;}uint64_t m37_service_target_root_commits(void){return 0;}uint64_t m37_service_target_publications(void){return 0;}uint64_t m37_service_target_terminal_fence(void){return 0;}
void m37_service_target_test_pre_submit_failure(void){}void m37_service_target_test_release_pre_submit(void){}void m37_service_target_test_lost_completion(void){}void m37_service_target_test_release_lost_completion(void){}void m37_service_target_test_delayed_completion(void){}void m37_service_target_test_release_delayed_completion(void){}int m37_service_target_test_exhaust_pending(void){return -1;}
#endif
