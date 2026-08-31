/* Candidate-derived M37-A-R publication boundary.  Role and channel are
 * decoded from the admitted binding; the physical node macro only identifies
 * which compiled qemu-virt adapter is executing. */
#include <stdint.h>

#include "m37_a_r_target_core.h"

#ifdef M37_A_R

#include "candidate_execution_core_r.h"
#include "i2_application_surface.h"
#include "m25_aethernet_native.h"
#include "m34_local_allocation.h"
#include "runtime_identity.h"

#define PROFILE 2ULL
#define WIRE_MAJOR 0ULL
#define WIRE_MINOR 1ULL
#define KEY_ID 1ULL
#define EPOCH 1ULL
#define MAX_PAYLOAD 512ULL
#define MAX_OPS 2000000ULL
#define MAX_CELLS 128000ULL

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
static m37_a_r_prepared_t g_prepared;
static uint8_t g_prepared_valid;

static int take(noun n,noun*h,noun*t){if(!noun_is_cell(n)||!h||!t)return 0;cell_t*c=(cell_t*)(uintptr_t)cell_ptr(n);*h=c->head;*t=c->tail;return 1;}
static int direct_is(noun n,uint64_t v){return noun_is_direct(n)&&direct_val(n)==v;}
static int fixed(noun n,uint8_t*out,unsigned len){return out&&noun_atom_read_fixed(n,out,len);}
static int nonzero(const uint8_t*b,unsigned n){uint8_t x=0;for(unsigned i=0;i<n;i++)x|=b[i];return x!=0;}
static int resource_id(noun gate,uint64_t*out)
{
    noun battery,sample,zero,state,tag,rest,header,versions,rid;
    return out&&take(gate,&battery,&sample)&&take(sample,&zero,&state)&&direct_is(zero,0)
       &&take(state,&tag,&rest)&&take(rest,&header,&rest)&&take(header,&versions,&rest)
       &&take(rest,&rid,&rest)&&noun_is_direct(rid)&&(*out=direct_val(rid),1);
}
static int parse_binding(noun n,m37_a_r_transport_binding_t*b)
{
    noun tag,rest,item;uint64_t fields[14];uint8_t bytes[8][32];
    if(!b||!take(n,&tag,&rest)||!i2_application_surface_tag_matches(tag,"m37-a-r-transport-binding-v1",28))return 0;
    for(unsigned i=0;i<14;i++)if(!take(rest,&item,&rest)||!noun_is_direct(item))return 0;else fields[i]=direct_val(item);
    b->local_device=fields[0];b->peer_device=fields[1];b->role=fields[2];b->channel=fields[3];
    b->local_port=fields[4];b->peer_port=fields[5];b->profile=fields[6];b->wire_major=fields[7];
    b->wire_minor=fields[8];b->key_id=fields[9];b->epoch=fields[10];b->max_payload=fields[11];
    b->max_ops=fields[12];b->max_cells=fields[13];
    for(unsigned i=0;i<4;i++)
        if(!take(rest,&item,&rest)||!fixed(item,bytes[i],i<2?16:32))return 0;
    if(!take(rest,&item,&rest)||!fixed(item,bytes[4],6)
       ||!take(rest,&item,&rest)||!fixed(item,bytes[5],6)
       ||!take(rest,&item,&rest)||!fixed(item,bytes[6],16)
       ||!take(rest,&item,&rest)||!fixed(item,bytes[7],16))return 0;
    for(unsigned i=0;i<11;i++)if(!take(rest,&item,&rest)||!noun_is_direct(item))return 0;else b->peer_descriptor[i]=direct_val(item);
    for(unsigned i=0;i<16;i++){b->outbound_binding[i]=bytes[0][i];b->inbound_binding[i]=bytes[1][i];}
    for(unsigned i=0;i<32;i++){b->schema_digest[i]=bytes[2][i];b->domain_digest[i]=bytes[3][i];}
    for(unsigned i=0;i<6;i++){b->local_mac[i]=bytes[4][i];b->peer_mac[i]=bytes[5][i];}
    for(unsigned i=0;i<16;i++){b->local_ip[i]=bytes[6][i];b->peer_ip[i]=bytes[7][i];}
    return direct_is(rest,0);
}
static int binding_valid(const m37_a_r_transport_binding_t*b)
{
    if(!b||b->local_device!=(uint64_t)M24_NODE_ID||!b->peer_device||b->peer_device==b->local_device
       ||(b->role!=1&&b->role!=2)||!b->channel||b->profile!=PROFILE||b->wire_major!=WIRE_MAJOR||b->wire_minor!=WIRE_MINOR
       ||b->key_id!=KEY_ID||b->epoch!=EPOCH||b->max_payload!=MAX_PAYLOAD||b->max_ops!=MAX_OPS||b->max_cells!=MAX_CELLS
       ||!nonzero(b->outbound_binding,16)||!nonzero(b->inbound_binding,16)||!nonzero(b->schema_digest,32)||!nonzero(b->domain_digest,32))return 0;
    for(unsigned i=0;i<32;i++)
        if(b->schema_digest[i]!=SCHEMA[i])return 0;
    for(unsigned i=0;i<32;i++)
        if(b->domain_digest[i]!=DOMAIN_DIGEST[i])return 0;
    for(unsigned i=0;i<11;i++)
        if(!b->peer_descriptor[i])return 0;
    if(!nonzero(b->local_mac,6)||!nonzero(b->peer_mac,6)
       ||!nonzero(b->local_ip,16)||!nonzero(b->peer_ip,16))return 0;
    return 1;
}
static int surface_from_gate(noun gate,M37ARNativeExecutionSurface*out)
{
    i2_application_service_surface_t app;
    noun ignored,state,tag,rest,program,dynamic,tables,exports,services,source_hash,binding;
    if(!out||!i2_application_surface_from_gate(gate,&app)
       ||app.publication_count!=1||app.ingress.sample_count!=1
       ||(app.ingress.sample_type[0]!=1&&app.ingress.sample_type[0]!=4))return 0;
    if(!take(gate,&ignored,&rest)||!take(rest,&ignored,&state)
       ||!take(state,&tag,&rest)||!take(rest,&ignored,&rest)
       ||!take(rest,&program,&dynamic)||!take(program,&tag,&rest)
       ||!take(rest,&ignored,&tables)||!take(tables,&ignored,&tables)
       ||!take(tables,&ignored,&tables)||!take(tables,&ignored,&tables)
       ||!take(tables,&exports,&services)||!take(exports,&source_hash,&binding))return 0;
    (void)source_hash;(void)services;
    m37_a_r_transport_binding_t b;
    if(!parse_binding(binding,&b)||!binding_valid(&b))return 0;
    for(unsigned i=0;i<sizeof *out;i++)((uint8_t*)out)[i]=0;
    out->binding=b;
    const i2_publication_attachment_t*p=&app.publications[0];
    const uint64_t f[11]={p->source_instance,p->source_event,p->source_ordinal,p->source_data,p->source_type,p->source_service,p->target_service,p->target_instance,p->target_event,p->target_data,p->target_type};
    for(unsigned i=0;i<11;i++)out->publication[i]=f[i];
    out->ingress_instance=app.ingress.instance;out->ingress_event=app.ingress.event;
    out->ingress_sample=app.ingress.sample_id[0];out->ingress_type=app.ingress.sample_type[0];
    out->route_count=app.event_edge_count;
    if(!out->route_count||out->route_count>M37_A_R_ROUTE_CAPACITY)return 0;
    for(uint32_t i=0;i<app.event_edge_count;i++){
        out->routes[i][0]=app.event_edges[i].ordinal;out->routes[i][1]=app.event_edges[i].source_instance;
        out->routes[i][2]=app.event_edges[i].source_event;out->routes[i][3]=app.event_edges[i].target_instance;
        out->routes[i][4]=app.event_edges[i].target_event;
    }
    return 1;
}
int m37_a_r_target_boot(noun gate,const runtime_identity_t*i,uint8_t capability)
{
    uint64_t rid;
    if(!i||capability!=RUNTIME_CAPABILITY_PROFILE_M25||i->runtime_abi[0]!=1||i->runtime_abi[1]!=9||i->host_abi[0]!=1||i->host_abi[1]!=3
       ||!runtime_identity_validate_gate(gate,i,0)||!resource_id(gate,&rid)||!m34_local_allocation_predecessor_matches(i))return -1;
    (void)rid;return candidate_execution_core_r_cold_boot();
}
int m37_a_r_target_prepare_gate(noun gate,const runtime_identity_t*i,uint8_t capability,noun*out)
{
    M37ARNativeExecutionSurface s;
    if(!out||capability!=RUNTIME_CAPABILITY_PROFILE_M25){g_prepared_valid=0;return -1;}
    if(!surface_from_gate(gate,&s)){g_prepared_valid=0;return -1;}
    if(!runtime_identity_validate_gate_header(gate,i,0)){g_prepared_valid=0;return -1;}
    if(candidate_execution_core_r_prepare(&s,gate,i,&g_prepared)!=0){g_prepared_valid=0;return -1;}
    g_prepared_valid=1;*out=gate;return 0;
}
void m37_a_r_target_publish_gate(noun gate,const runtime_identity_t*i,uint8_t capability){(void)i;(void)capability;if(g_prepared_valid&&gate==g_prepared.gate&&candidate_execution_core_r_activate(&g_prepared)==0)g_prepared_valid=0;}
int m37_a_r_target_init(void){return candidate_execution_core_r_init();}
int m37_a_r_target_set_running(int r){return candidate_execution_core_r_set_running(r);}
int m37_a_r_target_input(uint64_t type,uint64_t value){m37_a_r_ingress_t i={type,value};return candidate_execution_core_r_submit(&i);}
int m37_a_r_target_service_tick(void){return candidate_execution_core_r_pump();}
int m37_a_r_target_recover_tx(void){return candidate_execution_core_r_recover_tx();}
uint64_t m37_a_r_target_queue_len(void){return candidate_execution_core_r_queue_len();}uint64_t m37_a_r_target_output(void){return candidate_execution_core_r_output();}uint64_t m37_a_r_target_sequence(void){return candidate_execution_core_r_sequence();}uint64_t m37_a_r_target_high_water(void){return candidate_execution_core_r_high_water();}uint64_t m37_a_r_target_error(void){return candidate_execution_core_r_error();}uint64_t m37_a_r_target_root_commits(void){return candidate_execution_core_r_root_commits();}uint64_t m37_a_r_target_publications(void){return candidate_execution_core_r_publications();}
uint64_t m37_a_r_target_terminal_fence(void){return candidate_execution_core_r_terminal_fence();}
int m37_a_r_target_test_hold_processing(int e){return candidate_execution_core_r_test_hold_processing(e);}int m37_a_r_target_test_clear_error(void){return candidate_execution_core_r_test_clear_error();}int m37_a_r_target_test_rate_exhaust(void){return candidate_execution_core_r_test_rate_exhaust();}int m37_a_r_target_test_rate_reset(void){return candidate_execution_core_r_test_rate_reset();}int m37_a_r_target_test_allocation_pressure(void){return candidate_execution_core_r_test_allocation_pressure();}int m37_a_r_target_test_allocation_release(void){return candidate_execution_core_r_test_allocation_release();}
void m37_a_r_target_test_hold_tx(void){m25_native_test_hold_tx();}void m37_a_r_target_test_release_tx(void){m25_native_test_release_tx();}void m37_a_r_target_test_lost_completion(void){m37_a_r_adapter_test_lost_completion();}void m37_a_r_target_test_release_lost_completion(void){m37_a_r_adapter_test_release_lost_completion();}

#else
int m37_a_r_target_boot(noun n,const runtime_identity_t*i,uint8_t c){(void)n;(void)i;(void)c;return -1;}int m37_a_r_target_init(void){return -1;}int m37_a_r_target_set_running(int r){(void)r;return -1;}int m37_a_r_target_input(uint64_t t,uint64_t v){(void)t;(void)v;return -1;}int m37_a_r_target_service_tick(void){return 0;}int m37_a_r_target_recover_tx(void){return -1;}uint64_t m37_a_r_target_queue_len(void){return UINT64_MAX;}uint64_t m37_a_r_target_output(void){return UINT64_MAX;}uint64_t m37_a_r_target_sequence(void){return 0;}uint64_t m37_a_r_target_high_water(void){return 0;}uint64_t m37_a_r_target_error(void){return 0;}uint64_t m37_a_r_target_root_commits(void){return 0;}uint64_t m37_a_r_target_publications(void){return 0;}uint64_t m37_a_r_target_terminal_fence(void){return 0;}int m37_a_r_target_prepare_gate(noun n,const runtime_identity_t*i,uint8_t c,noun*o){(void)n;(void)i;(void)c;(void)o;return -1;}void m37_a_r_target_publish_gate(noun n,const runtime_identity_t*i,uint8_t c){(void)n;(void)i;(void)c;}int m37_a_r_target_test_hold_processing(int e){(void)e;return -1;}int m37_a_r_target_test_clear_error(void){return -1;}int m37_a_r_target_test_rate_exhaust(void){return -1;}int m37_a_r_target_test_rate_reset(void){return -1;}int m37_a_r_target_test_allocation_pressure(void){return -1;}int m37_a_r_target_test_allocation_release(void){return -1;}void m37_a_r_target_test_hold_tx(void){}void m37_a_r_target_test_release_tx(void){}void m37_a_r_target_test_lost_completion(void){}void m37_a_r_target_test_release_lost_completion(void){}
#endif
