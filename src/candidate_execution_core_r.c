/* M37-A-R bounded execution core.
 *
 * This is deliberately separate from the blocked M37-A core.  It executes
 * the candidate-derived M36 graph, carries UINT16 through the cross-resource
 * intent, and commits only after native completion.  Role is read from the
 * authenticated candidate binding; local_device is used only by the physical
 * adapter to bind the compiled machine endpoint.
 */
#include <stdint.h>

#include "candidate_execution_core_r.h"

#ifdef M37_A_R

#include "bounded_cue.h"
#include "i2_application_surface.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "runtime_stats.h"
#include "setjmp.h"

#define OPS 2000000ULL
#define CELLS 128000ULL
#define RATE_LIMIT 64ULL
#define ROUTE_FIELDS 5u
#define CAUSE_CAPACITY 16u
#define CAUSE_BUDGET 16u
#define WORK_BUDGET 17u
#define RECOVERY_ATTEMPTS 4u
#define PROFILE 2ULL
#define WIRE_MAJOR 0ULL
#define WIRE_MINOR 1ULL
#define KEY_ID 1ULL
#define EPOCH 1ULL
#define UINT_TYPE 4ULL
#define UINT_WIDTH 16ULL
#define UINT_MIN 0ULL
#define UINT_MAX 65535ULL
#define COMMIT 127996156276579ULL
#define RX_ORIGIN 0x3178723269ULL
#define INTERNAL_ORIGIN 0x316e693269ULL

static noun g_gate, g_graph_intent_tag;
static runtime_identity_t g_identity;
static M37ARNativeExecutionSurface g_surface;
static noun g_pending_event;
static uint64_t g_pending_value;
static m37_a_r_intent_t g_pending_intent;
static uint8_t g_pending_valid, g_active, g_running, g_source, g_native_initialized;
static uint8_t g_fifo_payload[M37_A_R_FIFO_CAPACITY][M37_A_R_MAX_PAYLOAD];
static uint32_t g_fifo_length[M37_A_R_FIFO_CAPACITY];
static uint64_t g_fifo_sequence[M37_A_R_FIFO_CAPACITY];
static uint32_t g_fifo_head, g_fifo_count;
static uint64_t g_next_sequence, g_high_water, g_admitted_high_water, g_last_error;
static uint64_t g_rate_start, g_rate_count, g_last_output;
static uint64_t g_root_commits, g_publications;
static uint8_t g_output_valid, g_hold_processing, g_allocation_pressure;
static uint8_t g_tx_recovery_pending, g_tx_recovery_attempts;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *c=(cell_t *)(uintptr_t)cell_ptr(n); *head=c->head; *tail=c->tail; return 1;
}
static int direct_is(noun n, uint64_t v){return noun_is_direct(n)&&direct_val(n)==v;}
static int cons(noun a,noun b,noun*out){return alloc_cell_checked(a,b,out);}
static int positive(noun n,uint64_t*out){if(!noun_is_direct(n)||!direct_val(n))return 0;if(out)*out=direct_val(n);return 1;}
static int same_descriptor(const uint64_t*a,const uint64_t*b){for(unsigned i=0;i<11;i++)if(a[i]!=b[i])return 0;return 1;}

static int build_slam(noun *out)
{
    noun a,b,c,d,e,f,g;
    if(!out||!cons(direct(0),direct(3),&a)||!cons(direct(6),a,&b)
       ||!cons(direct(0),direct(2),&c)||!cons(b,c,&d)||!cons(direct(10),d,&e)
       ||!cons(direct(2),e,&f)||!cons(direct(9),f,&g))return 0;
    *out=g;return 1;
}
static int product(noun result,noun*candidate,noun*causes)
{
    noun tag,body,effects,tail;
    return take(result,&tag,&body)&&direct_is(tag,COMMIT)&&take(body,&effects,&tail)
        &&direct_is(effects,0)&&take(tail,candidate,causes);
}
static int slam(noun gate,noun event,int external,noun*candidate,noun*causes)
{
    noun formula,carrier,subject,result;
    if(!build_slam(&formula)||!cons(external?direct(RX_ORIGIN):direct(INTERNAL_ORIGIN),event,&carrier)
       ||!cons(gate,carrier,&subject))return 0;
    int jump=setjmp(nock_abort);if(jump){nock_budget_finish();return 0;}
    nock_budget_set_limits(g_surface.binding.max_ops,g_surface.binding.max_cells);
    result=nock(subject,formula);nock_budget_finish();
    return product(result,candidate,causes)&&runtime_identity_validate_gate(*candidate,&g_identity,0);
}
static int route_fields(noun cause,uint64_t fields[5],noun*samples)
{
    noun tag,body,item;
    if(!take(cause,&tag,&body)||!i2_application_surface_tag_matches(tag,"i2-route-ei",11))return 0;
    for(unsigned i=0;i<5;i++)if(!take(body,&item,&body)||!positive(item,&fields[i]))return 0;
    *samples=body;return 1;
}
static int route_at(uint32_t index,uint64_t fields[5])
{
    uint32_t seen=0;
    for(uint32_t i=0;i<g_surface.route_count;i++)if(g_surface.routes[i][1]==g_surface.ingress_instance){
        if(seen++==index){for(unsigned j=0;j<5;j++)fields[j]=g_surface.routes[i][j];return 1;}}
    return 0;
}
static uint32_t outgoing_count(uint64_t instance,uint64_t event)
{uint32_t n=0;for(uint32_t i=0;i<g_surface.route_count;i++)if(g_surface.routes[i][1]==instance&&g_surface.routes[i][2]==event)n++;return n;}
static int outgoing_at(uint64_t instance,uint64_t event,uint32_t index,uint64_t fields[5])
{
    uint32_t seen=0;for(uint32_t i=0;i<g_surface.route_count;i++)if(g_surface.routes[i][1]==instance&&g_surface.routes[i][2]==event){
        if(seen++==index){for(unsigned j=0;j<5;j++)fields[j]=g_surface.routes[i][j];return 1;}}
    return 0;
}
static int fields_equal(const uint64_t*a,const uint64_t*b){for(unsigned i=0;i<5;i++)if(a[i]!=b[i])return 0;return 1;}

static int drain(noun candidate,noun causes,noun*out_candidate,noun*out_final_causes)
{
    noun queue[CAUSE_CAPACITY], pending=causes, cause, rest; uint32_t tail=0,count=0;
    while(take(pending,&cause,&rest)){
        uint64_t actual[5],expected[5];noun samples;
        if(tail>=CAUSE_CAPACITY||count>=CAUSE_BUDGET||!route_at(tail,expected)||!route_fields(cause,actual,&samples)||!fields_equal(actual,expected))return 0;
        for(uint32_t i=0;i<tail;i++){
            uint64_t old[5];noun s;
            if(!route_fields(queue[i],old,&s)
               ||(old[3]==actual[3]&&old[4]==actual[4]))return 0;
        }
        queue[tail++]=cause;count++;pending=rest;
    }
    if(!direct_is(pending,0)||!tail)return 0;
    uint32_t head=0,work=1,intents=0; noun current=candidate;
    while(head<tail){
        uint64_t fields[5],expected[5];noun samples,next_causes=NOUN_ZERO,next_candidate;
        noun children[CAUSE_CAPACITY];uint32_t out=0,child_count=0,intent_count=0;
        if(work>=WORK_BUDGET||!route_fields(queue[head],fields,&samples))return 0;
        out=outgoing_count(fields[3],fields[2]);if(out>CAUSE_CAPACITY||tail-head-1u+out>CAUSE_CAPACITY||count+out>CAUSE_BUDGET)return 0;
        for(uint32_t i=0;i<out;i++)if(!outgoing_at(fields[3],fields[2],i,expected))return 0;
        if(!slam(current,queue[head],0,&next_candidate,&next_causes))return 0;
        noun scan=next_causes,scan_tail,tag,body;
        while(take(scan,&cause,&scan_tail)){
            if(!take(cause,&tag,&body))return 0;
            if(noun_eq(tag,g_graph_intent_tag))intent_count++;
            else if(i2_application_surface_tag_matches(tag,"i2-route-ei",11)){
                uint64_t child[5];noun s;
                if(child_count>=out||!route_fields(cause,child,&s)||!outgoing_at(fields[3],fields[2],child_count,expected)||!fields_equal(child,expected))return 0;
                children[child_count++]=cause;
            } else return 0;
            scan=scan_tail;
        }
        if(!direct_is(scan,0)||child_count!=out||(out&&intent_count)||( !out&&intent_count>1))return 0;
        uint32_t remaining=tail-head-1u;
        for(uint32_t i=0;i<remaining;i++)queue[i]=queue[head+1u+i];
        for(uint32_t i=0;i<child_count;i++)queue[remaining+i]=children[i];
        tail=remaining+child_count;head=0;count+=child_count;work++;current=next_candidate;
        if(intent_count){*out_final_causes=next_causes;intents=intent_count;}
    }
    if(out_candidate)*out_candidate=current;
    return *out_final_causes&&intents==1;
}
static int build_external(uint64_t type,uint64_t value,noun*out)
{
    noun typed,var,samples,body,target;
    if(!out||type!=g_surface.ingress_type||(type==1&&value>1)||(type==4&&value>UINT_MAX))return 0;
    if(!cons(direct(type),direct(value),&typed)||!cons(direct(g_surface.ingress_sample),typed,&var)
       ||!cons(var,NOUN_ZERO,&samples)||!cons(direct(g_surface.ingress_event),samples,&body)
       ||!cons(direct(g_surface.ingress_instance),body,&target)||!cons(cord_from_bytes("i2-ei",5),target,&body)
       ||!cons(cord_from_bytes("i2-external",11),body,out))return 0;
    return 1;
}
static int parse_graph_intent(noun cause,const uint64_t expected[11],uint64_t*type,uint64_t*value)
{
    noun tag,body,item,typed,payload;uint64_t descriptor[11];
    if(!take(cause,&tag,&body)||!noun_eq(tag,g_graph_intent_tag))return 0;
    for(unsigned i=0;i<11;i++)if(!take(body,&item,&body)||!positive(item,&descriptor[i]))return 0;
    if(!take(body,&typed,&payload)||!noun_is_direct(typed)||!noun_is_direct(payload))return 0;
    uint64_t type_id=direct_val(typed),v=direct_val(payload);
    if(type_id!=expected[4]||(type_id==1&&v>1)||(type_id==4&&v>UINT_MAX)||!same_descriptor(descriptor,expected))return 0;
    if(type)*type=type_id;
    if(value)*value=v;
    return direct_is(payload, v);
}
static int run_graph(uint64_t type,uint64_t value,noun*candidate,noun*final_causes)
{
    noun external,root_candidate,root_causes;
    if(!g_surface.route_count||g_surface.route_count> M37_A_R_ROUTE_CAPACITY||!build_external(type,value,&external)
       ||!slam(g_gate,external,1,&root_candidate,&root_causes))return 0;
    return drain(root_candidate,root_causes,candidate,final_causes);
}
static int parse_graph_list(noun causes,const uint64_t expected[11],uint64_t*type,uint64_t*value)
{noun cause,rest;return take(causes,&cause,&rest)&&direct_is(rest,0)&&parse_graph_intent(cause,expected,type,value);}
static int build_wire(const uint64_t descriptor[11],uint64_t value,m37_a_r_intent_t*out)
{
    noun tail=direct(0),intent;const uint8_t*bytes;uint64_t length;
    if(!out||value>UINT_MAX)return 0;
    if(!cons(direct(value),tail,&tail))return 0;
    for(int i=10;i>=0;i--)if(!cons(direct(descriptor[i]),tail,&tail))return 0;
    if(!cons(direct(UINT_MAX),tail,&tail)||!cons(direct(UINT_MIN),tail,&tail)||!cons(direct(UINT_WIDTH),tail,&tail)
       ||!cons(direct(UINT_TYPE),tail,&tail)||!cons(cord_from_bytes("PUBLISH_1",9),tail,&tail)||!cons(direct(1),tail,&tail)
       ||!cons(cord_from_bytes("m36-t-envelope-v1",17),tail,&intent)
       ||jam_encode_bytes_checked(intent,&bytes,&length)!=0||!length||length>M37_A_R_MAX_PAYLOAD)return 0;
    for(uint64_t i=0;i<length;i++)out->payload[i]=bytes[i];
    out->payload_len=(uint32_t)length;
    return 1;
}
static int parse_wire(const uint8_t*payload,uint32_t length,uint64_t*value)
{
    noun decoded,tag,body,item,tail,publish;uint64_t descriptor[11];
    heap_scratch_reset();heap_set_mode(HEAP_MODE_SCRATCH);
    if(cue_bounded_bytes(payload,length,&cue_i2_limits,HEAP_MODE_SCRATCH,&decoded)!=CUE_BOUNDED_OK||!take(decoded,&tag,&body)
       ||!noun_eq(tag,cord_from_bytes("m36-t-envelope-v1",17)))goto bad;
    uint64_t fields[6];
    if(!take(body,&item,&body)||!noun_is_direct(item)||((fields[0]=direct_val(item))!=1)
       ||!take(body,&publish,&body)||!noun_eq(publish,cord_from_bytes("PUBLISH_1",9)))goto bad;
    for(unsigned i=2;i<6;i++)if(!take(body,&item,&body)||!noun_is_direct(item))goto bad;else fields[i]=direct_val(item);
    if(fields[2]!=UINT_TYPE||fields[3]!=UINT_WIDTH||fields[4]!=UINT_MIN||fields[5]!=UINT_MAX)goto bad;
    for(unsigned i=0;i<11;i++)if(!take(body,&item,&body)||!positive(item,&descriptor[i]))goto bad;
    if(!take(body,&item,&tail)||!direct_is(tail,0)||!noun_is_direct(item)||direct_val(item)>UINT_MAX||!same_descriptor(descriptor,g_surface.binding.peer_descriptor))goto bad;
    if(value)*value=direct_val(item);
    noun_tx_abort();
    return 1;
bad: if(noun_tx_active())noun_tx_abort();g_last_error=3;return 0;
}
static int rate_ok(uint64_t*start,uint64_t*count)
{
    uint64_t now=runtime_counter_now(),freq=runtime_counter_freq(),s=g_rate_start,c=g_rate_count;
    if(!s||(freq&&now-s>=freq)){s=now;c=0;}if(c>=RATE_LIMIT)return 0;if(start)*start=s;if(count)*count=c;return 1;
}
static int commit(noun candidate)
{
    noun staged;heap_persist_begin_tx();heap_set_mode(HEAP_MODE_PERSIST);
    if(!noun_copy_checked(candidate,&staged)){heap_persist_abort_tx();return 0;}
    g_gate=staged;heap_persist_commit_tx();g_root_commits++;return 1;
}
static int process_head(void)
{
    if(!g_fifo_count)return 0;
    uint32_t at=g_fifo_head;uint64_t value,start,count,type; noun candidate,causes;
    if(!parse_wire(g_fifo_payload[at],g_fifo_length[at],&value)){g_last_error=3;return -1;}
    if(!rate_ok(&start,&count)){g_last_error=10;return -1;}
    heap_scratch_reset();heap_set_mode(HEAP_MODE_SCRATCH);
    if(!run_graph(g_surface.ingress_type,value,&candidate,&causes)||!parse_graph_list(causes,g_surface.publication,&type,&value)||type!=g_surface.publication[4]){g_last_error=4;return -1;}
    if(!commit(candidate)){g_last_error=5;return -1;}
    g_fifo_head=(g_fifo_head+1u)%M37_A_R_FIFO_CAPACITY;g_fifo_count--;g_high_water=g_fifo_sequence[at];g_last_output=value;g_output_valid=1;g_publications++;
    g_rate_start=start;g_rate_count=count+1;g_last_error=0;return 1;
}
static int source_pump(void)
{
    if(!g_pending_valid)return 0;
    if(g_tx_recovery_pending&&g_tx_recovery_attempts>=RECOVERY_ATTEMPTS){g_last_error=9;return -1;}
    uint64_t start,count,type,value; noun candidate,causes,staged;
    if(!rate_ok(&start,&count)){g_last_error=10;return -1;}if(g_allocation_pressure){g_last_error=4;return -1;}
    heap_scratch_reset();heap_set_mode(HEAP_MODE_SCRATCH);
    if(!run_graph(g_surface.ingress_type,g_pending_value,&candidate,&causes)||!parse_graph_list(causes,g_surface.publication,&type,&value)||type!=g_surface.publication[4]||!build_wire(g_surface.publication,value,&g_pending_intent)){g_last_error=4;return -1;}
    g_pending_intent.sequence=g_next_sequence;heap_persist_begin_tx();heap_set_mode(HEAP_MODE_PERSIST);
    if(!noun_copy_checked(candidate,&staged)){heap_persist_abort_tx();g_last_error=4;return -1;}
    m37_a_r_native_status_t status=m37_a_r_adapter_send(&g_surface.binding,g_pending_intent.payload,g_pending_intent.payload_len,g_next_sequence);
    if(status!=M37_A_R_NATIVE_OK){heap_persist_abort_tx();g_last_error=status==M37_A_R_NATIVE_RING_FULL?6:5;
        if(status==M37_A_R_NATIVE_RING_FULL&&m37_a_r_adapter_tx_pending()){g_tx_recovery_pending=1;g_tx_recovery_attempts++;}return -1;}
    g_gate=staged;g_pending_valid=0;g_pending_event=NOUN_ZERO;g_next_sequence++;g_rate_start=start;g_rate_count=count+1;g_publications++;g_root_commits++;g_tx_recovery_pending=0;g_tx_recovery_attempts=0;heap_persist_commit_tx();g_last_error=0;return 1;
}

int candidate_execution_core_r_prepare(const M37ARNativeExecutionSurface*s,noun gate,const runtime_identity_t*i,m37_a_r_prepared_t*out)
{
    if(!s||!i||!out||!s->route_count||s->route_count>M37_A_R_ROUTE_CAPACITY||s->binding.max_payload!=M37_A_R_MAX_PAYLOAD||s->binding.max_ops!=OPS||s->binding.max_cells!=CELLS||s->binding.local_device!=(uint64_t)M24_NODE_ID||s->binding.peer_device==s->binding.local_device||!runtime_identity_validate_gate_header(gate,i,0))return -1;
    for(unsigned x=0;x<11;x++)if(!s->publication[x]||!s->binding.peer_descriptor[x])return -1;
    out->gate=gate;out->identity=*i;out->surface=*s;return 0;
}
int candidate_execution_core_r_activate(const m37_a_r_prepared_t*p)
{
    if(!p)return -1;
    g_gate=p->gate;g_identity=p->identity;g_surface=p->surface;
    g_graph_intent_tag=cord_from_bytes("i2-m25-intent-v1",16);
    if(!noun_is_atom(g_graph_intent_tag))return -1;
    runtime_identity_set(&g_identity);runtime_identity_set_capability_profile(RUNTIME_CAPABILITY_PROFILE_M25);
    g_pending_event=NOUN_ZERO;g_pending_valid=0;g_fifo_head=g_fifo_count=0;g_next_sequence=1;g_high_water=g_admitted_high_water=0;g_last_error=0;g_last_output=0;g_output_valid=0;g_rate_start=g_rate_count=0;g_root_commits=1;g_publications=0;g_active=1;g_running=0;g_source=g_surface.binding.role==1;g_native_initialized=0;g_hold_processing=0;g_allocation_pressure=0;g_tx_recovery_pending=0;g_tx_recovery_attempts=0;return 0;
}
int candidate_execution_core_r_init(void){if(!g_active||g_pending_valid||g_fifo_count||m37_a_r_adapter_tx_pending()||m37_a_r_adapter_init(&g_surface.binding)!=0)return -1;g_native_initialized=1;return 0;}
int candidate_execution_core_r_set_running(int running){if(!g_active||g_pending_valid||g_fifo_count||m37_a_r_adapter_tx_pending()||(running&&!g_native_initialized))return -1;g_running=running!=0;return 0;}
int candidate_execution_core_r_submit(const m37_a_r_ingress_t*i){
    if(!i||!g_active||!g_running||!g_source||g_pending_valid
       ||i->type!=g_surface.ingress_type
       ||(i->type==1&&i->value>1)||(i->type==4&&i->value>UINT_MAX))return -1;
    g_pending_value=i->value;g_pending_valid=1;g_last_error=0;return 0;
}
int candidate_execution_core_r_pump(void){if(!g_active||!g_running||!g_native_initialized)return 0;if(g_source)return source_pump();if(g_fifo_count&&!g_hold_processing)return process_head();m37_a_r_datagram_t d;m37_a_r_native_status_t s=m37_a_r_adapter_receive(&g_surface.binding,&d);if(s==M37_A_R_NATIVE_NO_PACKET)return 0;if(s!=M37_A_R_NATIVE_OK){g_last_error=1;return -1;}return candidate_execution_core_r_deliver(&(candidate_execution_delivery_r_t){d.payload,d.payload_len,d.sequence});}
int candidate_execution_core_r_deliver(const candidate_execution_delivery_r_t*d)
{
    if(!d||!g_active||!g_running||g_source||!d->payload||!d->payload_len||d->payload_len>M37_A_R_MAX_PAYLOAD||!d->sequence||d->sequence==UINT64_MAX||d->sequence<=g_admitted_high_water||g_fifo_count>=M37_A_R_FIFO_CAPACITY){g_last_error=2;return -1;}
    uint64_t value;if(!parse_wire(d->payload,d->payload_len,&value)){g_last_error=3;return -1;}
    uint32_t at=(g_fifo_head+g_fifo_count)%M37_A_R_FIFO_CAPACITY;for(uint32_t i=0;i<d->payload_len;i++)g_fifo_payload[at][i]=d->payload[i];g_fifo_length[at]=d->payload_len;g_fifo_sequence[at]=d->sequence;g_fifo_count++;g_admitted_high_water=d->sequence;if(g_hold_processing)return 1;return process_head();
}
int candidate_execution_core_r_recover_tx(void)
{
    if(!g_pending_valid||!g_tx_recovery_pending)return -1;
    while(g_pending_valid&&g_tx_recovery_attempts<RECOVERY_ATTEMPTS)candidate_execution_core_r_pump();
    if(g_pending_valid){if(m37_a_r_adapter_recover()!=0)return -1;g_pending_valid=0;g_pending_event=NOUN_ZERO;g_tx_recovery_pending=0;g_tx_recovery_attempts=0;g_last_error=9;return 0;}
    return 0;
}
uint64_t candidate_execution_core_r_queue_len(void){return g_active?g_fifo_count:UINT64_MAX;}
uint64_t candidate_execution_core_r_output(void){return g_output_valid?g_last_output:UINT64_MAX;}
uint64_t candidate_execution_core_r_sequence(void){return g_next_sequence;}
uint64_t candidate_execution_core_r_high_water(void){return g_high_water;}
uint64_t candidate_execution_core_r_error(void){return g_last_error;}
uint64_t candidate_execution_core_r_root_commits(void){return g_root_commits;}
uint64_t candidate_execution_core_r_publications(void){return g_publications;}
int candidate_execution_core_r_test_hold_processing(int enabled){if(!g_active||!g_running||g_source)return -1;g_hold_processing=enabled!=0;return 0;}
int candidate_execution_core_r_test_clear_error(void){if(!g_active)return -1;g_last_error=0;return 0;}
int candidate_execution_core_r_test_rate_exhaust(void){if(!g_active||!g_running||g_source)return -1;g_rate_start=runtime_counter_now();g_rate_count=RATE_LIMIT;g_last_error=10;return 0;}
int candidate_execution_core_r_test_rate_reset(void){if(!g_active||g_source)return -1;g_rate_start=g_rate_count=0;g_last_error=0;return 0;}
int candidate_execution_core_r_test_allocation_pressure(void){if(!g_active||!g_running||!g_source)return -1;g_allocation_pressure=1;return 0;}
int candidate_execution_core_r_test_allocation_release(void){if(!g_active||!g_source)return -1;g_allocation_pressure=0;noun_test_copy_fail_after(-1);g_last_error=0;return 0;}

#else
int candidate_execution_core_r_prepare(const M37ARNativeExecutionSurface*s,noun g,const runtime_identity_t*i,m37_a_r_prepared_t*o){(void)s;(void)g;(void)i;(void)o;return -1;}
int candidate_execution_core_r_activate(const m37_a_r_prepared_t*p){(void)p;return -1;}
int candidate_execution_core_r_init(void){return -1;}int candidate_execution_core_r_set_running(int r){(void)r;return -1;}int candidate_execution_core_r_submit(const m37_a_r_ingress_t*i){(void)i;return -1;}int candidate_execution_core_r_pump(void){return 0;}int candidate_execution_core_r_recover_tx(void){return -1;}
uint64_t candidate_execution_core_r_queue_len(void){return UINT64_MAX;}uint64_t candidate_execution_core_r_output(void){return UINT64_MAX;}uint64_t candidate_execution_core_r_sequence(void){return 0;}uint64_t candidate_execution_core_r_high_water(void){return 0;}uint64_t candidate_execution_core_r_error(void){return 0;}uint64_t candidate_execution_core_r_root_commits(void){return 0;}uint64_t candidate_execution_core_r_publications(void){return 0;}
int candidate_execution_core_r_test_hold_processing(int e){(void)e;return -1;}int candidate_execution_core_r_test_clear_error(void){return -1;}int candidate_execution_core_r_test_rate_exhaust(void){return -1;}int candidate_execution_core_r_test_rate_reset(void){return -1;}int candidate_execution_core_r_test_allocation_pressure(void){return -1;}int candidate_execution_core_r_test_allocation_release(void){return -1;}
#endif
