/* Retained adapter bridge for the M47 cold-boot mode. All captured causes are
 * C-owned until queue publication succeeds; no borrowed packet survives. */
#if defined(M47_MANAGED_SERVICES)
#include "m44_two_resource_supervisor.h"
static uint32_t m47_tx_epoch, m47_rx_epoch, m47_rx_valid, m47_rx_value;
static uint64_t m47_rx_token;
int m47_transport_config(noun config) {
    if (config==NOUN_ZERO) return 1; /* offline qualification / managed setup */
    return provider_config(config);
}
int m47_transport_start(void) {
    if (!provider_enabled) return 1;
    if (m37_a_r_adapter_init(&transport)) return 0;
    provider_fact("ready",0,0);
    uint64_t frequency; __asm__ volatile("mrs %0, cntfrq_el0":"=r"(frequency));
    uint64_t deadline=ticks()+10u*frequency;
    for (;;) {
        uint8_t ch;
        if (uart_getc_nb(&ch) && ch=='G') break;
        if (ticks()>=deadline) return 0;
    }
    return 1;
}
static M44Row m47_cause(uint32_t iid,uint32_t event,uint64_t token,uint32_t value,uint32_t status) {
    M44Row row={0}; row.event=iid*1024+event;
    if (event==4) { row.count=1; row.values[0]=(M44Value){iid*1024+5,2,status}; }
    else {
        uint32_t start=0;
        if (event==2) { row.values[0]=(M44Value){iid*1024+1,1,1}; start=1; }
        for (uint32_t i=0;i<4;i++) row.values[start+i]=(M44Value){iid*1024+11+i,2,(token>>(16*i))&65535u};
        row.count=start+4;
        if (event==3) {
            row.values[4]=(M44Value){iid*1024+3,2,value};
            row.values[5]=(M44Value){iid*1024+5,2,status}; row.count=6;
        }
    }
    return row;
}
uint32_t m47_transport_action(uint32_t operation,uint32_t slot,uint32_t iid,
                              uint32_t kind,uint32_t epoch,uint64_t token,uint32_t argument) {
    const M44State *s=m44_supervisor_state();
    if (!s || slot<1 || slot>2) return M44_INVALID;
    if (s->fenced) return M44_FENCED;
    if (epoch!=s->epoch || (s->lifecycle!=1 && s->lifecycle!=2)) return M44_INVALID;
    M47ProviderLedger p=s->providers[slot-1];
    M44Row row;
    if (operation==35) {
        if (kind!=2 || !token || token!=p.rx_token) return M44_INVALID;
        row=m47_cause(iid,2,token,0,0);
        return m47_provider_enqueue(slot,epoch,&row);
    }
    if (operation==36) {
        if (provider_enabled && m37_a_r_adapter_tx_pending()) return M44_INVALID;
        row=m47_cause(iid,4,0,0,argument);
        return m47_provider_enqueue(slot,epoch,&row);
    }
    if (!provider_enabled) return M44_INVALID;
    transport.epoch=epoch;
#if defined(M44_G0_TEST_CONTROLS)
    if (operation==37) { m37_a_r_adapter_test_lost_completion(); return M44_OK; }
    if (operation==38) { m37_a_r_adapter_test_release_lost_completion(); return M44_OK; }
#endif
    if (operation==32
#if defined(M44_G0_TEST_CONTROLS)
        || operation==39
#endif
        ) {
        if (kind!=1 || p.tx_state!=1 || p.tx_token!=token || !token ||
            !publication_build(p.tx_value)) return M44_INVALID;
        M44Status result=m47_provider_claim(slot,epoch,token);
        if (result) return result;
        pending_token=token; pending_value=p.tx_value; completion_observed=0; m47_tx_epoch=epoch;
#if defined(M44_G0_TEST_CONTROLS)
        if (operation==39) return M44_INVALID; /* claimed, deliberately no submit */
#endif
        m37_a_r_native_status_t r=m37_a_r_adapter_submit(&transport,pending_data,pending_bytes,token);
        provider_fact("submit",token,r);
        return r==M37_A_R_NATIVE_OK?M44_OK:M44_INVALID;
    }
    if (operation!=33 && operation!=34) return M44_INVALID;
    if (argument>1 || p.phase!=1 || p.release_queued) return M44_INVALID;
    if (s->counts[slot-1]>=16) return M44_FULL;
    if (operation==33 && (kind!=1 || p.tx_state!=2 || p.tx_token!=token || token!=pending_token || m47_tx_epoch!=epoch)) return M44_INVALID;
    if (operation==34 && (kind!=2 || p.rx_state)) return M44_INVALID;
    if (m47_rx_valid && m47_rx_epoch!=epoch) return M44_INVALID;
    uint64_t frequency; __asm__ volatile("mrs %0, cntfrq_el0":"=r"(frequency));
    uint64_t deadline=ticks()+10u*frequency;
    m37_a_r_native_status_t status=M37_A_R_NATIVE_NO_PACKET;
    do {
        if (operation==33) status=completion_observed?M37_A_R_NATIVE_OK:
            m37_a_r_adapter_poll_completion(&transport,pending_data,pending_bytes,token);
        else if (m47_rx_valid) status=M37_A_R_NATIVE_OK;
        else {
            m37_a_r_datagram_t d={0};
            status=m37_a_r_adapter_receive(&transport,&d);
            if (status==M37_A_R_NATIVE_OK) {
                if (!d.sequence || d.sequence>>63 || d.sequence<=p.rx_highwater ||
                    !publication_read(&d,&m47_rx_value)) status=M37_A_R_NATIVE_MALFORMED;
                else {
                    m47_rx_valid=1; m47_rx_token=d.sequence; m47_rx_epoch=epoch;
                    if (m47_provider_receive_hold(slot,epoch,1)!=M44_OK) return M44_INVALID;
                }
            }
        }
        if (!argument || (status!=M37_A_R_NATIVE_NO_PACKET && status!=M37_A_R_NATIVE_RING_FULL)) break;
    } while(ticks()<deadline);
    provider_fact(operation==33?"completion-poll":"receive",operation==33?token:m47_rx_token,status);
    if (status!=M37_A_R_NATIVE_OK) return M44_INVALID;
    if (operation==33) {
        completion_observed=1;
        row=m47_cause(iid,3,token,pending_value,0);
    } else row=m47_cause(iid,3,m47_rx_token,m47_rx_value,0);
    M44Status result=m47_provider_enqueue(slot,epoch,&row);
    if (!result && operation==34) {
        m47_rx_valid=0;
        if (m47_provider_receive_hold(slot,epoch,0)!=M44_OK) return M44_INVALID;
    }
    return result;
}
#endif
