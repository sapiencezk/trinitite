/* A transient call gate reuses M46's transaction without making its public
 * service refusal permissive. No callback or other operation may interleave. */
static M44Status m52_replacement_ready(void) {
    M44Status status=ready();
    if (status) return status;
    if (!authority.resident_replacement || live()->lifecycle!=1 || live()->fault)
        return M44_INVALID;
    M44ResourceInspection resources;
    if (m44_resource_inspect(authority.session,&authority,&resources)) return M44_INVALID;
#if defined(M54_RESIDENT_REPLACEMENT)
    if (authority.resident_replacement==2) {
        const M54Policy *p=&authority.policy;
        if (!p->slot || p->slot>2 || !p->instance ||
            p->instance>resources.instance_counts[p->slot-1] || !p->failure ||
            p->failure>resources.instances[p->slot-1][p->instance-1].value_count ||
            resources.instances[p->slot-1][p->instance-1].values[p->failure-1]) return M44_INVALID;
        return M44_OK;
    }
#endif
    if (resources.instance_counts[0]!=4 || resources.instances[0][1].value_count!=14 ||
        resources.instances[0][1].values[13]) return M44_INVALID;
    return M44_OK;
}
static int m52_activation_transferable(void) {
    const M44State *s=live();
    if (authority.receive_holds || s->publish_roundtrip>1) return 0;
    for (uint32_t slot=0;slot<2;slot++) {
        const M47ProviderLedger *p=&s->providers[slot];
        if (p->rx_state || p->release_queued || p->tx_state>M47_TX_COMMITTED ||
            s->counts[slot]+m51_reserved(s,slot,0)>16) return 0;
        if (p->tx_state && (slot!=1 || !s->publish_roundtrip)) return 0;
    }
    for (uint32_t i=0;i<2;i++) {
        const M49TimerLedger *t=&s->timers[i]; uint32_t matching=0;
        if (t->phase>M49_TIMER_QUEUED) return 0;
        if (!t->phase) {
            if (t->generation || t->duration_ms || t->deadline_ms || t->not_before_turn) return 0;
        } else if (!t->generation || t->generation!=t->highwater ||
                   !t->duration_ms || !t->not_before_turn || t->deadline_ms<t->duration_ms) return 0;
        for (uint32_t n=0;n<s->counts[0];n++) {
            const M44Row *row=&s->queues[0][n];
            if (row->event==m51_event(i,3) && row->count==4 &&
                m47_token(row,0)==t->generation) matching++;
        }
        if (matching!=(t->phase==M49_TIMER_QUEUED?1u:0u)) return 0;
    }
    return 1;
}
M44Status m52_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32]) {
    if (!compatibility || !d || d->source_event/1024u!=2) return M44_INVALID;
    M44Status status=m51_supervisor_init(session,d,handles,bindings,timers,back);
    if (status) return status;
    if (m52_validate_controller_session(session,&authority)) return M44_INVALID;
    byte_copy(authority.compatibility,compatibility,32);
    authority.deployment_generation=1; authority.resident_replacement=1;
    return M44_OK;
}
M44Status m52_supervisor_can_stage(uint32_t expected_generation) {
    M44Status status=m52_replacement_ready();
    if (status) return status;
    if (authority.candidate || expected_generation!=authority.deployment_generation ||
        expected_generation==UINT32_MAX || authority.candidate_serial==UINT32_MAX)
        return M44_INVALID;
    return M44_OK;
}
M44Status m52_supervisor_stage(ResourceSession *candidate,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32],uint32_t expected_generation,uint32_t *ticket) {
    if (ticket) *ticket=0;
    M44Status status=m52_supervisor_can_stage(expected_generation);
    if (status) return status;
    if (!bindings || !timers || !back ||
        byte_compare(bindings,authority.bindings,sizeof(authority.bindings)) ||
        byte_compare(timers,authority.timer_bindings,sizeof(authority.timer_bindings)) ||
        byte_compare(back,&authority.completion,sizeof(*back))) return M44_INVALID;
    authority.replacement_call=1;
    status=m46_supervisor_stage(candidate,d,handles,compatibility,expected_generation,ticket);
    authority.replacement_call=0;
    return status;
}
M44Status m52_supervisor_activate(uint32_t ticket,uint32_t expected_generation,
                                  uint32_t driver_holds) {
    M44Status status=m52_replacement_ready();
    if (status) return status;
    if (driver_holds || !m52_activation_transferable() || !authority.candidate ||
#if defined(M54_RESIDENT_REPLACEMENT)
        (authority.resident_replacement==2 ?
         m54_validate_replacement_pair(authority.session,authority.candidate,&authority,&authority.policy) :
         m52_validate_replacement_pair(authority.session,authority.candidate,&authority)))
#else
        m52_validate_replacement_pair(authority.session,authority.candidate,&authority))
#endif
        return M44_INVALID;
    authority.replacement_call=1;
    status=m46_supervisor_activate(ticket,expected_generation);
    authority.replacement_call=0;
    return status;
}
M44Status m52_supervisor_cancel(uint32_t ticket,uint32_t expected_generation) {
    M44Status status=ready();
    if (status && status!=M44_FENCED) return status;
    if (!authority.resident_replacement) return M44_INVALID;
    authority.replacement_call=1;
    status=m46_supervisor_cancel(ticket,expected_generation);
    authority.replacement_call=0;
    return status;
}
