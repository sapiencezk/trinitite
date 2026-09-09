/* The retained transaction owns the candidate and all external obligations.
 * M54 adds only the source-selected policy authorization. */
M44Status m54_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32],const M54Policy *policy) {
    if (!compatibility || !d || !policy || policy->slot!=d->source_slot ||
        policy->instance!=d->source_event/1024u) return M44_INVALID;
    M44Status status=m51_supervisor_init(session,d,handles,bindings,timers,back);
    if (status) return status;
    if (m54_validate_controller_session(session,&authority,policy)) return M44_INVALID;
    byte_copy(authority.compatibility,compatibility,32);
    authority.policy=*policy;
    authority.deployment_generation=1; authority.resident_replacement=2;
    return M44_OK;
}
M44Status m54_supervisor_stage(ResourceSession *candidate,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32],uint32_t generation,uint32_t *ticket,
    const M54Policy *policy) {
    if (ticket) *ticket=0;
    if (!policy || authority.resident_replacement!=2 ||
        byte_compare(policy,&authority.policy,sizeof(*policy))) return M44_INVALID;
    return m52_supervisor_stage(candidate,d,handles,bindings,timers,back,
                               compatibility,generation,ticket);
}
