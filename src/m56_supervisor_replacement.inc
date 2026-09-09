/* The retained transaction owns the candidate and all external obligations.
 * M56 adds signed values to only the source-selected policy authorization. */
M44Status m56_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32],const M54Policy *policy) {
    if (!compatibility || !d || d->service_value_type!=3 || !policy || policy->slot!=d->source_slot ||
        policy->instance!=d->source_event/1024u) return M44_INVALID;
    M44Status status=m51_supervisor_init(session,d,handles,bindings,timers,back);
    if (status) return status;
    if (m56_validate_controller_session(session,&authority,policy)) return M44_INVALID;
    byte_copy(authority.compatibility,compatibility,32);
    authority.policy=*policy;
    authority.deployment_generation=1; authority.resident_replacement=3;
    return M44_OK;
}
M44Status m56_supervisor_stage(ResourceSession *candidate,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back,
    const uint8_t compatibility[32],uint32_t generation,uint32_t *ticket,
    const M54Policy *policy) {
    if (ticket) *ticket=0;
    if (!policy || authority.resident_replacement!=3 ||
        byte_compare(policy,&authority.policy,sizeof(*policy))) return M44_INVALID;
    return m52_supervisor_stage(candidate,d,handles,bindings,timers,back,
                               compatibility,generation,ticket);
}
