/* Fixed two-timer controller obligations, within the retained transaction. */
#if defined(M51_CONTROLLER)
static uint32_t m51_event(uint32_t timer,uint32_t ordinal) {
  return authority.timer_bindings[timer].binding.instance_id*1024u+ordinal;
}
static int m51_private(uint32_t slot,uint32_t event) {
  for (uint32_t i=0;i<2;i++)
    if (slot+1==authority.timer_bindings[i].binding.slot && event==m51_event(i,3)) return 1;
  return 0;
}
static int m51_matching_cause(uint32_t timer) {
  uint32_t slot=authority.selected;
  const M44Row *row=&live()->queues[slot][0];
  return slot+1==authority.timer_bindings[timer].binding.slot && live()->counts[slot] &&
      row->event==m51_event(timer,3) && row->count==4 &&
      m47_token(row,0)==live()->timers[timer].generation &&
      live()->timers[timer].phase==M49_TIMER_QUEUED;
}
static uint32_t m51_reserved(const M44State *state,uint32_t slot,int consuming) {
  uint32_t reserved=(slot+1==authority.descriptor.source_slot && state->publish_roundtrip)?1u:0u;
  for (uint32_t i=0;i<2;i++)
    if (state->timers[i].phase==M49_TIMER_QUEUED &&
        !(consuming && m51_matching_cause(i))) reserved++;
  return reserved;
}
static uint32_t m51_capacity(uint32_t slot,int consuming) {
  return 16u-m51_reserved(live(),slot,consuming);
}
static int m51_room(const M44State *state,uint32_t slot,uint32_t add) {
  /* Output preparation sees the staged FIFO after retirement of its cause. */
  uint32_t count=state->counts[slot];
  return count+add+m51_reserved(state,slot,1)<=16;
}
static int m51_active(void) {
  return live()->timers[0].phase || live()->timers[1].phase || live()->publish_roundtrip;
}
static int m51_output(uint32_t slot,const M44Row *row) {
  for (uint32_t i=0;i<2;i++) {
    if (slot+1!=authority.timer_bindings[i].binding.slot) continue;
    M49TimerLedger *timer=&stage()->timers[i];
    if (row->event==m51_event(i,5)) {
      if (row->count!=5 || row->values[0].type!=4 || !authority.clock_valid) return 0;
      if (authority.timer_bindings[i].kind==2) {
        if (!row->values[0].raw) return 0;
        if (timer->phase==M49_TIMER_QUEUED && m51_matching_cause(i)) m49_clear(timer);
      }
      uint64_t token=m47_token(row,1);
      M49ClockArm arm={0};
      if (timer->phase!=M49_TIMER_FREE || token!=timer->highwater+1 ||
          !m49_clock_prepare_arm(live()->epoch,token,authority.clock_ms,
              row->values[0].raw,authority.clock_turn,&arm)) return 0;
      timer->phase=M49_TIMER_ARMED; timer->generation=token; timer->highwater=token;
      timer->duration_ms=row->values[0].raw; timer->deadline_ms=arm.deadline_ms;
      timer->not_before_turn=arm.not_before_turn;
    } else if (row->event==m51_event(i,6)) {
      if (row->count!=4 || (timer->phase!=M49_TIMER_ARMED && timer->phase!=M49_TIMER_QUEUED) ||
          m47_token(row,0)!=timer->generation) return 0;
      m49_clear(timer);
    }
  }
  return 1;
}
static int m51_consumed(uint32_t slot) {
  const M44Row *row=&live()->queues[slot][0];
  for (uint32_t i=0;i<2;i++) {
    M49TimerLedger *timer=&stage()->timers[i];
    if (slot+1==authority.timer_bindings[i].binding.slot && row->event==m51_event(i,3) &&
        timer->phase==M49_TIMER_QUEUED && row->count==4 && m47_token(row,0)==timer->generation)
      m49_clear(timer);
  }
  return 1;
}
static int m51_crossing(uint32_t slot,const M44Row *row) {
  M44State *state=stage();
  const M44Descriptor *d=&authority.descriptor;
  const M51ReturnBinding *back=&authority.completion;
  M44Row delivery={0}; uint32_t dest;
  if (slot+1==d->source_slot && row->event==d->source_event) {
    if (state->publish_roundtrip) return -1;
    dest=d->target_slot-1;
    delivery.event=d->target_event; delivery.count=d->value_count;
    for (uint32_t j=0;j<d->value_count;j++) {
      uint32_t found=0;
      for (uint32_t k=0;k<row->count;k++)
        if (row->values[k].id==d->source_ids[j] && row->values[k].type==d->types[j]) {
          delivery.values[j]=(M44Value){d->target_ids[j],d->types[j],row->values[k].raw}; found++;
        }
      if (found!=1) return -1;
    }
    state->publish_roundtrip=1;
    if (!m51_room(state,d->source_slot-1,0)) goto full;
  } else if (slot+1==back->source_slot && row->event==back->source_event) {
    const M44Row *cause=&live()->queues[slot][0];
    const M47ProviderLedger *provider=&live()->providers[slot];
    if (!state->publish_roundtrip || authority.controller_cnf ||
        provider->tx_state!=M47_TX_COMPLETION_QUEUED || !live()->counts[slot] ||
        cause->event!=m47_event(slot,3) || cause->count!=6 ||
        m47_token(cause,0)!=provider->tx_token) return -1;
    dest=back->target_slot-1; delivery.event=back->target_event; delivery.count=1;
    uint32_t found=0;
    for (uint32_t k=0;k<row->count;k++)
      if (row->values[k].id==back->source_id && row->values[k].type==back->type) {
        delivery.values[0]=(M44Value){back->target_id,back->type,row->values[k].raw}; found++;
      }
    if (found!=1) return -1;
    state->publish_roundtrip=0; authority.controller_cnf=1;
  } else return 0;
  if (!m51_room(state,dest,1) || state->sequence==UINT32_MAX) goto full;
  if (!valid_row(dest,&delivery,0)) return -1;
  delivery.sequence=++state->sequence;
  state->queues[dest][state->counts[dest]++]=delivery;
  return 1;
full:
  authority.turn_fault=M44_FAULT_DELIVERY_RESERVATION;
  return -1;
}
static M44Status m51_clock(void) {
  uint32_t selected=2;
  for (uint32_t i=0;i<2;i++) {
    const M49TimerLedger *timer=&live()->timers[i];
    if (timer->phase!=M49_TIMER_ARMED || authority.clock_ms<timer->deadline_ms ||
        authority.clock_turn<timer->not_before_turn) continue;
    if (selected==2 || timer->deadline_ms<live()->timers[selected].deadline_ms) selected=i;
  }
  if (selected==2) return M44_NO_WORK;
  const M49TimerLedger *timer=&live()->timers[selected];
  const M49TimerBinding *binding=&authority.timer_bindings[selected].binding;
  uint32_t slot=binding->slot-1,other=1-slot;
  /* One occupied private FIFO row plus a fixed future request/return pair. */
  if (live()->counts[slot]+m51_reserved(live(),slot,0)+2>16 ||
      live()->counts[other]+m51_reserved(live(),other,0)+1>16) return M44_FULL;
  M44Row row={0}; row.event=m51_event(selected,3); row.count=4;
  for (uint32_t n=0;n<4;n++) row.values[n]=(M44Value){binding->instance_id*1024u+7+n,2,
      (uint32_t)((timer->generation>>(16*n))&65535)};
  if (!valid_row(slot,&row,0)) return M44_INVALID;
  authority.busy=1; *stage()=*live(); stage()->timers[selected].phase=M49_TIMER_QUEUED;
  stage()->queues[slot][stage()->counts[slot]++]=row;
  return m47_publish();
}
M44Status m51_supervisor_init(ResourceSession *session,const M44Descriptor *d,
    const M44Saved handles[2],const M47ProviderBinding bindings[2],
    const M51TimerBinding timers[2],const M51ReturnBinding *back) {
  if (authority.initialized || !d || !bindings || !timers || !back ||
      d->source_slot!=1 || d->target_slot!=2 || d->batch_bound!=1 || d->value_count!=2 ||
      bindings[0].kind!=2 || bindings[1].kind!=1 || timers[0].kind!=1 || timers[1].kind!=2 ||
      back->source_slot!=2 || back->target_slot!=1 || back->type!=2 ||
      back->source_event!=bindings[1].instance_id*1024u+6 ||
      back->source_id!=bindings[1].instance_id*1024u+5 ||
      back->target_event/1024u!=d->source_event/1024u ||
      back->target_id/1024u!=back->target_event/1024u) return M44_INVALID;
  const uint32_t expire_ids[]={7,8,9,10}, uint_types[]={2,2,2,2};
  const uint32_t arm_ids[]={1,3,4,5,6}, arm_types[]={4,2,2,2,2}, cancel_ids[]={3,4,5,6};
  for (uint32_t i=0;i<2;i++) {
    uint32_t iid=timers[i].binding.instance_id;
    if (timers[i].binding.slot!=1 || !iid || iid>8 ||
        iid==bindings[0].instance_id || iid==d->source_event/1024u ||
        (i && iid==timers[0].binding.instance_id) || !d->time_values[0] ||
        !m47_signature(d,0,iid,3,0,expire_ids,uint_types,4) ||
        !m47_signature(d,0,iid,5,1,arm_ids,arm_types,5) ||
        !m47_signature(d,0,iid,6,1,cancel_ids,uint_types,4)) return M44_INVALID;
  }
  uint32_t matches=0;
  for (uint32_t i=0;i<d->ingress_count[0];i++) if (d->ingress[0][i].event==back->target_event) {
    const M44Boundary *row=&d->ingress[0][i];
    if (row->count!=1 || row->values[0].id!=back->target_id || row->values[0].type!=2) return M44_INVALID;
    matches++;
  }
  if (matches!=1) return M44_INVALID;
  M44Status status=m47_supervisor_init(session,d,handles,bindings);
  if (!status) {
    authority.controller=1; authority.timed=1;
    authority.timer_bindings[0]=timers[0]; authority.timer_bindings[1]=timers[1];
    authority.completion=*back;
  }
  return status;
}
#endif
