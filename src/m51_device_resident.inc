/* Shared two-timer owner descriptor reader. M51/M52 retain their schema;
 * M53 uses source-derived instances with the same service/ownership ABI. */
#if defined(M51_CONTROLLER)
#if defined(M53_RESIDENT_COMPOSITION)
static int controller_descriptor_read(noun value,noun expected,const char *schema,const char *domain,uint32_t profile) {
#else
static int m51_descriptor_read(noun value,noun expected) {
#endif
  noun tag,body,f[5],providers[2],p[7],timers[2],wrapper[2],timer[6],back[5],values[1],binding[3];
  uint8_t actual[32],supplied[32],numeric[32],names[4][65]; uint32_t version,count;
  if (!pair(value,&tag,&body) ||
#if defined(M53_RESIDENT_COMPOSITION)
      !text_is(tag,schema) ||
#else
      !text_is(tag,"m51-resident-controller-deployment-v1") ||
#endif
      !record(body,f,5) || !scalar(f[0],1,&version) || version!=1 ||
      !record(f[2],providers,2) || !record(f[3],timers,2) || !record(f[4],back,5) ||
      !hash_noun(value,
#if defined(M53_RESIDENT_COMPOSITION)
          domain,
#else
          "1499kernel-m51-resident-controller-deployment-v1",
#endif
          1,actual) ||
      !digest(expected,supplied) || !same(actual,supplied,32) ||
      !hash_noun(f[1],"1499kernel-m44-deployment-v1",1,numeric) ||
      !descriptor_read(f[1],cord_from_bytes((const char *)numeric,32)) ||
      descriptor_timed_profile!=
#if defined(M53_RESIDENT_COMPOSITION)
          profile
#else
          3
#endif
          ) return 0;
  for (uint32_t i=0;i<2;i++) {
    M47ProviderBinding *b=&m47_bindings[i];
    if (!record(providers[i],p,7) || !scalar(p[0],2,&b->slot) || b->slot!=i+1 ||
        !m47_source_name(p[1],names[i]) || !scalar(p[2],2,&b->kind) ||
        b->kind!=(i?1u:2u) || !scalar(p[3],8,&b->instance_id) || !b->instance_id) return 0;
    uint32_t init[]={1},pub[]={3,4},sub[]={2,3,4},intent[]={7};
    if (!m47_binding_table(p[4],i,b->instance_id,init,1,0) ||
        !m47_binding_table(p[5],i,b->instance_id,b->kind==1?pub:sub,b->kind==1?2:3,0) ||
        !m47_binding_table(p[6],i,b->instance_id,intent,b->kind==1?1:0,1)) return 0;
  }
  if (same(names[0],names[1],65)) return 0;
  for (uint32_t i=0;i<2;i++) {
    M51TimerBinding *b=&resident_timer_bindings[i];
    if (!record(timers[i],wrapper,2) || !scalar(wrapper[0],2,&b->kind) || b->kind!=i+1 ||
        !record(wrapper[1],timer,6) || !scalar(timer[0],2,&b->binding.slot) ||
        b->binding.slot!=1 || !m47_source_name(timer[1],names[i+2]) ||
        !scalar(timer[2],8,&b->binding.instance_id) || !b->binding.instance_id) return 0;
    for (uint32_t j=0;j<i+2;j++) if (same(names[j],names[i+2],65)) return 0;
    uint32_t iid=b->binding.instance_id;
    if (iid==m47_bindings[0].instance_id ||
        (i && iid==resident_timer_bindings[0].binding.instance_id)) return 0;
    uint32_t public_events[2]={0},public_count=0,expire[]={3},effects[]={5,6};
    for (uint32_t event=1;event<=2;event++)
      for (uint32_t j=0;j<descriptor.ingress_count[0];j++)
        if (descriptor.ingress[0][j].event==iid*1024u+event) public_events[public_count++]=event;
    if (!m49_timer_table(timer[3],0,iid,public_events,public_count,0) ||
        !m49_timer_table(timer[4],0,iid,expire,1,0) ||
        !m49_timer_table(timer[5],0,iid,effects,2,1)) return 0;
  }
  M51ReturnBinding *r=&resident_completion;
  if (!scalar(back[0],2,&r->source_slot) || r->source_slot!=2 ||
      !scalar(back[1],65535,&r->source_event) || !r->source_event ||
      !scalar(back[2],2,&r->target_slot) || r->target_slot!=1 ||
      !scalar(back[3],65535,&r->target_event) || !r->target_event ||
      !list(back[4],values,1,&count) || count!=1 || !record(values[0],binding,3) ||
      !scalar(binding[0],65535,&r->source_id) || !r->source_id ||
      !scalar(binding[1],65535,&r->target_id) || !r->target_id ||
      !scalar(binding[2],2,&r->type) || r->type!=2) return 0;
  return 1;
}
#if defined(M53_RESIDENT_COMPOSITION)
static int m51_descriptor_read(noun value,noun expected) {
  return controller_descriptor_read(value,expected,"m51-resident-controller-deployment-v1",
      "1499kernel-m51-resident-controller-deployment-v1",3);
}
static int m53_descriptor_read(noun value,noun expected) {
  return controller_descriptor_read(value,expected,"m53-resident-composition-deployment-v1",
      "1499kernel-m53-resident-composition-deployment-v1",4);
}
#endif
#endif
