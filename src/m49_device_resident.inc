/* M49 content-bound boot binding. Included after M47 helper definitions. */
#if defined(M49_MANAGED_DELAY)
static int m49_timer_table(noun n,uint32_t slot,uint32_t iid,
    const uint32_t *events,uint32_t expected,int output) {
    noun rows[2],fields[2],values[5],value[2];uint32_t count;
    if (!list(n,rows,2,&count) || count!=expected) return 0;
    for (uint32_t i=0;i<count;i++) {
        uint32_t code,nv;
        if (!record(rows[i],fields,2) || !scalar(fields[0],65535,&code) ||
            code!=iid*1024+events[i] || !list(fields[1],values,5,&nv)) return 0;
        const M44Boundary *table=output?descriptor.outputs[slot]:descriptor.ingress[slot];
        uint32_t total=output?descriptor.output_count[slot]:descriptor.ingress_count[slot],found=0;
        for (uint32_t j=0;j<total;j++) if (table[j].event==code) {
            if (table[j].count!=nv) return 0;
            for (uint32_t k=0;k<nv;k++) {
                uint32_t id,type;
                if (!record(values[k],value,2) || !scalar(value[0],65535,&id) ||
                    !scalar(value[1],4,&type) || id!=table[j].values[k].id ||
                    type!=table[j].values[k].type) return 0;
            }
            found++;
        }
        if (found!=1) return 0;
    }
    return 1;
}
static int m49_descriptor_read(noun value,noun expected) {
    noun tag,body,f[4],rows[2],p[7],timer[6];
    uint8_t actual[32],supplied[32],numeric[32],names[3][65];uint32_t version;
    const char *schema="m49-managed-delay-deployment-v1";
    const char *domain="1499kernel-m49-managed-delay-deployment-v1";
#if defined(M50_PERIODIC)
    uint32_t profile=1;
    if (managed_cycle) {
        schema="m50-managed-cycle-deployment-v1";
        domain="1499kernel-m50-managed-cycle-deployment-v1";
        profile=2;
    }
#endif
    if (!pair(value,&tag,&body) || !text_is(tag,schema) ||
        !record(body,f,4) || !scalar(f[0],1,&version) || version!=1 ||
        !record(f[2],rows,2) || !record(f[3],timer,6) ||
        !hash_noun(value,domain,1,actual) ||
        !digest(expected,supplied) || !same(actual,supplied,32) ||
        !hash_noun(f[1],"1499kernel-m44-deployment-v1",1,numeric) ||
        !descriptor_read(f[1],cord_from_bytes((const char *)numeric,32)) ||
#if defined(M50_PERIODIC)
        descriptor_timed_profile!=profile
#else
        !descriptor_timed_profile
#endif
        ) return 0;
    for (uint32_t i=0;i<2;i++) {
        M47ProviderBinding *b=&m47_bindings[i];
        if (!record(rows[i],p,7) || !scalar(p[0],2,&b->slot) || b->slot!=i+1 ||
            !m47_source_name(p[1],names[i]) || !scalar(p[2],2,&b->kind) || !b->kind ||
            !scalar(p[3],8,&b->instance_id) || !b->instance_id) return 0;
        uint32_t init[]={1},pub[]={3,4},sub[]={2,3,4},intent[]={7};
        if (!m47_binding_table(p[4],i,b->instance_id,init,1,0) ||
            !m47_binding_table(p[5],i,b->instance_id,b->kind==1?pub:sub,b->kind==1?2:3,0) ||
            !m47_binding_table(p[6],i,b->instance_id,intent,b->kind==1?1:0,1)) return 0;
    }
    if (m47_bindings[0].kind+m47_bindings[1].kind!=3 || same(names[0],names[1],65) ||
        !scalar(timer[0],2,&m49_timer_binding.slot) || !m49_timer_binding.slot ||
        m49_timer_binding.slot!=descriptor.source_slot || !m47_source_name(timer[1],names[2]) ||
        same(names[0],names[2],65) || same(names[1],names[2],65) ||
        !scalar(timer[2],8,&m49_timer_binding.instance_id) || !m49_timer_binding.instance_id) return 0;
    uint32_t slot=m49_timer_binding.slot-1,iid=m49_timer_binding.instance_id;
    if (iid==m47_bindings[slot].instance_id) return 0;
    uint32_t public_events[2]={2,0},public_count=1,expire[]={3},effects[]={5,6};
    for (uint32_t i=0;i<descriptor.ingress_count[slot];i++)
        if (descriptor.ingress[slot][i].event==iid*1024+1) {
            public_events[0]=1; public_events[1]=2;public_count=2;
        }
    return m49_timer_table(timer[3],slot,iid,public_events,public_count,0) &&
        m49_timer_table(timer[4],slot,iid,expire,1,0) &&
        m49_timer_table(timer[5],slot,iid,effects,2,1);
}
#endif
