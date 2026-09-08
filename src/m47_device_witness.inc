/* Included by the generic device witness after its bounded noun helpers. */
#if defined(M47_MANAGED_SERVICES)
static int m47_binding_table(noun n, uint32_t slot, uint32_t iid,
                             const uint32_t *ordinals, uint32_t expected, int output) {
    noun rows[3], fields[2], values[6], value[2];
    uint32_t count;
    if (!list(n,rows,3,&count) || count!=expected) return 0;
    for (uint32_t i=0;i<count;i++) {
        uint32_t code, nv;
        if (!record(rows[i],fields,2) || !scalar(fields[0],65535,&code) ||
            code != iid*1024+ordinals[i] || !list(fields[1],values,6,&nv)) return 0;
        const M44Boundary *table=output?descriptor.outputs[slot]:descriptor.ingress[slot];
        uint32_t total=output?descriptor.output_count[slot]:descriptor.ingress_count[slot], found=0;
        for (uint32_t j=0;j<total;j++) if (table[j].event==code) {
            if (table[j].count!=nv) return 0;
            for (uint32_t k=0;k<nv;k++) {
                uint32_t id,type;
                if (!record(values[k],value,2) || !scalar(value[0],65535,&id) ||
                    !scalar(value[1],2,&type) || id!=table[j].values[k].id || type!=table[j].values[k].type) return 0;
            }
            found++;
        }
        if (found!=1) return 0;
    }
    return 1;
}
static int m47_source_name(noun value,uint8_t out[65]) {
    if (!noun_atom_read_fixed(value,out,65)) return 0;
    uint32_t i=0;
    for (;i<65 && out[i];i++) {
        uint8_t c=out[i];
        int letter=(c>='A' && c<='Z') || (c>='a' && c<='z');
        if (!letter && (!i || !((c>='0' && c<='9') || c=='_'))) return 0;
    }
    if (!i || i>64) return 0;
    for (;i<65;i++) if (out[i]) return 0;
    return 1;
}
static int m47_descriptor_read(noun value, noun expected) {
    noun tag,body,f[3],rows[2],p[7];
    uint8_t actual[32],supplied[32],numeric[32],name[2][65];
    uint32_t version;
    if (!pair(value,&tag,&body) || !text_is(tag,"m47-managed-services-deployment-v1") ||
        !record(body,f,3) || !scalar(f[0],1,&version) || version!=1 ||
        !record(f[2],rows,2) || !hash_noun(value,"1499kernel-m47-managed-services-deployment-v1",1,actual) ||
        !digest(expected,supplied) || !same(actual,supplied,32) ||
        !hash_noun(f[1],"1499kernel-m44-deployment-v1",1,numeric) ||
        !descriptor_read(f[1],cord_from_bytes((const char *)numeric,32))) return 0;
    for (uint32_t i=0;i<2;i++) {
        M47ProviderBinding *b=&m47_bindings[i];
        if (!record(rows[i],p,7) || !scalar(p[0],2,&b->slot) || b->slot!=i+1 ||
            !m47_source_name(p[1],name[i]) ||
            !scalar(p[2],2,&b->kind) || !b->kind ||
            !scalar(p[3],8,&b->instance_id) || !b->instance_id) return 0;
        uint32_t init[]={1},pub[]={3,4},sub[]={2,3,4},intent[]={7};
        if (!m47_binding_table(p[4],i,b->instance_id,init,1,0) ||
            !m47_binding_table(p[5],i,b->instance_id,b->kind==1?pub:sub,b->kind==1?2:3,0) ||
            !m47_binding_table(p[6],i,b->instance_id,intent,b->kind==1?1:0,1)) return 0;
    }
    return m47_bindings[0].kind+m47_bindings[1].kind==3 && !same(name[0],name[1],65);
}
static uint32_t m47_command(const Command *c) {
    if (c->op==22) { uint32_t token=0; return m46_supervisor_stage(0,0,0,0,1,&token); }
    if (c->op==23) return m46_supervisor_activate(1,1);
    if (c->op==24) return m46_supervisor_cancel(1,1);
#if defined(M44_G0_TEST_CONTROLS)
    if (c->op==30) return m47_provider_enqueue(c->slot,c->epoch,&c->row);
    if (c->op==31) return m47_provider_claim(c->slot,c->epoch,c->provider_token);
#endif
    if (c->slot<1 || c->slot>2) return M44_INVALID;
    return m47_transport_action(c->op,c->slot,m47_bindings[c->slot-1].instance_id,
                                m47_bindings[c->slot-1].kind,c->epoch,c->provider_token,c->argument);
}
#endif
