/* Trusted immutable local catalog. Candidate parsing borrows only fixed boot
 * buffers; supervisor and driver retain their own active descriptor bindings. */
static int m52_catalog_validate(void) {
    /* Validation owns no durable nouns. In particular, a good core followed by
     * a bad admission must not leave that core allocated in the persistent
     * arena on every refused STAGE. Abort each temporary cue transaction. */
    for (uint32_t slot=0;slot<2;slot++) for (uint32_t part=0;part<2;part++) {
        uint32_t column=1-part; noun value;
        int ok=cue_bounded_bytes(m44_boot_catalog_storage(slot,column),
            catalog_bytes[slot][column],&cue_i2_limits,HEAP_MODE_SCRATCH,&value)==CUE_BOUNDED_OK;
        if (ok) ok=part?admission_matches(value,slot):payload_matches(value,slot);
        noun_tx_abort(); heap_scratch_reset();
        if (!ok) return 0;
    }
    return 1;
}
static int m52_envelope(noun input,noun packages[4],noun *script,uint32_t *count,
                        uint32_t *mode,noun *transport_binding) {
    noun tag,body,f[3];
    if (!pair(input,&tag,&body)) return 0;
    *mode=text_is(tag,"m52-resident-boot-v1")?1:0;
#if defined(M44_G0_TEST_CONTROLS)
    if (text_is(tag,"m52-driver-test-v1")) *mode=2;
#endif
    return *mode && record(body,f,3) && list(f[0],packages,4,count) && *count &&
        ((*script=f[1]),(*transport_binding=f[2]),1);
}
static int m52_package_read(uint32_t index,uint8_t compatibility[32]) {
    noun input,packages[4],script,entry[3],tag,body,f[3],catalog[2],parts[2],transport_binding;
    uint32_t count,version,mode; uint8_t identity[32],supplied[32];
    const uint8_t *base=(const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes=0;
    for (uint32_t i=0;i<8;i++) bytes|=(uint64_t)base[i]<<(i*8u);
    if (!bytes || bytes>1024u*1024u || !index || index>package_count) return 0;
    int ok=cue_bounded_bytes(base+16,bytes,&cue_i2_limits,HEAP_MODE_SCRATCH,&input)==CUE_BOUNDED_OK;
    if (ok) ok=m52_envelope(input,packages,&script,&count,&mode,&transport_binding) && count==package_count &&
        record(packages[index-1],entry,3) && pair(entry[0],&tag,&body) &&
        text_is(tag,"m52-compatible-controller-package-v1") && record(body,f,3) &&
        scalar(f[0],1,&version) && version==1 && digest(f[2],compatibility) &&
        hash_noun(entry[0],"1499kernel-m52-package-v1",1,identity) &&
        digest(entry[1],supplied) && same(identity,supplied,32) &&
        same(identity,package_identity[index-1],32) &&
        hash_noun(f[1],"1499kernel-m51-resident-controller-deployment-v1",1,supplied);
    if (ok) {
        for (uint32_t i=0;i<sizeof(descriptor);i++) ((uint8_t *)&descriptor)[i]=0;
        ok=m51_descriptor_read(f[1],cord_from_bytes((const char *)supplied,32)) &&
            record(entry[2],catalog,2);
    }
    for (uint32_t i=0;ok && i<2;i++) {
        ok=record(catalog[i],parts,2);
        for (uint32_t p=0;ok && p<2;p++)
            ok=atom_copy(parts[p],m44_boot_catalog_storage(i,p),MAX_JAM,&catalog_bytes[i][p]);
    }
    noun_tx_abort(); heap_scratch_reset(); return ok;
}
static M44Status m52_local_replace(void *unused,const M48LocalRequest *r,uint32_t holds) {
    (void)unused;
    /* M48 header translation: target carries deployment generation, and the
     * otherwise unused event carries the activation/cancel ticket. No IEC row
     * is admitted by this bridge. Validate the complete shape before LOAD. */
    if (!managed_replacement || !r || r->row.count || r->command<1 || r->command>3)
        return M44_INVALID;
    const uint32_t expected_generation=r->target,candidate_ticket=r->row.event;
    if (r->command==1) {
        if (candidate_ticket || !r->slot || r->slot>package_count ||
            same(package_identity[r->slot-1],package_identity[active_package-1],32)) return M44_INVALID;
        M44Status status=m52_supervisor_can_stage(expected_generation);
        if (status) return status;
        session=m46_supervisor_active_session();
        uint32_t bank=session==m44_boot_session_storage()?1:0,ticket=0;
        M46LoadedPackage candidate;
        status=m46_load(r->slot,bank,&candidate);
        if (status==M44_FENCED) {
            uart_puts("M44 terminal=refuse\r\n"); finish(); return status;
        }
        if (!status) status=m52_supervisor_stage(candidate.session,candidate.descriptor,
            candidate.handles,m47_bindings,m51_timer_bindings,&m51_completion,
            candidate.compatibility,expected_generation,&ticket);
        if (!status) staged_package=r->slot;
        else if (candidate.session && m46_resource_discard_unclaimed(candidate.session)) {
            /* No published state is reconstructed after private ownership corruption. */
            uart_puts("M44 terminal=refuse\r\n"); finish(); return M44_FENCED;
        }
        return status;
    }
    if (r->slot || !candidate_ticket) return M44_INVALID;
    M44Status status=r->command==2?
        m52_supervisor_activate(candidate_ticket,expected_generation,holds):
        m52_supervisor_cancel(candidate_ticket,expected_generation);
    if (!status) {
        if (r->command==2) active_package=staged_package;
        staged_package=0; session=m46_supervisor_active_session();
    }
    return status;
}
#if defined(M44_G0_TEST_CONTROLS)
static M44Status m52_test_command(const Command *c) {
    if (!managed_replacement) return M44_INVALID;
    if (c->op==48) {
        if (c->argument==4) return m45_supervisor_test_resource_control(1)==M38_STATUS_OK?M44_OK:M44_INVALID;
        if (c->argument>=10 && c->argument<=12) stage_fault=c->argument;
        else if (c->argument==1 || c->argument==2 || c->argument==3 || c->argument==5)
            m46_supervisor_test_fault(c->argument);
        else return M44_INVALID;
        return M44_OK;
    }
    if (c->op==49) { m46_supervisor_test_generation(c->argument); return M44_OK; }
    if (c->op==50) { m46_supervisor_test_ticket_serial(c->argument); return M44_OK; }
    if (c->op==51) return m44_supervisor_dispatch();
    if (c->op==52) {
        m49_fixture_ms=c->provider_token;
        return m49_supervisor_clock(c->epoch,m49_fixture_ms,m48_turns);
    }
    if (c->op==53) return m47_provider_enqueue(c->slot,c->epoch,&c->row);
    if (c->op==54) return m47_provider_claim(c->slot,c->epoch,c->provider_token);
    if (c->op==55) return m47_provider_receive_hold(c->slot,c->epoch,c->argument);
    return M44_INVALID;
}
#endif
static int m52_device_try_boot(noun input) {
    noun tag,body,packages[4],script,rows[MAX_COMMANDS],f[6],entry[3],transport_binding;
    uint32_t count,mode;
    if (!pair(input,&tag,&body) || (!text_is(tag,"m52-resident-boot-v1")
#if defined(M44_G0_TEST_CONTROLS)
        && !text_is(tag,"m52-driver-test-v1")
#endif
        )) return 0;
    if (!m52_envelope(input,packages,&script,&package_count,&mode,&transport_binding) ||
        !list(script,rows,MAX_COMMANDS,&count) || (mode==1 && count) ||
        !m47_transport_config(transport_binding)) goto invalid;
#if !defined(M44_G0_TEST_CONTROLS)
    if (mode!=1) goto invalid;
#endif
    for (uint32_t i=0;i<package_count;i++)
        if (!record(packages[i],entry,3) || !digest(entry[1],package_identity[i])) goto invalid;
    for (uint32_t i=0;i<count;i++) {
        Command *c=&commands[i];
        uint8_t token[8];
        if (!record(rows[i],f,6) || !scalar(f[0],55,&c->op) || !c->op ||
            !scalar(f[1],UINT32_MAX,&c->slot) || !typed_row(f[2],&c->row) ||
            !scalar(f[3],UINT32_MAX,&c->argument) || !scalar(f[4],UINT32_MAX,&c->epoch) ||
            !noun_atom_read_fixed(f[5],token,8) ||
            (!(c->op==40 || c->op==42 || c->op==43 || c->op==52) && token[7]>127)) goto invalid;
        c->provider_token=0;
        for (uint32_t j=0;j<8;j++) c->provider_token|=(uint64_t)token[j]<<(8*j);
        if (c->op>=45 && c->op<=47 && (c->row.event || c->row.count ||
            c->provider_token>UINT32_MAX || (c->op==45 && c->provider_token))) goto invalid;
    }
    noun_tx_abort(); heap_scratch_reset();
    managed_replacement=managed_services=managed_delay=managed_controller=1;
    if (m38_resource_runtime_init(m44_boot_control(),65536,m44_boot_workspace(),
        4u*1024u*1024u,&runtime)) goto invalid;
    M46LoadedPackage initial;
    if (m46_load(1,0,&initial) || m52_supervisor_init(initial.session,initial.descriptor,
        initial.handles,m47_bindings,m51_timer_bindings,&m51_completion,initial.compatibility)) goto invalid;
    session=initial.session; active_package=live_replacement=1; resident_mode=mode;
    size_t storage=m44_supervisor_storage_bytes()+sizeof(commands)+sizeof(descriptor)+sizeof(handles)+
        sizeof(catalog_bytes)+sizeof(runtime)+sizeof(session)+sizeof(expected_generation)+
        sizeof(expected_package)+sizeof(package_identity)+sizeof(m47_bindings)+
        sizeof(m51_timer_bindings)+sizeof(m51_completion)+m48_storage_bytes()+64;
    if (storage>768u*1024u) goto invalid;
    uart_puts("M44 setup=0\r\nM44 storage="); number(storage); uart_puts("\r\n");
    if (m48_run(mode,count)) return 1;
    goto failed;
invalid:
    uart_puts("M44 setup=1\r\n");
failed:
    uart_puts("M44 terminal=refuse\r\n"); finish(); return 1;
}
