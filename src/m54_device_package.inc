/* Called by the shared resident catalog loader. The selected policy is copied
 * out of scratch and validated against the loaded payload before boot/stage. */
static int m54_package_read(uint32_t index,uint8_t compatibility[32]) {
    noun input,packages[4],script,entry[3],tag,body,f[4],catalog[2],parts[2],transport;
    noun selector[8]; uint32_t count,version,mode,fields[8];
    uint8_t identity[32],supplied[32];
    const uint8_t *base=(const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes=0;
    for (uint32_t i=0;i<8;i++) bytes|=(uint64_t)base[i]<<(i*8u);
    if (!bytes || bytes>1024u*1024u || !index || index>package_count) return 0;
    int ok=cue_bounded_bytes(base+16,bytes,&cue_i2_limits,HEAP_MODE_SCRATCH,&input)==CUE_BOUNDED_OK;
    if (ok) ok=m52_envelope(input,packages,&script,&count,&mode,&transport) && count==package_count &&
        record(packages[index-1],entry,3) && pair(entry[0],&tag,&body) &&
        text_is(tag,"m54-compatible-resident-package-v1") && record(body,f,4) &&
        scalar(f[0],1,&version) && version==1 && record(f[2],selector,8) &&
        digest(f[3],compatibility) && hash_noun(entry[0],"1499kernel-m54-package-v1",1,identity) &&
        digest(entry[1],supplied) && same(identity,supplied,32) &&
        same(identity,package_identity[index-1],32) &&
        hash_noun(f[1],"1499kernel-m53-resident-composition-deployment-v1",1,supplied);
    for (uint32_t i=0;ok && i<8;i++) ok=scalar(selector[i],65535,&fields[i]) && fields[i];
    if (ok) {
        for (uint32_t i=0;i<sizeof(descriptor);i++) ((uint8_t *)&descriptor)[i]=0;
        ok=m53_descriptor_read(f[1],cord_from_bytes((const char *)supplied,32)) &&
            record(entry[2],catalog,2);
    }
    for (uint32_t i=0;ok && i<2;i++) {
        ok=record(catalog[i],parts,2);
        for (uint32_t p=0;ok && p<2;p++)
            ok=atom_copy(parts[p],m44_boot_catalog_storage(i,p),MAX_JAM,&catalog_bytes[i][p]);
    }
    if (ok) resident_policy=(M54Policy){fields[0],fields[1],fields[2],fields[3],
                                      fields[4],fields[5],fields[6],fields[7]};
    noun_tx_abort(); heap_scratch_reset(); return ok;
}
