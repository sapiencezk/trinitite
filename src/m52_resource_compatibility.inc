/* Fixed numeric M51 controller contract. No source-language interpreter. */
static int m52_healthy_expression(noun expression) {
    noun f[3]; uint32_t kind,type,value;
    return wave_record(expression,f,3) && wave_u(f[0],2,&kind) &&
        wave_u(f[1],2,&type) && type==2 && wave_u(f[2],65535,&value) &&
        ((kind==1 && value==9) || kind==2);
}
static int m52_healthy_body(noun a,noun b) {
    noun aa[3],bb[3],ax[2],bx[2];
    if (!wave_record(a,aa,3) || !wave_record(b,bb,3) ||
        !wave_record(aa[0],ax,2) || !wave_record(bb[0],bx,2) ||
        ax[0]!=direct(8) || bx[0]!=direct(8) ||
        !m52_healthy_expression(ax[1]) || !m52_healthy_expression(bx[1])) return 0;
    /* Both tails are pinned to BUSY:=1 and INFLIGHT_ALARM:=0, even when
     * comparing a boot package with itself. */
    for (uint32_t i=1;i<3;i++) {
        noun fields[2],rhs[3];
        if (!noun_eq(aa[i],bb[i]) || !wave_record(aa[i],fields,2) ||
            fields[0]!=direct(i==1?11:13) || !wave_record(fields[1],rhs,3) ||
            rhs[0]!=direct(2) || rhs[1]!=direct(2) || rhs[2]!=direct(i==1?1:0)) return 0;
    }
    return 1;
}
static int m52_payload_compatible(noun a,noun b,uint32_t slot) {
    noun at,ab,bt,bb,af[2],bf[2],as[5],bs[5],types_a[8],types_b[8];
    uint32_t ac,bc;
    if (!m46_payload_compatible(a,b) || !wave_pair(a,&at,&ab) ||
        !wave_pair(b,&bt,&bb) || !wave_record(ab,af,2) || !wave_record(bb,bf,2) ||
        !wave_record(af[1],as,5) || !wave_record(bf[1],bs,5) ||
        !wave_list(as[0],types_a,8,&ac) || !wave_list(bs[0],types_b,8,&bc)) return 0;
    uint32_t healthy=0;
    for (uint32_t i=0;i<ac;i++) {
        noun ax[6],bx[6];
        if (!wave_record(types_a[i],ax,6) || !wave_record(types_b[i],bx,6)) return 0;
        if (slot!=0 || i!=1) {
            if (!noun_eq(ax[5],bx[5])) return 0;
            continue;
        }
        noun al=ax[5],bl=bx[5],ah,bh,ar[2],br[2];
        while (al!=NOUN_ZERO) {
            if (!wave_pair(al,&ah,&al) || !wave_pair(bl,&bh,&bl) ||
                !wave_record(ah,ar,2) || !wave_record(bh,br,2)) return 0;
            if (ar[0]==direct(3)) {
                if (!m52_healthy_body(ar[1],br[1])) return 0;
                healthy++;
            } else if (!noun_eq(ar[1],br[1])) return 0;
        }
    }
    return slot==0 ? healthy==1 : healthy==0;
}
M38Status m52_validate_replacement_pair(ResourceSession *old,ResourceSession *candidate,
                                       const void *owner) {
    M38Status status=m46_validate_replacement_pair(old,candidate,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *a,*b;
        if (!wave_plan_for_slot(old,i,&a) || !wave_plan_for_slot(candidate,i,&b) ||
            (i==0 && (a->instance_count!=4 || a->instance_types[1]!=2)) ||
            !m52_payload_compatible(a->payload,b->payload,i)) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}
M38Status m52_validate_controller_session(ResourceSession *session,const void *owner) {
    M38Status status=m44_access(session,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *plan;
        if (!wave_plan_for_slot(session,i,&plan) ||
            (i==0 && (plan->instance_count!=4 || plan->instance_types[1]!=2)) ||
            !m52_payload_compatible(plan->payload,plan->payload,i)) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}
