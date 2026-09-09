/* Keep the disabled M56 translation unit identical to the retained M54 ABI.
 * The two explicit callers share the comparison only when signed replacement
 * is compiled in; the type is never supplied by package input. */
#if defined(M56_SIGNED_REPLACEMENT)
#define POLICY_TYPE_PARAMETER ,uint32_t value_type
#define POLICY_TYPE_ARGUMENT(type) ,type
#define POLICY_VALUE_TYPE value_type
#else
#define POLICY_TYPE_PARAMETER
#define POLICY_TYPE_ARGUMENT(type)
#define POLICY_VALUE_TYPE 2
#endif
/* Shared M54/M56 numeric compatibility with exactly one authorized RHS change.
 * The m54 helper names retain the original internal ABI; explicit validators
 * below select unsigned M54 or signed M56 without package-selected types.
 * Structural admission already bounded all lists. M46 pins non-algorithm
 * payload material; this pass pins every unselected assignment as well. */
static int m54_expression(noun expression,const M54Policy *p POLICY_TYPE_PARAMETER) {
    noun f[3]; uint32_t kind,type,value;
    return wave_record(expression,f,3) && wave_u(f[0],2,&kind) &&
        wave_u(f[1],POLICY_VALUE_TYPE,&type) && type==POLICY_VALUE_TYPE && wave_u(f[2],65535,&value) &&
        ((kind==1 && value==p->reference) || kind==2);
}
static int m54_body(noun a,noun b,const M54Policy *p POLICY_TYPE_PARAMETER) {
    noun ah,bh,af[2],bf[2]; uint32_t index=0,selected=0,targets=0;
    while (a!=NOUN_ZERO && b!=NOUN_ZERO) {
        if (!wave_pair(a,&ah,&a) || !wave_pair(b,&bh,&b) ||
            !wave_record(ah,af,2) || !wave_record(bh,bf,2)) return 0;
        index++;
        if (af[0]==direct(p->target)) targets++;
        if (index==p->assignment) {
            if (af[0]!=direct(p->target) || bf[0]!=direct(p->target) ||
                !m54_expression(af[1],p POLICY_TYPE_ARGUMENT(POLICY_VALUE_TYPE)) || !m54_expression(bf[1],p POLICY_TYPE_ARGUMENT(POLICY_VALUE_TYPE))) return 0;
            selected++;
        } else if (!noun_eq(ah,bh)) return 0;
    }
    return a==b && selected==1 && targets==1;
}
static int m54_values(noun values,const M54Policy *p POLICY_TYPE_PARAMETER) {
    noun head,f[4]; uint32_t found=0;
    if (!p->target || !p->reference || !p->failure || p->reference==p->failure) return 0;
    while (values!=NOUN_ZERO) {
        if (!wave_pair(values,&head,&values) || !wave_record(head,f,4)) return 0;
        if (f[0]==direct(p->target)) {
            if (f[1]!=direct(1) || f[2]!=direct(POLICY_VALUE_TYPE)) return 0;
            found|=1;
        }
        if (f[0]==direct(p->reference)) {
            if (f[1]!=direct(2) || f[2]!=direct(POLICY_VALUE_TYPE)) return 0;
            found|=2;
        }
        if (f[0]==direct(p->failure)) {
            if (f[1]!=direct(2) || f[2]!=direct(2) || f[3]!=NOUN_ZERO) return 0;
            found|=4;
        }
    }
    return found==7;
}
static int m54_payload_compatible(const WavePlan *a,const WavePlan *b,
                                  uint32_t slot,const M54Policy *p POLICY_TYPE_PARAMETER) {
    noun at,ab,bt,bb,af[2],bf[2],as[5],bs[5],types_a[8],types_b[8];
    uint32_t ac,bc,selected=0;
    if (!p || p->slot<1 || p->slot>2 || !p->instance || !p->type ||
        !p->algorithm || !p->assignment || !m46_payload_compatible(a->payload,b->payload) ||
        !wave_pair(a->payload,&at,&ab) || !wave_pair(b->payload,&bt,&bb) ||
        !wave_record(ab,af,2) || !wave_record(bb,bf,2) ||
        !wave_record(af[1],as,5) || !wave_record(bf[1],bs,5) ||
        !wave_list(as[0],types_a,8,&ac) || !wave_list(bs[0],types_b,8,&bc)) return 0;
    if (slot+1==p->slot) {
        if (p->instance>a->instance_count || a->instance_types[p->instance-1]!=p->type) return 0;
        uint32_t uses=0;
        for (uint32_t i=0;i<a->instance_count;i++) uses+=a->instance_types[i]==p->type;
        if (uses!=1) return 0;
    }
    for (uint32_t i=0;i<ac;i++) {
        noun ax[6],bx[6];
        if (!wave_record(types_a[i],ax,6) || !wave_record(types_b[i],bx,6)) return 0;
        if (slot+1!=p->slot || ax[0]!=direct(p->type)) {
            if (!noun_eq(ax[5],bx[5])) return 0;
            continue;
        }
        if (!m54_values(ax[2],p POLICY_TYPE_ARGUMENT(POLICY_VALUE_TYPE))) return 0;
        noun al=ax[5],bl=bx[5],ah,bh,ar[2],br[2];
        while (al!=NOUN_ZERO) {
            if (!wave_pair(al,&ah,&al) || !wave_pair(bl,&bh,&bl) ||
                !wave_record(ah,ar,2) || !wave_record(bh,br,2)) return 0;
            if (ar[0]==direct(p->algorithm)) {
                if (!m54_body(ar[1],br[1],p POLICY_TYPE_ARGUMENT(POLICY_VALUE_TYPE))) return 0;
                selected++;
            } else if (!noun_eq(ar[1],br[1])) return 0;
        }
    }
    return selected==(slot+1==p->slot?1u:0u);
}
M38Status m54_validate_replacement_pair(ResourceSession *old,ResourceSession *candidate,
                                       const void *owner,const M54Policy *p) {
    M38Status status=m46_validate_replacement_pair(old,candidate,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *a,*b;
        if (!wave_plan_for_slot(old,i,&a) || !wave_plan_for_slot(candidate,i,&b) ||
            !m54_payload_compatible(a,b,i,p POLICY_TYPE_ARGUMENT(2))) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}
M38Status m54_validate_controller_session(ResourceSession *session,const void *owner,
                                         const M54Policy *p) {
    M38Status status=m44_access(session,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *plan;
        if (!wave_plan_for_slot(session,i,&plan) ||
            !m54_payload_compatible(plan,plan,i,p POLICY_TYPE_ARGUMENT(2))) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}

#if defined(M56_SIGNED_REPLACEMENT)
/* Only this explicit authority admits signed target/reference values.
 * Literal atoms use M55 biased carriers; selector ordinals do not. */
M38Status m56_validate_replacement_pair(ResourceSession *old,ResourceSession *candidate,
                                       const void *owner,const M54Policy *p) {
    M38Status status=m46_validate_replacement_pair(old,candidate,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *a,*b;
        if (!wave_plan_for_slot(old,i,&a) || !wave_plan_for_slot(candidate,i,&b) ||
            !m54_payload_compatible(a,b,i,p POLICY_TYPE_ARGUMENT(3))) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}
M38Status m56_validate_controller_session(ResourceSession *session,const void *owner,
                                         const M54Policy *p) {
    M38Status status=m44_access(session,owner);
    if (status) return status;
    for (uint32_t i=0;i<2;i++) {
        WavePlan *plan;
        if (!wave_plan_for_slot(session,i,&plan) ||
            !m54_payload_compatible(plan,plan,i,p POLICY_TYPE_ARGUMENT(3))) return M38_STATUS_REQUEST_INVALID;
    }
    return M38_STATUS_OK;
}
#endif

#undef POLICY_TYPE_PARAMETER
#undef POLICY_TYPE_ARGUMENT
#undef POLICY_VALUE_TYPE
