/* Resident local driver. Boot source/catalog validation is shared with M47.
 * UART is trusted local ingress; no provider observation opcodes exist here. */
#if defined(M48_RESIDENT)
#include "m48_resident_driver.h"
#if defined(M52_RESIDENT_REPLACEMENT)
static M44Status m52_local_replace(void *,const M48LocalRequest *,uint32_t);
#if defined(M44_G0_TEST_CONTROLS)
static M44Status m52_test_command(const Command *);
#endif
#endif
static M48ResidentDriver m48_driver;
static uint8_t m48_input[232];
static uint32_t m48_input_used, m48_input_wanted;
static uint64_t m48_turns;
static uint64_t m48_input_last, m48_frequency;
static uint32_t m48_input_refusals;
#if defined(M52_RESIDENT_REPLACEMENT)
static M48LocalRequest m52_pending_request;
static uint32_t m52_pending_valid,m52_pending_id;
#endif
static uint64_t m48_counter(void) {
    uint64_t value; __asm__ volatile("mrs %0, cntvct_el0":"=r"(value)); return value;
}
#if defined(M49_MANAGED_DELAY)
#include "m49_clock_adapter.h"
static uint64_t m49_clock_turn;
#if defined(M44_G0_TEST_CONTROLS)
static uint64_t m49_fixture_ms;
static uint32_t m49_fixture_dispatch_fault;
static M44Status m49_fake_before_dispatch(void *unused) {
    (void)unused;
    const M44State *state=m44_supervisor_state();
    M44Status status=state ? m49_supervisor_clock(state->epoch,m49_fixture_ms,m48_turns) : M44_INVALID;
    state=m44_supervisor_state();
    /* G0 only: fail publication after local/provider/clock admission so the
     * probe reaches the actual IEC ARM/CANCEL transaction. */
    if (m49_fixture_dispatch_fault && state && state->lifecycle==1 &&
        (state->counts[0] || state->counts[1]) &&
        (status==M44_OK || status==M44_NO_WORK || status==M44_FULL)) {
        m44_supervisor_test_fault(m49_fixture_dispatch_fault,0);
        m49_fixture_dispatch_fault=0;
    }
    return status;
}
#endif
static M44Status m49_before_dispatch(void *unused) {
    (void)unused;
    uint64_t ticks=m48_counter();
    uint64_t now;
    if (!m49_clock_milliseconds(ticks,m48_frequency,&now)) return M44_INVALID;
    const M44State *state=m44_supervisor_state();
    if (!state || m49_clock_turn==UINT64_MAX) return M44_INVALID;
    return m49_supervisor_clock(state->epoch,now,++m49_clock_turn);
}
#endif
static uint32_t m48_word(uint32_t offset) {
    uint32_t value=0;
    for (uint32_t i=0;i<4;i++) value|=(uint32_t)m48_input[offset+i]<<(8*i);
    return value;
}
/* Header M48! + uint32 body bytes. Body is eight uint32 fields:
 * request-id, kind, epoch, slot, command, target, event, value-count;
 * followed by value-count triples (id,type,raw), all little endian.
 * At most 32 UART bytes and one complete request are consumed per turn. */
static int m48_local_read(M48LocalRequest *request,uint32_t *id) {
    static const uint8_t magic[4]={'M','4','8','!'};
    uint8_t ch;
    uint64_t now=m48_counter();
    if (m48_input_used && now-m48_input_last>=m48_frequency) {
        m48_input_used=0; if (m48_input_refusals!=UINT32_MAX) m48_input_refusals++;
    }
    for (uint32_t budget=0;budget<32 && uart_getc_nb(&ch);budget++) {
        m48_input_last=now;
        if (m48_input_used<4) {
            if (ch==magic[m48_input_used]) m48_input[m48_input_used++]=ch;
            else m48_input_used=ch==magic[0]?1:0;
            continue;
        }
        m48_input[m48_input_used++]=ch;
        if (m48_input_used==8) {
            uint32_t size=m48_word(4);
            if (size<32 || size>224 || (size&3)) {
                m48_input_used=0;
                if (m48_input_refusals!=UINT32_MAX) m48_input_refusals++;
                continue;
            }
            m48_input_wanted=size+8;
        }
        if (m48_input_used<8 || m48_input_used!=m48_input_wanted) continue;
        *request=(M48LocalRequest){0};
        *id=m48_word(8); request->kind=(M48LocalKind)m48_word(12);
        request->epoch=m48_word(16); request->slot=m48_word(20);
        request->command=m48_word(24); request->target=m48_word(28);
        request->row.event=m48_word(32); request->row.count=m48_word(36);
        if (request->row.count>16 || m48_input_wanted!=40+12*request->row.count ||
            request->kind<1 || request->kind>
#if defined(M52_RESIDENT_REPLACEMENT)
            (managed_replacement?4:3)
#else
            3
#endif
            ) request->kind=(M48LocalKind)99;
        else for (uint32_t i=0;i<request->row.count;i++) {
            request->row.values[i]=(M44Value){m48_word(40+12*i),m48_word(44+12*i),m48_word(48+12*i)};
        }
        if ((request->kind==M48_LOCAL_MANAGE && (request->slot || request->row.event || request->row.count)) ||
            (request->kind==M48_LOCAL_RELEASE && (request->command || request->target || request->row.event || request->row.count)) ||
            (request->kind==M48_LOCAL_INGRESS && (request->command || request->target))) request->kind=(M48LocalKind)99;
        m48_input_used=0; return 1;
    }
    return 0;
}
static int m48_emit(uint32_t index,uint32_t request,const M48TurnResult *r) {
    const uint32_t stages[]={r->local,r->completion_poll,r->receive_poll,
        r->completion_admit,r->receive_admit,r->response_admit,r->dispatch,r->claim,r->submit};
    uart_puts("M48 {\"row\":"); number(index); uart_puts(",\"request\":"); number(request);
    uart_puts(",\"turn\":"); number(m48_turns); uart_puts(",\"stages\":[");
    for (uint32_t i=0;i<9;i++) { if (i) uart_putc(','); number(stages[i]); }
    uart_puts("],\"driver\":[");
    const uint64_t held[]={m48_driver.rx_valid,m48_driver.rx_epoch,m48_driver.rx_token,m48_driver.rx_value,
        m48_driver.tx_valid,m48_driver.tx_observed,m48_driver.tx_epoch,m48_driver.tx_token,m48_driver.tx_value};
    for (uint32_t i=0;i<9;i++) { if (i) uart_putc(','); number(held[i]); }
    uart_puts("],\"memory\":["); number(heap_cells_used(HEAP_MODE_PERSIST)); uart_putc(',');
    number(heap_cells_used(HEAP_MODE_SCRATCH)); uart_putc(','); number(atom_store_bytes_used());

#if defined(M49_MANAGED_DELAY)
    if (managed_delay) { uart_puts("],\"clock\":"); number(m48_driver.before_dispatch_status); uart_puts(",\"input_refusals\":"); }
    else
#endif
    { uart_puts("],\"input_refusals\":"); }
    number(m48_input_refusals);
#if defined(M52_RESIDENT_REPLACEMENT)
    if (managed_replacement
#if defined(M53_RESIDENT_COMPOSITION)
        || managed_composition
#endif
        ) {
        M46ResourceDiagnostics diagnostics={0};
        (void)m46_supervisor_diagnostics(&diagnostics);
        uart_puts(",\"registered_sessions\":"); number(diagnostics.registered_sessions);
        uart_puts(",\"issued_capability\":"); number(diagnostics.issued_capability);
#if defined(M44_G0_TEST_CONTROLS)
        uart_puts(",\"replacement_busy_mask\":"); number(m46_supervisor_test_busy_mask());
#endif
    }
#endif
#if defined(M51_CONTROLLER)
    if (managed_controller) { uart_puts(",\"completion_status\":");number(m48_driver.tx_status); }
#endif
    uart_puts("}\r\n");
    return emit(index,r->local==M48_SKIPPED?0:r->local,0);
}
#if defined(M44_G0_TEST_CONTROLS)
/* Only the separate qualification boot tag supplies external observations.
 * The driver and canonical supervisor/evaluator are the actual native code. */
typedef struct { uint32_t rx,rx_epoch,rx_value,completion,completion_epoch,completion_value,
    refuse_submit,physical_pending; uint64_t rx_token,completion_token; } M48Fixture;
static M48Fixture m48_fixture;
#if defined(M51_CONTROLLER)
static uint32_t m51_fixture_completion_status;
#endif
static M48IOStatus m48_fake_rx(void *ctx,uint32_t epoch,uint64_t *token,uint32_t *value) {
    M48Fixture *f=ctx; if (!f->rx) return M48_EMPTY;
    f->rx=0; if (epoch!=f->rx_epoch) return M48_REFUSED;
    *token=f->rx_token; *value=f->rx_value; return M48_READY;
}
static M48IOStatus m48_fake_completion(void *ctx,uint32_t epoch,uint64_t token,uint32_t value) {
    M48Fixture *f=ctx; if (!f->completion) return M48_EMPTY;
    f->completion=0;
    if (epoch!=f->completion_epoch || token!=f->completion_token || value!=f->completion_value) return M48_REFUSED;
    f->physical_pending=0; return M48_READY;
}
#if defined(M51_CONTROLLER)
static M48IOStatus m51_fake_completion(void *ctx,uint32_t epoch,uint64_t token,uint32_t value,uint32_t *status) {
    M48IOStatus result=m48_fake_completion(ctx,epoch,token,value);
    if (result==M48_READY) *status=m51_fixture_completion_status;
    return result;
}
#endif
static M48IOStatus m48_fake_submit(void *ctx,uint32_t epoch,uint64_t token,uint32_t value) {
    M48Fixture *f=ctx; (void)epoch; (void)token; (void)value;
    if (f->refuse_submit) return M48_REFUSED;
    f->physical_pending=1; return M48_READY;
}
static M48IOStatus m48_fake_release(void *ctx) {
    return ((M48Fixture *)ctx)->physical_pending?M48_REFUSED:M48_READY;
}
static int m48_qualified_run(uint32_t count,uint32_t blocked) {
    M48Adapter adapter={.context=&m48_fixture,.receive=m48_fake_rx,.completion=m48_fake_completion,
        .submit=m48_fake_submit,.release_ready=m48_fake_release};
#if defined(M51_CONTROLLER)
    if (managed_controller) adapter.completion_result=m51_fake_completion;
#endif
    if (m48_resident_init(&m48_driver,m47_bindings,&adapter)!=M44_OK) return 0;
#if defined(M52_RESIDENT_REPLACEMENT)
    if (managed_replacement) m48_driver.replacement=m52_local_replace;
#endif
#if defined(M49_MANAGED_DELAY)
    if (managed_delay) m48_driver.before_dispatch=m49_fake_before_dispatch;
#endif
    M48TurnResult empty={M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,
        M48_SKIPPED,M48_SKIPPED,M48_SKIPPED,M48_SKIPPED};
    if (blocked && !m48_report_begin()) return 0;
    if (!m48_emit(0,0,&empty)) return 0;
    if (blocked) {
        if (!m48_report_end()) return 0;
        uart_test_tx_stuck(1);
        if (m48_report_drain()!=0 || m48_report_idle()) return 0;
    }
    M48TurnResult last=empty;
    for (uint32_t i=0;i<count;i++) {
        const Command *c=&commands[i]; M48LocalRequest request={0};
        request.epoch=c->epoch; request.slot=c->slot; request.row=c->row;
#if defined(M52_RESIDENT_REPLACEMENT)
        if (managed_replacement && c->op>=48) {
            m48_turns++;
            M48TurnResult result=empty;
            result.local=m52_test_command(c);
            m48_driver.before_dispatch_status=M48_SKIPPED;
            if (!m48_emit(i+1,i+1,&result)) return 0;
            continue;
        }
        if (managed_replacement && c->op>=45 && c->op<=47) {
            request.kind=M52_LOCAL_REPLACEMENT;
            request.command=c->op-44; request.target=c->argument;
            request.row.event=(uint32_t)c->provider_token;
        } else
#endif
        if (c->op==1) request.kind=M48_LOCAL_INGRESS;
        else if (c->op==17) { request.kind=M48_LOCAL_MANAGE; request.command=c->argument; request.target=c->slot; }
        else if (c->op==36) request.kind=M48_LOCAL_RELEASE;
        else if (c->op==30 || c->op==34) {
            if (c->op==34) {
                for (uint32_t j=0;j<M44_FIFO_CAPACITY;j++)
                    if (m44_supervisor_enqueue(c->slot,&c->row)!=M44_OK) return 0;
            }
            if (m48_fixture.rx) return 0;
            m48_fixture.rx=1; m48_fixture.rx_epoch=c->epoch;
            m48_fixture.rx_token=c->provider_token; m48_fixture.rx_value=c->argument;
        } else if (c->op==31
#if defined(M51_CONTROLLER)
                   || (managed_controller && c->op==44)
#endif
        ) {
#if defined(M51_CONTROLLER)
            m51_fixture_completion_status=c->op==44?c->slot:0;
#endif
            if (m48_fixture.completion) return 0;
            m48_fixture.completion=1; m48_fixture.completion_epoch=c->epoch;
            m48_fixture.completion_token=c->provider_token; m48_fixture.completion_value=c->argument;
        } else if (c->op==37 && c->argument<=1) m48_fixture.refuse_submit=c->argument;
        else if (c->op==5) m44_supervisor_test_fault(c->slot,c->argument);
        else if (c->op==6 && c->argument<=16) {
            for (uint32_t j=0;j<c->argument;j++) if (m44_supervisor_enqueue(c->slot,&c->row)!=M44_OK) return 0;
        }
#if defined(M49_MANAGED_DELAY)
        else if (managed_delay && c->op==40) m49_fixture_ms=c->provider_token;
        else if (managed_delay && c->op==41 && c->argument>=1 && c->argument<=2) m49_fixture_dispatch_fault=c->argument;
        /* G0 external facts sharing one boundary: a local request or bounded
         * queue prefill arrives with this turn's clock sample. */
        else if (managed_delay && c->op==42 && c->argument==0) {
            m49_fixture_ms=c->provider_token; request.kind=M48_LOCAL_INGRESS;
        } else if (managed_delay && c->op==43 && c->argument<=16) {
            for (uint32_t j=0;j<c->argument;j++)
                if (m44_supervisor_enqueue(c->slot,&c->row)!=M44_OK) return 0;
            m49_fixture_ms=c->provider_token;
        }
#endif
        else if (c->op!=2) return 0;
        m48_turns++;
        M48TurnResult result=m48_resident_turn(&m48_driver,request.kind?&request:0);
        if (blocked) {
            if (m48_report_drain()!=0 || m48_report_idle()) return 0;
            last=result;
        } else if (!m48_emit(i+1,i+1,&result)) return 0;
    }
    if (blocked) {
        uart_test_tx_stuck(0);
        for (uint32_t i=0;i<M48_REPORT_CAPACITY && !m48_report_idle();i++) m48_report_drain();
        if (!m48_report_idle() || !m48_emit(1,1,&last)) return 0;
        uart_puts("M48 backpressure=pass\r\n");
    }
    uart_puts("M44 terminal=complete\r\n"); finish(); return 1;
}
#endif
static size_t m48_storage_bytes(void) {
    return sizeof(m48_driver)+sizeof(m48_input)+sizeof(m48_input_used)+sizeof(m48_input_wanted)+sizeof(m48_turns)
        +sizeof(m48_input_last)+sizeof(m48_frequency)+sizeof(m48_input_refusals)+M48_REPORT_CAPACITY+32
#if defined(M52_RESIDENT_REPLACEMENT)
        +sizeof(m52_pending_request)+sizeof(m52_pending_valid)+sizeof(m52_pending_id)
#endif
#if defined(M44_G0_TEST_CONTROLS)
        +sizeof(m48_fixture)
#if defined(M49_MANAGED_DELAY)
        +sizeof(m49_fixture_ms)+sizeof(m49_fixture_dispatch_fault)
#endif
#endif
#if defined(M49_MANAGED_DELAY)
        +sizeof(m49_clock_turn)
#endif
        ;
}
static int m48_run(uint32_t mode,uint32_t count) {
#if defined(M44_G0_TEST_CONTROLS)
    if (mode>=2) return m48_qualified_run(count,mode==3);
#else
    (void)mode; (void)count;
#endif
    M48Adapter adapter;
    if (!m48_transport_init(&adapter) || m48_resident_init(&m48_driver,m47_bindings,&adapter)!=M44_OK) return 0;
#if defined(M52_RESIDENT_REPLACEMENT)
    if (managed_replacement) m48_driver.replacement=m52_local_replace;
#endif
    __asm__ volatile("mrs %0, cntfrq_el0":"=r"(m48_frequency));
    if (!m48_frequency || !m48_report_begin()) return 0;
#if defined(M49_MANAGED_DELAY)
    if (managed_delay) {
        if (m48_frequency>UINT64_MAX/1000u) return 0;
        m48_driver.before_dispatch=m49_before_dispatch;
    }
#endif
#if defined(M49_MANAGED_DELAY)
#if defined(M50_PERIODIC)
#if defined(M51_CONTROLLER)
#if defined(M53_RESIDENT_COMPOSITION)
#if defined(M54_RESIDENT_REPLACEMENT)
#if defined(M56_SIGNED_REPLACEMENT)
    if (managed_replacement==3) uart_puts("M56 resident=ready\r\n");
    else
#endif
#if defined(M55_SIGNED_RESIDENT)
    if (managed_signed_resident) uart_puts("M55 resident=ready\r\n");
    else
#endif
    if (managed_replacement==2) uart_puts("M54 resident=ready\r\n");
    else
#endif
    if (managed_composition) uart_puts("M53 resident=ready\r\n");
    else
#endif
#if defined(M52_RESIDENT_REPLACEMENT)
    if (managed_replacement) uart_puts("M52 resident=ready\r\n");
    else
#endif
    if (managed_controller) uart_puts("M51 resident=ready\r\n");
    else
#endif
    if (managed_cycle) uart_puts("M50 resident=ready\r\n");
    else
#endif
    if (managed_delay) uart_puts("M49 resident=ready\r\n");
    else
#endif
    uart_puts("M48 resident=ready\r\n");
    uint32_t index=0,dirty=0;
    if (!emit(index,0,0)) return 0;
    if (!m48_report_end()) return 0;
    for (;;) {
        M48LocalRequest request; uint32_t id=0;
        m48_report_drain();
        /* A pending response applies backpressure to the local request path;
         * provider and IEC progress below remains independent of serial TX. */
        int input;
#if defined(M52_RESIDENT_REPLACEMENT)
        if (managed_replacement
#if defined(M53_RESIDENT_COMPOSITION)
            || managed_composition
#endif
            ) {
            /* Collect one bounded request even while telemetry drains. Its
             * execution still waits for report capacity and rechecks authority. */
            if (!m52_pending_valid)
                m52_pending_valid=m48_local_read(&m52_pending_request,&m52_pending_id);
            input=m52_pending_valid && m48_report_idle();
            if (input) {
                request=m52_pending_request; id=m52_pending_id; m52_pending_valid=0;
            }
        } else
#endif
        input=m48_report_idle()?m48_local_read(&request,&id):0;
        if (m48_turns!=UINT64_MAX) m48_turns++;
        M48TurnResult result=m48_resident_turn(&m48_driver,input?&request:0);
        int progress=input || result.dispatch==M44_OK || result.dispatch==M44_RETIRED ||
            result.completion_admit==M44_OK || result.receive_admit==M44_OK ||
            result.response_admit==M44_OK || result.claim==M44_OK;
#if defined(M49_MANAGED_DELAY)
        progress |= managed_delay && m48_driver.before_dispatch_status==M44_OK;
#endif
        dirty |= progress;
        if (dirty && m48_report_idle()) {
            if (index!=UINT32_MAX) index++;
            if (!m48_report_begin() || !m48_emit(index,id,&result)) return 0;
            if (!m48_report_end()) {
                if (!m48_report_begin()) return 0;
                uart_puts("M48 report=overflow\r\n");
                if (!m48_report_end()) return 0;
            }
            dirty=0;
        }
    }
}
#endif
