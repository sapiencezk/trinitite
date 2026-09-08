/* Test-only generic transaction probe; all cross-operation nouns are Jam copies. */
#include <stdint.h>
#include <stddef.h>
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "noun.h"
#include "uart.h"
#include "m38_resource_runtime.h"
#include "m44_resource_transaction.h"
#include "m44_g0_witness.h"
#include "m39_resource_witness.h"
#define MAX_JAM (128u * 1024u)
#define MAX_ARGUMENT 4096u
#define MAX_COMMANDS 176u
typedef struct { uint32_t bytes; uint8_t jam[MAX_ARGUMENT]; } Saved;
typedef struct { uint32_t op, slot, mode, value; Saved arg; } Command;
static uint8_t catalog_jams[2][2][MAX_JAM];
static uint32_t catalog_bytes[2][2];
static Command commands[MAX_COMMANDS];
static Saved handles[2], snapshots[2], previous_snapshots[2];
typedef struct { uint32_t sequence, value; } QueueMetadata;
static QueueMetadata committed, staged;
static ResourceRuntime *runtime;
static ResourceSession *session;
static const char owner;
static uint32_t prepares, commits, mode, next_value, nested_public, nested_private, metadata_only;
static size_t length(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static noun cord(const char *s) { return cord_from_bytes(s, length(s)); }
static int pair(noun n, noun *a, noun *b) {
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n); *a = c->head; *b = c->tail; return 1;
}
static int record(noun n, noun *out, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) if (!pair(n, &out[i], &n)) return 0;
    return n == NOUN_ZERO;
}
static int list(noun n, noun *out, uint32_t max, uint32_t *count) {
    *count = 0;
    while (n != NOUN_ZERO) {
        if (*count == max || !pair(n, &out[*count], &n)) return 0;
        (*count)++;
    }
    return 1;
}
static int scalar(noun n, uint32_t max, uint32_t *out) {
    if (!noun_is_direct(n) || direct_val(n) > max) return 0;
    *out = direct_val(n); return 1;
}
static int build(const noun *values, uint32_t count, noun *out) {
    *out = NOUN_ZERO;
    while (count) if (!alloc_cell_checked(values[--count], *out, out)) return 0;
    return 1;
}
static int tagged(const char *tag, const char *schema, const noun *values, uint32_t count, noun *out) {
    noun row[17], body;
    if (count > 16) return 0;
    row[0] = cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1u] = values[i];
    return build(row, count + 1u, &body) && alloc_cell_checked(cord(tag), body, out);
}
static int tagged_fields(noun value, const char *tag, const char *schema, noun *out, uint32_t count) {
    noun got_tag, body, rows[17];
    uint8_t bytes[128] = {0};
    if (count > 16 || !pair(value, &got_tag, &body)
        || !noun_atom_read_fixed(got_tag, bytes, sizeof(bytes))) return 0;
    for (uint32_t i = 0; i < sizeof(bytes); i++)
        if (bytes[i] != (i < length(tag) ? (uint8_t)tag[i] : 0)) return 0;
    if (!record(body, rows, count + 1u) || !noun_atom_read_fixed(rows[0], bytes, sizeof(bytes))) return 0;
    for (uint32_t i = 0; i < sizeof(bytes); i++)
        if (bytes[i] != (i < length(schema) ? (uint8_t)schema[i] : 0)) return 0;
    for (uint32_t i = 0; i < count; i++) out[i] = rows[i + 1u];
    return 1;
}
static int atom_copy(noun n, uint8_t *out, uint32_t max, uint32_t *bytes) {
    uint32_t size = 0;
    if (noun_is_direct(n)) {
        uint64_t value = direct_val(n);
        do { size++; value >>= 8; } while (value);
    } else if (noun_is_indirect(n)) {
        atom_t *a = atom_store_get(indirect_hash(n));
        if (!a || !a->size || a->size > max / 8u) return 0;
        uint64_t last = a->limbs[a->size - 1u];
        uint32_t top = 8;
        while (top > 1 && !(last >> ((top - 1u) * 8u))) top--;
        size = (a->size - 1u) * 8u + top;
    } else return 0;
    if (size > max || !noun_atom_read_fixed(n, out, size)) return 0;
    *bytes = size; return 1;
}
static int decode(const uint8_t *bytes, uint32_t size, noun *out) {
    if (!size || cue_bounded_bytes(bytes, size, &cue_i2_limits,
                                   HEAP_MODE_PERSIST, out) != CUE_BOUNDED_OK) return 0;
    noun_tx_commit(); return 1;
}
static int save(noun value, Saved *out) {
    const uint8_t *bytes; uint64_t size;
    jam_admission_budget_t budget; jam_admission_budget_init(&budget, 2000000);
    if (jam_encode_bytes_identity_bounded(value, &bytes, &size, &budget) || size > MAX_ARGUMENT) return 0;
    for (uint32_t i = 0; i < size; i++) out->jam[i] = bytes[i];
    out->bytes = size; return 1;
}
static void number(uint64_t n) {
    char buf[21]; uint32_t used = 0;
    do { buf[used++] = '0' + n % 10; n /= 10; } while (n);
    while (used) uart_putc(buf[--used]);
}
static int prepare(void *context, noun result) {
    (void)context;
    /* Validate staged output while borrowed, retaining only fixed-width metadata. */
    if (metadata_only ? result != NOUN_ZERO : !noun_is_cell(result)) return 0;
    prepares++;
    staged = (QueueMetadata){committed.sequence + 1u, next_value};
    if (mode == 2) {
        const ResourceResultView *v = 0;
        nested_public = m38_resource_session_dispatch(session, NOUN_ZERO, &v);
        nested_private = m44_resource_dispatch(session, &owner, NOUN_ZERO, 0, &v);
    }
    if (mode >= 3) m44_resource_test_fail_publication(session, mode - 2u);
    return mode != 1;
}
static void commit(void *context) { (void)context; committed = staged; commits++; }
static void finish(void) {
    register uint64_t function __asm__("x0") = 0x84000008;
    __asm__ volatile("hvc #0" : "+r"(function) : : "memory");
    for (;;) __asm__ volatile("wfe");
}
static int emit(uint32_t row, M38Status status, const ResourceResultView *view) {
    uart_puts("M44G0 row="); number(row); uart_puts(" status="); number(status);
    uart_puts(" wire="); number(view ? view->wire_status : 0);
    uart_puts(" prepares="); number(prepares); uart_puts(" commits="); number(commits);
    uart_puts(" sequence="); number(committed.sequence); uart_puts(" value="); number(committed.value);
    uart_puts(" nested_public="); number(nested_public); uart_puts(" nested_private="); number(nested_private);
    uart_puts(" jam=");
    if (view) {
        Saved saved;
        if (!save(*view->root_slot, &saved)) return 0;
        const char *hex = "0123456789abcdef";
        for (uint32_t i=0;i<saved.bytes;i++) { uart_putc(hex[saved.jam[i] >> 4]); uart_putc(hex[saved.jam[i] & 15]); }
    } else uart_puts("none");
    uart_puts("\r\n"); return 1;
}
int m44_g0_try_boot(noun input) {
    noun tag, body, envelope[2], rows[MAX_COMMANDS], fields[5];
    uint8_t tag_bytes[32]; uint32_t count;
    if (!pair(input, &tag, &body) || !noun_atom_read_fixed(tag, tag_bytes, sizeof(tag_bytes))) return 0;
    const char *name = "m44-g0-v1";
    for (uint32_t i=0;i<sizeof(tag_bytes);i++) if (tag_bytes[i] != (i<length(name)?name[i]:0)) return 0;
    if (!record(body,envelope,2) || !record(envelope[0],rows,2)) goto fail;
    for (uint32_t i=0;i<2;i++) {
        if (!record(rows[i],fields,2)) goto fail;
        for(uint32_t j=0;j<2;j++) if(!atom_copy(fields[j],catalog_jams[i][j],MAX_JAM,&catalog_bytes[i][j])) goto fail;
    }
    if(!list(envelope[1],rows,MAX_COMMANDS,&count)) goto fail;
    for(uint32_t i=0;i<count;i++) {
        Command *c=&commands[i];
        if(!record(rows[i],fields,5) || !scalar(fields[0],14,&c->op) || !c->op
           || !scalar(fields[1],1,&c->slot) || !scalar(fields[3],4,&c->mode)
           || !scalar(fields[4],65535,&c->value) || !atom_copy(fields[2],c->arg.jam,MAX_ARGUMENT,&c->arg.bytes)) goto fail;
    }
    noun_tx_abort(); heap_scratch_reset();
    SupervisorAdmissionEntry entries[2]; SupervisorAdmissionCatalog catalog; SessionCapability capability;
    for(uint32_t i=0;i<2;i++) entries[i]=(SupervisorAdmissionEntry){catalog_jams[i][0],catalog_bytes[i][0],catalog_jams[i][1],catalog_bytes[i][1]};
    M38Status status=m38_supervisor_admission_catalog_make(&catalog,entries,2);
    if(!status) status=m38_resource_runtime_init(m44_boot_control(),65536,
        m44_boot_workspace(),4u*1024u*1024u,&runtime);
    if(!status) status=m38_resource_session_init(runtime,m44_boot_session_storage(),
        2u*1024u*1024u,&catalog,&session,&capability);
    uart_puts("M44G0 setup="); number(status); uart_puts("\r\n");
    if(status) goto fail;
    for(uint32_t i=0;i<count;i++) {
        Command *c=&commands[i]; const ResourceResultView *view=0;
        noun argument, args, request, handle, hs[2], ss[2];
        heap_set_mode(HEAP_MODE_PERSIST);
        if(!decode(c->arg.jam,c->arg.bytes,&argument)) goto fail;
        mode=c->mode; next_value=c->value; metadata_only=c->op==11; nested_public=0; nested_private=0;
        M44PublicationHooks hooks={prepare,commit,0};
        if(c->op==6 || c->op==14) {
            for(uint32_t j=0;j<2;j++) if(!decode(handles[j].jam,handles[j].bytes,&hs[j])) goto fail;
            if(c->op==14) {
                uint32_t kind; noun fields[4];
                if(!scalar(argument,4,&kind) || !record(hs[1],fields,4)) goto fail;
                if(kind==1) hs[1]=NOUN_ZERO;
                else if(kind==2) hs[1]=hs[0];
                else {
                    fields[kind==3?2:0]=direct(999);
                    if(!build(fields,4,&hs[1])) goto fail;
                }
            }
            status=m44_resource_claim(session,&owner,hs);
        }
        else if(c->op==8) status=m38_resource_session_reset(runtime,session);
        else if(c->op==9) status=m38_resource_session_dispose(runtime,session);
        else if(c->op==11) status=m44_resource_publish(session,&owner,&hooks);
        else if(c->op==4 || c->op==5 || c->op==10 || c->op==12) {
            for(uint32_t j=0;j<2;j++) {
                if(!decode(handles[j].jam,handles[j].bytes,&hs[j])) goto fail;
                ss[j]=NOUN_ZERO;
                Saved *source=c->op==12?&previous_snapshots[j]:&snapshots[j];
                if(c->op!=4 && !decode(source->jam,source->bytes,&ss[j])) goto fail;
            }
            if(c->op==10) ss[1]=NOUN_ZERO;
            status=m44_resource_group(session,&owner,c->op!=4,hs,ss,&hooks,&view);
        } else {
            uint32_t operation=c->op==7?2:c->op==13?3:c->op;
            if(operation==1) {
                uint32_t index;
                if(!scalar(argument,1,&index) || !decode(catalog_jams[index][1],catalog_bytes[index][1],&args)) goto fail;
            } else {
                if(!decode(handles[c->slot].jam,handles[c->slot].bytes,&handle)) goto fail;
                noun af[2]={handle,argument}; if(!build(af,2,&args)) goto fail;
            }
            noun rf[2]={direct(operation),args};
            if(!tagged("m38-resource-abi-v1-request","m38-resource-abi-v1-request-schema-v1",rf,2,&request)) goto fail;
            status=(c->op==2 || c->op==3)?m44_resource_dispatch(session,&owner,request,&hooks,&view):m38_resource_session_dispatch(session,request,&view);
        }
        if(!emit(i,status,view)) goto fail;
        if(!status && view && c->op==1 && view->wire_status==1) {
            noun rf[2], loaded[2];
            if(!tagged_fields(*view->root_slot,"m38-resource-abi-v1-result","m38-resource-abi-v1-result-schema-v1",rf,2)
               || !record(rf[1],loaded,2) || !save(loaded[0],&handles[c->slot])) goto fail;
        }
        if(!status && view && c->op==4 && view->wire_status==4) {
            noun gt, gb, results[2], rf[2];
            if(!pair(*view->root_slot,&gt,&gb) || !record(gb,results,2)) goto fail;
            for(uint32_t j=0;j<2;j++) previous_snapshots[j]=snapshots[j];
            for(uint32_t j=0;j<2;j++) if(!tagged_fields(results[j],"m38-resource-abi-v1-result","m38-resource-abi-v1-result-schema-v1",rf,2)
                || !save(rf[1],&snapshots[j])) goto fail;
        }
    }
    uart_puts("M44G0 terminal=complete\r\n"); finish(); return 1;
fail:
    uart_puts("M44G0 terminal=refuse\r\n"); finish(); return 1;
}
