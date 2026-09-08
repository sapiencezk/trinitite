#include <stdint.h>
#include <stddef.h>
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "noun.h"
#include "uart.h"
#include "m38_resource_runtime.h"
#include "m39_resource_witness.h"
#if defined(M44_TWO_RESOURCE)
#include "m44_device_witness.h"
#endif
#if defined(M44_G0_TEST_CONTROLS)
#include "m44_g0_witness.h"
#endif
#include "m37_a_r_adapter.h"

/* Generic, test-only D8 supervisor. The image contains no IEC fixture, source
 * labels, accepted-core table, or formula selector. All catalog and command
 * bytes are copied out of the input noun before the first promotion. Handles
 * and snapshots cross operations only as external canonical Jam bytes. */
#define MAX_JAM (128u * 1024u)
#define MAX_COMMANDS 128u
#define MAX_ARGUMENT 4096u
typedef struct Command {
    uint32_t operation, handle, bytes;
    uint8_t argument[MAX_ARGUMENT];
} Command;
typedef struct Saved {
    uint32_t bytes;
    uint8_t jam[MAX_ARGUMENT];
} Saved;
static uint8_t control[64u * 1024u] __attribute__((aligned(64)));
static uint8_t workspace[4u * 1024u * 1024u] __attribute__((aligned(64)));
static uint8_t session_storage[2u * 1024u * 1024u] __attribute__((aligned(64)));
#if defined(M44_TWO_RESOURCE)
void *m44_boot_control(void) { return control; }
void *m44_boot_workspace(void) { return workspace; }
void *m44_boot_session_storage(void) { return session_storage; }
#endif
static uint8_t catalog_jams[2][2][MAX_JAM];
#if defined(M44_TWO_RESOURCE)
void *m44_boot_catalog_storage(uint32_t slot, uint32_t part) {
    return slot < 2 && part < 2 ? catalog_jams[slot][part] : 0;
}
#endif
static uint32_t catalog_bytes[2][2];
static Command commands[MAX_COMMANDS];
static Saved handles[8], snapshots[8];
/* A supervisor binding maps numeric typed effects to one transport channel.
 * It has no IEC type names or executable formula selection. */
static m37_a_r_transport_binding_t transport;
static uint32_t provider_enabled, provider_handle, intent_code, cause_code, release_code;
static uint32_t intent_ids[6], cause_ids[6], release_id;
static uint64_t pending_token, received_token;
static uint8_t pending_data[512];
static uint32_t pending_bytes, pending_value, completion_error, completion_observed;
static uint32_t local_descriptor[11];

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
static int provider_config(noun value) {
    if (value == NOUN_ZERO) return 1;
    noun config[5], b[16], mapping[4], ids[11];
    uint32_t scalars[6];
    if (!record(value, config, 5) || !record(config[0], b, 16) || !record(config[1], mapping, 4)) return 0;
    for (uint32_t i = 0; i < 6; i++) if (!scalar(b[i], 65535, &scalars[i]) || !scalars[i]) return 0;
    transport.local_device = scalars[0]; transport.peer_device = scalars[1];
    transport.role = scalars[2]; transport.channel = scalars[3];
    transport.local_port = scalars[4]; transport.peer_port = scalars[5];
    transport.profile = 2; transport.wire_major = 0; transport.wire_minor = 1;
    transport.key_id = 1; transport.epoch = 1; transport.max_payload = 512;
    transport.max_ops = 2000000; transport.max_cells = 128000;
    if (!noun_atom_read_fixed(b[6], transport.outbound_binding, 16)
        || !noun_atom_read_fixed(b[7], transport.inbound_binding, 16)
        || !noun_atom_read_fixed(b[8], transport.schema_digest, 32)
        || !noun_atom_read_fixed(b[9], transport.domain_digest, 32)
        || !noun_atom_read_fixed(b[10], transport.local_mac, 6)
        || !noun_atom_read_fixed(b[11], transport.peer_mac, 6)
        || !noun_atom_read_fixed(b[12], transport.local_ip, 16)
        || !noun_atom_read_fixed(b[13], transport.peer_ip, 16)
        || !scalar(mapping[0], 7, &provider_handle)
        || !scalar(mapping[1], 65535, &intent_code)
        || !scalar(mapping[2], 65535, &cause_code) || !cause_code
        || !scalar(mapping[3], 65535, &release_code) || !release_code
        || !scalar(config[4], 65535, &release_id) || !release_id) return 0;
    for (uint32_t j = 0; j < 2; j++) {
        if (!record(config[2 + j], ids, 6)) return 0;
        for (uint32_t i = 0; i < 6; i++)
            if (!scalar(ids[i], 65535, j ? &cause_ids[i] : &intent_ids[i])) return 0;
    }
    for (uint32_t j = 0; j < 2; j++) {
        if (!record(b[14 + j], ids, 11)) return 0;
        for (uint32_t i = 0; i < 11; i++) {
            uint32_t value;
            if (!scalar(ids[i], 65535, &value) || !value) return 0;
            if (j) transport.peer_descriptor[i] = value;
            else local_descriptor[i] = value;
        }
    }
    provider_enabled = 1; return 1;
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
static void provider_fact(const char *kind, uint64_t token, uint32_t status) {
    uart_puts("M39 provider="); uart_puts(kind); uart_puts(" token="); number(token);
    uart_puts(" status="); number(status); uart_puts("\r\n");
}
static int publication_build(uint32_t value) {
    noun fields[18] = {direct(1), cord("PUBLISH_1"), direct(4), direct(16), direct(0), direct(65535)};
    for (uint32_t i = 0; i < 11; i++) fields[6 + i] = direct(local_descriptor[i]);
    fields[17] = direct(value);
    noun body, publication;
    if (!build(fields, 18, &body) || !alloc_cell_checked(cord("m36-t-envelope-v1"), body, &publication)) return 0;
    const uint8_t *bytes; uint64_t size;
    jam_admission_budget_t budget; jam_admission_budget_init(&budget, 2000000);
    if (jam_encode_bytes_identity_bounded(publication, &bytes, &size, &budget) || size > sizeof(pending_data)) return 0;
    for (uint32_t i = 0; i < size; i++) pending_data[i] = bytes[i];
    pending_bytes = size; return 1;
}
static int publication_read(const m37_a_r_datagram_t *datagram, uint32_t *value) {
    noun publication, tag, body, fields[18];
    if (datagram->payload_len > 512 || !decode(datagram->payload, datagram->payload_len, &publication)
        || !pair(publication, &tag, &body) || !record(body, fields, 18)) return 0;
    uint8_t bytes[32] = {0};
    if (!noun_atom_read_fixed(tag, bytes, 32)) return 0;
    const char *text = "m36-t-envelope-v1";
    for (uint32_t i = 0; i < 32; i++) if (bytes[i] != (i < length(text) ? text[i] : 0)) return 0;
    if (!noun_atom_read_fixed(fields[1], bytes, 32)) return 0;
    text = "PUBLISH_1";
    for (uint32_t i = 0; i < 32; i++) if (bytes[i] != (i < length(text) ? text[i] : 0)) return 0;
    const uint32_t expected[6] = {1, 0, 4, 16, 0, 65535};
    for (uint32_t i = 0; i < 17; i++) {
        uint32_t got;
        if (i == 1) continue;
        if (!scalar(fields[i], 65535, &got)
            || got != (i < 6 ? expected[i] : transport.peer_descriptor[i - 6])) return 0;
    }
    if (!scalar(fields[17], 65535, value)) return 0;
    const uint8_t *canonical; uint64_t size;
    jam_admission_budget_t budget; jam_admission_budget_init(&budget, 2000000);
    if (jam_encode_bytes_identity_bounded(publication, &canonical, &size, &budget) || size != datagram->payload_len) return 0;
    for (uint32_t i = 0; i < size; i++) if (canonical[i] != datagram->payload[i]) return 0;
    return 1;
}
static int provider_effects(const ResourceResultView *view, uint32_t handle) {
    if (!provider_enabled || handle != provider_handle || !view || view->wire_status != 2) return 1;
    noun result[2], body[4], effect_list[1], effects[32]; uint32_t count;
    if (!tagged_fields(*view->root_slot, "m38-resource-abi-v1-result", "m38-resource-abi-v1-result-schema-v1", result, 2)
        || !record(result[1], body, 4)
        || !tagged_fields(body[1], "m38-resource-abi-v1-numeric-effects", "m38-resource-abi-v1-numeric-effects-schema-v1", effect_list, 1)
        || !list(effect_list[0], effects, 32, &count)) return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun effect[2], values[6], vf[3]; uint32_t code, raw[6], id, type;
        if (!tagged_fields(effects[i], "m38-resource-abi-v1-numeric-effect", "m38-resource-abi-v1-numeric-effect-schema-v1", effect, 2)
            || !scalar(effect[0], 65535, &code)) return 0;
        if (!intent_code || code != intent_code) continue;
        if (pending_token || !record(effect[1], values, 6)) return 0;
        for (uint32_t j = 0; j < 6; j++)
            if (!tagged_fields(values[j], "m38-resource-abi-v1-numeric-value", "m38-resource-abi-v1-numeric-value-schema-v1", vf, 3)
                || !scalar(vf[0], 65535, &id) || id != intent_ids[j]
                || !scalar(vf[1], 2, &type) || type != 2 || !scalar(vf[2], 65535, &raw[j])) return 0;
        if (raw[3] > 32767 || raw[5] > 2) return 0;
        uint64_t token = raw[0] | ((uint64_t)raw[1] << 16) | ((uint64_t)raw[2] << 32) | ((uint64_t)raw[3] << 48);
        if (!token) return 0;
        if (!publication_build(raw[4])) return 0;
        pending_token = token; pending_value = raw[4]; completion_observed = 0;
        m37_a_r_native_status_t status = m37_a_r_adapter_submit(&transport, pending_data, pending_bytes, token);
        provider_fact("submit", token, status);
        /* Even a failed/uncertain submit leaves the IEC intent pending. */
    }
    return 1;
}
static int provider_stimulus(uint32_t code, const uint32_t *ids, const uint32_t *raw, uint32_t count, noun *out) {
    noun values[6], value_list;
    if (count > 6) return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun fields[3] = {direct(ids[i]), direct(2), direct(raw[i])};
        if (!tagged("m38-resource-abi-v1-numeric-value", "m38-resource-abi-v1-numeric-value-schema-v1", fields, 3, &values[i])) return 0;
    }
    if (!build(values, count, &value_list)) return 0;
    noun fields[2] = {direct(code), value_list};
    return tagged("m38-resource-abi-v1-numeric-stimulus", "m38-resource-abi-v1-numeric-stimulus-schema-v1", fields, 2, out);
}
static uint64_t ticks(void) { uint64_t n; __asm__ volatile("mrs %0, cntpct_el0" : "=r"(n)); return n; }
/* Only these provider calls can manufacture a private input. Ordinary POKE
 * is checked separately and cannot address cause_code/release_code. A wait
 * is bounded at ten seconds; a zero wait is an immediate pending probe. */
static M38Status provider_input(uint32_t operation, noun argument, noun *out, uint64_t *token_out) {
    uint32_t option;
    if (!provider_enabled || !scalar(argument, 2, &option)) return M38_STATUS_REQUEST_INVALID;
    if (operation == 8) {
        if (!provider_stimulus(release_code, &release_id, &option, 1, out)) return M38_STATUS_INTERNAL;
        provider_fact("release-request", pending_token, option); return M38_STATUS_OK;
    }
    uint64_t frequency; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    uint64_t deadline = ticks() + frequency * 10u;
    m37_a_r_native_status_t status = M37_A_R_NATIVE_NO_PACKET;
    m37_a_r_datagram_t datagram = {0};
    do {
        if (operation == 6) {
            if (!pending_token) return M38_STATUS_REQUEST_INVALID;
            status = completion_observed ? M37_A_R_NATIVE_OK :
                m37_a_r_adapter_poll_completion(&transport, pending_data, pending_bytes, pending_token);
        } else status = m37_a_r_adapter_receive(&transport, &datagram);
        if (!option || (status != M37_A_R_NATIVE_NO_PACKET
            && !(operation == 6 && status == M37_A_R_NATIVE_RING_FULL))) break;
    } while (ticks() < deadline);
    uint64_t token = operation == 6 ? pending_token : datagram.sequence;
    provider_fact(operation == 6 ? "completion-poll" : "receive", token, status);
    if (status != M37_A_R_NATIVE_OK) return M38_STATUS_REQUEST_INVALID;
    uint32_t value, result_status;
    if (operation == 6) {
        completion_observed = 1;
        value = pending_value;
        result_status = completion_error;
    } else {
        if (token <= received_token || token >> 63 || !publication_read(&datagram, &value)) return M38_STATUS_REQUEST_INVALID;
        result_status = completion_error;
    }
    uint32_t raw[6] = {token & 65535u, (token >> 16) & 65535u, (token >> 32) & 65535u,
                       (token >> 48) & 65535u, value, result_status};
    if (!provider_stimulus(cause_code, cause_ids, raw, 6, out)) return M38_STATUS_INTERNAL;
    *token_out = token; return M38_STATUS_OK;
}
static int emit(uint32_t row, M38Status status, const ResourceResultView *view) {
    uart_puts("M39 row="); number(row); uart_puts(" status="); number(status);
    uart_puts(" wire="); number(view ? view->wire_status : 0); uart_puts(" jam=");
    if (view) {
        const uint8_t *bytes; uint64_t size;
        jam_admission_budget_t budget; jam_admission_budget_init(&budget, 2000000);
        if (jam_encode_bytes_identity_bounded(*view->root_slot, &bytes, &size, &budget)) return 0;
        const char *digits = "0123456789abcdef";
        for (uint32_t i = 0; i < size; i++) {
            uart_putc(digits[bytes[i] >> 4]); uart_putc(digits[bytes[i] & 15]);
        }
    } else uart_puts("none");
    uart_puts("\r\n"); return 1;
}
static void finish(void) {
    register uint64_t function __asm__("x0") = 0x84000008;
    __asm__ volatile("hvc #0" : "+r"(function) : : "memory");
    for (;;) __asm__ volatile("wfe");
}

void m39_resource_boot(void) {
    noun input, envelope[3], rows[MAX_COMMANDS], fields[3];
    uint32_t count, command_count;
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < 8; i++) bytes |= (uint64_t)base[i] << (8u * i);
    if (!bytes || bytes > 1024u * 1024u
        || cue_bounded_bytes((const uint8_t *)(uintptr_t)(PILL_BASE + 16u), bytes,
                             &cue_i2_limits, HEAP_MODE_SCRATCH, &input) != CUE_BOUNDED_OK) goto fail;
#if defined(M44_G0_TEST_CONTROLS)
    if (m44_g0_try_boot(input)) return;
#endif
#if defined(M44_TWO_RESOURCE)
    if (m44_device_try_boot(input)) return;
#endif
    if (!record(input, envelope, 3) || !provider_config(envelope[2])
        || !list(envelope[0], rows, 2, &count) || !count) goto fail;
    for (uint32_t i = 0; i < count; i++) {
        if (!record(rows[i], fields, 2)) goto fail;
        for (uint32_t j = 0; j < 2; j++)
            if (!atom_copy(fields[j], catalog_jams[i][j], MAX_JAM, &catalog_bytes[i][j])) goto fail;
    }
    if (!list(envelope[1], rows, MAX_COMMANDS, &command_count)) goto fail;
    for (uint32_t i = 0; i < command_count; i++) {
        Command *c = &commands[i];
        if (!record(rows[i], fields, 3) || !scalar(fields[0], 10, &c->operation)
            || !c->operation || !scalar(fields[1], 7, &c->handle)
            || !atom_copy(fields[2], c->argument, MAX_ARGUMENT, &c->bytes)) goto fail;
    }
    noun_tx_abort(); heap_scratch_reset();
    ResourceRuntime *runtime = 0; ResourceSession *session = 0; SessionCapability capability = 0;
    SupervisorAdmissionEntry entries[2]; SupervisorAdmissionCatalog catalog;
    for (uint32_t i = 0; i < count; i++)
        entries[i] = (SupervisorAdmissionEntry){catalog_jams[i][0], catalog_bytes[i][0],
                                               catalog_jams[i][1], catalog_bytes[i][1]};
    M38Status setup = m38_supervisor_admission_catalog_make(&catalog, entries, count);
    if (!setup) setup = m38_resource_runtime_init(control, sizeof(control), workspace, sizeof(workspace), &runtime);
    if (!setup) setup = m38_resource_session_init(runtime, session_storage, sizeof(session_storage),
                                                &catalog, &session, &capability);
    uart_puts("M39 setup="); number(setup); uart_puts("\r\n");
    if (setup) goto fail;
    if (provider_enabled) {
        int native_status = m37_a_r_adapter_init(&transport);
        provider_fact("init", 0, (uint32_t)native_status);
        if (native_status) goto fail;
        /* Both generic guests finish native setup before traffic starts. */
        uart_puts("M39 provider=ready token=0 status=0\r\n");
        uint64_t frequency; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
        uint64_t deadline = ticks() + frequency * 10u; uint8_t start = 0;
        while (!uart_getc_nb(&start) && ticks() < deadline) { }
        if (start != 'G') goto fail;
    }
    for (uint32_t i = 0; i < command_count; i++) {
        Command *c = &commands[i]; noun argument, handle, args, request;
        uint32_t operation = c->operation, restore_slot = c->handle;
        uint64_t provider_token = 0;
        heap_set_mode(HEAP_MODE_PERSIST);
        if (!decode(c->argument, c->bytes, &argument)) goto fail;
        if (operation == 9) {
            uint32_t control;
            if (!provider_enabled || !scalar(argument, 6, &control)) goto fail;
            if (control == 1) m37_a_r_adapter_test_delayed_completion();
            if (control == 2) m37_a_r_adapter_test_release_delayed_completion();
            if (control == 3) m37_a_r_adapter_test_lost_completion();
            if (control == 4) m37_a_r_adapter_test_release_lost_completion();
            if (control == 5) completion_error = 2; /* qualification-only provider error after exact used-ring proof */
            if (control == 6) completion_error = 0;
            provider_fact("test-control", 0, control);
            if (!emit(i, M38_STATUS_OK, 0)) goto fail;
            continue;
        }
        /* Generic qualification operation 10 attempts RESTORE using another
         * script slot's saved snapshot. It exercises capability/profile fences
         * through the unchanged public RESTORE request, without forging handles. */
        if (operation == 10) {
            if (!scalar(argument, 7, &restore_slot)) goto fail;
            operation = 5;
        }
        if (operation >= 6) {
            M38Status status = c->handle == provider_handle ? provider_input(operation, argument, &argument, &provider_token)
                                                          : M38_STATUS_REQUEST_INVALID;
            if (status) { if (!emit(i, status, 0)) goto fail; continue; }
            operation = 2;
        } else if (operation == 2 && provider_enabled) {
            noun stimulus_fields[2]; uint32_t event;
            if (!tagged_fields(argument, "m38-resource-abi-v1-numeric-stimulus", "m38-resource-abi-v1-numeric-stimulus-schema-v1", stimulus_fields, 2)
                || !scalar(stimulus_fields[0], 65535, &event)) goto fail;
            if (event == cause_code || event == release_code || event < 1024u) {
                provider_fact("ordinary-origin-refusal", 0, event);
                if (!emit(i, M38_STATUS_REQUEST_INVALID, 0)) goto fail;
                continue;
            }
        }
        if (operation == 1) {
            uint32_t index;
            if (!scalar(argument, count - 1u, &index)
                || !decode(catalog_jams[index][1], catalog_bytes[index][1], &args)) goto fail;
        } else {
            if (!decode(handles[c->handle].jam, handles[c->handle].bytes, &handle)) goto fail;
            if (operation == 4) args = handle;
            else {
                if (operation == 5
                    && !decode(snapshots[restore_slot].jam, snapshots[restore_slot].bytes, &argument)) goto fail;
                noun pair_fields[2] = {handle, argument};
                if (!build(pair_fields, 2, &args)) goto fail;
            }
        }
        noun request_fields[3] = {cord("m38-resource-abi-v1-request-schema-v1"), direct(operation), args};
        noun body;
        if (!build(request_fields, 3, &body)
            || !alloc_cell_checked(cord("m38-resource-abi-v1-request"), body, &request)) goto fail;
        const ResourceResultView *view = 0;
        M38Status status = m38_resource_session_dispatch(session, request, &view);
        if (!emit(i, status, view)) goto fail;
        if (status == M38_STATUS_OK && view && view->wire_status == operation) {
            if (c->operation == 6) pending_token = 0;
            if (c->operation == 7) received_token = provider_token;
            if (!provider_effects(view, c->handle)) goto fail;
            noun tag, result_body, result_fields[3], loaded[2];
            if (!pair(*view->root_slot, &tag, &result_body) || !record(result_body, result_fields, 3)) goto fail;
            if (operation == 1) {
                if (!record(result_fields[2], loaded, 2) || !save(loaded[0], &handles[c->handle])) goto fail;
            }
            if (operation == 4 && !save(result_fields[2], &snapshots[c->handle])) goto fail;
        }
    }
    uart_puts("M39 terminal=complete\r\n"); finish(); return;
fail:
    uart_puts("M39 terminal=refuse\r\n"); finish();
}
