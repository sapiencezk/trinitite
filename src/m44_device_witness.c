/* Generic boot-supplied M44 device command harness. No IEC algorithms live here. */
#include <stdint.h>
#include <stddef.h>
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "noun.h"
#include "uart.h"
#include "sha256.h"
#include "m38_resource_runtime.h"
#include "m39_resource_witness.h"
#include "m44_two_resource_supervisor.h"
#include "m44_device_witness.h"
#define MAX_JAM (128u * 1024u)
#define MAX_COMMANDS 256u
#define DESCRIPTOR_BYTES (64u * 1024u)
typedef struct { uint32_t op, slot, argument; M44Row row; } Command;
static Command commands[MAX_COMMANDS];
static M44Descriptor descriptor;
static M44Saved handles[2];
static uint32_t catalog_bytes[2][2];
static ResourceRuntime *runtime;
static ResourceSession *session;
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
static int save(noun value, M44Saved *out) {
    const uint8_t *bytes; uint64_t size;
    jam_admission_budget_t budget; jam_admission_budget_init(&budget, 2000000);
    if (jam_encode_bytes_identity_bounded(value, &bytes, &size, &budget) || size > M44_SAVED_BYTES) return 0;
    for (uint32_t i = 0; i < size; i++) out->jam[i] = bytes[i];
    out->bytes = size; return 1;
}
static void number(uint64_t n) {
    char buf[21]; uint32_t used = 0;
    do { buf[used++] = '0' + n % 10; n /= 10; } while (n);
    while (used) uart_putc(buf[--used]);
}

static int text_is(noun n, const char *expected) {
    uint8_t bytes[128] = {0};
    if (!noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (uint32_t i = 0; i < sizeof(bytes); i++)
        if (bytes[i] != (i < length(expected) ? (uint8_t)expected[i] : 0)) return 0;
    return 1;
}
static int same(const uint8_t *a, const uint8_t *b, uint32_t count) {
    for (uint32_t i = 0; i < count; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static int digest(noun n, uint8_t out[32]) {
    return noun_atom_read_fixed(n, out, 32);
}
static int hash_noun(noun n, const char *domain, int separator, uint8_t out[32]) {
    const uint8_t *bytes;
    uint64_t size;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000);
    if (jam_encode_bytes_identity_bounded(n, &bytes, &size, &budget)
        || size > DESCRIPTOR_BYTES) return 0;
    sha256_ctx_t context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)domain, length(domain) + separator);
    sha256_update(&context, bytes, size);
    sha256_final(&context, out);
    return 1;
}
static int boundaries(noun n, M44Boundary *out, uint32_t *count) {
    noun rows[M44_MAX_BOUNDARIES], fields[2], values[16], value[2];
    if (!list(n, rows, M44_MAX_BOUNDARIES, count)) return 0;
    for (uint32_t i = 0; i < *count; i++) {
        M44Boundary *row = &out[i];
        if (!record(rows[i], fields, 2) || !scalar(fields[0], 65535, &row->event)
            || !row->event || !list(fields[1], values, 16, &row->count)) return 0;
        if (i && out[i - 1].event >= row->event) return 0;
        for (uint32_t j = 0; j < row->count; j++) {
            if (!record(values[j], value, 2)
                || !scalar(value[0], 65535, &row->values[j].id) || !row->values[j].id
                || !scalar(value[1], 3, &row->values[j].type) || !row->values[j].type) return 0;
            for (uint32_t k = 0; k < j; k++)
                if (row->values[k].id == row->values[j].id) return 0;
        }
    }
    return 1;
}
static int resource_path(noun n, uint8_t out[132], uint32_t *dot) {
    if (!noun_atom_read_fixed(n, out, 132)) return 0;
    uint32_t size = 0, dots = 0;
    for (; size < 132 && out[size]; size++) {
        uint8_t c = out[size];
        if (c == '.') { *dot = size; dots++; continue; }
        if (!((c == '_' && size && out[size - 1] != '.') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9' && size && out[size - 1] != '.'))) return 0;
    }
    if (size >= 132 || dots != 1 || !*dot || *dot > 64 || *dot >= size - 1 || size - *dot - 1 > 64) return 0;
    for (uint32_t i = size; i < 132; i++) if (out[i]) return 0;
    return 1;
}
static int descriptor_read(noun value, noun expected) {
    noun tag, body, fields[7], resources[2], resource[7], link[5], values[16], binding[3];
    uint32_t version, capacity;
    uint8_t supplied[32], source[32], provenance[32], paths[2][132];
    uint32_t dots[2];
    if (!pair(value, &tag, &body) || !text_is(tag, "m44-two-resource-deployment-v1")
        || !record(body, fields, 7) || !scalar(fields[0], 1, &version) || version != 1
        || !digest(fields[1], source) || !digest(fields[2], provenance)
        || !record(fields[3], resources, 2) || !record(fields[4], link, 5)
        || !scalar(fields[5], 16, &descriptor.batch_bound) || !descriptor.batch_bound
        || !scalar(fields[6], 16, &capacity) || capacity != 16
        || !hash_noun(value, "1499kernel-m44-deployment-v1", 1, descriptor.identity)
        || !digest(expected, supplied) || !same(supplied, descriptor.identity, 32)) return 0;
    for (uint32_t i = 0; i < 2; i++) {
        uint32_t slot;
        if (!record(resources[i], resource, 7) || !scalar(resource[0], 2, &slot) || slot != i + 1
            || !resource_path(resource[1], paths[i], &dots[i])
            || !digest(resource[2], descriptor.core_identity[i])
            || !digest(resource[3], descriptor.payload_identity[i])
            || !digest(resource[4], descriptor.admission_identity[i])
            || !boundaries(resource[5], descriptor.ingress[i], &descriptor.ingress_count[i])
            || !boundaries(resource[6], descriptor.outputs[i], &descriptor.output_count[i])) return 0;
    }
    if (dots[0] != dots[1] || !same(paths[0], paths[1], dots[0])) return 0;
    uint32_t first = 0;
    while (first < 132 && paths[0][first] == paths[1][first]) first++;
    if (first == 132 || paths[0][first] >= paths[1][first]) return 0;
    if (!scalar(link[0], 2, &descriptor.source_slot) || !descriptor.source_slot
        || !scalar(link[1], 65535, &descriptor.source_event) || !descriptor.source_event
        || !scalar(link[2], 2, &descriptor.target_slot) || !descriptor.target_slot
        || descriptor.source_slot == descriptor.target_slot
        || !scalar(link[3], 65535, &descriptor.target_event) || !descriptor.target_event
        || !list(link[4], values, 16, &descriptor.value_count)) return 0;
    for (uint32_t i = 0; i < descriptor.value_count; i++) {
        if (!record(values[i], binding, 3)
            || !scalar(binding[0], 65535, &descriptor.source_ids[i]) || !descriptor.source_ids[i]
            || !scalar(binding[1], 65535, &descriptor.target_ids[i]) || !descriptor.target_ids[i]
            || !scalar(binding[2], 3, &descriptor.types[i]) || !descriptor.types[i]) return 0;
    }
    return 1;
}

/* Compare the descriptor with the exact admitted numeric boundary table.
 * D8 independently validates this core and all admission-record identities. */
static int payload_matches(noun core, uint32_t slot) {
    noun formula, payload, tag, body, pf[2], fields[5], rows[128], row[3], values[16], value[2];
    if (!pair(core, &formula, &payload) || !pair(payload, &tag, &body)
        || !text_is(tag, "m38-d0-r2-resource-payload") || !record(body, pf, 2)
        || !record(pf[1], fields, 5)) return 0;
    descriptor.signed_values[slot] = text_is(pf[0], "m41-resource-payload-schema-v1");
    if (!descriptor.signed_values[slot] && !text_is(pf[0], "m38-d0-r2-resource-payload-schema-v2")) return 0;
    for (uint32_t direction = 0; direction < 2; direction++) {
        uint32_t count;
        const M44Boundary *expected = direction ? descriptor.outputs[slot] : descriptor.ingress[slot];
        uint32_t expected_count = direction ? descriptor.output_count[slot] : descriptor.ingress_count[slot];
        if (!list(fields[3 + direction], rows, 128, &count) || count != expected_count) return 0;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t instance, event, n;
            if (!record(rows[i], row, 3) || !scalar(row[0], 8, &instance)
                || !scalar(row[1], 65535, &event) || instance != event / 1024
                || event != expected[i].event || !list(row[2], values, 16, &n)
                || n != expected[i].count) return 0;
            for (uint32_t j = 0; j < n; j++) {
                uint32_t id, type;
                if (!record(values[j], value, 2) || !scalar(value[0], 65535, &id)
                    || !scalar(value[1], 3, &type)
                    || id != expected[i].values[j].id || type != expected[i].values[j].type) return 0;
            }
        }
    }
    return 1;
}
static int admission_matches(noun admission, uint32_t slot) {
    noun tag, body, fields[11];
    uint8_t core[32], payload[32], identity[32];
    if (!pair(admission, &tag, &body) || !record(body, fields, 11)
        || !digest(fields[1], core) || !digest(fields[5], payload)
        || !same(core, descriptor.core_identity[slot], 32)
        || !same(payload, descriptor.payload_identity[slot], 32)) return 0;
    const char *domain = descriptor.signed_values[slot]
        ? "1499kernel:i2:m41:session-admission-record:v1"
        : "1499kernel:i2:m38:resource-abi-v1:session-admission-record:v1";
    return hash_noun(admission, domain, 0, identity)
        && same(identity, descriptor.admission_identity[slot], 32);
}

static int typed_row(noun value, M44Row *out) {
    noun fields[3], values[16], row[3];
    if (!record(value, fields, 3) || !scalar(fields[0], 65535, &out->event)
        || !scalar(fields[1], UINT32_MAX, &out->sequence)
        || !list(fields[2], values, 16, &out->count)) return 0;
    for (uint32_t i = 0; i < out->count; i++) {
        M44Value *v = &out->values[i];
        if (!record(values[i], row, 3) || !scalar(row[0], 65535, &v->id)
            || !scalar(row[1], 3, &v->type) || !scalar(row[2], 65535, &v->raw)) return 0;
    }
    return 1;
}
static void values_json(const M44Value *values, uint32_t count) {
    uart_putc('[');
    for (uint32_t i = 0; i < count; i++) {
        if (i) uart_putc(',');
        uart_putc('['); number(values[i].id); uart_putc(','); number(values[i].type);
        uart_putc(','); number(values[i].raw); uart_putc(']');
    }
    uart_putc(']');
}
static void row_json(const M44Row *row) {
    uart_putc('['); number(row->event); uart_putc(','); number(row->sequence);
    uart_putc(','); values_json(row->values, row->count); uart_putc(']');
}
static int emit(uint32_t index, uint32_t status, uint32_t token) {
    const M44State *state = m44_supervisor_state();
    M44ResourceInspection resources;
    if (!state || m44_supervisor_inspect(&resources) != M44_OK) return 0;
    uart_puts("M44 {\"row\":"); number(index); uart_puts(",\"status\":"); number(status);
    uart_puts(",\"token\":"); number(token); uart_puts(",\"cursor\":"); number(state->cursor);
    uart_puts(",\"sequence\":"); number(state->sequence); uart_puts(",\"fault\":"); number(state->fault);
#if defined(M45_MANAGED_LIFECYCLE)
    if (m45_supervisor_is_managed()) {
        uart_puts(",\"managed\":"); number(1);
        uart_puts(",\"lifecycle\":"); number(state->lifecycle);
        uart_puts(",\"epoch\":"); number(state->epoch);
    }
#endif
    uart_puts(",\"fenced\":"); number(state->fenced); uart_puts(",\"queues\":[");
    for (uint32_t slot = 0; slot < 2; slot++) {
        if (slot) uart_putc(',');
        uart_putc('[');
        for (uint32_t j = 0; j < state->counts[slot]; j++) {
            if (j) uart_putc(',');
            row_json(&state->queues[slot][j]);
        }
        uart_putc(']');
    }
    uart_puts("],\"outputs\":[");
    for (uint32_t i = 0; i < state->output_count; i++) {
        if (i) uart_putc(',');
        uart_putc('['); number(state->output_slots[i]); uart_putc(',');
        row_json(&state->outputs[i]); uart_putc(']');
    }
    uart_puts("],\"capability\":"); number(resources.capability);
    uart_puts(",\"resources\":[");
    for (uint32_t slot = 0; slot < 2; slot++) {
        if (slot) uart_putc(',');
        uart_puts("{\"generation\":"); number(resources.generations[slot]);
        uart_puts(",\"nonce\":"); number(resources.snapshot_nonces[slot]);
        uart_puts(",\"instances\":[");
        for (uint32_t i = 0; i < resources.instance_counts[slot]; i++) {
            const M44InstanceInspection *instance = &resources.instances[slot][i];
            if (i) uart_putc(',');
            uart_putc('['); number(i + 1); uart_putc(','); number(instance->active); uart_puts(",[");
            for (uint32_t j = 0; j < instance->value_count; j++) {
                if (j) uart_putc(',');
                uart_putc('['); number(j + 1); uart_putc(','); number(instance->types[j]);
                uart_putc(','); number(instance->values[j]); uart_putc(']');
            }
            uart_puts("]]");
        }
        uart_puts("]}");
    }
    uart_puts("]}\r\n");
    return 1;
}
static void finish(void) {
    register uint64_t function __asm__("x0") = 0x84000008;
    __asm__ volatile("hvc #0" : "+r"(function) : : "memory");
    for (;;) __asm__ volatile("wfe");
}

int m44_device_try_boot(noun input) {
    noun tag, body, envelope[5], catalog[2], entry[2], rows[MAX_COMMANDS], command[4];
    uint32_t count, boot_failure;
#if defined(M45_MANAGED_LIFECYCLE)
    if (!pair(input, &tag, &body)) return 0;
    uint32_t managed = text_is(tag, "m45-device-boot-v1");
    if (!managed && !text_is(tag, "m44-device-boot-v1")) return 0;
#else
    if (!pair(input, &tag, &body) || !text_is(tag, "m44-device-boot-v1")) return 0;
#endif
    if (!record(body, envelope, 5) || !descriptor_read(envelope[0], envelope[1])
        || !record(envelope[2], catalog, 2) || !list(envelope[3], rows, MAX_COMMANDS, &count)
        || !scalar(envelope[4], 5, &boot_failure)) goto invalid;
#if !defined(M44_G0_TEST_CONTROLS)
    if (boot_failure) goto invalid;
#endif
    for (uint32_t i = 0; i < 2; i++) {
        if (!record(catalog[i], entry, 2)) goto invalid;
        for (uint32_t part = 0; part < 2; part++)
            if (!atom_copy(entry[part], m44_boot_catalog_storage(i, part), MAX_JAM,
                           &catalog_bytes[i][part])) goto invalid;
    }
    for (uint32_t i = 0; i < count; i++) {
        Command *c = &commands[i];
        if (!record(rows[i], command, 4) || !scalar(command[0],
#if defined(M45_MANAGED_LIFECYCLE)
            managed ? 21 : 16,
#else
            16,
#endif
            &c->op) || !c->op
            || !scalar(command[1], 2, &c->slot) || !typed_row(command[2], &c->row)
            || !scalar(command[3], UINT32_MAX, &c->argument)) goto invalid;
#if !defined(M44_G0_TEST_CONTROLS)
        if (c->op == 5 || c->op == 6 || (c->op >= 14
#if defined(M45_MANAGED_LIFECYCLE)
            && c->op != 17
#endif
            )) goto invalid;
#endif
    }
    /* All long-lived boot material is now fixed C storage. */
    noun_tx_abort(); heap_scratch_reset();
    for (uint32_t i = 0; i < 2; i++) {
        noun core, admission;
        if (!decode(m44_boot_catalog_storage(i, 1), catalog_bytes[i][1], &core)
            || !payload_matches(core, i)
            || !decode(m44_boot_catalog_storage(i, 0), catalog_bytes[i][0], &admission)
            || !admission_matches(admission, i)) goto invalid;
    }
    SupervisorAdmissionEntry entries[2];
    SupervisorAdmissionCatalog admitted;
    SessionCapability capability;
    for (uint32_t i = 0; i < 2; i++)
        entries[i] = (SupervisorAdmissionEntry){m44_boot_catalog_storage(i, 0), catalog_bytes[i][0],
                                               m44_boot_catalog_storage(i, 1), catalog_bytes[i][1]};
    uint32_t catalog_count = 2;
    if (catalog_bytes[0][0] == catalog_bytes[1][0] && catalog_bytes[0][1] == catalog_bytes[1][1]
        && same(m44_boot_catalog_storage(0, 0), m44_boot_catalog_storage(1, 0), catalog_bytes[0][0])
        && same(m44_boot_catalog_storage(0, 1), m44_boot_catalog_storage(1, 1), catalog_bytes[0][1]))
        catalog_count = 1; /* Two independent handles can share one immutable core. */
    M38Status status = m38_supervisor_admission_catalog_make(&admitted, entries, catalog_count);
    if (!status) status = m38_resource_runtime_init(m44_boot_control(), 65536,
        m44_boot_workspace(), 4u * 1024u * 1024u, &runtime);
    if (!status) status = m38_resource_session_init(runtime, m44_boot_session_storage(),
        2u * 1024u * 1024u, &admitted, &session, &capability);
    if (status) goto invalid;
    for (uint32_t i = 0; i < 2; i++) {
        noun core, request, result[2], loaded[2], handle_fields[4];
        const ResourceResultView *view;
        uint8_t identity[32];
        if (!decode(m44_boot_catalog_storage(i, 1), catalog_bytes[i][1], &core)
            || !tagged("m38-resource-abi-v1-request", "m38-resource-abi-v1-request-schema-v1",
                       (noun[2]){direct(1), core}, 2, &request)
            || m38_resource_session_dispatch(session, request, &view) != M38_STATUS_OK
            || !view || view->wire_status != 1
            || !tagged_fields(*view->root_slot, "m38-resource-abi-v1-result",
                              "m38-resource-abi-v1-result-schema-v1", result, 2)
            || !record(result[1], loaded, 2) || !record(loaded[0], handle_fields, 4)
            || !digest(handle_fields[3], identity)
            || !same(identity, descriptor.admission_identity[i], 32)
            || !save(loaded[0], &handles[i])) goto invalid;
        /* After lease acquisition any boot refusal is terminal until reboot. */
        if (boot_failure == 1 && i == 0) goto invalid;
    }
#if defined(M44_G0_TEST_CONTROLS)
    if (boot_failure >= 2) {
        if (boot_failure == 2) handles[1].bytes = 0;
        else if (boot_failure == 3) handles[1] = handles[0];
        else {
            noun handle, fields[4];
            if (!decode(handles[1].jam, handles[1].bytes, &handle) || !record(handle, fields, 4)) goto failed;
            fields[boot_failure == 4 ? 2 : 0] = direct(999);
            if (!build(fields, 4, &handle) || !save(handle, &handles[1])) goto failed;
        }
        if (m44_supervisor_init(session, &descriptor, handles) != M44_INVALID) goto failed;
        noun handle, selector, args, request;
        const ResourceResultView *view;
        if (!decode(handles[0].jam, handles[0].bytes, &handle)
            || !tagged("m38-resource-abi-v1-numeric-selector", "m38-resource-abi-v1-numeric-selector-schema-v1",
                       (noun[1]){direct(1)}, 1, &selector)
            || !build((noun[2]){handle, selector}, 2, &args)
            || !tagged("m38-resource-abi-v1-request", "m38-resource-abi-v1-request-schema-v1",
                       (noun[2]){direct(3), args}, 2, &request)
            || m38_resource_session_dispatch(session, request, &view) != M38_STATUS_OK
            || !view || view->wire_status != 3) goto failed;
        uart_puts("M44 preclaim-refusal-public-peek=pass\r\n");
        goto invalid;
    }
#endif
#if defined(M45_MANAGED_LIFECYCLE)
    if ((managed ? m45_supervisor_init(session, &descriptor, handles)
                 : m44_supervisor_init(session, &descriptor, handles)) != M44_OK) goto invalid;
#else
    if (m44_supervisor_init(session, &descriptor, handles) != M44_OK) goto invalid;
#endif
    size_t storage = m44_supervisor_storage_bytes() + sizeof(commands) + sizeof(descriptor)
        + sizeof(handles) + sizeof(catalog_bytes) + sizeof(runtime) + sizeof(session);
    if (storage > 512u * 1024u) goto invalid;
    uart_puts("M44 setup=0\r\n");
    uart_puts("M44 storage=");
    number(storage);
    uart_puts("\r\n");
    uint32_t tokens[2] = {0, 0};
    if (!emit(0, M44_OK, 0)) goto failed;
    for (uint32_t i = 0; i < count; i++) {
        const Command *c = &commands[i];
        uint32_t result = M44_INVALID, token = 0;
        if (c->op == 1) result = m44_supervisor_enqueue(c->slot, &c->row);
        else if (c->op == 2) result = m44_supervisor_dispatch();
        else if (c->op == 3 && c->argument < 2) {
            result = m44_supervisor_capture(&token);
            if (result == M44_OK) tokens[c->argument] = token;
        } else if (c->op == 4 && c->argument < 2) result = m44_supervisor_restore(tokens[c->argument]);
#if defined(M44_G0_TEST_CONTROLS)
        else if (c->op == 5) { m44_supervisor_test_fault(c->slot, c->argument); result = M44_OK; }
        else if (c->op == 6) { m44_supervisor_test_sequence(c->argument); result = M44_OK; }
        else if (c->op == 14) { m44_supervisor_test_busy(); result = M44_OK; }
        else if (c->op == 15) result = m44_supervisor_test_busy_mask();
        else if (c->op == 16 && c->argument <= 10000) {
            uint64_t persist = heap_cells_used(HEAP_MODE_PERSIST), scratch = heap_cells_used(HEAP_MODE_SCRATCH);
            uint64_t atoms = atom_store_bytes_used();
            M44ResourceInspection inspection;
            result = M44_OK;
            for (uint32_t j = 0; j < c->argument; j++)
                if (m44_supervisor_inspect(&inspection) != M44_OK) result = M44_INVALID;
            if (persist != heap_cells_used(HEAP_MODE_PERSIST) || scratch != heap_cells_used(HEAP_MODE_SCRATCH)
                || atoms != atom_store_bytes_used()) result = M44_INVALID;
        }
#if defined(M45_MANAGED_LIFECYCLE)
        else if (c->op == 18) result = m45_supervisor_test_busy_mask();
        else if (c->op == 20) result = m45_supervisor_test_resource_control(c->argument);
        else if (c->op == 21) { m45_supervisor_test_epoch(c->argument); result = M44_OK; }
        else if (c->op == 19 && c->argument <= 10000) {
            uint64_t persist = heap_cells_used(HEAP_MODE_PERSIST), scratch = heap_cells_used(HEAP_MODE_SCRATCH);
            uint64_t atoms = atom_store_bytes_used();
            result = M44_OK;
            for (uint32_t j = 0; j < c->argument; j++)
                if (m45_supervisor_manage(7, 0) != 0) result = M44_INVALID;
            if (persist != heap_cells_used(HEAP_MODE_PERSIST) || scratch != heap_cells_used(HEAP_MODE_SCRATCH)
                || atoms != atom_store_bytes_used()) result = M44_INVALID;
        }
#endif
#endif
#if defined(M45_MANAGED_LIFECYCLE)
        else if (c->op == 17) result = m45_supervisor_manage(c->argument, c->slot);
#endif
        else if (c->op == 7 || c->op == 13) {
            const ResourceResultView *view = 0;
            /* Claimed-session fence runs before request parsing, even for an
             * otherwise hostile caller. G0 separately checks valid requests. */
            result = m38_resource_session_dispatch(session, NOUN_ZERO, &view);
        } else if (c->op == 8) result = m38_resource_session_reset(runtime, session);
        else if (c->op == 9) result = m38_resource_session_dispose(runtime, session);
        else if ((c->op == 11 || c->op == 12) && c->argument < 2) {
            uint8_t identity[32];
            for (uint32_t j = 0; j < 32; j++) identity[j] = descriptor.identity[j];
            if (c->op == 11) identity[0] ^= 1;
            result = m44_supervisor_restore_checked(tokens[c->argument], identity,
                capability + (c->op == 12 ? 1 : 0));
        }
        if (!emit(i + 1, result, token)) goto failed;
    }
    uart_puts("M44 terminal=complete\r\n"); finish(); return 1;
invalid:
    uart_puts("M44 setup=1\r\n");
failed:
    uart_puts("M44 terminal=refuse\r\n"); finish(); return 1;
}
