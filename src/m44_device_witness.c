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
#if defined(M48_RESIDENT)
#include "m48_report.h"
/* Only resident report capture redirects UART. Retained finite witnesses keep
 * their existing output path and byte representation. */
static void m48_output_putc(char c) {
    if (m48_report_capturing()) m48_report_putc((uint8_t)c);
    else uart_putc(c);
}
static void m48_output_puts(const char *s) {
    if (m48_report_capturing()) m48_report_puts(s);
    else uart_puts(s);
}
#define uart_putc m48_output_putc
#define uart_puts m48_output_puts
#endif
#define MAX_JAM (128u * 1024u)
#define MAX_COMMANDS 256u
#define DESCRIPTOR_BYTES (64u * 1024u)
typedef struct { uint32_t op, slot, argument; M44Row row;
#if defined(M47_MANAGED_SERVICES)
 uint32_t epoch; uint64_t provider_token;
#endif
 } Command;
static Command commands[MAX_COMMANDS];
static M44Descriptor descriptor;
static M44Saved handles[2];
static uint32_t catalog_bytes[2][2];
static ResourceRuntime *runtime;
static ResourceSession *session;
#if defined(M47_MANAGED_SERVICES)
static uint32_t managed_services;
static M47ProviderBinding m47_bindings[2];
#if defined(M49_MANAGED_DELAY)
static uint32_t managed_delay;
#if defined(M50_PERIODIC)
static uint32_t managed_cycle;
#endif
static M49TimerBinding m49_timer_binding;
#if defined(M51_CONTROLLER)
static uint32_t managed_controller;
#if defined(M53_RESIDENT_COMPOSITION)
static uint32_t managed_composition;
#if defined(M55_SIGNED_RESIDENT)
static uint32_t managed_signed_resident;
#endif
#endif
static M51TimerBinding resident_timer_bindings[2];
static M51ReturnBinding resident_completion;
#endif
#endif
#endif
#if defined(M48_RESIDENT)
static uint32_t resident_mode;
#endif
#if defined(M46_LIVE_REPLACEMENT)
static int m46_device_try_boot(noun input);
static uint32_t live_replacement, active_package, staged_package;
static uint32_t expected_generation[MAX_COMMANDS], expected_package[MAX_COMMANDS];
#if defined(M52_RESIDENT_REPLACEMENT)
static uint32_t managed_replacement;
#if defined(M54_RESIDENT_REPLACEMENT)
static M54Policy resident_policy;
#endif
static int m52_device_try_boot(noun input);
static int m52_package_read(uint32_t index, uint8_t compatibility[32]);
static int m52_catalog_validate(void);
#endif
#endif
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
#if defined(M49_MANAGED_DELAY)
static uint32_t descriptor_timed_profile;
#endif
static uint32_t descriptor_type_max(void) {
#if defined(M49_MANAGED_DELAY)
    if (descriptor_timed_profile) return 4;
#endif
    return 3;
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
                || !scalar(value[1], descriptor_type_max(), &row->values[j].type) || !row->values[j].type) return 0;
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
    if (!pair(value, &tag, &body)) return 0;
#if defined(M49_MANAGED_DELAY)
    descriptor_timed_profile=text_is(tag,"m49-two-resource-deployment-v1");
#if defined(M50_PERIODIC)
    if (text_is(tag,"m50-two-resource-deployment-v1")) descriptor_timed_profile=2;
#if defined(M51_CONTROLLER)
    if (text_is(tag,"m51-two-resource-deployment-v1")) descriptor_timed_profile=3;
#if defined(M53_RESIDENT_COMPOSITION)
    if (text_is(tag,"m53-two-resource-deployment-v1")) descriptor_timed_profile=4;
#if defined(M55_SIGNED_RESIDENT)
    if (text_is(tag,"m55-two-resource-deployment-v1")) descriptor_timed_profile=5;
    descriptor.service_value_type=descriptor_timed_profile==5?3:0;
#endif
#endif
#endif
#endif
    if (!descriptor_timed_profile && !text_is(tag,"m44-two-resource-deployment-v1")) return 0;
#else
    if (!text_is(tag,"m44-two-resource-deployment-v1")) return 0;
#endif
    if (!record(body, fields, 7) || !scalar(fields[0], 1, &version) || version != 1
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
            || !scalar(binding[2], descriptor_type_max(), &descriptor.types[i]) || !descriptor.types[i]) return 0;
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
#if defined(M49_MANAGED_DELAY)
    descriptor.time_values[slot]=descriptor_timed_profile && text_is(pf[0],"m49-resource-payload-schema-v1");
    if (!descriptor.time_values[slot] && !descriptor.signed_values[slot] && !text_is(pf[0],"m38-d0-r2-resource-payload-schema-v2")) return 0;
#else
    if (!descriptor.signed_values[slot] && !text_is(pf[0], "m38-d0-r2-resource-payload-schema-v2")) return 0;
#endif
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
                    || !scalar(value[1], descriptor_type_max(), &type)
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
#if defined(M49_MANAGED_DELAY)
    if (descriptor.time_values[slot]) domain="1499kernel:i2:m49:session-admission-record:v1";
#endif
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
            || !scalar(row[1], descriptor_type_max(), &v->type) || !scalar(row[2], descriptor_type_max()==4 && v->type==4 ? UINT32_MAX : 65535, &v->raw)) return 0;
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
#if defined(M46_LIVE_REPLACEMENT)
    if (live_replacement) {
        uart_puts(",\"deployment_generation\":"); number(m46_supervisor_generation());
        uart_puts(",\"active_package\":"); number(active_package);
        uart_puts(",\"candidate_token\":"); number(m46_supervisor_candidate_token());
    }
#endif
#if defined(M45_MANAGED_LIFECYCLE)
    if (m45_supervisor_is_managed()) {
        uart_puts(",\"managed\":"); number(1);
        uart_puts(",\"lifecycle\":"); number(state->lifecycle);
        uart_puts(",\"epoch\":"); number(state->epoch);
    }
#endif
#if defined(M47_MANAGED_SERVICES)
    if (managed_services) {
        uart_puts(",\"receive_holds\":"); number(m47_provider_receive_holds());
        uart_puts(",\"providers\":[");
        for (uint32_t i=0;i<2;i++) {
            const M47ProviderLedger *p=&state->providers[i];
            if (i) uart_putc(',');
            uart_putc('['); number(p->phase); uart_putc(','); number(p->tx_state);
            uart_putc(','); number(p->tx_token); uart_putc(','); number(p->tx_value);
            uart_putc(','); number(p->rx_highwater); uart_putc(','); number(p->rx_token);
            uart_putc(','); number(p->rx_state); uart_putc(','); number(p->release_queued);
            uart_putc(']');
        }
        uart_putc(']');
    }
#endif
#if defined(M49_MANAGED_DELAY)
    if (managed_delay) {
        const M49TimerLedger *timer=&state->timer;
        uart_puts(",\"timer\":["); number(timer->phase);uart_putc(',');number(timer->generation);
        uart_putc(',');number(timer->highwater);uart_putc(',');number(timer->duration_ms);
        uart_putc(',');number(timer->deadline_ms);uart_putc(',');number(timer->not_before_turn);uart_putc(']');
    }
#endif
#if defined(M51_CONTROLLER)
    if (managed_controller) {
        uart_puts(",\"roundtrip\":");number(state->publish_roundtrip);
        uart_puts(",\"timers\":[");
        for (uint32_t i=0;i<2;i++) {
            const M49TimerLedger *t=&state->timers[i];
            if (i) uart_putc(',');
            uart_putc('[');number(t->phase);uart_putc(',');number(t->generation);
            uart_putc(',');number(t->highwater);uart_putc(',');number(t->duration_ms);
            uart_putc(',');number(t->deadline_ms);uart_putc(',');number(t->not_before_turn);uart_putc(']');
        }
        uart_putc(']');
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

#include "m47_device_witness.inc"
#include "m49_device_resident.inc"
#include "m51_device_resident.inc"
#include "m48_device_resident.inc"

int m44_device_try_boot(noun input) {
#if defined(M52_RESIDENT_REPLACEMENT)
    if (m52_device_try_boot(input)) return 1;
#endif
#if defined(M46_LIVE_REPLACEMENT)
    if (m46_device_try_boot(input)) return 1;
#endif
#if defined(M47_MANAGED_SERVICES)
    noun tag, body, envelope[6], catalog[2], entry[2], rows[MAX_COMMANDS], command[6];
#else
    noun tag, body, envelope[5], catalog[2], entry[2], rows[MAX_COMMANDS], command[4];
#endif
    uint32_t count, boot_failure;
#if defined(M45_MANAGED_LIFECYCLE)
    if (!pair(input, &tag, &body)) return 0;
    uint32_t managed = text_is(tag, "m45-device-boot-v1");
#if defined(M47_MANAGED_SERVICES)
    managed_services = text_is(tag,"m47-device-boot-v1");
#if defined(M48_RESIDENT)
    resident_mode=text_is(tag,"m48-resident-boot-v1");
#if defined(M49_MANAGED_DELAY)
    managed_delay=text_is(tag,"m49-resident-boot-v1");
#if defined(M50_PERIODIC)
    managed_cycle=text_is(tag,"m50-resident-boot-v1");
    managed_delay |= managed_cycle;
#if defined(M51_CONTROLLER)
    managed_controller=text_is(tag,"m51-resident-boot-v1");
#if defined(M53_RESIDENT_COMPOSITION)
    managed_composition=text_is(tag,"m53-resident-boot-v1");
#if defined(M55_SIGNED_RESIDENT)
    managed_signed_resident=text_is(tag,"m55-resident-boot-v1");
    managed_composition |= managed_signed_resident;
#endif
    managed_controller |= managed_composition;
#endif
    managed_delay |= managed_controller;
#endif
#endif
    if (managed_delay) resident_mode=1;
#endif
#if defined(M44_G0_TEST_CONTROLS)
#if defined(M49_MANAGED_DELAY)
    if (text_is(tag,"m49-driver-test-v1")) { managed_delay=1; resident_mode=2; }
#if defined(M50_PERIODIC)
    if (text_is(tag,"m50-driver-test-v1")) { managed_cycle=1; managed_delay=1; resident_mode=2; }
#if defined(M51_CONTROLLER)
    if (text_is(tag,"m51-driver-test-v1")) { managed_controller=1; managed_delay=1; resident_mode=2; }
#if defined(M53_RESIDENT_COMPOSITION)
    if (text_is(tag,"m53-driver-test-v1")) { managed_composition=1; managed_controller=1; managed_delay=1; resident_mode=2; }
#if defined(M55_SIGNED_RESIDENT)
    if (text_is(tag,"m55-driver-test-v1")) { managed_signed_resident=1; managed_composition=1; managed_controller=1; managed_delay=1; resident_mode=2; }
#endif
#endif
#endif
#endif
#endif
    if (text_is(tag,"m48-driver-test-v1")) resident_mode=2;
    if (text_is(tag,"m48-backpressure-test-v1")) resident_mode=3;
#endif
    managed_services |= resident_mode!=0;
#endif
    managed |= managed_services;
#endif
    if (!managed && !text_is(tag, "m44-device-boot-v1")) return 0;
#else
    if (!pair(input, &tag, &body) || !text_is(tag, "m44-device-boot-v1")) return 0;
#endif
    #if defined(M47_MANAGED_SERVICES)
    if (managed_services) {
        if (!record(body,envelope,6) ||
#if defined(M49_MANAGED_DELAY)
            !(
#if defined(M51_CONTROLLER)
#if defined(M53_RESIDENT_COMPOSITION)
#if defined(M55_SIGNED_RESIDENT)
              managed_signed_resident ? m55_descriptor_read(envelope[0],envelope[1]) :
#endif
              managed_composition ? m53_descriptor_read(envelope[0],envelope[1]) :
#endif
              managed_controller ? m51_descriptor_read(envelope[0],envelope[1]) :
#endif
              managed_delay ? m49_descriptor_read(envelope[0],envelope[1]) : m47_descriptor_read(envelope[0],envelope[1])) ||
#else
            !m47_descriptor_read(envelope[0],envelope[1]) ||
#endif
            !m47_transport_config(envelope[5])) goto invalid;
    } else
    if (!record(body, envelope, 5) || !descriptor_read(envelope[0], envelope[1])) goto invalid;
    if (0
#else
    if (!record(body, envelope, 5) || !descriptor_read(envelope[0], envelope[1])
#endif
        || !record(envelope[2], catalog, 2) || !list(envelope[3], rows, MAX_COMMANDS, &count)
        || !scalar(envelope[4], 5, &boot_failure)) goto invalid;
#if defined(M48_RESIDENT)
    if (resident_mode==1 && (count || boot_failure)) goto invalid;
#endif
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
        if (!record(rows[i], command,
#if defined(M47_MANAGED_SERVICES)
            managed_services ? 6 :
#endif
            4) || !scalar(command[0],
#if defined(M45_MANAGED_LIFECYCLE)
            #if defined(M47_MANAGED_SERVICES)
#if defined(M49_MANAGED_DELAY) && defined(M44_G0_TEST_CONTROLS)
#if defined(M51_CONTROLLER)
            managed_controller ? 44 :
#endif
            managed_delay ? 43 :
#endif
            managed_services ? 39 :
#endif
            managed ? 21 : 16,
#else
            16,
#endif
            &c->op) || !c->op
            || !scalar(command[1], 2, &c->slot) || !typed_row(command[2], &c->row)
            || !scalar(command[3], UINT32_MAX, &c->argument)) goto invalid;
#if defined(M47_MANAGED_SERVICES)
        if (managed_services) {
            uint8_t token[8];
            if (!scalar(command[4],UINT32_MAX,&c->epoch) ||
                !noun_atom_read_fixed(command[5],token,8) ||
#if defined(M49_MANAGED_DELAY) && defined(M44_G0_TEST_CONTROLS)
                (!(managed_delay && (c->op==40 || c->op==42 || c->op==43)) && token[7]>127)
#else
                token[7]>127
#endif
                ) goto invalid;
            c->provider_token=0;
            for (uint32_t j=0;j<8;j++) c->provider_token |= (uint64_t)token[j]<<(8*j);
        }
#endif
#if !defined(M44_G0_TEST_CONTROLS)
        if (c->op == 5 || c->op == 6 || (c->op >= 14
#if defined(M45_MANAGED_LIFECYCLE)
            && c->op != 17
#if defined(M47_MANAGED_SERVICES)
            && !(managed_services && ((c->op>=22 && c->op<=24) || (c->op>=32 && c->op<=36)))
#endif
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
    if ((
#if defined(M47_MANAGED_SERVICES)
#if defined(M49_MANAGED_DELAY)
#if defined(M50_PERIODIC)
#if defined(M51_CONTROLLER)
         managed_controller ? m51_supervisor_init(session,&descriptor,handles,m47_bindings,resident_timer_bindings,&resident_completion) :
#endif
         managed_cycle ? m50_supervisor_init(session,&descriptor,handles,m47_bindings,m49_timer_binding) :
#endif
         managed_delay ? m49_supervisor_init(session,&descriptor,handles,m47_bindings,m49_timer_binding) :
#endif
         managed_services ? m47_supervisor_init(session,&descriptor,handles,m47_bindings) :
#endif
         managed ? m45_supervisor_init(session, &descriptor, handles)
                 : m44_supervisor_init(session, &descriptor, handles)) != M44_OK) goto invalid;
#else
    if (m44_supervisor_init(session, &descriptor, handles) != M44_OK) goto invalid;
#endif
    size_t storage = m44_supervisor_storage_bytes() + sizeof(commands) + sizeof(descriptor)
        + sizeof(handles) + sizeof(catalog_bytes) + sizeof(runtime) + sizeof(session);
#if defined(M48_RESIDENT)
    storage += m48_storage_bytes()+sizeof(resident_mode);
#if defined(M49_MANAGED_DELAY)
    storage += sizeof(managed_delay)+sizeof(m49_timer_binding);
#if defined(M50_PERIODIC)
    storage += sizeof(managed_cycle);
#if defined(M51_CONTROLLER)
    storage += sizeof(managed_controller)+sizeof(resident_timer_bindings)+sizeof(resident_completion);
#if defined(M53_RESIDENT_COMPOSITION)
    storage += sizeof(managed_composition);
#endif
#endif
#endif
#endif
#endif
    if (storage >
#if defined(M46_LIVE_REPLACEMENT)
        768u * 1024u
#else
        512u * 1024u
#endif
        ) goto invalid;
    uart_puts("M44 setup=0\r\n");
    uart_puts("M44 storage=");
    number(storage);
    uart_puts("\r\n");
#if defined(M48_RESIDENT)
    if (resident_mode) { if (!m48_run(resident_mode,count)) goto failed; return 1; }
#endif
    #if defined(M47_MANAGED_SERVICES)
    if (managed_services && !m47_transport_start()) goto failed;
#endif
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
#if defined(M47_MANAGED_SERVICES)
        else if (managed_services && c->op>=22) result = m47_command(c);
#endif
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

#if defined(M46_LIVE_REPLACEMENT)
/* The immutable boot pill is the local package allowlist. Re-decode it while
 * staging, then copy the selected bytes into the existing admission workspace.
 * No borrowed cell or package pointer survives a runtime promotion. */
static uint32_t package_count, stage_fault;
static uint8_t package_identity[4][32];
/* Explicit loader result. Descriptor/handle views borrow the existing fixed C
 * decode buffers until the next load. Init/stage copies them synchronously;
 * no moving noun pointer is exposed by this result. */
typedef struct {
    ResourceSession *session;
    const M44Descriptor *descriptor;
    const M44Saved *handles;
    uint8_t compatibility[32];
} M46LoadedPackage;

static int m46_envelope(noun input, noun packages[4], noun *script, uint32_t *count) {
    noun tag, body, fields[2];
    return pair(input, &tag, &body) && text_is(tag, "m46-device-boot-v1")
        && record(body, fields, 2) && list(fields[0], packages, 4, count)
        && *count && ((*script = fields[1]), 1);
}

static int m46_package_read(uint32_t index, uint8_t compatibility[32]) {
    noun input, packages[4], script, entry[3], tag, body, fields[3], catalog[2], parts[2];
    uint32_t count, version;
    uint8_t identity[32], supplied[32];
    const uint8_t *base = (const uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < 8; i++) bytes |= (uint64_t)base[i] << (i * 8u);
    if (!bytes || bytes > 1024u * 1024u || !index || index > package_count) return 0;
    int ok = cue_bounded_bytes(base + 16, bytes, &cue_i2_limits,
                              HEAP_MODE_SCRATCH, &input) == CUE_BOUNDED_OK;
    if (ok) ok = m46_envelope(input, packages, &script, &count) && count == package_count
        && record(packages[index - 1], entry, 3)
        && pair(entry[0], &tag, &body) && text_is(tag, "m46-compatible-package-v1")
        && record(body, fields, 3) && scalar(fields[0], 1, &version) && version == 1
        && digest(fields[2], compatibility)
        && hash_noun(entry[0], "1499kernel-m46-package-v1", 1, identity)
        && digest(entry[1], supplied) && same(identity, supplied, 32)
        && same(identity, package_identity[index - 1], 32)
        && hash_noun(fields[1], "1499kernel-m44-deployment-v1", 1, supplied);
    if (ok) {
        /* Descriptor read independently recomputes its canonical identity. */
        noun expected = cord_from_bytes((const char *)supplied, 32);
        for (uint32_t i = 0; i < sizeof(descriptor); i++) ((uint8_t *)&descriptor)[i] = 0;
        ok = descriptor_read(fields[1], expected) && record(entry[2], catalog, 2);
    }
    for (uint32_t i = 0; ok && i < 2; i++) {
        ok = record(catalog[i], parts, 2);
        for (uint32_t part = 0; ok && part < 2; part++)
            ok = atom_copy(parts[part], m44_boot_catalog_storage(i, part), MAX_JAM,
                           &catalog_bytes[i][part]);
    }
    noun_tx_abort();
    heap_scratch_reset();
    return ok;
}

static M44Status m46_load(uint32_t index, uint32_t bank, M46LoadedPackage *loaded) {
    ResourceSession **loaded_session = &loaded->session;
    *loaded_session = 0;
    loaded->descriptor = &descriptor;
    loaded->handles = handles;
    if (!(
#if defined(M52_RESIDENT_REPLACEMENT)
        managed_replacement ? m52_package_read(index, loaded->compatibility) :
#endif
        m46_package_read(index, loaded->compatibility))) return M44_INVALID;
#if defined(M52_RESIDENT_REPLACEMENT)
    if (managed_replacement) {
        if (!m52_catalog_validate()) return M44_INVALID;
    } else
#endif
    for (uint32_t i = 0; i < 2; i++) {
        noun core, admission;
        if (!decode(m44_boot_catalog_storage(i, 1), catalog_bytes[i][1], &core)
            || !payload_matches(core, i)
            || !decode(m44_boot_catalog_storage(i, 0), catalog_bytes[i][0], &admission)
            || !admission_matches(admission, i)) return M44_INVALID;
    }
    SupervisorAdmissionEntry entries[2];
    SupervisorAdmissionCatalog admitted;
    SessionCapability capability;
    for (uint32_t i = 0; i < 2; i++)
        entries[i] = (SupervisorAdmissionEntry){m44_boot_catalog_storage(i, 0), catalog_bytes[i][0],
                                               m44_boot_catalog_storage(i, 1), catalog_bytes[i][1]};
    uint32_t count = 2;
    if (catalog_bytes[0][0] == catalog_bytes[1][0] && catalog_bytes[0][1] == catalog_bytes[1][1]
        && same(entries[0].record_jam, entries[1].record_jam, catalog_bytes[0][0])
        && same(entries[0].resource_core_jam, entries[1].resource_core_jam, catalog_bytes[0][1])) count = 1;
    M38Status status = m38_supervisor_admission_catalog_make(&admitted, entries, count);
    if (!status) status = m38_resource_session_init(runtime,
        (uint8_t *)m44_boot_session_storage() + bank * 1024u * 1024u,
        1024u * 1024u, &admitted, loaded_session, &capability);
    if (status) return M44_INVALID;
    for (uint32_t i = 0; i < 2; i++) {
        noun core, request, result[2], loaded[2], hf[4];
        uint8_t identity[32];
        const ResourceResultView *view;
        if (!decode(m44_boot_catalog_storage(i, 1), catalog_bytes[i][1], &core)
            || !tagged("m38-resource-abi-v1-request", "m38-resource-abi-v1-request-schema-v1",
                       (noun[2]){direct(1), core}, 2, &request)
            || m38_resource_session_dispatch(*loaded_session, request, &view) != M38_STATUS_OK
            || !view || view->wire_status != 1
            || !tagged_fields(*view->root_slot, "m38-resource-abi-v1-result",
                              "m38-resource-abi-v1-result-schema-v1", result, 2)
            || !record(result[1], loaded, 2) || !record(loaded[0], hf, 4)
            || !digest(hf[3], identity) || !same(identity, descriptor.admission_identity[i], 32)
            || !save(loaded[0], &handles[i])) goto failure;
#if defined(M44_G0_TEST_CONTROLS)
        if (stage_fault == 10u + i) { stage_fault = 0; goto failure; }
        if (stage_fault == 12 && i == 0) goto failure;
#endif
    }
    return M44_OK;
failure:
#if defined(M44_G0_TEST_CONTROLS)
    /* An allocating public dispose could fail here and strand a registry slot.
     * Prove private abandonment succeeds even when the next copy must fail. */
    if (stage_fault == 12) noun_test_copy_fail_after(0);
#endif
    status = m46_resource_discard_unclaimed(*loaded_session);
#if defined(M44_G0_TEST_CONTROLS)
    if (stage_fault == 12) { noun_test_copy_fail_after(-1); stage_fault = 0; }
#endif
    if (status) return M44_FENCED; /* Unexpected ownership corruption is terminal to the loader. */
    *loaded_session = 0;
    return M44_INVALID;
}

static uint64_t m46_ticks(void) {
    uint64_t ticks;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(ticks));
    return ticks;
}

static void m46_measure(uint32_t row, uint32_t operation, uint64_t elapsed) {
    M46ResourceDiagnostics diagnostics = {0};
    uint64_t frequency;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    (void)m46_supervisor_diagnostics(&diagnostics);
    uart_puts("M46 measure={\"row\":"); number(row);
    uart_puts(",\"operation\":"); number(operation);
    uart_puts(",\"ticks\":"); number(elapsed);
    uart_puts(",\"counter_frequency_hz\":"); number(frequency);
    uart_puts(",\"persistent_cells\":"); number(heap_cells_used(HEAP_MODE_PERSIST));
    uart_puts(",\"scratch_cells\":"); number(heap_cells_used(HEAP_MODE_SCRATCH));
    uart_puts(",\"atom_bytes\":"); number(atom_store_bytes_used());
    uart_puts(",\"cell_bytes\":"); number(sizeof(cell_t));
    uart_puts(",\"persistent_peak_bytes\":"); number(noun_m46_heap_peak_bytes(HEAP_MODE_PERSIST));
    uart_puts(",\"scratch_peak_bytes\":"); number(noun_m46_heap_peak_bytes(HEAP_MODE_SCRATCH));
    uart_puts(",\"atom_peak_bytes\":"); number(noun_m46_atom_peak_bytes());
    uart_puts(",\"atom_index_occupancy\":"); number(atom_store_index_occupancy());
    uart_puts(",\"atom_index_peak\":"); number(noun_m46_atom_index_peak());
    uart_puts(",\"atom_index_capacity\":"); number(atom_store_index_capacity());
    uart_puts(",\"copy_map_peak\":"); number(noun_copy_map_hwm());
    uart_puts(",\"copy_map_capacity\":"); number(noun_copy_map_capacity());
    uart_puts(",\"commit_metadata_bytes\":"); number(sizeof(M44Descriptor) + 2 * sizeof(M44Saved));
    uart_puts(",\"registered_sessions\":"); number(diagnostics.registered_sessions);
    uart_puts(",\"issued_capability\":"); number(diagnostics.issued_capability);
    uart_puts(",\"session_storage_bytes\":"); number(diagnostics.session_storage_bytes);
    uart_puts(",\"session_actual_bytes\":"); number(diagnostics.session_actual_bytes);
    uart_puts("}\r\n");
}

static int m46_device_try_boot(noun input) {
    noun tag, body, packages[4], script, rows[MAX_COMMANDS], fields[6], entry[3];
    uint32_t count;
    if (!pair(input, &tag, &body) || !text_is(tag, "m46-device-boot-v1")) return 0;
    if (!m46_envelope(input, packages, &script, &package_count)
        || !list(script, rows, MAX_COMMANDS, &count)) goto invalid;
    for (uint32_t i = 0; i < package_count; i++)
        if (!record(packages[i], entry, 3) || !digest(entry[1], package_identity[i])) goto invalid;
    for (uint32_t i = 0; i < count; i++) {
        Command *c = &commands[i];
        if (!record(rows[i], fields, 6) || !scalar(fields[0], 28, &c->op) || !c->op
            || !scalar(fields[1], 4, &c->slot) || !typed_row(fields[2], &c->row)
            || !scalar(fields[3], UINT32_MAX, &c->argument)
            || !scalar(fields[4], UINT32_MAX, &expected_generation[i])
            || !scalar(fields[5], 4, &expected_package[i])) goto invalid;
#if !defined(M44_G0_TEST_CONTROLS)
        if (c->op == 5 || c->op == 6 || (c->op >= 14 && c->op != 17 &&
            c->op != 22 && c->op != 23 && c->op != 24)) goto invalid;
#endif
    }
    noun_tx_abort(); heap_scratch_reset();
    if (m38_resource_runtime_init(m44_boot_control(), 65536, m44_boot_workspace(),
                                 4u * 1024u * 1024u, &runtime)) goto invalid;
    M46LoadedPackage initial;
    if (m46_load(1, 0, &initial)
        || m46_supervisor_init(initial.session, initial.descriptor, initial.handles,
                               initial.compatibility)) goto invalid;
    session = initial.session;
    active_package = 1; live_replacement = 1;
    size_t storage = m44_supervisor_storage_bytes() + sizeof(commands) + sizeof(descriptor)
        + sizeof(handles) + sizeof(catalog_bytes) + sizeof(runtime) + sizeof(session)
        + sizeof(expected_generation) + sizeof(expected_package) + sizeof(package_identity) + 24;
    if (storage > 768u * 1024u) goto invalid;
    uart_puts("M44 setup=0\r\nM44 storage="); number(storage); uart_puts("\r\n");
    uint32_t checkpoints[2] = {0, 0}, tickets[2] = {0, 0};
    if (!emit(0, M44_OK, 0)) goto failed;
    m46_measure(0, 0, 0);
    for (uint32_t i = 0; i < count; i++) {
        const Command *c = &commands[i];
        uint32_t result = M44_INVALID, token = 0;
        uint64_t start = m46_ticks();
        session = m46_supervisor_active_session();
        if (expected_generation[i] != m46_supervisor_generation()
            || expected_package[i] != active_package) goto observed;
        if (c->op == 1) result = m44_supervisor_enqueue(c->slot, &c->row);
        else if (c->op == 2) result = m44_supervisor_dispatch();
        else if (c->op == 3 && c->argument < 2) {
            result = m44_supervisor_capture(&token);
            if (!result) checkpoints[c->argument] = token;
        } else if (c->op == 4 && c->argument < 2)
            result = m44_supervisor_restore(checkpoints[c->argument]);
        else if (c->op == 17) result = m45_supervisor_manage(c->argument, c->slot);
        else if (c->op == 22 && c->argument < 2 && c->slot && c->slot <= package_count) {
            const M44State *state = m44_supervisor_state();
            if (state->fenced) { result = M44_FENCED; goto observed; }
            if (state->lifecycle != 1 || m46_supervisor_candidate_token()
                || m46_supervisor_generation() == UINT32_MAX
                || same(package_identity[c->slot - 1], package_identity[active_package - 1], 32)) goto observed;
            M46LoadedPackage candidate;
            uint32_t bank = session == m44_boot_session_storage() ? 1 : 0;
            result = m46_load(c->slot, bank, &candidate);
            if (!result) result = m46_supervisor_stage(candidate.session, candidate.descriptor,
                candidate.handles, candidate.compatibility, expected_generation[i], &token);
            if (!result) { tickets[c->argument] = token; staged_package = c->slot; }
            else if (candidate.session && m46_resource_discard_unclaimed(candidate.session)) goto failed;
            if (result == M44_FENCED) goto failed;
        } else if (c->op == 23 && c->argument < 2) {
            result = m46_supervisor_activate(tickets[c->argument], expected_generation[i]);
            if (!result) { active_package = staged_package; staged_package = 0; }
        } else if (c->op == 24 && c->argument < 2) {
            result = m46_supervisor_cancel(tickets[c->argument], expected_generation[i]);
            if (!result) staged_package = 0;
        } else if (c->op == 7 || c->op == 13) {
            const ResourceResultView *view = 0;
            result = m38_resource_session_dispatch(session, NOUN_ZERO, &view);
        } else if (c->op == 8) result = m38_resource_session_reset(runtime, session);
        else if (c->op == 9) result = m38_resource_session_dispose(runtime, session);
        else if ((c->op == 11 || c->op == 12) && c->argument < 2) {
            M44ResourceInspection inspection;
            uint8_t identity[32];
            if (m44_supervisor_inspect(&inspection)) goto observed;
            for (uint32_t j = 0; j < 32; j++) identity[j] = m46_supervisor_active_descriptor()->identity[j];
            if (c->op == 11) identity[0] ^= 1;
            result = m44_supervisor_restore_checked(checkpoints[c->argument], identity,
                inspection.capability + (c->op == 12 ? 1 : 0));
        }
#if defined(M44_G0_TEST_CONTROLS)
        else if (c->op == 5) { m44_supervisor_test_fault(c->slot, c->argument); result = M44_OK; }
        else if (c->op == 6) { m44_supervisor_test_sequence(c->argument); result = M44_OK; }
        else if (c->op == 20) result = m45_supervisor_test_resource_control(c->argument);
        else if (c->op == 21) { m45_supervisor_test_epoch(c->argument); result = M44_OK; }
        else if (c->op == 25) {
            if (c->argument >= 10 && c->argument <= 12) stage_fault = c->argument;
            else m46_supervisor_test_fault(c->argument);
            result = M44_OK;
        } else if (c->op == 26) result = m46_supervisor_test_busy_mask();
        else if (c->op == 27) { m46_supervisor_test_generation(c->argument); result = M44_OK; }
        else if (c->op == 28) { m46_supervisor_test_ticket_serial(c->argument); result = M44_OK; }
#endif
observed:
        start = m46_ticks() - start;
        if (!emit(i + 1, result, token)) goto failed;
        m46_measure(i + 1, c->op, start);
    }
    uart_puts("M44 terminal=complete\r\n"); finish(); return 1;
invalid:
    uart_puts("M44 setup=1\r\n");
failed:
    uart_puts("M44 terminal=refuse\r\n"); finish(); return 1;
}
#endif
#if defined(M52_RESIDENT_REPLACEMENT)
#include "m52_device_resident.inc"
#endif
