#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "jam.h"
#include "m38_resource_runtime.h"
#include "m38_resource_test_controls.h"
#include "memory.h"
#include "noun.h"
#include "sha256.h"
#include "uart.h"

/*
 * M38-D8 Wave B B1 is deliberately a separate driver.  It is a scalar
 * semantic/lifetime witness, not a second runtime and not an extension of the
 * Wave A choreography.  It owns no ResourceSession state and never retains a
 * raw handle as authority across a dispatch; handles and result observations
 * are copied into fixed-width witness records.  A few raw result/cell nouns
 * are retained deliberately only as negative-test inputs for cross-session
 * refusal and stale-cell safety probes.
 */

#define B1_CORE_COUNT                 2u
#define B1_MAX_CORE_JAM_BYTES        (128u * 1024u)
#define B1_MAX_RECORD_JAM_BYTES      (128u * 1024u)
#define B1_MAX_PLAN_TYPES            8u
#define B1_MAX_PLAN_EVENTS           16u
#define B1_MAX_PLAN_VALUES           16u
#define B1_MAX_PLAN_STATES           8u
#define B1_MAX_PLAN_INSTANCES         8u
#define B1_MAX_LIVE_HANDLES           8u
#define B1_CELL_EXHAUSTION_COUNT   128001u
#define B1_OP_LOAD                    1u
#define B1_OP_POKE                    2u
#define B1_OP_PEEK                    3u
#define B1_OP_SNAPSHOT                4u
#define B1_OP_RESTORE                 5u

#define B1_WIRE_REFUSE              255u

static const char B1_REQUEST_TAG[] = "m38-resource-abi-v1-request";
static const char B1_REQUEST_SCHEMA[] = "m38-resource-abi-v1-request-schema-v1";
static const char B1_RESULT_TAG[] = "m38-resource-abi-v1-result";
static const char B1_STIMULUS_TAG[] = "m38-resource-abi-v1-numeric-stimulus";
static const char B1_STIMULUS_SCHEMA[] = "m38-resource-abi-v1-numeric-stimulus-schema-v1";
static const char B1_SELECTOR_TAG[] = "m38-resource-abi-v1-numeric-selector";
static const char B1_SELECTOR_SCHEMA[] = "m38-resource-abi-v1-numeric-selector-schema-v1";
static const char B1_VALUE_TAG[] = "m38-resource-abi-v1-numeric-value";
static const char B1_VALUE_SCHEMA[] = "m38-resource-abi-v1-numeric-value-schema-v1";

static uint8_t b1_control[64u * 1024u] __attribute__((aligned(64)));
static uint8_t b1_workspace[4u * 1024u * 1024u] __attribute__((aligned(64)));
static uint8_t b1_session_a[2u * 1024u * 1024u] __attribute__((aligned(64)));
static uint8_t b1_session_b[2u * 1024u * 1024u] __attribute__((aligned(64)));
static uint8_t b1_jams[B1_CORE_COUNT][2][B1_MAX_CORE_JAM_BYTES]
    __attribute__((aligned(64)));

typedef struct B1Type {
    uint32_t id;
    uint32_t value_count;
    uint32_t value_ids[B1_MAX_PLAN_VALUES];
    uint32_t value_types[B1_MAX_PLAN_VALUES];
    uint32_t event_count;
    uint32_t event_ids[B1_MAX_PLAN_EVENTS];
    uint32_t event_value_counts[B1_MAX_PLAN_EVENTS];
    uint32_t event_value_ids[B1_MAX_PLAN_EVENTS][B1_MAX_PLAN_VALUES];
    uint32_t state_count;
    uint32_t state_id;
} B1Type;

typedef struct B1Plan {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t instance_types[B1_MAX_PLAN_INSTANCES];
    B1Type types[B1_MAX_PLAN_TYPES];
    uint32_t stimulus_type;
    uint32_t stimulus_event;
    uint32_t stimulus_count;
    uint32_t stimulus_ids[B1_MAX_PLAN_VALUES];
} B1Plan;

typedef struct B1Handle {
    uint64_t capability;
    uint32_t slot;
    uint64_t generation;
    uint8_t admission_id[32];
    uint8_t valid;
} B1Handle;

typedef struct B1Mark {
    const ResourceResultView *view;
    uintptr_t view_address;
    uintptr_t root_slot_address;
    uint64_t generation;
    uint8_t wire_status;
    uint8_t owner;
    uint8_t valid;
    uint8_t sha256[32];
} B1Mark;

typedef struct B1StaleProof {
    uint64_t address;
    uint64_t before_selector;
    uint64_t before_base;
    uint64_t before_top;
    uint64_t after_selector;
    uint64_t after_active_base;
    uint64_t after_active_top;
    uint64_t after_inactive_base;
    uint64_t after_inactive_top;
    uint64_t status;
    uint8_t before_active;
    uint8_t after_active;
    uint8_t after_inactive;
    uint8_t selector_flipped;
    uint8_t valid;
} B1StaleProof;

static B1Mark b1_known[2][2];
static B1StaleProof b1_stale_proof;
static uint32_t b1_record_bytes[2];
static uint32_t b1_core_bytes[2];
static uint32_t b1_rows;
static uint32_t b1_passes;
static uint32_t b1_failures;
static uint64_t b1_summary_hash;
static M38Status b1_last_status;

static size_t b1_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static noun b1_cord(const char *s)
{
    return cord_from_bytes(s, b1_strlen(s));
}

static int b1_pair(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = cell->head;
    *tail = cell->tail;
    return 1;
}

static int b1_record(noun n, noun *out, uint32_t count)
{
    noun current = n;
    for (uint32_t i = 0; i < count; i++) {
        if (!b1_pair(current, &out[i], &current)) return 0;
    }
    return current == NOUN_ZERO;
}

static int b1_list(noun n, noun *out, uint32_t limit, uint32_t *count)
{
    noun current = n;
    uint32_t used = 0;
    while (current != NOUN_ZERO) {
        if (used == limit || !b1_pair(current, &out[used], &current)) return 0;
        used++;
    }
    *count = used;
    return 1;
}

static int b1_atom_text(noun n, const char *text)
{
    uint8_t bytes[256];
    size_t length = b1_strlen(text);
    if (length >= sizeof(bytes) || !noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (size_t i = 0; i < length; i++)
        if (bytes[i] != (uint8_t)text[i]) return 0;
    for (size_t i = length; i < sizeof(bytes); i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int b1_u(noun n, uint64_t maximum, uint32_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) > maximum) return 0;
    *out = (uint32_t)direct_val(n);
    return 1;
}

static int b1_u64(noun n, uint64_t *out)
{
    uint8_t bytes[8] = {0};
    uint64_t value = 0;
    if (!out || !noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (uint32_t i = 0; i < sizeof(bytes); i++) value |= (uint64_t)bytes[i] << (8u * i);
    *out = value;
    return 1;
}

static int b1_build_list(const noun *items, uint32_t count, noun *out)
{
    noun result = NOUN_ZERO;
    for (uint32_t i = count; i != 0; i--) {
        noun next;
        if (!alloc_cell_checked(items[i - 1u], result, &next)) return 0;
        result = next;
    }
    *out = result;
    return 1;
}

static int b1_build_record(const noun *items, uint32_t count, noun *out)
{
    return b1_build_list(items, count, out);
}

static int b1_build_tagged(const char *tag, const char *schema,
                           const noun *fields, uint32_t count, noun *out)
{
    noun row[17];
    if (count >= 16u) return 0;
    row[0] = b1_cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1u] = fields[i];
    noun body;
    if (!b1_build_record(row, count + 1u, &body)) return 0;
    return alloc_cell_checked(b1_cord(tag), body, out);
}

static int b1_parse_plan(noun core, B1Plan *out)
{
    noun formula, payload, payload_tag, payload_body, pf[2], semantic[5];
    noun types[8], instances[8];
    uint32_t type_count, instance_count;
    B1Plan plan = {0};
    if (!b1_pair(core, &formula, &payload)
        || !b1_pair(payload, &payload_tag, &payload_body)
        || !b1_atom_text(payload_tag, "m38-d0-r2-resource-payload")
        || !b1_record(payload_body, pf, 2)
        || !b1_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
        || !b1_record(pf[1], semantic, 5)
        || !b1_list(semantic[0], types, 8, &type_count)
        || !b1_list(semantic[1], instances, 8, &instance_count)
        || type_count == 0 || instance_count == 0) return 0;
    plan.type_count = type_count;
    plan.instance_count = instance_count;
    for (uint32_t i = 0; i < type_count; i++) {
        noun tf[6], events[16], values[16], states[8];
        uint32_t event_count, value_count, state_count;
        B1Type *type = &plan.types[i];
        if (!b1_record(types[i], tf, 6)
            || !b1_u(tf[0], 8, &type->id) || type->id != i + 1u
            || !b1_list(tf[1], events, 16, &event_count)
            || !b1_list(tf[2], values, 16, &value_count)
            || !b1_list(tf[3], states, 8, &state_count)
            || value_count == 0 || state_count == 0) return 0;
        type->event_count = event_count;
        type->value_count = value_count;
        type->state_count = state_count;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[4];
            if (!b1_record(values[j], vf, 4)
                || !b1_u(vf[0], 16, &type->value_ids[j])
                || type->value_ids[j] != j + 1u
                || !b1_u(vf[2], 2, &type->value_types[j])
                || (type->value_types[j] != 1 && type->value_types[j] != 2)) return 0;
        }
        for (uint32_t j = 0; j < state_count; j++) {
            noun sf[3];
            uint32_t state_id, initial;
            if (!b1_record(states[j], sf, 3)
                || !b1_u(sf[0], 8, &state_id)
                || !b1_u(sf[1], 1, &initial)) return 0;
            if (initial != 0) type->state_id = state_id;
        }
        if (type->state_id == 0) return 0;
        for (uint32_t j = 0; j < event_count; j++) {
            noun ef[3], event_values[16];
            uint32_t direction, event_value_count;
            if (!b1_record(events[j], ef, 3)
                || !b1_u(ef[0], 0xFFFFu, &type->event_ids[j])
                || type->event_ids[j] == 0
                || !b1_u(ef[1], 2, &direction)
                || !b1_list(ef[2], event_values, 16, &event_value_count)) return 0;
            type->event_value_counts[j] = event_value_count;
            for (uint32_t k = 0; k < event_value_count; k++)
                if (!b1_u(event_values[k], 16, &type->event_value_ids[j][k])) return 0;
        }
    }
    for (uint32_t i = 0; i < instance_count; i++) {
        noun fields[2];
        uint32_t id, type_id;
        if (!b1_record(instances[i], fields, 2)
            || !b1_u(fields[0], 8, &id) || id != i + 1u
            || !b1_u(fields[1], 8, &type_id) || type_id == 0 || type_id > type_count) return 0;
        plan.instance_types[i] = type_id;
    }
    for (uint32_t i = 0; i < type_count; i++) {
        for (uint32_t j = 0; j < plan.types[i].event_count; j++) {
            if (plan.types[i].event_value_counts[j] != 0) {
                plan.stimulus_type = i + 1u;
                plan.stimulus_event = plan.types[i].event_ids[j];
                plan.stimulus_count = plan.types[i].event_value_counts[j];
                for (uint32_t k = 0; k < plan.stimulus_count; k++)
                    plan.stimulus_ids[k] = plan.types[i].event_value_ids[j][k];
                *out = plan;
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t b1_atom_bytes(noun atom)
{
    if (noun_is_direct(atom)) {
        uint64_t value = direct_val(atom);
        uint32_t bytes = 0;
        while (value != 0) { bytes++; value >>= 8; }
        return bytes == 0 ? 1u : bytes;
    }
    if (!noun_is_indirect(atom)) return 0;
    atom_t *stored = atom_store_get(indirect_hash(atom));
    if (!stored || stored->size == 0 || stored->size > B1_MAX_CORE_JAM_BYTES / sizeof(uint64_t)) return 0;
    uint64_t last = stored->limbs[stored->size - 1u];
    uint32_t significant = sizeof(uint64_t);
    while (significant > 1u && ((last >> ((significant - 1u) * 8u)) & 0xffu) == 0) significant--;
    return (uint32_t)((stored->size - 1u) * sizeof(uint64_t) + significant);
}

static int b1_decode_pill(noun *out)
{
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < 8; i++) bytes |= (uint64_t)base[i] << (8u * i);
    if (bytes == 0 || bytes > 1024u * 1024u) return 0;
    return cue_bounded_bytes((const uint8_t *)(uintptr_t)(PILL_BASE + 16u), bytes,
                             &cue_i2_limits, HEAP_MODE_SCRATCH, out) == CUE_BOUNDED_OK;
}

static int b1_extract_jams(noun input, uint32_t record_bytes[2], uint32_t core_bytes[2])
{
    noun rows[2], pair[2];
    uint32_t count;
    if (!b1_list(input, rows, 2, &count) || count != 2) return 0;
    for (uint32_t i = 0; i < 2; i++) {
        if (!b1_record(rows[i], pair, 2)) return 0;
        record_bytes[i] = b1_atom_bytes(pair[0]);
        core_bytes[i] = b1_atom_bytes(pair[1]);
        if (record_bytes[i] == 0 || core_bytes[i] == 0
            || record_bytes[i] > B1_MAX_RECORD_JAM_BYTES
            || core_bytes[i] > B1_MAX_CORE_JAM_BYTES
            || !noun_atom_read_fixed(pair[0], b1_jams[i][0], record_bytes[i])
            || !noun_atom_read_fixed(pair[1], b1_jams[i][1], core_bytes[i])) return 0;
    }
    return 1;
}

static int b1_digest_atom(const uint8_t digest[32], noun *out)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    for (uint32_t i = 0; i < 4; i++)
        for (uint32_t j = 0; j < 8; j++) limbs[i] |= (uint64_t)digest[i * 8u + j] << (j * 8u);
    return make_atom_checked(limbs, 4, out);
}

static int b1_u64_atom(uint64_t value, noun *out)
{
    if (value <= 0x7FFFFFFFFFFFFFFFULL) { *out = direct(value); return 1; }
    return make_atom_checked(&value, 1, out);
}

static int b1_make_value(uint32_t id, uint32_t type, uint32_t value, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(value)};
    return b1_build_tagged(B1_VALUE_TAG, B1_VALUE_SCHEMA, fields, 3, out);
}

static int b1_make_stimulus(const B1Plan *plan, uint32_t delta, noun *out)
{
    const B1Type *type = &plan->types[plan->stimulus_type - 1u];
    noun values[B1_MAX_PLAN_VALUES];
    for (uint32_t i = 0; i < plan->stimulus_count; i++) {
        uint32_t kind = 0;
        for (uint32_t j = 0; j < type->value_count; j++)
            if (type->value_ids[j] == plan->stimulus_ids[i]) kind = type->value_types[j];
        if ((kind != 1 && kind != 2)
            || !b1_make_value(plan->stimulus_ids[i], kind, kind == 1 ? (delta & 1u) : delta, &values[i])) return 0;
    }
    noun list, fields[2];
    if (!b1_build_list(values, plan->stimulus_count, &list)) return 0;
    fields[0] = direct(plan->stimulus_event);
    fields[1] = list;
    return b1_build_tagged(B1_STIMULUS_TAG, B1_STIMULUS_SCHEMA, fields, 2, out);
}

static int b1_make_selector(noun *out)
{
    noun field = direct(1);
    return b1_build_tagged(B1_SELECTOR_TAG, B1_SELECTOR_SCHEMA, &field, 1, out);
}

static int b1_make_request(uint32_t operation, noun args, noun *out)
{
    noun fields[2] = {direct(operation), args};
    return b1_build_tagged(B1_REQUEST_TAG, B1_REQUEST_SCHEMA, fields, 2, out);
}

static int b1_result_body(const ResourceResultView *view, noun *out)
{
    noun tag, body, fields[3];
    if (!view || !view->root_slot || !b1_pair(*view->root_slot, &tag, &body)
        || !b1_atom_text(tag, B1_RESULT_TAG) || !b1_record(body, fields, 3)) return 0;
    *out = fields[2];
    return 1;
}

static int b1_handle_from_noun(noun value, B1Handle *out)
{
    noun fields[4];
    if (!out || !b1_record(value, fields, 4) || !b1_u64(fields[0], &out->capability)
        || out->capability == 0 || !b1_u(fields[1], B1_MAX_LIVE_HANDLES, &out->slot)
        || out->slot == 0 || !b1_u64(fields[2], &out->generation)
        || out->generation == 0 || !noun_atom_read_fixed(fields[3], out->admission_id, 32)) return 0;
    out->valid = 1;
    return 1;
}

static int b1_handle_to_noun(const B1Handle *handle, noun *out)
{
    noun fields[4], admission;
    if (!handle || !handle->valid || !b1_u64_atom(handle->capability, &fields[0])
        || !b1_digest_atom(handle->admission_id, &admission)
        || !b1_u64_atom(handle->generation, &fields[2])) return 0;
    fields[1] = direct(handle->slot);
    fields[3] = admission;
    return b1_build_record(fields, 4, out);
}

static int b1_handle_from_load(const ResourceResultView *view, B1Handle *out)
{
    noun body, fields[2];
    return b1_result_body(view, &body) && b1_record(body, fields, 2)
        && b1_handle_from_noun(fields[0], out);
}

static int b1_snapshot_request(const ResourceResultView *snapshot_view,
                               const B1Handle *request_handle,
                               noun *out)
{
    noun body, fields[3], snapshot_fields[3], handle, snapshot;
    uint64_t nonce;
    if (!b1_result_body(snapshot_view, &body) || !b1_record(body, fields, 3)
        || !b1_handle_to_noun(request_handle, &handle)
        || !b1_u64(fields[2], &nonce)) return 0;
    snapshot_fields[0] = fields[0];
    snapshot_fields[1] = fields[1];
    snapshot_fields[2] = direct(nonce);
    if (!b1_build_record(snapshot_fields, 3, &snapshot)) return 0;
    noun request_args[2] = {handle, snapshot};
    noun args;
    return b1_build_record(request_args, 2, &args) && b1_make_request(B1_OP_RESTORE, args, out);
}

static int b1_handle_request(uint32_t operation, const B1Handle *handle,
                             noun second, noun *out)
{
    noun handle_noun, args;
    if (!b1_handle_to_noun(handle, &handle_noun)) return 0;
    if (operation == B1_OP_SNAPSHOT) return b1_make_request(operation, handle_noun, out);
    noun fields[2] = {handle_noun, second};
    if (!b1_build_record(fields, 2, &args)) return 0;
    return b1_make_request(operation, args, out);
}

static int b1_root_sha(const ResourceResultView *view, uint8_t out[32])
{
    const uint8_t *bytes;
    uint64_t length;
    jam_admission_budget_t budget;
    if (!view || !view->root_slot) return 0;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(*view->root_slot, &bytes, &length, &budget) != 0) return 0;
    sha256_hash(bytes, length, out);
    return 1;
}

static void b1_mark(B1Mark *out, const ResourceResultView *view)
{
    out->view = view;
    out->view_address = (uintptr_t)view;
    out->root_slot_address = view ? (uintptr_t)view->root_slot : 0;
    out->generation = view ? view->generation : 0;
    out->wire_status = view ? view->wire_status : 0;
    out->owner = view ? (uint8_t)view->owner : 0;
    out->valid = view && view->root_slot && b1_root_sha(view, out->sha256);
}

static int b1_same(const B1Mark *left, const B1Mark *right)
{
    if (!left->valid || !right->valid) return 1;
    for (uint32_t i = 0; i < 32; i++)
        if (left->sha256[i] != right->sha256[i]) return 0;
    return left->view == right->view
        && left->view_address == right->view_address
        && left->root_slot_address == right->root_slot_address
        && left->generation == right->generation
        && left->wire_status == right->wire_status
        && left->owner == right->owner;
}

static void b1_refresh_known(void)
{
    for (uint32_t session = 0; session < 2; session++)
        for (uint32_t owner = 0; owner < 2; owner++)
            if (b1_known[session][owner].valid) b1_mark(&b1_known[session][owner], b1_known[session][owner].view);
}

static void b1_put_u64(uint64_t value)
{
    char buffer[24];
    uint32_t used = 0;
    do { buffer[used++] = (char)('0' + (value % 10u)); value /= 10u; } while (value != 0);
    while (used != 0) uart_putc((uint8_t)buffer[--used]);
}

static void b1_put_hex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) uart_putc((uint8_t)digits[(value >> shift) & 0xfu]);
}

static uint64_t b1_persist_base(uint64_t selector)
{
    return (uint64_t)HEAP_BASE + selector * (uint64_t)HEAP_PERSIST_HALF;
}

static int b1_range_contains(uint64_t address, uint64_t base, uint64_t top)
{
    return top >= base && top - base >= sizeof(cell_t)
        && address >= base && address <= top - sizeof(cell_t);
}

static void b1_emit_stale_proof(void)
{
    uart_puts("M38D8B1 v=1 stale-proof addr="); b1_put_hex(b1_stale_proof.address);
    uart_puts(" before_selector="); b1_put_u64(b1_stale_proof.before_selector);
    uart_puts(" before_base="); b1_put_hex(b1_stale_proof.before_base);
    uart_puts(" before_top="); b1_put_hex(b1_stale_proof.before_top);
    uart_puts(" after_selector="); b1_put_u64(b1_stale_proof.after_selector);
    uart_puts(" after_active_base="); b1_put_hex(b1_stale_proof.after_active_base);
    uart_puts(" after_active_top="); b1_put_hex(b1_stale_proof.after_active_top);
    uart_puts(" after_inactive_base="); b1_put_hex(b1_stale_proof.after_inactive_base);
    uart_puts(" after_inactive_top="); b1_put_hex(b1_stale_proof.after_inactive_top);
    uart_puts(" before_active="); b1_put_u64(b1_stale_proof.before_active);
    uart_puts(" after_active="); b1_put_u64(b1_stale_proof.after_active);
    uart_puts(" after_inactive="); b1_put_u64(b1_stale_proof.after_inactive);
    uart_puts(" selector_flipped="); b1_put_u64(b1_stale_proof.selector_flipped);
    uart_puts(" status="); b1_put_u64(b1_stale_proof.status);
    uart_puts(" valid="); b1_put_u64(b1_stale_proof.valid);
    uart_puts("\r\n");
}

static void b1_put_sha(const uint8_t digest[32])
{
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < 32; i++) {
        uart_putc((uint8_t)digits[digest[i] >> 4]);
        uart_putc((uint8_t)digits[digest[i] & 0xfu]);
    }
}

static uint64_t b1_hash_bytes(uint64_t hash, const uint8_t *bytes, size_t count)
{
    for (size_t i = 0; i < count; i++) { hash ^= bytes[i]; hash *= UINT64_C(1099511628211); }
    return hash;
}

static uint64_t b1_hash_u64(uint64_t hash, uint64_t value)
{
    for (uint32_t i = 0; i < 8; i++) { hash ^= (uint8_t)(value >> (8u * i)); hash *= UINT64_C(1099511628211); }
    return hash;
}

static void b1_row(const char *name, int pass, M38Status status,
                   const ResourceResultView *view, int preserved, uint32_t detail)
{
    uint8_t wire = view ? view->wire_status : 0;
    uint8_t published = view ? 1u : 0u;
    b1_summary_hash = b1_hash_bytes(b1_summary_hash, (const uint8_t *)name, b1_strlen(name));
    b1_summary_hash = b1_hash_u64(b1_summary_hash, (uint64_t)status);
    b1_summary_hash = b1_hash_u64(b1_summary_hash, wire);
    b1_summary_hash = b1_hash_u64(b1_summary_hash, published);
    b1_summary_hash = b1_hash_u64(b1_summary_hash, (uint64_t)preserved);
    b1_summary_hash = b1_hash_u64(b1_summary_hash, detail);
    b1_rows++;
    if (pass) b1_passes++; else b1_failures++;
    uart_puts("M38D8B1 v=1 row="); b1_put_u64(b1_rows);
    uart_puts(" case="); uart_puts(name); uart_puts(" verdict="); uart_puts(pass ? "pass" : "fail");
    uart_puts(" st="); b1_put_u64(status); uart_puts(" wire="); b1_put_u64(wire);
    uart_puts(" view="); b1_put_u64(published); uart_puts(" preserve="); b1_put_u64(preserved);
    uart_puts(" detail="); b1_put_u64(detail);
    uart_puts(" a_addr="); b1_put_hex(b1_known[0][0].view_address);
    uart_puts(" a_slot="); b1_put_hex(b1_known[0][0].root_slot_address);
    uart_puts(" a_gen="); b1_put_u64(b1_known[0][0].generation);
    uart_puts(" a_sha="); if (b1_known[0][0].valid) b1_put_sha(b1_known[0][0].sha256); else uart_puts("none");
    uart_puts(" b_addr="); b1_put_hex(b1_known[1][0].view_address);
    uart_puts(" b_slot="); b1_put_hex(b1_known[1][0].root_slot_address);
    uart_puts(" b_gen="); b1_put_u64(b1_known[1][0].generation);
    uart_puts(" b_sha="); if (b1_known[1][0].valid) b1_put_sha(b1_known[1][0].sha256); else uart_puts("none");
    uart_puts(" summary="); b1_put_hex(b1_summary_hash); uart_puts("\r\n");
}

static uint8_t b1_mask_all(void) { return 0x0fu; }

static int b1_call(const char *name, ResourceSession *session, uint32_t target,
                   noun request, M38Status expected_status, uint8_t expected_wire,
                   uint8_t expected_view, uint8_t preserve_mask, uint32_t detail,
                   const ResourceResultView **view_out)
{
    B1Mark before[2][2], after[2][2];
    for (uint32_t s = 0; s < 2; s++) for (uint32_t o = 0; o < 2; o++) {
        before[s][o] = b1_known[s][o];
        after[s][o] = b1_known[s][o];
    }
    const ResourceResultView *view = 0;
    M38Status status = m38_resource_session_dispatch(session, request, &view);
    b1_last_status = status;
    for (uint32_t s = 0; s < 2; s++) for (uint32_t o = 0; o < 2; o++)
        if (after[s][o].valid) b1_mark(&after[s][o], after[s][o].view);
    int preserved = 1;
    for (uint32_t s = 0; s < 2; s++) for (uint32_t o = 0; o < 2; o++)
        if ((preserve_mask & (uint8_t)(1u << (s * 2u + o))) != 0
            && !b1_same(&before[s][o], &after[s][o])) preserved = 0;
    int shape = status == expected_status && ((expected_view == 0 && view == 0)
        || (expected_view != 0 && view && view->wire_status == expected_wire));
    if (status == M38_STATUS_OK && view && view->owner <= M38_RESULT_OWNER_REFUSAL)
        b1_mark(&b1_known[target][view->owner == M38_RESULT_OWNER_PRIMARY ? 0 : 1], view);
    int pass = shape && preserved;
    b1_row(name, pass, status, view, preserved, detail);
    if (view_out) *view_out = view;
    return pass;
}

static int b1_load_request(uint32_t core_index, noun *out)
{
    noun core;
    heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(b1_jams[core_index][1], b1_core_bytes[core_index],
                          &cue_i2_limits, HEAP_MODE_PERSIST, &core) != CUE_BOUNDED_OK) return 0;
    noun_tx_commit();
    return b1_make_request(B1_OP_LOAD, core, out);
}

static int b1_valid_request(uint32_t operation, const B1Handle *handle,
                            const B1Plan *plan, uint32_t delta, noun *out)
{
    noun second = NOUN_ZERO;
    if (operation == B1_OP_POKE && !b1_make_stimulus(plan, delta, &second)) return 0;
    if (operation == B1_OP_PEEK && !b1_make_selector(&second)) return 0;
    return b1_handle_request(operation, handle, second, out);
}

static void b1_lifecycle_row(const char *name, M38Status status, int pass, uint32_t detail)
{
    b1_row(name, pass, status, 0, 1, detail);
}

static int b1_setup_plans(B1Plan plans[2])
{
    for (uint32_t i = 0; i < B1_CORE_COUNT; i++) {
        noun core;
        heap_set_mode(HEAP_MODE_SCRATCH);
        if (cue_bounded_bytes(b1_jams[i][1], b1_core_bytes[i], &cue_i2_limits,
                              HEAP_MODE_SCRATCH, &core) != CUE_BOUNDED_OK
            || !b1_parse_plan(core, &plans[i])) return 0;
        noun_tx_commit();
    }
    return 1;
}

static int b1_make_cycle(noun *out)
{
    heap_set_mode(HEAP_MODE_PERSIST);
    if (!alloc_cell_checked(NOUN_ZERO, NOUN_ZERO, out)) return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(*out);
    cell->head = *out;
    cell->tail = NOUN_ZERO;
    return 1;
}

static int b1_make_chain(uint32_t count, noun *out)
{
    noun current = NOUN_ZERO;
    heap_set_mode(HEAP_MODE_PERSIST);
    for (uint32_t i = 0; i < count; i++)
        if (!alloc_cell_checked(direct(i), current, &current)) return 0;
    *out = current;
    return 1;
}

static int b1_snapshot_state_sha(const ResourceResultView *view, uint8_t digest[32])
{
    noun body, fields[3];
    if (!b1_result_body(view, &body) || !b1_record(body, fields, 3)) return 0;
    const uint8_t *bytes;
    uint64_t length;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(fields[1], &bytes, &length, &budget) != 0) return 0;
    sha256_hash(bytes, length, digest);
    return 1;
}

static int b1_read_load_view(const ResourceResultView *view, B1Handle *out)
{
    return view && view->owner == M38_RESULT_OWNER_PRIMARY
        && view->wire_status == B1_OP_LOAD && b1_handle_from_load(view, out);
}

void m38_resource_b1_boot(void)
{
    noun input;
    B1Plan plans[2];
    SupervisorAdmissionEntry entries[2];
    SupervisorAdmissionCatalog catalog;
    ResourceRuntime *runtime = 0;
    ResourceSession *session_a = 0, *session_b = 0;
    SessionCapability cap_a = 0, cap_b = 0;
    B1Handle handle_a = {0}, handle_b0 = {0}, handle_b1 = {0};
    const ResourceResultView *view = 0;
    const ResourceResultView *snapshot_a_view = 0;
    const ResourceResultView *snapshot_b_view = 0;
    noun request, selector, stimulus;

    b1_summary_hash = UINT64_C(1469598103934665603);
    b1_rows = b1_passes = b1_failures = 0;
    b1_stale_proof = (B1StaleProof){0};
    for (uint32_t i = 0; i < 2; i++) for (uint32_t j = 0; j < 2; j++) b1_known[i][j].valid = 0;

    if (!b1_decode_pill(&input)) goto setup_refuse;
    if (!b1_extract_jams(input, b1_record_bytes, b1_core_bytes)) goto setup_refuse;
    if (noun_tx_active()) noun_tx_abort();
    heap_scratch_reset();
    if (!b1_setup_plans(plans)) goto setup_refuse;
    entries[0] = (SupervisorAdmissionEntry){b1_jams[0][0], b1_record_bytes[0], b1_jams[0][1], b1_core_bytes[0]};
    entries[1] = (SupervisorAdmissionEntry){b1_jams[1][0], b1_record_bytes[1], b1_jams[1][1], b1_core_bytes[1]};
    if (m38_supervisor_admission_catalog_make(&catalog, entries, 2) != M38_STATUS_OK
        || m38_resource_runtime_init(b1_control, sizeof(b1_control), b1_workspace, sizeof(b1_workspace), &runtime) != M38_STATUS_OK
        || m38_resource_session_init(runtime, b1_session_a, sizeof(b1_session_a), &catalog, &session_a, &cap_a) != M38_STATUS_OK
        || m38_resource_session_init(runtime, b1_session_b, sizeof(b1_session_b), &catalog, &session_b, &cap_b) != M38_STATUS_OK
        || cap_a == cap_b || cap_a == 0 || cap_b == 0) goto setup_refuse;

    /* The fault is armed before the first LOAD.  A contract-conforming cache
     * inserts once here, refuses atomically, and then succeeds on retry. */
    m38_resource_test_fail_next(runtime, M38_FAULT_CUE_CACHE_INSERT);
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("first-load-cache-insert", session_a, 0, request,
                  M38_STATUS_CUE_CACHE_INSERT, 0, 0, b1_mask_all(), 1, &view);
    if (b1_last_status == M38_STATUS_CUE_CACHE_INSERT) {
        if (!b1_load_request(0, &request)) goto setup_refuse;
        (void)b1_call("first-load-retry", session_a, 0, request,
                      M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 2, &view);
    }
    if (!b1_read_load_view(view, &handle_a)) goto setup_refuse;

    m38_resource_test_fail_next(runtime, M38_FAULT_CUE_CACHE_INSERT);
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("repeat-load-cache-reuse", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 3, &view);
    if (b1_last_status == M38_STATUS_CUE_CACHE_INSERT) {
        if (!b1_load_request(0, &request)) goto setup_refuse;
        (void)b1_call("repeat-load-retry", session_a, 0, request,
                      M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 4, &view);
    }
    if (!b1_read_load_view(view, &handle_a)) goto setup_refuse;
    /* A cache-hit control is intentionally not consumed; keep it from
     * leaking into the next session's first LOAD. */
    m38_resource_test_fail_next(runtime, M38_FAULT_NONE);

    if (!b1_load_request(1, &request)) goto setup_refuse;
    (void)b1_call("session-b-load-event-data-order", session_b, 1, request,
                  M38_STATUS_OK, B1_OP_LOAD, 1, 0x0bu, 5, &view);
    if (!b1_read_load_view(view, &handle_b1)) goto setup_refuse;
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("session-b-load-counter-threshold", session_b, 1, request,
                  M38_STATUS_OK, B1_OP_LOAD, 1, 0x0bu, 6, &view);
    if (!b1_read_load_view(view, &handle_b0)) goto setup_refuse;

    /* Exactly eight handles are admitted; the ninth is an ordinary refusal. */
    for (uint32_t i = 3; i <= B1_MAX_LIVE_HANDLES; i++) {
        if (!b1_load_request(0, &request)) goto setup_refuse;
        (void)b1_call("live-handle-admit", session_a, 0, request,
                      M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 7u + i, &view);
        if (!b1_read_load_view(view, &handle_a)) goto setup_refuse;
    }
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("live-handle-ninth-refusal", session_a, 0, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x0du, 15, &view);

    if (!b1_valid_request(B1_OP_PEEK, &handle_b1, &plans[1], 0, &request)) goto setup_refuse;
    (void)b1_call("interleaved-global-promotion-isolation", session_b, 1, request,
                  M38_STATUS_OK, B1_OP_PEEK, 1, 0x0bu, 20, &view);
    if (!b1_make_selector(&selector)) goto setup_refuse;
    /* A's handle is intentionally submitted to B: authority must refuse. */
    if (!b1_handle_request(B1_OP_PEEK, &handle_a, selector, &request)) goto setup_refuse;
    (void)b1_call("cross-session-handle-a-to-b", session_b, 1, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x07u, 21, &view);
    if (!b1_make_selector(&selector)) goto setup_refuse;
    if (!b1_handle_request(B1_OP_PEEK, &handle_b1, selector, &request)) goto setup_refuse;
    (void)b1_call("cross-session-handle-b-to-a", session_a, 0, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x0du, 22, &view);

    /* A result noun is safely traversable but is not a request for B. */
    noun a_result = *b1_known[0][0].view->root_slot;
    (void)b1_call("cross-session-result-a-to-b", session_b, 1, a_result,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x07u, 23, &view);
    noun b_result = *b1_known[1][0].view->root_slot;
    (void)b1_call("cross-session-result-b-to-a", session_a, 0, b_result,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x0du, 24, &view);

    if (!b1_handle_request(B1_OP_SNAPSHOT, &handle_a, NOUN_ZERO, &request)) goto setup_refuse;
    (void)b1_call("snapshot-a", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_SNAPSHOT, 1, 0x0eu, 25, &snapshot_a_view);
    if (!snapshot_a_view) goto setup_refuse;
    if (!b1_handle_request(B1_OP_SNAPSHOT, &handle_b0, NOUN_ZERO, &request)) goto setup_refuse;
    (void)b1_call("snapshot-b", session_b, 1, request,
                  M38_STATUS_OK, B1_OP_SNAPSHOT, 1, 0x0bu, 26, &snapshot_b_view);
    if (!snapshot_b_view) goto setup_refuse;
    uint8_t state_a_sha[32], state_b_sha[32];
    int equal_state = b1_snapshot_state_sha(snapshot_a_view, state_a_sha)
        && b1_snapshot_state_sha(snapshot_b_view, state_b_sha);
    for (uint32_t i = 0; i < 32 && equal_state; i++) if (state_a_sha[i] != state_b_sha[i]) equal_state = 0;
    if (!b1_snapshot_request(snapshot_a_view, &handle_b0, &request)) goto setup_refuse;
    (void)b1_call("equal-state-wrong-handle-restore", session_b, 1, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x07u, equal_state ? 27 : 28, &view);
    if (!b1_snapshot_request(snapshot_a_view, &handle_a, &request)) goto setup_refuse;
    (void)b1_call("restore-a", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_RESTORE, 1, 0x0eu, 29, &view);

    if (!b1_valid_request(B1_OP_PEEK, &handle_a, &plans[0], 0, &request)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_BROKER_BEGIN);
    (void)b1_call("fault-broker-begin", session_a, 0, request,
                  M38_STATUS_BROKER_BEGIN, 0, 0, b1_mask_all(), 30, &view);
    if (!b1_valid_request(B1_OP_PEEK, &handle_a, &plans[0], 0, &request)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_SLOT_PUBLICATION);
    (void)b1_call("fault-slot-publication", session_a, 0, request,
                  M38_STATUS_SLOT_PUBLICATION, 0, 0, b1_mask_all(), 31, &view);
    if (!b1_valid_request(B1_OP_POKE, &handle_a, &plans[0], 3, &stimulus)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_EVALUATOR_ABORT);
    (void)b1_call("fault-evaluator-abort", session_a, 0, stimulus,
                  M38_STATUS_EVALUATOR_ABORT, 0, 0, b1_mask_all(), 32, &view);
    if (!b1_valid_request(B1_OP_PEEK, &handle_a, &plans[0], 0, &request)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_ATOM_RESULT_STAGING);
    (void)b1_call("fault-atom-result-staging", session_a, 0, request,
                  M38_STATUS_ATOM_RESULT_STAGING, 0, 0, b1_mask_all(), 33, &view);
    if (!b1_valid_request(B1_OP_PEEK, &handle_a, &plans[0], 0, &request)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_COLLECTIVE_COMMIT);
    (void)b1_call("fault-collective-commit", session_a, 0, request,
                  M38_STATUS_COLLECTIVE_COMMIT, 0, 0, b1_mask_all(), 34, &view);
    if (!b1_handle_request(B1_OP_SNAPSHOT, &handle_a, NOUN_ZERO, &request)) goto setup_refuse;
    (void)b1_call("fault-restore-snapshot", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_SNAPSHOT, 1, 0x0eu, 35, &snapshot_a_view);
    if (!snapshot_a_view || !b1_snapshot_request(snapshot_a_view, &handle_a, &request)) goto setup_refuse;
    m38_resource_test_fail_next(runtime, M38_FAULT_RESTORE_COMMIT);
    (void)b1_call("fault-restore-commit", session_a, 0, request,
                  M38_STATUS_RESTORE_COMMIT, 0, 0, b1_mask_all(), 36, &view);
    if (!b1_snapshot_request(snapshot_a_view, &handle_a, &request)) goto setup_refuse;
    (void)b1_call("fault-restore-retry", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_RESTORE, 1, 0x0eu, 37, &view);

    B1Handle old_handle_a = handle_a;
    M38Status lifecycle = m38_resource_session_reset(runtime, session_a);
    b1_refresh_known();
    b1_lifecycle_row("reset-preserves-capability", lifecycle, lifecycle == M38_STATUS_OK, 38);
    if (!b1_make_selector(&selector) || !b1_handle_request(B1_OP_PEEK, &old_handle_a, selector, &request)) goto setup_refuse;
    (void)b1_call("reset-invalidates-old-handle", session_a, 0, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x0du, 39, &view);
    m38_resource_test_fail_next(runtime, M38_FAULT_CUE_CACHE_INSERT);
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("reset-preserves-cache", session_a, 0, request,
                  M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 40, &view);
    /* A reused cache deliberately does not consume the first-LOAD fault;
     * clear that one-shot control before dispose/reinit exercises an empty
     * cache again. */
    m38_resource_test_fail_next(runtime, M38_FAULT_NONE);
    int same_capability = b1_read_load_view(view, &handle_a) && handle_a.capability == old_handle_a.capability
        && handle_a.generation != old_handle_a.generation;
    b1_row("reset-handle-generation", same_capability, M38_STATUS_OK, view, 1,
            same_capability ? 1u : 0u);

    lifecycle = m38_resource_session_dispose(runtime, session_a);
    b1_refresh_known();
    b1_lifecycle_row("dispose-clears-session", lifecycle, lifecycle == M38_STATUS_OK, 41);
    if (!b1_make_selector(&selector) || !b1_handle_request(B1_OP_PEEK, &old_handle_a, selector, &request)) goto setup_refuse;
    (void)b1_call("disposed-session-refusal", session_a, 0, request,
                  M38_STATUS_SESSION_CLOSED, 0, 0, b1_mask_all(), 42, &view);
    ResourceSession *reinit_session = 0;
    SessionCapability reinit_cap = 0;
    lifecycle = m38_resource_session_init(runtime, b1_session_a, sizeof(b1_session_a), &catalog,
                                          &reinit_session, &reinit_cap);
    int fresh_capability = lifecycle == M38_STATUS_OK && reinit_cap != old_handle_a.capability;
    b1_lifecycle_row("reinit-fresh-capability", lifecycle, fresh_capability, 43);
    session_a = reinit_session;
    if (!b1_make_selector(&selector) || !b1_handle_request(B1_OP_PEEK, &old_handle_a, selector, &request)) goto setup_refuse;
    (void)b1_call("reinit-refuses-old-authority", session_a, 0, request,
                  M38_STATUS_OK, B1_WIRE_REFUSE, 1, 0x0du, 44, &view);
    m38_resource_test_fail_next(runtime, M38_FAULT_CUE_CACHE_INSERT);
    if (!b1_load_request(0, &request)) goto setup_refuse;
    (void)b1_call("reinit-load", session_a, 0, request,
                  M38_STATUS_CUE_CACHE_INSERT, 0, 0, b1_mask_all(), 45, &view);
    if (b1_last_status == M38_STATUS_CUE_CACHE_INSERT) {
        if (!b1_load_request(0, &request)) goto setup_refuse;
        (void)b1_call("reinit-load-retry", session_a, 0, request,
                      M38_STATUS_OK, B1_OP_LOAD, 1, 0x0eu, 46, &view);
    }
    if (!b1_read_load_view(view, &handle_a)) goto setup_refuse;

    /* Allocate the negative-test cell in the active persistent semispace,
     * then make it inactive by a real collective promotion.  The request
     * used as the promotion control is built in scratch so only the named
     * cell is the stale witness. */
    noun stale;
    heap_set_mode(HEAP_MODE_PERSIST);
    uint64_t stale_before_selector = heap_persist_selector();
    uint64_t stale_before_base = b1_persist_base(stale_before_selector);
    uint64_t stale_before_top = stale_before_base + (uint64_t)HEAP_PERSIST_HALF;
    if (!alloc_cell_checked(direct(7), direct(9), &stale)) goto setup_refuse;
    b1_stale_proof.address = (uint64_t)cell_ptr(stale);
    b1_stale_proof.before_selector = stale_before_selector;
    b1_stale_proof.before_base = stale_before_base;
    b1_stale_proof.before_top = stale_before_top;
    b1_stale_proof.before_active = b1_range_contains(
        b1_stale_proof.address, stale_before_base, stale_before_top);
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!b1_valid_request(B1_OP_PEEK, &handle_b1, &plans[1], 0, &request)) goto setup_refuse;
    (void)b1_call("stale-cell-promotion-control", session_b, 1, request,
                  M38_STATUS_OK, B1_OP_PEEK, 1, 0x0bu, 46, &view);
    b1_stale_proof.after_selector = heap_persist_selector();
    b1_stale_proof.after_active_base = b1_persist_base(b1_stale_proof.after_selector);
    b1_stale_proof.after_active_top = b1_stale_proof.after_active_base
        + (uint64_t)HEAP_PERSIST_HALF;
    uint64_t stale_inactive_selector = b1_stale_proof.after_selector ^ 1u;
    b1_stale_proof.after_inactive_base = b1_persist_base(stale_inactive_selector);
    b1_stale_proof.after_inactive_top = b1_stale_proof.after_inactive_base
        + (uint64_t)HEAP_PERSIST_HALF;
    b1_stale_proof.after_active = b1_range_contains(
        b1_stale_proof.address, b1_stale_proof.after_active_base,
        b1_stale_proof.after_active_top);
    b1_stale_proof.after_inactive = b1_range_contains(
        b1_stale_proof.address, b1_stale_proof.after_inactive_base,
        b1_stale_proof.after_inactive_top);
    b1_stale_proof.selector_flipped =
        b1_stale_proof.after_selector != b1_stale_proof.before_selector;
    (void)b1_call("request-invalid-forged-cell", session_a, 0, cell_noun(0x12345678u),
                  M38_STATUS_REQUEST_INVALID, 0, 0, b1_mask_all(), 47, &view);
    (void)b1_call("request-invalid-out-of-range-cell", session_a, 0,
                  cell_noun((uint32_t)(HEAP_TOP + 8u)), M38_STATUS_REQUEST_INVALID,
                  0, 0, b1_mask_all(), 48, &view);
    (void)b1_call("request-invalid-misaligned-cell", session_a, 0,
                  cell_noun((uint32_t)(HEAP_BASE + 1u)), M38_STATUS_REQUEST_INVALID,
                  0, 0, b1_mask_all(), 49, &view);
    (void)b1_call("request-invalid-stale-cell", session_a, 0, stale,
                  M38_STATUS_REQUEST_INVALID, 0, 0, b1_mask_all(), 50, &view);
    b1_stale_proof.status = b1_last_status;
    b1_stale_proof.valid = b1_stale_proof.before_active
        && b1_stale_proof.selector_flipped
        && !b1_stale_proof.after_active
        && b1_stale_proof.after_inactive
        && b1_stale_proof.status == M38_STATUS_REQUEST_INVALID;
    b1_emit_stale_proof();
    (void)b1_call("request-invalid-missing-indirect-atom", session_a, 0,
                  indirect(UINT64_C(0x3ffffffffffffffe)), M38_STATUS_REQUEST_INVALID,
                  0, 0, b1_mask_all(), 51, &view);
    noun cycle;
    if (!b1_make_cycle(&cycle)) goto setup_refuse;
    (void)b1_call("request-invalid-cycle", session_a, 0, cycle,
                  M38_STATUS_REQUEST_INVALID, 0, 0, b1_mask_all(), 52, &view);
    noun deep;
    if (!b1_make_chain(258u, &deep)) goto setup_refuse;
    (void)b1_call("request-invalid-depth-exhaustion", session_a, 0, deep,
                  M38_STATUS_REQUEST_INVALID, 0, 0, b1_mask_all(), 53, &view);
    noun wide;
    if (!b1_make_chain(B1_CELL_EXHAUSTION_COUNT, &wide)) goto setup_refuse;
    (void)b1_call("request-invalid-cell-exhaustion", session_a, 0, wide,
                  M38_STATUS_REQUEST_INVALID, 0, 0, b1_mask_all(), 54, &view);

    uart_puts("M38D8B1 v=1 summary rows="); b1_put_u64(b1_rows);
    uart_puts(" pass="); b1_put_u64(b1_passes); uart_puts(" fail="); b1_put_u64(b1_failures);
    uart_puts(" hash="); b1_put_hex(b1_summary_hash); uart_puts("\r\n");
    uart_puts("M38D8B1 v=1 terminal=complete\r\n");
    return;

setup_refuse:
    uart_puts("M38D8B1 v=1 terminal=refuse\r\n");
}
