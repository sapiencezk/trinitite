#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "jam.h"
#include "m38_resource_b2_observability.h"
#include "m38_resource_test_controls.h"
#include "m38_resource_runtime.h"
#include "memory.h"
#include "noun.h"
#include "nock.h"
#include "uart.h"

#define B2_CORE_COUNT 2u
#define B2_MAX_CORE_JAM_BYTES (128u * 1024u)
#define B2_MAX_RECORD_JAM_BYTES (128u * 1024u)
#define B2_MAX_PLAN_TYPES 8u
#define B2_MAX_PLAN_EVENTS 16u
#define B2_MAX_PLAN_VALUES 16u
#define B2_MAX_PLAN_STATES 8u
#define B2_MAX_PLAN_INSTANCES 8u
#define B2_MAX_VALUES 16u
#define B2_HANDLE_DIGEST_BYTES 32u
#define B2_MAX_LIVE_HANDLES 8u
#define B2_LAYOUT_CHURN_CELLS 64u

#define B2_OP_LOAD 1u
#define B2_OP_POKE 2u
#define B2_OP_PEEK 3u
#define B2_OP_SNAPSHOT 4u
#define B2_OP_RESTORE 5u

#define B2_WIRE_OK 0u
#define B2_WIRE_REFUSE 255u

static const char B2_REQUEST_TAG[] = "m38-resource-abi-v1-request";
static const char B2_REQUEST_SCHEMA[] = "m38-resource-abi-v1-request-schema-v1";
static const char B2_RESULT_TAG[] = "m38-resource-abi-v1-result";
static const char B2_STIMULUS_TAG[] = "m38-resource-abi-v1-numeric-stimulus";
static const char B2_STIMULUS_SCHEMA[] = "m38-resource-abi-v1-numeric-stimulus-schema-v1";
static const char B2_SELECTOR_TAG[] = "m38-resource-abi-v1-numeric-selector";
static const char B2_SELECTOR_SCHEMA[] = "m38-resource-abi-v1-numeric-selector-schema-v1";


/* A published LOAD noun is movable.  This witness-owned record is the only
 * handle state retained across a later runtime operation: it contains only
 * validated fixed-width scalars and the canonical 32-byte admission digest. */
typedef struct B2HandleExternal {
    uint64_t capability;
    uint32_t slot;
    uint64_t generation;
    uint8_t admission_id[B2_HANDLE_DIGEST_BYTES];
} B2HandleExternal;

static uint8_t b2_control[64u * 1024u]
    __attribute__((aligned(64)));
static uint8_t b2_workspace[4u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t b2_session_a[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t b2_session_b[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t b2_jams[B2_CORE_COUNT][2][B2_MAX_CORE_JAM_BYTES]
    __attribute__((aligned(64)));
typedef struct B2PlanType {
    uint32_t id;
    uint32_t value_count;
    uint32_t state_id;
    uint32_t value_ids[B2_MAX_PLAN_VALUES];
    uint32_t value_types[B2_MAX_PLAN_VALUES];
    uint32_t event_count;
    uint32_t event_ids[B2_MAX_PLAN_EVENTS];
    uint32_t event_value_counts[B2_MAX_PLAN_EVENTS];
    uint32_t event_value_ids[B2_MAX_PLAN_EVENTS][B2_MAX_PLAN_VALUES];
    uint32_t state_count;
} B2PlanType;

typedef struct B2Plan {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t instance_types[B2_MAX_PLAN_INSTANCES];
    B2PlanType types[B2_MAX_PLAN_TYPES];
} B2Plan;

static size_t b2_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static noun b2_cord(const char *s)
{
    return cord_from_bytes(s, b2_strlen(s));
}

static int b2_pair(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int b2_record(noun n, noun *out, uint32_t count)
{
    noun cur = n;
    for (uint32_t i = 0; i < count; i++) {
        if (!b2_pair(cur, &out[i], &cur)) return 0;
    }
    return cur == NOUN_ZERO;
}

static int b2_list(noun n, noun *out, uint32_t limit, uint32_t *count)
{
    noun cur = n;
    uint32_t used = 0;
    while (cur != NOUN_ZERO) {
        if (used == limit || !b2_pair(cur, &out[used], &cur)) return 0;
        used++;
    }
    *count = used;
    return 1;
}

static int b2_atom_text(noun n, const char *s)
{
    uint8_t bytes[256];
    size_t len = b2_strlen(s);
    if (len >= sizeof(bytes) || !noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != (uint8_t)s[i]) return 0;
    for (size_t i = len; i < sizeof(bytes); i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int b2_u(noun n, uint64_t max, uint32_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) > max) return 0;
    *out = (uint32_t)direct_val(n);
    return 1;
}

static int b2_u64(noun n, uint64_t max, uint64_t *out)
{
    uint8_t bytes[sizeof(uint64_t)] = {0};
    uint64_t value = 0;
    if (!out || !noun_is_atom(n)
        || !noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (uint32_t i = 0; i < sizeof(bytes); i++)
        value |= (uint64_t)bytes[i] << (8u * i);
    if (value > max) return 0;
    *out = value;
    return 1;
}

static int b2_u64_atom(uint64_t value, noun *out)
{
    if (!out) return 0;
    if (value <= 0x7FFFFFFFFFFFFFFFULL) {
        *out = direct(value);
        return 1;
    }
    return make_atom_checked(&value, 1, out);
}

static int b2_digest_atom(const uint8_t digest[B2_HANDLE_DIGEST_BYTES],
                               noun *out)
{
    uint64_t limbs[B2_HANDLE_DIGEST_BYTES / sizeof(uint64_t)] = {0};
    if (!digest || !out) return 0;
    for (uint32_t i = 0; i < B2_HANDLE_DIGEST_BYTES / sizeof(uint64_t); i++)
        for (uint32_t j = 0; j < sizeof(uint64_t); j++)
            limbs[i] |= (uint64_t)digest[i * sizeof(uint64_t) + j] << (8u * j);
    return make_atom_checked(limbs, B2_HANDLE_DIGEST_BYTES / sizeof(uint64_t), out);
}

static int b2_build_list(const noun *items, uint32_t count, noun *out)
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

static int b2_build_record(const noun *items, uint32_t count, noun *out)
{
    return b2_build_list(items, count, out);
}

static int b2_build_tagged(const char *tag, const char *schema,
                                const noun *fields, uint32_t count, noun *out)
{
    noun row[1u + B2_MAX_VALUES];
    if (count >= 1u + B2_MAX_VALUES) return 0;
    row[0] = b2_cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1u] = fields[i];
    noun body;
    if (!b2_build_record(row, count + 1u, &body)) return 0;
    return alloc_cell_checked(b2_cord(tag), body, out);
}

static B2PlanType *b2_plan_type(B2Plan *plan, uint32_t id)
{
    return id >= 1u && id <= plan->type_count ? &plan->types[id - 1u] : 0;
}

/* This is a witness-local numeric profile view.  It derives stimuli from the
 * admitted payload noun and never reaches into ResourceSession internals. */
static int b2_parse_plan(noun core, B2Plan *out)
{
    noun formula, payload, payload_tag, payload_body, pf[2], semantic[5];
    noun types[B2_MAX_PLAN_TYPES], instances[B2_MAX_PLAN_INSTANCES];
    uint32_t type_count, instance_count;
    if (!b2_pair(core, &formula, &payload)
        || !b2_pair(payload, &payload_tag, &payload_body)
        || !b2_atom_text(payload_tag, "m38-d0-r2-resource-payload")
        || !b2_record(payload_body, pf, 2)
        || !b2_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
        || !b2_record(pf[1], semantic, 5)
        || !b2_list(semantic[0], types, B2_MAX_PLAN_TYPES, &type_count)
        || !b2_list(semantic[1], instances, B2_MAX_PLAN_INSTANCES, &instance_count)
        || type_count == 0 || instance_count == 0)
        return 0;
    B2Plan plan = {0};
    plan.type_count = type_count;
    plan.instance_count = instance_count;
    for (uint32_t i = 0; i < type_count; i++) {
        noun tf[6], events[B2_MAX_PLAN_EVENTS], values[B2_MAX_PLAN_VALUES];
        noun states[B2_MAX_PLAN_STATES];
        uint32_t event_count, value_count, state_count;
        B2PlanType *type = &plan.types[i];
        if (!b2_record(types[i], tf, 6)
            || !b2_u(tf[0], B2_MAX_PLAN_TYPES, &type->id)
            || type->id != i + 1u
            || !b2_list(tf[1], events, B2_MAX_PLAN_EVENTS, &event_count)
            || !b2_list(tf[2], values, B2_MAX_PLAN_VALUES, &value_count)
            || !b2_list(tf[3], states, B2_MAX_PLAN_STATES, &state_count)
            || value_count == 0 || state_count == 0)
            return 0;
        type->event_count = event_count;
        for (uint32_t j = 0; j < event_count; j++) {
            noun ef[3], event_values[B2_MAX_PLAN_VALUES];
            uint32_t direction, event_value_count;
            if (!b2_record(events[j], ef, 3)
                || !b2_u(ef[0], 0xFFFF, &type->event_ids[j])
                || type->event_ids[j] == 0
                || !b2_u(ef[1], 2, &direction)
                || !b2_list(ef[2], event_values, B2_MAX_PLAN_VALUES,
                                  &event_value_count)) return 0;
            type->event_value_counts[j] = event_value_count;
            for (uint32_t k = 0; k < event_value_count; k++)
                if (!b2_u(event_values[k], B2_MAX_PLAN_VALUES,
                               &type->event_value_ids[j][k])
                    || type->event_value_ids[j][k] == 0) return 0;
        }
        type->value_count = value_count;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[4];
            uint32_t ignored_initial;
            if (!b2_record(values[j], vf, 4)
                || !b2_u(vf[0], B2_MAX_PLAN_VALUES, &type->value_ids[j])
                || type->value_ids[j] != j + 1u
                || !b2_u(vf[2], 2, &type->value_types[j])
                || (type->value_types[j] != 1 && type->value_types[j] != 2)
                || !b2_u(vf[3], type->value_types[j] == 1 ? 1 : 65535,
                              &ignored_initial)) return 0;
        }
        type->state_count = state_count;
        uint32_t initial_states = 0;
        for (uint32_t j = 0; j < state_count; j++) {
            noun sf[3];
            uint32_t id, initial;
            if (!b2_record(states[j], sf, 3)
                || !b2_u(sf[0], B2_MAX_PLAN_STATES, &id)
                || id != j + 1u || !b2_u(sf[1], 1, &initial)) return 0;
            if (initial != 0) {
                initial_states++;
                type->state_id = id;
            }
        }
        if (initial_states != 1 || type->state_id == 0) return 0;
    }
    for (uint32_t i = 0; i < instance_count; i++) {
        noun fields[2];
        uint32_t id, type_id;
        if (!b2_record(instances[i], fields, 2)
            || !b2_u(fields[0], B2_MAX_PLAN_INSTANCES, &id)
            || id != i + 1u
            || !b2_u(fields[1], B2_MAX_PLAN_TYPES, &type_id)
            || !b2_plan_type(&plan, type_id)) return 0;
        plan.instance_types[i] = type_id;
    }
    *out = plan;
    return 1;
}

static int b2_make_value(uint32_t id, uint32_t type, uint32_t value, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(value)};
    return b2_build_tagged("m38-resource-abi-v1-numeric-value",
                               "m38-resource-abi-v1-numeric-value-schema-v1",
                               fields, 3, out);
}

static int b2_make_request(uint32_t operation, noun args, noun *out)
{
    noun fields[2] = {direct(operation), args};
    return b2_build_tagged(B2_REQUEST_TAG, B2_REQUEST_SCHEMA,
                                fields, 2, out);
}

static int b2_result_body(const ResourceResultView *view, noun *body)
{
    noun tag, result_body, fields[3];
    if (!view || !view->root_slot
        || !b2_pair(*view->root_slot, &tag, &result_body)
        || !b2_atom_text(tag, B2_RESULT_TAG)
        || !b2_record(result_body, fields, 3)) return 0;
    *body = fields[2];
    return 1;
}

static int b2_layout_churn(void)
{
    /* Deliberately consume a fixed bounded prefix of the active persist
     * semispace before each post-LOAD request.  The public operation sequence
     * is unchanged; this makes the two-flip stale-pointer control deterministic
     * instead of depending on incidental allocation layout. */
    noun filler = NOUN_ZERO;
    for (uint32_t i = 0; i < B2_LAYOUT_CHURN_CELLS; i++) {
        noun next;
        if (!alloc_cell_checked(direct(0xA500u + i), filler, &next)) return 0;
        filler = next;
    }
    return 1;
}

static int b2_handle_to_noun(const B2HandleExternal *handle, noun *out)
{
    noun fields[4], admission;
    if (!handle || !out || handle->capability == 0 || handle->slot == 0
        || handle->generation == 0
        || !b2_u64_atom(handle->capability, &fields[0])
        || !b2_u64_atom(handle->generation, &fields[2])
        || !b2_digest_atom(handle->admission_id, &admission)) return 0;
    fields[1] = direct(handle->slot);
    fields[3] = admission;
    return b2_build_record(fields, 4, out);
}

static int b2_make_handle_request(uint32_t operation,
                                       const B2HandleExternal *handle,
                                       noun second, noun *request)
{
    noun handle_noun, args;
    if (!b2_layout_churn() || !b2_handle_to_noun(handle, &handle_noun))
        return 0;
    if (operation == B2_OP_SNAPSHOT) args = handle_noun;
    else {
        noun fields[2] = {handle_noun, second};
        if (!b2_build_record(fields, 2, &args)) return 0;
    }
    return b2_make_request(operation, args, request);
}

static void b2_terminal(const char *status)
{
    uart_puts("M38D2 v=1 terminal=");
    uart_puts(status);
    uart_puts("\r\n");
}

static uint32_t b2_atom_bytes(noun atom)
{
    if (noun_is_direct(atom)) {
        uint64_t value = direct_val(atom);
        uint32_t bytes = 0;
        while (value != 0) { bytes++; value >>= 8; }
        return bytes == 0 ? 1u : bytes;
    }
    if (!noun_is_indirect(atom)) return 0;
    atom_t *stored = atom_store_get(indirect_hash(atom));
    if (!stored || stored->size == 0
        || stored->size > B2_MAX_CORE_JAM_BYTES / sizeof(uint64_t)) return 0;
    uint64_t last = stored->limbs[stored->size - 1u];
    uint32_t significant = sizeof(uint64_t);
    while (significant > 1u && ((last >> ((significant - 1u) * 8u)) & 0xffu) == 0)
        significant--;
    return (uint32_t)((stored->size - 1u) * sizeof(uint64_t) + significant);
}

static int b2_decode_pill(noun *input)
{
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < 8; i++) bytes |= (uint64_t)base[i] << (8u * i);
    if (bytes == 0 || bytes > 1024u * 1024u) return 0;
    noun decoded;
    if (cue_bounded_bytes((const uint8_t *)(uintptr_t)(PILL_BASE + 16u), bytes,
                          &cue_i2_limits, HEAP_MODE_SCRATCH, &decoded)
        != CUE_BOUNDED_OK) return 0;
    *input = decoded;
    return 1;
}

static int b2_extract_jams(noun input, uint32_t record_bytes[2],
                                uint32_t core_bytes[2])
{
    noun rows[2], pair[2];
    uint32_t row_count;
    if (!b2_list(input, rows, 2, &row_count) || row_count != 2) return 0;
    for (uint32_t i = 0; i < 2; i++) {
        if (!b2_record(rows[i], pair, 2)) return 0;
        record_bytes[i] = b2_atom_bytes(pair[0]);
        core_bytes[i] = b2_atom_bytes(pair[1]);
        if (record_bytes[i] == 0 || core_bytes[i] == 0
            || record_bytes[i] > B2_MAX_RECORD_JAM_BYTES
            || core_bytes[i] > B2_MAX_CORE_JAM_BYTES
            || !noun_atom_read_fixed(pair[0], b2_jams[i][0], record_bytes[i])
            || !noun_atom_read_fixed(pair[1], b2_jams[i][1], core_bytes[i])) return 0;
    }
    return 1;
}

typedef struct B2StateExternal {
    uint32_t state_ids[B2_MAX_PLAN_INSTANCES];
    uint32_t values[B2_MAX_PLAN_INSTANCES][B2_MAX_PLAN_VALUES];
} B2StateExternal;

typedef struct B2SnapshotExternal {
    B2HandleExternal handle;
    B2StateExternal state;
    uint64_t nonce;
    uint8_t valid;
} B2SnapshotExternal;

static const char B2_PROFILE_ID[] =
    "1499kernel-i2-m38-numeric-execution-profile-v1-bounded";

static int b2_handle_from_noun(noun value, B2HandleExternal *out)
{
    noun fields[4];
    uint64_t capability, generation;
    uint32_t slot;
    if (!out || !b2_record(value, fields, 4)
        || !b2_u64(fields[0], UINT64_MAX, &capability) || capability == 0
        || !b2_u(fields[1], B2_MAX_LIVE_HANDLES, &slot) || slot == 0
        || !b2_u64(fields[2], UINT64_MAX, &generation) || generation == 0
        || !noun_atom_read_fixed(fields[3], out->admission_id,
                                 B2_HANDLE_DIGEST_BYTES)) return 0;
    out->capability = capability;
    out->slot = slot;
    out->generation = generation;
    return 1;
}

static int b2_state_export(noun value, const B2Plan *plan,
                           B2SnapshotExternal *out)
{
    noun tag, body, fields[4], instances[B2_MAX_PLAN_INSTANCES];
    uint32_t instance_count;
    if (!out || !b2_pair(value, &tag, &body)
        || !b2_atom_text(tag, "m38-resource-abi-v1-numeric-state")
        || !b2_record(body, fields, 4)
        || !b2_atom_text(fields[2], B2_PROFILE_ID)
        || !b2_list(fields[3], instances, B2_MAX_PLAN_INSTANCES, &instance_count)
        || instance_count != plan->instance_count) return 0;
    for (uint32_t i = 0; i < instance_count; i++) {
        noun instance_tag, instance_body, instance_fields[4];
        noun values[B2_MAX_PLAN_VALUES];
        uint32_t instance, state_id, value_count;
        if (!b2_pair(instances[i], &instance_tag, &instance_body)
            || !b2_atom_text(instance_tag, "m38-resource-abi-v1-instance-state")
            || !b2_record(instance_body, instance_fields, 4)
            || !b2_u(instance_fields[1], B2_MAX_PLAN_INSTANCES, &instance)
            || instance == 0
            || !b2_u(instance_fields[2], B2_MAX_PLAN_STATES, &state_id)
            || !b2_list(instance_fields[3], values, B2_MAX_PLAN_VALUES, &value_count)
            || instance > plan->instance_count
            || value_count != plan->types[plan->instance_types[instance - 1u] - 1u].value_count)
            return 0;
        uint32_t index = instance - 1u;
        const B2PlanType *type = &plan->types[plan->instance_types[index] - 1u];
        if (state_id == 0 || state_id > type->state_count) return 0;
        out->state.state_ids[index] = state_id;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value_tag, value_body, value_fields[4];
            uint32_t id, kind, raw;
            if (!b2_pair(values[j], &value_tag, &value_body)
                || !b2_atom_text(value_tag, "m38-resource-abi-v1-numeric-value")
                || !b2_record(value_body, value_fields, 4)
                || !b2_u(value_fields[1], B2_MAX_PLAN_VALUES, &id)
                || id != type->value_ids[j]
                || !b2_u(value_fields[2], 2, &kind)
                || kind != type->value_types[j]
                || !b2_u(value_fields[3], kind == 1 ? 1 : 65535, &raw)) return 0;
            out->state.values[index][j] = raw;
        }
    }
    return 1;
}

static int b2_snapshot_export(const ResourceResultView *view, const B2Plan *plan,
                              B2SnapshotExternal *out)
{
    noun body, fields[3];
    if (!out || !view || !b2_result_body(view, &body)
        || !b2_record(body, fields, 3)
        || !b2_handle_from_noun(fields[0], &out->handle)
        || !b2_state_export(fields[1], plan, out)
        || !b2_u64(fields[2], UINT64_MAX, &out->nonce)) return 0;
    out->valid = 1;
    return 1;
}

static int b2_state_build(const B2SnapshotExternal *snapshot,
                          const B2Plan *plan, noun *out)
{
    noun instances[B2_MAX_PLAN_INSTANCES], admission;
    if (!snapshot || !snapshot->valid
        || !b2_digest_atom(snapshot->handle.admission_id, &admission)) return 0;
    for (uint32_t i = plan->instance_count; i != 0; i--) {
        uint32_t index = i - 1u;
        const B2PlanType *type = &plan->types[plan->instance_types[index] - 1u];
        noun values[B2_MAX_PLAN_VALUES];
        for (uint32_t j = type->value_count; j != 0; j--) {
            uint32_t value = j - 1u;
            if (!b2_make_value(type->value_ids[value], type->value_types[value],
                               snapshot->state.values[index][value], &values[value])) return 0;
        }
        noun value_list, instance_fields[3];
        if (!b2_build_list(values, type->value_count, &value_list)) return 0;
        instance_fields[0] = direct(index + 1u);
        instance_fields[1] = direct(snapshot->state.state_ids[index]);
        instance_fields[2] = value_list;
        if (!b2_build_tagged("m38-resource-abi-v1-instance-state",
                             "m38-resource-abi-v1-instance-state-schema-v1",
                             instance_fields, 3, &instances[index])) return 0;
    }
    noun instance_list, fields[3];
    if (!b2_build_list(instances, plan->instance_count, &instance_list)) return 0;
    fields[0] = admission;
    fields[1] = b2_cord(B2_PROFILE_ID);
    fields[2] = instance_list;
    return b2_build_tagged("m38-resource-abi-v1-numeric-state",
                           "m38-resource-abi-v1-numeric-state-schema-v1",
                           fields, 3, out);
}

static int b2_snapshot_to_noun(const B2SnapshotExternal *snapshot,
                               const B2Plan *plan, noun *out)
{
    noun handle, state, fields[3];
    if (!snapshot || !snapshot->valid
        || !b2_handle_to_noun(&snapshot->handle, &handle)
        || !b2_state_build(snapshot, plan, &state)) return 0;
    fields[0] = handle;
    fields[1] = state;
    fields[2] = direct(snapshot->nonce);
    return b2_build_record(fields, 3, out);
}

static int b2_handle_from_view(const ResourceResultView *view,
                               B2HandleExternal *out)
{
    noun body, fields[3];
    uint32_t count;
    if (!view || !out || !view->root_slot || !b2_result_body(view, &body)) return 0;
    count = (view->wire_status == B2_OP_LOAD) ? 2u : 3u;
    if ((view->wire_status != B2_OP_LOAD && view->wire_status != B2_OP_SNAPSHOT
         && view->wire_status != B2_OP_RESTORE)
        || !b2_record(body, fields, count)) return 0;
    return b2_handle_from_noun(fields[0], out);
}

static void b2_put_u64(uint64_t value)
{
    char buf[24];
    uint32_t used = 0;
    if (value == 0) {
        uart_putc('0');
        return;
    }
    while (value != 0) {
        buf[used++] = (char)('0' + value % 10u);
        value /= 10u;
    }
    while (used != 0) uart_putc((uint8_t)buf[--used]);
}

static void b2_csv(uint64_t value, uint32_t *first)
{
    if (!*first) uart_putc(',');
    *first = 0;
    b2_put_u64(value);
}

static void b2_emit_session(const M38B2SessionSnapshot *session)
{
    uint32_t first = 1;
    b2_csv(session->state, &first);
    b2_csv(session->in_flight, &first);
    b2_csv(session->registry_index, &first);
    b2_csv(session->capability, &first);
    b2_csv(session->primary_root, &first);
    b2_csv(session->refusal_root, &first);
    b2_csv(session->primary_view_root_slot, &first);
    b2_csv(session->refusal_view_root_slot, &first);
    b2_csv(session->primary_view_generation, &first);
    b2_csv(session->refusal_view_generation, &first);
    b2_csv(session->primary_view_wire, &first);
    b2_csv(session->refusal_view_wire, &first);
    b2_csv(session->primary_view_owner, &first);
    b2_csv(session->refusal_view_owner, &first);
    b2_csv(session->parse_count, &first);
    b2_csv(session->catalog_valid_mask, &first);
    b2_csv(session->cache_valid_mask, &first);
    for (uint32_t i = 0; i < M38_B2_CATALOG_COUNT; i++) b2_csv(session->catalog_roots[i], &first);
    for (uint32_t i = 0; i < M38_B2_CATALOG_COUNT; i++) b2_csv(session->cache_roots[i], &first);
    for (uint32_t i = 0; i < M38_B2_CATALOG_COUNT; i++) b2_csv(session->cache_formula_roots[i], &first);
    for (uint32_t i = 0; i < M38_B2_CATALOG_COUNT; i++) b2_csv(session->cache_payload_roots[i], &first);
    b2_csv(session->slot_used_mask, &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_catalog[i], &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_generation[i], &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_snapshot_nonce[i], &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_handle_roots[i], &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_state_roots[i], &first);
    for (uint32_t i = 0; i < M38_B2_HANDLE_COUNT; i++) b2_csv(session->slot_snapshot_roots[i], &first);
}

static void b2_emit_runtime(const M38B2Snapshot *snapshot)
{
    uint32_t first = 1;
    b2_csv(snapshot->runtime_state, &first);
    b2_csv(snapshot->broker_owner, &first);
    b2_csv(snapshot->session_count, &first);
    b2_csv(snapshot->next_capability, &first);
    b2_csv(snapshot->broker_transaction_id, &first);
    b2_csv(snapshot->promoted_root_count, &first);
    b2_csv(snapshot->next_fault, &first);
    b2_csv(snapshot->persist_selector, &first);
    b2_csv(snapshot->persistent_cells, &first);
    b2_csv(snapshot->scratch_cells, &first);
    b2_csv(snapshot->atom_bytes, &first);
    b2_csv(snapshot->atom_index_occupancy, &first);
    b2_csv(snapshot->atom_index_probe_depth, &first);
    b2_csv(snapshot->live_roots, &first);
    b2_csv(snapshot->scratch_mark, &first);
    b2_csv(snapshot->noun_transaction_active, &first);
    b2_csv(snapshot->evaluator_ops, &first);
    b2_csv(snapshot->evaluator_cells, &first);
    b2_csv(snapshot->evaluator_peak_depth, &first);
    b2_csv(snapshot->evaluator_abort_reason, &first);
}

static uint64_t b2_sequence;

static void b2_emit_row(uint32_t case_id, uint32_t phase, uint32_t sid,
                        uint32_t operation, uint64_t status,
                        const ResourceResultView *view,
                        const M38B2Snapshot *snapshot)
{
    uart_puts("M38D2 v=1 seq="); b2_put_u64(++b2_sequence);
    uart_puts(" case="); b2_put_u64(case_id);
    uart_puts(" phase="); b2_put_u64(phase);
    uart_puts(" sid="); b2_put_u64(sid);
    uart_puts(" op="); b2_put_u64(operation);
    uart_puts(" st="); b2_put_u64(status);
    uart_puts(" wire="); b2_put_u64(view ? view->wire_status : 0);
    uart_puts(" view="); b2_put_u64(view ? 1 : 0);
    uart_puts(" owner="); b2_put_u64(view ? view->owner : 0);
    uart_puts(" rt="); b2_emit_runtime(snapshot);
    uart_puts(" sa="); b2_emit_session(&snapshot->sessions[0]);
    uart_puts(" sb="); b2_emit_session(&snapshot->sessions[1]);
    uart_puts("\r\n");
}

static int b2_dispatch(ResourceSession *session, noun request,
                       M38Status *status_out,
                       const ResourceResultView **view_out)
{
    const ResourceResultView *view = 0;
    M38Status status = m38_resource_session_dispatch(session, request, &view);
    if (status_out) *status_out = status;
    if (view_out) *view_out = view;
    return 1;
}

static int b2_recue_core(uint32_t index, const uint32_t core_bytes[2], noun *out)
{
    heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(b2_jams[index][1], core_bytes[index], &cue_i2_limits,
                          HEAP_MODE_PERSIST, out) != CUE_BOUNDED_OK) return 0;
    noun_tx_commit();
    return 1;
}

static int b2_make_selector(noun *out)
{
    noun fields[1] = {direct(1)};
    return b2_build_tagged(B2_SELECTOR_TAG, B2_SELECTOR_SCHEMA, fields, 1, out);
}

static int b2_make_stimulus_delta(const B2Plan *plan, uint32_t delta, noun *out)
{
    const B2PlanType *chosen = 0;
    uint32_t event_index = 0;
    for (uint32_t i = 0; i < plan->type_count && !chosen; i++) {
        const B2PlanType *type = &plan->types[i];
        for (uint32_t j = 0; j < type->event_count; j++) {
            if (type->event_value_counts[j] == 0) continue;
            uint32_t first_id = type->event_value_ids[j][0];
            for (uint32_t k = 0; k < type->value_count; k++) {
                if (type->value_ids[k] == first_id && type->value_types[k] == 1) {
                    chosen = type;
                    event_index = j;
                    break;
                }
            }
            if (chosen) break;
        }
    }
    if (!chosen) return 0;
    noun values[B2_MAX_PLAN_VALUES];
    uint32_t value_count = chosen->event_value_counts[event_index];
    for (uint32_t i = 0; i < value_count; i++) {
        uint32_t id = chosen->event_value_ids[event_index][i], kind = 0;
        for (uint32_t j = 0; j < chosen->value_count; j++)
            if (chosen->value_ids[j] == id) kind = chosen->value_types[j];
        uint32_t value = kind == 1 ? delta & 1u : delta;
        if ((kind != 1 && kind != 2)
            || !b2_make_value(id, kind, value, &values[i])) return 0;
    }
    noun value_list, fields[2];
    if (!b2_build_list(values, value_count, &value_list)) return 0;
    fields[0] = direct(chosen->event_ids[event_index]);
    fields[1] = value_list;
    return b2_build_tagged(B2_STIMULUS_TAG, B2_STIMULUS_SCHEMA, fields, 2, out);
}

static int b2_session_bytes_equal(const M38B2SessionSnapshot *left,
                                  const M38B2SessionSnapshot *right)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    for (size_t i = 0; i < sizeof(*left); i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/* Fault injection may consume the one-shot selector and advance diagnostic
 * counters.  The semantic projection deliberately excludes those counters,
 * while retaining every runtime-owned root, generation, cache, slot, and
 * allocator scalar that must roll back. */
static int b2_semantic_equal(const M38B2Snapshot *left,
                             const M38B2Snapshot *right)
{
    if (!left || !right
        || left->runtime_state != right->runtime_state
        || left->broker_owner != right->broker_owner
        || left->session_count != right->session_count
        || left->next_capability != right->next_capability
        || left->promoted_root_count != right->promoted_root_count
        || left->persist_selector != right->persist_selector
        || left->persistent_cells != right->persistent_cells
        || left->scratch_cells != right->scratch_cells
        || left->atom_bytes != right->atom_bytes
        || left->atom_index_occupancy != right->atom_index_occupancy
        || left->atom_index_probe_depth != right->atom_index_probe_depth
        || left->live_roots != right->live_roots
        || left->scratch_mark != right->scratch_mark
        || left->noun_transaction_active != right->noun_transaction_active)
        return 0;
    for (uint32_t i = 0; i < M38_B2_SESSION_COUNT; i++)
        if (!b2_session_bytes_equal(&left->sessions[i], &right->sessions[i])) return 0;
    return 1;
}

static int b2_run_fault_case(ResourceRuntime *runtime, uint32_t case_id,
                             ResourceSession *session, uint32_t sid,
                             uint32_t operation, noun request,
                             M38FaultPoint fault, M38Status expected_fault,
                             M38B2Snapshot *before_out,
                             const ResourceResultView **retry_view_out)
{
    M38B2Snapshot before, faulted, after, retried;
    const ResourceResultView *view = 0;
    M38Status status;
    m38_resource_b2_snapshot(&before);
    b2_emit_row(case_id, 0, sid, operation, 999, 0, &before);
    m38_resource_test_fail_next(runtime, fault);
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&faulted);
    b2_emit_row(case_id, 1, sid, operation, status, view, &faulted);
    if (status != expected_fault || view != 0 || !b2_semantic_equal(&before, &faulted))
        return 0;
    m38_resource_b2_snapshot(&after);
    b2_emit_row(case_id, 2, sid, operation, 999, 0, &after);
    if (!b2_semantic_equal(&faulted, &after)) return 0;
    view = 0;
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&retried);
    b2_emit_row(case_id, 3, sid, operation, status, view, &retried);
    if (status != M38_STATUS_OK || !view || view->wire_status != operation)
        return 0;
    if (before_out) *before_out = before;
    if (retry_view_out) *retry_view_out = view;
    return 1;
}

static int b2_run_runtime_busy_case(ResourceRuntime *runtime,
                                    ResourceSession *session,
                                    uint32_t sid, uint32_t operation,
                                    noun request,
                                    const ResourceResultView **retry_view_out)
{
    M38B2Snapshot before, held, after, retried;
    const ResourceResultView *view = 0;
    M38Status status;
    m38_resource_b2_snapshot(&before);
    b2_emit_row(101, 0, sid, operation, 999, 0, &before);
    m38_resource_test_hold_runtime_busy(runtime);
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&held);
    b2_emit_row(101, 1, sid, operation, status, view, &held);
    if (status != M38_STATUS_RUNTIME_BUSY || view != 0) return 0;
    m38_resource_test_release_busy(runtime, 0);
    m38_resource_b2_snapshot(&after);
    b2_emit_row(101, 2, sid, operation, 999, 0, &after);
    if (!b2_semantic_equal(&before, &after)) return 0;
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&retried);
    b2_emit_row(101, 3, sid, operation, status, view, &retried);
    if (status != M38_STATUS_OK || !view || view->wire_status != operation)
        return 0;
    if (retry_view_out) *retry_view_out = view;
    return 1;
}

static int b2_run_session_busy_case(ResourceRuntime *runtime,
                                    ResourceSession *session,
                                    uint32_t sid, uint32_t operation,
                                    noun request,
                                    const ResourceResultView **retry_view_out)
{
    M38B2Snapshot before, held, after, retried;
    const ResourceResultView *view = 0;
    M38Status status;
    m38_resource_b2_snapshot(&before);
    b2_emit_row(102, 0, sid, operation, 999, 0, &before);
    m38_resource_test_hold_session_busy(session);
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&held);
    b2_emit_row(102, 1, sid, operation, status, view, &held);
    if (status != M38_STATUS_SESSION_BUSY || view != 0) return 0;
    m38_resource_test_release_busy(runtime, session);
    m38_resource_b2_snapshot(&after);
    b2_emit_row(102, 2, sid, operation, 999, 0, &after);
    if (!b2_semantic_equal(&before, &after)) return 0;
    b2_dispatch(session, request, &status, &view);
    m38_resource_b2_snapshot(&retried);
    b2_emit_row(102, 3, sid, operation, status, view, &retried);
    if (status != M38_STATUS_OK || !view || view->wire_status != operation)
        return 0;
    if (retry_view_out) *retry_view_out = view;
    return 1;
}

static int b2_lifecycle_row(uint32_t case_id, uint32_t sid, uint32_t phase,
                            M38Status status)
{
    M38B2Snapshot snapshot;
    m38_resource_b2_snapshot(&snapshot);
    b2_emit_row(case_id, phase, sid, 0, phase == 0 ? 999 : status, 0, &snapshot);
    return 1;
}

void m38_resource_b2_boot(void)
{
    noun input;
    uint32_t record_bytes[2], core_bytes[2];
    b2_sequence = 0;
    if (!b2_decode_pill(&input) || !b2_extract_jams(input, record_bytes, core_bytes)) {
        b2_terminal("refuse");
        return;
    }
    if (noun_tx_active()) noun_tx_abort();
    heap_scratch_reset();

    SupervisorAdmissionEntry entries[2] = {
        {b2_jams[0][0], record_bytes[0], b2_jams[0][1], core_bytes[0]},
        {b2_jams[1][0], record_bytes[1], b2_jams[1][1], core_bytes[1]},
    };
    SupervisorAdmissionCatalog catalog;
    ResourceRuntime *runtime = 0;
    ResourceSession *session_a = 0, *session_b = 0;
    SessionCapability cap_a = 0, cap_b = 0;
    if (m38_supervisor_admission_catalog_make(&catalog, entries, 2) != M38_STATUS_OK
        || m38_resource_runtime_init(b2_control, sizeof(b2_control),
                                     b2_workspace, sizeof(b2_workspace), &runtime)
            != M38_STATUS_OK
        || m38_resource_session_init(runtime, b2_session_a, sizeof(b2_session_a),
                                     &catalog, &session_a, &cap_a) != M38_STATUS_OK
        || m38_resource_session_init(runtime, b2_session_b, sizeof(b2_session_b),
                                     &catalog, &session_b, &cap_b) != M38_STATUS_OK) {
        b2_terminal("refuse");
        return;
    }
    (void)cap_a;
    (void)cap_b;

    B2Plan plans[2];
    noun cores[2];
    for (uint32_t i = 0; i < B2_CORE_COUNT; i++) {
        if (!b2_recue_core(i, core_bytes, &cores[i])
            || !b2_parse_plan(cores[i], &plans[i])) {
            b2_terminal("refuse");
            return;
        }
    }

    B2HandleExternal handles[2] = {0};
    const ResourceResultView *view = 0;
    M38Status status;
    noun request;
    if (!b2_make_request(B2_OP_LOAD, cores[0], &request)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_dispatch(session_a, request, &status, &view)) {
        b2_terminal("refuse");
        return;
    }
    if (status != M38_STATUS_OK || !view || view->wire_status != B2_OP_LOAD
        || !b2_handle_from_view(view, &handles[0])) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_recue_core(1, core_bytes, &cores[1])
        || !b2_make_request(B2_OP_LOAD, cores[1], &request)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_dispatch(session_b, request, &status, &view)) {
        b2_terminal("refuse");
        return;
    }
    if (status != M38_STATUS_OK || !view || view->wire_status != B2_OP_LOAD
        || !b2_handle_from_view(view, &handles[1])) {
        b2_terminal("refuse");
        return;
    }

    noun selector;
    if (!b2_make_selector(&selector)
        || !b2_make_handle_request(B2_OP_PEEK, &handles[0], selector, &request)
        || !b2_dispatch(session_b, request, &status, &view)
        || status != M38_STATUS_OK || !view || view->wire_status != B2_WIRE_REFUSE
        || view->owner != M38_RESULT_OWNER_REFUSAL) {
        b2_terminal("refuse");
        return;
    }
    M38B2Snapshot refusal_snapshot;
    m38_resource_b2_snapshot(&refusal_snapshot);
    b2_emit_row(100, 0, 2, B2_OP_PEEK, status, view, &refusal_snapshot);
    if (!b2_make_selector(&selector)
        || !b2_make_handle_request(B2_OP_PEEK, &handles[1], selector, &request)
        || !b2_dispatch(session_a, request, &status, &view)
        || status != M38_STATUS_OK || !view || view->wire_status != B2_WIRE_REFUSE
        || view->owner != M38_RESULT_OWNER_REFUSAL) {
        b2_terminal("refuse");
        return;
    }
    m38_resource_b2_snapshot(&refusal_snapshot);
    b2_emit_row(100, 1, 1, B2_OP_PEEK, status, view, &refusal_snapshot);

    B2SnapshotExternal saved_snapshot = {0};
    if (!b2_make_handle_request(B2_OP_SNAPSHOT, &handles[0], NOUN_ZERO, &request)
        || !b2_dispatch(session_a, request, &status, &view)
        || status != M38_STATUS_OK || !view || view->wire_status != B2_OP_SNAPSHOT
        || !b2_snapshot_export(view, &plans[0], &saved_snapshot)
        || !b2_handle_from_view(view, &handles[0])) {
        b2_terminal("refuse");
        return;
    }

    const ResourceResultView *retry_view = 0;
    noun stimulus;
    if (!b2_make_stimulus_delta(&plans[0], 1, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_fault_case(runtime, 1, session_a, 1, B2_OP_POKE, request,
                              M38_FAULT_BROKER_BEGIN, M38_STATUS_BROKER_BEGIN,
                              0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }

    /* The cache insertion point is normally cold only during the first LOAD;
     * this B2-only preparation hook makes that exact point reachable again
     * without changing the public runtime path. */
    if (!b2_recue_core(0, core_bytes, &cores[0])
        || !b2_make_request(B2_OP_LOAD, cores[0], &request)) {
        b2_terminal("refuse");
        return;
    }
    m38_resource_test_invalidate_cache(session_a, 0);
    if (!b2_run_fault_case(runtime, 2, session_a, 1, B2_OP_LOAD, request,
                           M38_FAULT_CUE_CACHE_INSERT, M38_STATUS_CUE_CACHE_INSERT,
                           0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }

    if (!b2_make_stimulus_delta(&plans[0], 3, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_fault_case(runtime, 3, session_a, 1, B2_OP_POKE, request,
                              M38_FAULT_SLOT_PUBLICATION, M38_STATUS_SLOT_PUBLICATION,
                              0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_make_stimulus_delta(&plans[0], 5, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_fault_case(runtime, 4, session_a, 1, B2_OP_POKE, request,
                              M38_FAULT_EVALUATOR_ABORT, M38_STATUS_EVALUATOR_ABORT,
                              0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_make_stimulus_delta(&plans[0], 7, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_fault_case(runtime, 5, session_a, 1, B2_OP_POKE, request,
                              M38_FAULT_ATOM_RESULT_STAGING, M38_STATUS_ATOM_RESULT_STAGING,
                              0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_make_stimulus_delta(&plans[0], 9, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_fault_case(runtime, 6, session_a, 1, B2_OP_POKE, request,
                              M38_FAULT_COLLECTIVE_COMMIT, M38_STATUS_COLLECTIVE_COMMIT,
                              0, &retry_view)) {
        b2_terminal("refuse");
        return;
    }

    noun snapshot_noun;
    if (!b2_snapshot_to_noun(&saved_snapshot, &plans[0], &snapshot_noun)
        || !b2_make_handle_request(B2_OP_RESTORE, &handles[0], snapshot_noun, &request)
        || !b2_run_fault_case(runtime, 7, session_a, 1, B2_OP_RESTORE, request,
                              M38_FAULT_RESTORE_COMMIT, M38_STATUS_RESTORE_COMMIT,
                              0, &retry_view)
        || !b2_handle_from_view(retry_view, &handles[0])) {
        b2_terminal("refuse");
        return;
    }

    if (!b2_make_stimulus_delta(&plans[0], 11, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_runtime_busy_case(runtime, session_a, 1, B2_OP_POKE, request,
                                     &retry_view)) {
        b2_terminal("refuse");
        return;
    }
    if (!b2_make_stimulus_delta(&plans[0], 13, &stimulus)
        || !b2_make_handle_request(B2_OP_POKE, &handles[0], stimulus, &request)
        || !b2_run_session_busy_case(runtime, session_a, 1, B2_OP_POKE, request,
                                     &retry_view)) {
        b2_terminal("refuse");
        return;
    }

    const ResourceResultView *accepted_before_reset = retry_view;
    uint64_t accepted_generation = accepted_before_reset->generation;
    if (!b2_lifecycle_row(200, 1, 0, M38_STATUS_OK)
        || m38_resource_session_reset(runtime, session_a) != M38_STATUS_OK) {
        b2_terminal("refuse");
        return;
    }
    if (!accepted_before_reset->root_slot
        || accepted_before_reset->owner != M38_RESULT_OWNER_NONE
        || accepted_before_reset->generation == accepted_generation
        || *accepted_before_reset->root_slot != NOUN_ZERO) {
        b2_terminal("refuse");
        return;
    }
    b2_lifecycle_row(200, 1, 2, M38_STATUS_OK);

    if (!b2_lifecycle_row(201, 1, 0, M38_STATUS_OK)
        || m38_resource_session_dispose(runtime, session_a) != M38_STATUS_OK) {
        b2_terminal("refuse");
        return;
    }
    b2_lifecycle_row(201, 1, 2, M38_STATUS_OK);

    ResourceSession *reinitialized = 0;
    SessionCapability fresh_capability = 0;
    if (!b2_lifecycle_row(202, 1, 0, M38_STATUS_OK)
        || m38_resource_session_init(runtime, b2_session_a, sizeof(b2_session_a),
                                     &catalog, &reinitialized, &fresh_capability)
            != M38_STATUS_OK
        || fresh_capability == 0) {
        b2_terminal("refuse");
        return;
    }
    session_a = reinitialized;
    b2_lifecycle_row(202, 1, 2, M38_STATUS_OK);

    if (!b2_recue_core(0, core_bytes, &cores[0])
        || !b2_make_request(B2_OP_LOAD, cores[0], &request)
        || !b2_dispatch(session_a, request, &status, &view)
        || status != M38_STATUS_OK || !view || view->wire_status != B2_OP_LOAD
        || !b2_handle_from_view(view, &handles[0])) {
        b2_terminal("refuse");
        return;
    }
    M38B2Snapshot reinit_snapshot;
    m38_resource_b2_snapshot(&reinit_snapshot);
    b2_emit_row(203, 1, 1, B2_OP_LOAD, status, view, &reinit_snapshot);
    b2_terminal("pass");
}
