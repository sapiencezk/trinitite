#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "m38_resource_runtime.h"
#include "memory.h"
#include "noun.h"
#include "nock.h"
#include "uart.h"

#define WITNESS_CORE_COUNT 2u
#define WITNESS_MAX_CORE_JAM_BYTES (128u * 1024u)
#define WITNESS_MAX_RECORD_JAM_BYTES (128u * 1024u)
#define WITNESS_MAX_PLAN_TYPES 8u
#define WITNESS_MAX_PLAN_EVENTS 16u
#define WITNESS_MAX_PLAN_VALUES 16u
#define WITNESS_MAX_PLAN_STATES 8u
#define WITNESS_MAX_PLAN_INSTANCES 8u
#define WITNESS_MAX_VALUES 16u

#define WITNESS_OP_LOAD 1u
#define WITNESS_OP_POKE 2u
#define WITNESS_OP_PEEK 3u
#define WITNESS_OP_SNAPSHOT 4u
#define WITNESS_OP_RESTORE 5u

#define WITNESS_WIRE_OK 0u
#define WITNESS_WIRE_REFUSE 255u

static const char WITNESS_REQUEST_TAG[] = "m38-resource-abi-v1-request";
static const char WITNESS_REQUEST_SCHEMA[] = "m38-resource-abi-v1-request-schema-v1";
static const char WITNESS_RESULT_TAG[] = "m38-resource-abi-v1-result";
static const char WITNESS_STIMULUS_TAG[] = "m38-resource-abi-v1-numeric-stimulus";
static const char WITNESS_STIMULUS_SCHEMA[] = "m38-resource-abi-v1-numeric-stimulus-schema-v1";
static const char WITNESS_SELECTOR_TAG[] = "m38-resource-abi-v1-numeric-selector";
static const char WITNESS_SELECTOR_SCHEMA[] = "m38-resource-abi-v1-numeric-selector-schema-v1";

static const uint32_t WITNESS_RUNTIME_CONTROL_BYTES = 64u * 1024u;
static const uint32_t WITNESS_RUNTIME_WORKSPACE_BYTES = 4u * 1024u * 1024u;
static const uint32_t WITNESS_SESSION_BYTES = 2u * 1024u * 1024u;

static uint8_t witness_control[64u * 1024u]
    __attribute__((aligned(64)));
static uint8_t witness_workspace[4u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t witness_session_a[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t witness_session_b[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t witness_jams[WITNESS_CORE_COUNT][2][WITNESS_MAX_CORE_JAM_BYTES]
    __attribute__((aligned(64)));
typedef struct WitnessPlanType {
    uint32_t id;
    uint32_t value_count;
    uint32_t state_id;
    uint32_t value_ids[WITNESS_MAX_PLAN_VALUES];
    uint32_t value_types[WITNESS_MAX_PLAN_VALUES];
    uint32_t event_count;
    uint32_t event_ids[WITNESS_MAX_PLAN_EVENTS];
    uint32_t event_value_counts[WITNESS_MAX_PLAN_EVENTS];
    uint32_t event_value_ids[WITNESS_MAX_PLAN_EVENTS][WITNESS_MAX_PLAN_VALUES];
    uint32_t state_count;
} WitnessPlanType;

typedef struct WitnessPlan {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t instance_types[WITNESS_MAX_PLAN_INSTANCES];
    WitnessPlanType types[WITNESS_MAX_PLAN_TYPES];
} WitnessPlan;

static size_t witness_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static noun witness_cord(const char *s)
{
    return cord_from_bytes(s, witness_strlen(s));
}

static int witness_pair(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int witness_record(noun n, noun *out, uint32_t count)
{
    noun cur = n;
    for (uint32_t i = 0; i < count; i++) {
        if (!witness_pair(cur, &out[i], &cur)) return 0;
    }
    return cur == NOUN_ZERO;
}

static int witness_list(noun n, noun *out, uint32_t limit, uint32_t *count)
{
    noun cur = n;
    uint32_t used = 0;
    while (cur != NOUN_ZERO) {
        if (used == limit || !witness_pair(cur, &out[used], &cur)) return 0;
        used++;
    }
    *count = used;
    return 1;
}

static int witness_atom_text(noun n, const char *s)
{
    uint8_t bytes[256];
    size_t len = witness_strlen(s);
    if (len >= sizeof(bytes) || !noun_atom_read_fixed(n, bytes, sizeof(bytes))) return 0;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != (uint8_t)s[i]) return 0;
    for (size_t i = len; i < sizeof(bytes); i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int witness_u(noun n, uint64_t max, uint32_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) > max) return 0;
    *out = (uint32_t)direct_val(n);
    return 1;
}

static int witness_build_list(const noun *items, uint32_t count, noun *out)
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

static int witness_build_record(const noun *items, uint32_t count, noun *out)
{
    return witness_build_list(items, count, out);
}

static int witness_build_tagged(const char *tag, const char *schema,
                                const noun *fields, uint32_t count, noun *out)
{
    noun row[1u + WITNESS_MAX_VALUES];
    if (count >= 1u + WITNESS_MAX_VALUES) return 0;
    row[0] = witness_cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1u] = fields[i];
    noun body;
    if (!witness_build_record(row, count + 1u, &body)) return 0;
    return alloc_cell_checked(witness_cord(tag), body, out);
}

static WitnessPlanType *witness_plan_type(WitnessPlan *plan, uint32_t id)
{
    return id >= 1u && id <= plan->type_count ? &plan->types[id - 1u] : 0;
}

/* This is a witness-local numeric profile view.  It derives stimuli from the
 * admitted payload noun and never reaches into ResourceSession internals. */
static int witness_parse_plan(noun core, WitnessPlan *out)
{
    noun formula, payload, payload_tag, payload_body, pf[2], semantic[5];
    noun types[WITNESS_MAX_PLAN_TYPES], instances[WITNESS_MAX_PLAN_INSTANCES];
    uint32_t type_count, instance_count;
    if (!witness_pair(core, &formula, &payload)
        || !witness_pair(payload, &payload_tag, &payload_body)
        || !witness_atom_text(payload_tag, "m38-d0-r2-resource-payload")
        || !witness_record(payload_body, pf, 2)
        || !witness_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
        || !witness_record(pf[1], semantic, 5)
        || !witness_list(semantic[0], types, WITNESS_MAX_PLAN_TYPES, &type_count)
        || !witness_list(semantic[1], instances, WITNESS_MAX_PLAN_INSTANCES, &instance_count)
        || type_count == 0 || instance_count == 0)
        return 0;
    WitnessPlan plan = {0};
    plan.type_count = type_count;
    plan.instance_count = instance_count;
    for (uint32_t i = 0; i < type_count; i++) {
        noun tf[6], events[WITNESS_MAX_PLAN_EVENTS], values[WITNESS_MAX_PLAN_VALUES];
        noun states[WITNESS_MAX_PLAN_STATES];
        uint32_t event_count, value_count, state_count;
        WitnessPlanType *type = &plan.types[i];
        if (!witness_record(types[i], tf, 6)
            || !witness_u(tf[0], WITNESS_MAX_PLAN_TYPES, &type->id)
            || type->id != i + 1u
            || !witness_list(tf[1], events, WITNESS_MAX_PLAN_EVENTS, &event_count)
            || !witness_list(tf[2], values, WITNESS_MAX_PLAN_VALUES, &value_count)
            || !witness_list(tf[3], states, WITNESS_MAX_PLAN_STATES, &state_count)
            || value_count == 0 || state_count == 0)
            return 0;
        type->event_count = event_count;
        for (uint32_t j = 0; j < event_count; j++) {
            noun ef[3], event_values[WITNESS_MAX_PLAN_VALUES];
            uint32_t direction, event_value_count;
            if (!witness_record(events[j], ef, 3)
                || !witness_u(ef[0], 0xFFFF, &type->event_ids[j])
                || type->event_ids[j] == 0
                || !witness_u(ef[1], 2, &direction)
                || !witness_list(ef[2], event_values, WITNESS_MAX_PLAN_VALUES,
                                  &event_value_count)) return 0;
            type->event_value_counts[j] = event_value_count;
            for (uint32_t k = 0; k < event_value_count; k++)
                if (!witness_u(event_values[k], WITNESS_MAX_PLAN_VALUES,
                               &type->event_value_ids[j][k])
                    || type->event_value_ids[j][k] == 0) return 0;
        }
        type->value_count = value_count;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[4];
            uint32_t ignored_initial;
            if (!witness_record(values[j], vf, 4)
                || !witness_u(vf[0], WITNESS_MAX_PLAN_VALUES, &type->value_ids[j])
                || type->value_ids[j] != j + 1u
                || !witness_u(vf[2], 2, &type->value_types[j])
                || (type->value_types[j] != 1 && type->value_types[j] != 2)
                || !witness_u(vf[3], type->value_types[j] == 1 ? 1 : 65535,
                              &ignored_initial)) return 0;
        }
        type->state_count = state_count;
        uint32_t initial_states = 0;
        for (uint32_t j = 0; j < state_count; j++) {
            noun sf[3];
            uint32_t id, initial;
            if (!witness_record(states[j], sf, 3)
                || !witness_u(sf[0], WITNESS_MAX_PLAN_STATES, &id)
                || id != j + 1u || !witness_u(sf[1], 1, &initial)) return 0;
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
        if (!witness_record(instances[i], fields, 2)
            || !witness_u(fields[0], WITNESS_MAX_PLAN_INSTANCES, &id)
            || id != i + 1u
            || !witness_u(fields[1], WITNESS_MAX_PLAN_TYPES, &type_id)
            || !witness_plan_type(&plan, type_id)) return 0;
        plan.instance_types[i] = type_id;
    }
    *out = plan;
    return 1;
}

static int witness_make_value(uint32_t id, uint32_t type, uint32_t value, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(value)};
    return witness_build_tagged("m38-resource-abi-v1-numeric-value",
                               "m38-resource-abi-v1-numeric-value-schema-v1",
                               fields, 3, out);
}

static int witness_make_stimulus(const WitnessPlan *plan, noun *out)
{
    const WitnessPlanType *chosen = 0;
    uint32_t event_index = 0;
    for (uint32_t i = 0; i < plan->type_count && !chosen; i++) {
        const WitnessPlanType *type = &plan->types[i];
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
    noun values[WITNESS_MAX_PLAN_VALUES];
    uint32_t value_count = chosen->event_value_counts[event_index];
    for (uint32_t i = 0; i < value_count; i++) {
        uint32_t id = chosen->event_value_ids[event_index][i];
        uint32_t type = 0;
        for (uint32_t j = 0; j < chosen->value_count; j++)
            if (chosen->value_ids[j] == id) type = chosen->value_types[j];
        if ((type != 1 && type != 2)
            || !witness_make_value(id, type, type == 1 ? 0 : 12, &values[i])) return 0;
    }
    noun value_list, fields[2];
    if (!witness_build_list(values, value_count, &value_list)) return 0;
    fields[0] = direct(chosen->event_ids[event_index]);
    fields[1] = value_list;
    return witness_build_tagged(WITNESS_STIMULUS_TAG, WITNESS_STIMULUS_SCHEMA,
                                fields, 2, out);
}

static int witness_make_request(uint32_t operation, noun args, noun *out)
{
    noun fields[2] = {direct(operation), args};
    return witness_build_tagged(WITNESS_REQUEST_TAG, WITNESS_REQUEST_SCHEMA,
                                fields, 2, out);
}

static int witness_result_body(const ResourceResultView *view, noun *body)
{
    noun tag, result_body, fields[3];
    if (!view || !view->root_slot
        || !witness_pair(*view->root_slot, &tag, &result_body)
        || !witness_atom_text(tag, WITNESS_RESULT_TAG)
        || !witness_record(result_body, fields, 3)) return 0;
    *body = fields[2];
    return 1;
}

static int witness_handle_from_load(const ResourceResultView *view, noun *handle)
{
    if (view && view->handle_slot && *view->handle_slot != NOUN_ZERO) {
        *handle = *view->handle_slot;
        return 1;
    }
    noun body, fields[2];
    return witness_result_body(view, &body)
        && witness_record(body, fields, 2)
        && (*handle = fields[0], 1);
}

static int witness_make_handle_request(uint32_t operation, noun handle,
                                       noun second, noun *request)
{
    noun args;
    if (operation == WITNESS_OP_SNAPSHOT) args = handle;
    else {
        noun fields[2] = {handle, second};
        if (!witness_build_record(fields, 2, &args)) return 0;
    }
    return witness_make_request(operation, args, request);
}

static void witness_line(const char *operation, M38Status status,
                         const ResourceResultView *view)
{
    uart_puts("M38D8A v=1 op=");
    uart_puts(operation);
    uart_puts(" status=");
    if (status == M38_STATUS_OK && view) uart_puts("ok");
    else if (status == M38_STATUS_REQUEST_INVALID) uart_puts("request-invalid");
    else if (status == M38_STATUS_OK) uart_puts("no-view");
    else uart_puts("fault");
    uart_puts("\r\n");
}

static void witness_terminal(const char *status)
{
    uart_puts("M38D8A v=1 terminal=");
    uart_puts(status);
    uart_puts("\r\n");
}

static uint32_t witness_atom_bytes(noun atom)
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
        || stored->size > WITNESS_MAX_CORE_JAM_BYTES / sizeof(uint64_t)) return 0;
    uint64_t last = stored->limbs[stored->size - 1u];
    uint32_t significant = sizeof(uint64_t);
    while (significant > 1u && ((last >> ((significant - 1u) * 8u)) & 0xffu) == 0)
        significant--;
    return (uint32_t)((stored->size - 1u) * sizeof(uint64_t) + significant);
}

static int witness_decode_pill(noun *input)
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

static int witness_extract_jams(noun input, uint32_t record_bytes[2],
                                uint32_t core_bytes[2])
{
    noun rows[2], pair[2];
    uint32_t row_count;
    if (!witness_list(input, rows, 2, &row_count) || row_count != 2) return 0;
    for (uint32_t i = 0; i < 2; i++) {
        if (!witness_record(rows[i], pair, 2)) return 0;
        record_bytes[i] = witness_atom_bytes(pair[0]);
        core_bytes[i] = witness_atom_bytes(pair[1]);
        if (record_bytes[i] == 0 || core_bytes[i] == 0
            || record_bytes[i] > WITNESS_MAX_RECORD_JAM_BYTES
            || core_bytes[i] > WITNESS_MAX_CORE_JAM_BYTES
            || !noun_atom_read_fixed(pair[0], witness_jams[i][0], record_bytes[i])
            || !noun_atom_read_fixed(pair[1], witness_jams[i][1], core_bytes[i])) return 0;
    }
    return 1;
}

void m38_resource_wave_a_boot(void)
{
    noun input;
    uint32_t record_bytes[2], core_bytes[2];
    if (!witness_decode_pill(&input) || !witness_extract_jams(input, record_bytes, core_bytes)) {
        witness_terminal("refuse");
        return;
    }
    if (noun_tx_active()) noun_tx_abort();
    heap_scratch_reset();

    SupervisorAdmissionEntry entries[2] = {
        {witness_jams[0][0], record_bytes[0], witness_jams[0][1], core_bytes[0]},
        {witness_jams[1][0], record_bytes[1], witness_jams[1][1], core_bytes[1]},
    };
    SupervisorAdmissionCatalog catalog;
    ResourceRuntime *runtime;
    if (m38_supervisor_admission_catalog_make(&catalog, entries, 2) != M38_STATUS_OK
        || m38_resource_runtime_init(witness_control, WITNESS_RUNTIME_CONTROL_BYTES,
                                     witness_workspace, WITNESS_RUNTIME_WORKSPACE_BYTES,
                                     &runtime) != M38_STATUS_OK) {
        witness_terminal("refuse");
        return;
    }
    ResourceSession *session_a, *session_b;
    SessionCapability cap_a, cap_b;
    if (m38_resource_session_init(runtime, witness_session_a, WITNESS_SESSION_BYTES,
                                  &catalog, &session_a, &cap_a) != M38_STATUS_OK
        || m38_resource_session_init(runtime, witness_session_b, WITNESS_SESSION_BYTES,
                                     &catalog, &session_b, &cap_b) != M38_STATUS_OK) {
        witness_terminal("refuse");
        return;
    }
    (void)cap_a;
    (void)cap_b;

    noun cores[2];
    WitnessPlan plans[2];
    for (uint32_t i = 0; i < 2; i++) {
        heap_set_mode(HEAP_MODE_PERSIST);
        if (cue_bounded_bytes(witness_jams[i][1], core_bytes[i], &cue_i2_limits,
                              HEAP_MODE_PERSIST, &cores[i]) != CUE_BOUNDED_OK
            || !witness_parse_plan(cores[i], &plans[i])) {
            witness_terminal("refuse");
            return;
        }
        noun_tx_commit();
    }

    noun request, handle_a, handle_b, stimulus_a, stimulus_b, selector;
    const ResourceResultView *view = 0;
    const ResourceResultView *load_view_a = 0;
    if (!witness_make_request(WITNESS_OP_LOAD, cores[0], &request)) {
        witness_terminal("refuse");
        return;
    }
    M38Status status = m38_resource_session_dispatch(session_a, request, &view);
    witness_line("LOAD-A", status, view);
    if (status != M38_STATUS_OK || !witness_handle_from_load(view, &handle_a)) {
        witness_terminal("refuse");
        return;
    }
    load_view_a = view;

    /* Promotion rewrites persist roots.  Re-cue this externally owned core
     * before submitting the second session's load. */
    heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(witness_jams[1][1], core_bytes[1], &cue_i2_limits,
                          HEAP_MODE_PERSIST, &cores[1]) != CUE_BOUNDED_OK) {
        witness_terminal("refuse");
        return;
    }
    noun_tx_commit();
    if (!witness_make_request(WITNESS_OP_LOAD, cores[1], &request)) {
        witness_terminal("refuse");
        return;
    }
    view = 0;
    status = m38_resource_session_dispatch(session_b, request, &view);
    witness_line("LOAD-B", status, view);
    if (status != M38_STATUS_OK || !witness_handle_from_load(view, &handle_b)) {
        witness_terminal("refuse");
        return;
    }
    const ResourceResultView *load_view_b = view;
    if (!witness_make_stimulus(&plans[0], &stimulus_a)
        || !witness_make_stimulus(&plans[1], &stimulus_b)) {
        witness_terminal("refuse");
        return;
    }
    noun selector_fields[1] = {direct(1)};
    if (!witness_build_tagged(WITNESS_SELECTOR_TAG, WITNESS_SELECTOR_SCHEMA,
                              selector_fields, 1, &selector)) {
        witness_terminal("refuse");
        return;
    }

    heap_set_mode(HEAP_MODE_PERSIST);
    view = 0;
    if (!witness_handle_from_load(load_view_a, &handle_a)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_handle_request(WITNESS_OP_POKE, handle_a, stimulus_a, &request)) {
        witness_terminal("refuse");
        return;
    }
    status = m38_resource_session_dispatch(session_a, request, &view);
    witness_line("POKE-A", status, view);
    if (status != M38_STATUS_OK || !view) { witness_terminal("refuse"); return; }

    heap_set_mode(HEAP_MODE_PERSIST);
    view = 0;
    if (!witness_handle_from_load(load_view_b, &handle_b)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_stimulus(&plans[1], &stimulus_b)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_handle_request(WITNESS_OP_POKE, handle_b, stimulus_b, &request)) {
        witness_terminal("refuse");
        return;
    }
    status = m38_resource_session_dispatch(session_b, request, &view);
    witness_line("POKE-B", status, view);
    if (status != M38_STATUS_OK || !view) { witness_terminal("refuse"); return; }

    heap_set_mode(HEAP_MODE_PERSIST);
    view = 0;
    if (!witness_handle_from_load(load_view_b, &handle_b)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_build_tagged(WITNESS_SELECTOR_TAG, WITNESS_SELECTOR_SCHEMA,
                              selector_fields, 1, &selector)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_handle_request(WITNESS_OP_PEEK, handle_b, selector, &request)) {
        witness_terminal("refuse");
        return;
    }
    status = m38_resource_session_dispatch(session_b, request, &view);
    witness_line("PEEK-B", status, view);
    if (status != M38_STATUS_OK || !view) { witness_terminal("refuse"); return; }

    heap_set_mode(HEAP_MODE_PERSIST);
    view = 0;
    if (!witness_handle_from_load(load_view_a, &handle_a)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_handle_request(WITNESS_OP_SNAPSHOT, handle_a, NOUN_ZERO, &request)) {
        witness_terminal("refuse");
        return;
    }
    status = m38_resource_session_dispatch(session_a, request, &view);
    witness_line("SNAPSHOT-A", status, view);
    noun snapshot;
    if (status != M38_STATUS_OK || !view || !witness_result_body(view, &snapshot)) {
        witness_terminal("refuse");
        return;
    }

    heap_set_mode(HEAP_MODE_PERSIST);
    view = 0;
    if (!witness_handle_from_load(load_view_a, &handle_a)) {
        witness_terminal("refuse");
        return;
    }
    if (!witness_make_handle_request(WITNESS_OP_RESTORE, handle_a, snapshot, &request)) {
        witness_terminal("refuse");
        return;
    }
    status = m38_resource_session_dispatch(session_a, request, &view);
    witness_line("RESTORE-A", status, view);
    if (status != M38_STATUS_OK || !view) {
        witness_terminal("refuse");
        return;
    }
    witness_terminal("pass");
}
