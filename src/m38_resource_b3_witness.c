#include <stddef.h>
#include <stdint.h>

#include "bounded_cue.h"
#include "jam.h"
#include "m38_resource_b3_observability.h"
#include "m38_resource_runtime.h"
#include "m38_resource_test_controls.h"
#include "memory.h"
#include "noun.h"
#include "nock.h"
#include "uart.h"

#define B3_CORE_COUNT 2u
#define B3_MAX_JAM_BYTES (128u * 1024u)
#define B3_MAX_RECORD_BYTES (128u * 1024u)
#define B3_MAX_TYPES 8u
#define B3_MAX_EVENTS 16u
#define B3_MAX_VALUES 16u
#define B3_MAX_STATES 8u
#define B3_MAX_INSTANCES 8u
#define B3_HANDLE_BYTES 32u
#define B3_MAX_HANDLES 8u

#define B3_OP_LOAD 1u
#define B3_OP_POKE 2u
#define B3_WIRE_LOAD 1u
#define B3_WIRE_POKE 2u

static const char B3_REQUEST_TAG[] = "m38-resource-abi-v1-request";
static const char B3_REQUEST_SCHEMA[] = "m38-resource-abi-v1-request-schema-v1";
static const char B3_RESULT_TAG[] = "m38-resource-abi-v1-result";
static const char B3_STIMULUS_TAG[] = "m38-resource-abi-v1-numeric-stimulus";
static const char B3_STIMULUS_SCHEMA[] =
    "m38-resource-abi-v1-numeric-stimulus-schema-v1";

static uint8_t b3_control[64u * 1024u] __attribute__((aligned(64)));
static uint8_t b3_workspace[4u * 1024u * 1024u]
    __attribute__((aligned(64)));
static uint8_t b3_session_a[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
#if M38_D8_B3_SESSIONS == 2
static uint8_t b3_session_b[2u * 1024u * 1024u]
    __attribute__((aligned(64)));
#endif
static uint8_t b3_jams[B3_CORE_COUNT][2][B3_MAX_JAM_BYTES]
    __attribute__((aligned(64)));
static void b3_put_u64(uint64_t value);

typedef struct B3Handle {
    uint64_t capability;
    uint32_t slot;
    uint64_t generation;
    uint8_t admission_id[B3_HANDLE_BYTES];
} B3Handle;

typedef struct B3Type {
    uint32_t id;
    uint32_t value_count;
    uint32_t value_ids[B3_MAX_VALUES];
    uint32_t value_types[B3_MAX_VALUES];
    uint32_t event_count;
    uint32_t event_ids[B3_MAX_EVENTS];
    uint32_t event_value_counts[B3_MAX_EVENTS];
    uint32_t event_value_ids[B3_MAX_EVENTS][B3_MAX_VALUES];
} B3Type;

typedef struct B3Plan {
    uint32_t type_count;
    B3Type types[B3_MAX_TYPES];
} B3Plan;

static B3Plan b3_plans[B3_CORE_COUNT];

typedef struct B3Row {
    uint32_t sequence;
    uint32_t session;
    uint32_t operation;
    uint32_t load_index;
    uint32_t core;
    uint32_t sessions;
    uint32_t cores;
    M38Status status;
    uint64_t wire_status;
    uint64_t view_present;
    uint64_t zero_residue;
    uint64_t selector_before;
    uint64_t selector_after;
    M38B3Metrics before;
    M38B3Metrics after;
    uint64_t evaluator_ops;
    uint64_t evaluator_cells;
    uint64_t evaluator_depth;
} B3Row;

static B3Row b3_work_row __attribute__((section(".data"), aligned(64)));

static uint32_t b3_sequence __attribute__((section(".data")));

static size_t b3_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static noun b3_cord(const char *s)
{
    return cord_from_bytes(s, b3_strlen(s));
}

static int b3_pair(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int b3_record(noun n, noun *out, uint32_t count)
{
    noun cur = n;
    for (uint32_t i = 0; i < count; i++) {
        if (!b3_pair(cur, &out[i], &cur)) return 0;
    }
    return cur == NOUN_ZERO;
}

static int b3_list(noun n, noun *out, uint32_t limit, uint32_t *count)
{
    noun cur = n;
    uint32_t used = 0;
    while (cur != NOUN_ZERO) {
        if (used == limit || !b3_pair(cur, &out[used], &cur)) return 0;
        used++;
    }
    *count = used;
    return 1;
}

static int b3_atom_text(noun n, const char *s)
{
    uint8_t bytes[256];
    size_t len = b3_strlen(s);
    if (len >= sizeof(bytes) || !noun_atom_read_fixed(n, bytes, sizeof(bytes)))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != (uint8_t)s[i]) return 0;
    for (size_t i = len; i < sizeof(bytes); i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int b3_u(noun n, uint64_t max, uint32_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) > max) return 0;
    *out = (uint32_t)direct_val(n);
    return 1;
}

static int b3_u64(noun n, uint64_t max, uint64_t *out)
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

static int b3_u64_atom(uint64_t value, noun *out)
{
    if (!out) return 0;
    if (value <= 0x7FFFFFFFFFFFFFFFULL) {
        *out = direct(value);
        return 1;
    }
    return make_atom_checked(&value, 1, out);
}

static int b3_digest_atom(const uint8_t digest[B3_HANDLE_BYTES], noun *out)
{
    uint64_t limbs[B3_HANDLE_BYTES / sizeof(uint64_t)] = {0};
    if (!digest || !out) return 0;
    for (uint32_t i = 0; i < B3_HANDLE_BYTES / sizeof(uint64_t); i++)
        for (uint32_t j = 0; j < sizeof(uint64_t); j++)
            limbs[i] |= (uint64_t)digest[i * sizeof(uint64_t) + j] << (8u * j);
    return make_atom_checked(limbs, B3_HANDLE_BYTES / sizeof(uint64_t), out);
}

static int b3_build_list(const noun *items, uint32_t count, noun *out)
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

static int b3_build_tagged(const char *tag, const char *schema,
                           const noun *fields, uint32_t count, noun *out)
{
    noun row[1u + B3_MAX_VALUES];
    if (count >= 1u + B3_MAX_VALUES) return 0;
    row[0] = b3_cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1u] = fields[i];
    noun body;
    if (!b3_build_list(row, count + 1u, &body)) return 0;
    return alloc_cell_checked(b3_cord(tag), body, out);
}

static uint32_t b3_atom_bytes(noun atom)
{
    if (noun_is_direct(atom)) {
        uint64_t value = direct_val(atom);
        uint32_t bytes = 0;
        while (value != 0u) { bytes++; value >>= 8; }
        return bytes == 0u ? 1u : bytes;
    }
    if (!noun_is_indirect(atom)) return 0;
    atom_t *stored = atom_store_get(indirect_hash(atom));
    if (!stored || stored->size == 0u
        || stored->size > B3_MAX_JAM_BYTES / sizeof(uint64_t)) return 0;
    uint64_t last = stored->limbs[stored->size - 1u];
    uint32_t significant = sizeof(uint64_t);
    while (significant > 1u
           && ((last >> ((significant - 1u) * 8u)) & 0xffu) == 0u)
        significant--;
    return (uint32_t)((stored->size - 1u) * sizeof(uint64_t) + significant);
}

static int b3_decode_pill(noun *input, uint32_t record_bytes[B3_CORE_COUNT],
                          uint32_t core_bytes[B3_CORE_COUNT])
{
    volatile uint8_t *base = (volatile uint8_t *)(uintptr_t)PILL_BASE;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < 8u; i++) bytes |= (uint64_t)base[i] << (8u * i);
    if (!input || bytes == 0u || bytes > 1024u * 1024u) return 0;
    noun decoded;
    if (cue_bounded_bytes((const uint8_t *)(uintptr_t)(PILL_BASE + 16u), bytes,
                          &cue_i2_limits, HEAP_MODE_SCRATCH, &decoded)
            != CUE_BOUNDED_OK) return 0;
    noun rows[B3_CORE_COUNT], pair[2];
    uint32_t row_count;
    if (!b3_list(decoded, rows, B3_CORE_COUNT, &row_count)
        || row_count != B3_CORE_COUNT) return 0;
    for (uint32_t i = 0; i < B3_CORE_COUNT; i++) {
        if (!b3_record(rows[i], pair, 2)) return 0;
        record_bytes[i] = b3_atom_bytes(pair[0]);
        core_bytes[i] = b3_atom_bytes(pair[1]);
        if (record_bytes[i] == 0u || core_bytes[i] == 0u
            || record_bytes[i] > B3_MAX_RECORD_BYTES
            || core_bytes[i] > B3_MAX_JAM_BYTES
            || !noun_atom_read_fixed(pair[0], b3_jams[i][0], record_bytes[i])
            || !noun_atom_read_fixed(pair[1], b3_jams[i][1], core_bytes[i]))
            return 0;
    }
    *input = decoded;
    return 1;
}

static int b3_parse_plan(noun core, B3Plan *out)
{
    noun formula, payload, payload_tag, payload_body, pf[2], semantic[5];
    noun types[B3_MAX_TYPES], instances[B3_MAX_INSTANCES];
    uint32_t type_count, instance_count;
    if (!b3_pair(core, &formula, &payload)
        || !b3_pair(payload, &payload_tag, &payload_body)
        || !b3_atom_text(payload_tag, "m38-d0-r2-resource-payload")
        || !b3_record(payload_body, pf, 2)
        || !b3_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
        || !b3_record(pf[1], semantic, 5)
        || !b3_list(semantic[0], types, B3_MAX_TYPES, &type_count)
        || !b3_list(semantic[1], instances, B3_MAX_INSTANCES, &instance_count)
        || type_count == 0u || instance_count == 0u)
        return 0;
    (void)formula;
    B3Plan plan = {0};
    plan.type_count = type_count;
    for (uint32_t i = 0; i < type_count; i++) {
        noun tf[6], events[B3_MAX_EVENTS], values[B3_MAX_VALUES];
        noun states[B3_MAX_STATES];
        uint32_t event_count, value_count, state_count;
        B3Type *type = &plan.types[i];
        if (!b3_record(types[i], tf, 6)
            || !b3_u(tf[0], B3_MAX_TYPES, &type->id)
            || type->id != i + 1u
            || !b3_list(tf[1], events, B3_MAX_EVENTS, &event_count)
            || !b3_list(tf[2], values, B3_MAX_VALUES, &value_count)
            || !b3_list(tf[3], states, B3_MAX_STATES, &state_count)
            || value_count == 0u || state_count == 0u)
            return 0;
        type->event_count = event_count;
        type->value_count = value_count;
        for (uint32_t j = 0; j < event_count; j++) {
            noun ef[3], event_values[B3_MAX_VALUES];
            uint32_t direction, event_value_count;
            if (!b3_record(events[j], ef, 3)
                || !b3_u(ef[0], 0xFFFFu, &type->event_ids[j])
                || type->event_ids[j] == 0u
                || !b3_u(ef[1], 2u, &direction)
                || !b3_list(ef[2], event_values, B3_MAX_VALUES,
                             &event_value_count)) return 0;
            type->event_value_counts[j] = event_value_count;
            for (uint32_t k = 0; k < event_value_count; k++)
                if (!b3_u(event_values[k], B3_MAX_VALUES,
                          &type->event_value_ids[j][k])
                    || type->event_value_ids[j][k] == 0u) return 0;
        }
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[4];
            uint32_t initial;
            if (!b3_record(values[j], vf, 4)
                || !b3_u(vf[0], B3_MAX_VALUES, &type->value_ids[j])
                || type->value_ids[j] != j + 1u
                || !b3_u(vf[2], 2u, &type->value_types[j])
                || (type->value_types[j] != 1u && type->value_types[j] != 2u)
                || !b3_u(vf[3], type->value_types[j] == 1u ? 1u : 65535u,
                         &initial)) return 0;
        }
    }
    for (uint32_t i = 0; i < instance_count; i++) {
        noun fields[2];
        uint32_t id, type_id;
        if (!b3_record(instances[i], fields, 2)
            || !b3_u(fields[0], B3_MAX_INSTANCES, &id)
            || id != i + 1u
            || !b3_u(fields[1], B3_MAX_TYPES, &type_id)
            || type_id == 0u || type_id > plan.type_count) return 0;
    }
    *out = plan;
    return 1;
}

static int b3_make_value(uint32_t id, uint32_t type, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(type == 1u ? 0u : 12u)};
    return b3_build_tagged("m38-resource-abi-v1-numeric-value",
                           "m38-resource-abi-v1-numeric-value-schema-v1",
                           fields, 3, out);
}

static int b3_make_stimulus(const B3Plan *plan, noun *out)
{
    const B3Type *chosen = 0;
    uint32_t event_index = 0;
    for (uint32_t i = 0; i < plan->type_count && !chosen; i++) {
        const B3Type *type = &plan->types[i];
        for (uint32_t j = 0; j < type->event_count; j++) {
            if (type->event_value_counts[j] == 0u) continue;
            uint32_t id = type->event_value_ids[j][0];
            for (uint32_t k = 0; k < type->value_count; k++)
                if (type->value_ids[k] == id && type->value_types[k] == 1u) {
                    chosen = type;
                    event_index = j;
                    break;
                }
            if (chosen) break;
        }
    }
    if (!chosen) return 0;
    noun values[B3_MAX_VALUES];
    uint32_t count = chosen->event_value_counts[event_index];
    for (uint32_t i = 0; i < count; i++) {
        uint32_t id = chosen->event_value_ids[event_index][i], type = 0;
        for (uint32_t j = 0; j < chosen->value_count; j++)
            if (chosen->value_ids[j] == id) type = chosen->value_types[j];
        if ((type != 1u && type != 2u) || !b3_make_value(id, type, &values[i]))
            return 0;
    }
    noun value_list, fields[2];
    if (!b3_build_list(values, count, &value_list)) return 0;
    fields[0] = direct(chosen->event_ids[event_index]);
    fields[1] = value_list;
    return b3_build_tagged(B3_STIMULUS_TAG, B3_STIMULUS_SCHEMA, fields, 2, out);
}

static int b3_make_request(uint32_t operation, noun args, noun *out)
{
    noun fields[2] = {direct(operation), args};
    return b3_build_tagged(B3_REQUEST_TAG, B3_REQUEST_SCHEMA, fields, 2, out);
}

static int b3_result_body(const ResourceResultView *view, noun *body)
{
    noun tag, result_body, fields[3];
    if (!view || !view->root_slot
        || !b3_pair(*view->root_slot, &tag, &result_body)
        || !b3_atom_text(tag, B3_RESULT_TAG)
        || !b3_record(result_body, fields, 3)) return 0;
    *body = fields[2];
    return 1;
}

static int b3_handle_from_load(const ResourceResultView *view, B3Handle *handle)
{
    noun body, fields[2], handle_fields[4];
    uint64_t capability, generation;
    uint32_t slot;
    if (!view || !handle || view->owner != M38_RESULT_OWNER_PRIMARY
        || view->wire_status != B3_WIRE_LOAD
        || !b3_result_body(view, &body)
        || !b3_record(body, fields, 2)
        || !b3_record(fields[0], handle_fields, 4)
        || !b3_u64(handle_fields[0], UINT64_MAX, &capability)
        || capability == 0u
        || !b3_u(handle_fields[1], B3_MAX_HANDLES, &slot)
        || slot == 0u
        || !b3_u64(handle_fields[2], UINT64_MAX, &generation)
        || generation == 0u
        || !noun_atom_read_fixed(handle_fields[3], handle->admission_id,
                                 B3_HANDLE_BYTES)) return 0;
    handle->capability = capability;
    handle->slot = slot;
    handle->generation = generation;
    return 1;
}

static int b3_handle_to_noun(const B3Handle *handle, noun *out)
{
    noun fields[4], admission;
    if (!handle || !out || handle->capability == 0u || handle->slot == 0u
        || handle->generation == 0u
        || !b3_u64_atom(handle->capability, &fields[0])
        || !b3_u64_atom(handle->generation, &fields[2])
        || !b3_digest_atom(handle->admission_id, &admission)) return 0;
    fields[1] = direct(handle->slot);
    fields[3] = admission;
    return b3_build_list(fields, 4, out);
}

static int b3_core_noun(uint32_t index, uint32_t bytes, noun *out)
{
    if (index >= B3_CORE_COUNT || bytes == 0u || bytes > B3_MAX_JAM_BYTES)
        return 0;
    heap_set_mode(HEAP_MODE_PERSIST);
    if (cue_bounded_bytes(b3_jams[index][1], bytes, &cue_i2_limits,
                          HEAP_MODE_PERSIST, out) != CUE_BOUNDED_OK) return 0;
    noun_tx_commit();
    return 1;
}

static void b3_put_u64(uint64_t value)
{
    char digits[24];
    uint32_t used = 0;
    if (value == 0u) {
        uart_puts("0");
        return;
    }
    while (value != 0u) {
        digits[used++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (used != 0u) uart_putc((uint8_t)digits[--used]);
}

static void b3_put_metrics(const M38B3Metrics *m)
{
    b3_put_u64(m->persistent_cells_current);
    uart_puts(","); b3_put_u64(m->scratch_cells_current);
    uart_puts(","); b3_put_u64(m->persistent_cells_hwm);
    uart_puts(","); b3_put_u64(m->scratch_cells_hwm);
    uart_puts(","); b3_put_u64(m->atom_bytes_current);
    uart_puts(","); b3_put_u64(m->atom_bytes_hwm);
    uart_puts(","); b3_put_u64(m->atom_index_occupancy_current);
    uart_puts(","); b3_put_u64(m->atom_index_occupancy_hwm);
    uart_puts(","); b3_put_u64(m->atom_index_probe_depth_hwm);
    uart_puts(","); b3_put_u64(m->copied_session_a_cells);
    uart_puts(","); b3_put_u64(m->copied_session_b_cells);
    uart_puts(","); b3_put_u64(m->copied_staged_cells);
    uart_puts(","); b3_put_u64(m->copy_map_passes);
    uart_puts(","); b3_put_u64(m->copy_map_clear_bytes);
    uart_puts(","); b3_put_u64(m->copy_map_peak_entries);
    uart_puts(","); b3_put_u64(m->copy_map_peak_probe_depth);
}

static void b3_put_row(const B3Row *row)
{
    uart_puts("M38D8B3 row="); b3_put_u64(row->sequence);
    uart_puts(" session="); b3_put_u64(row->session);
    uart_puts(" op="); b3_put_u64(row->operation);
    uart_puts(" load="); b3_put_u64(row->load_index);
    uart_puts(" core="); b3_put_u64(row->core);
    uart_puts(" sessions="); b3_put_u64(row->sessions);
    uart_puts(" cores="); b3_put_u64(row->cores);
    uart_puts(" status="); b3_put_u64(row->status);
    uart_puts(" wire="); b3_put_u64(row->wire_status);
    uart_puts(" view="); b3_put_u64(row->view_present);
    uart_puts(" zero="); b3_put_u64(row->zero_residue);
    uart_puts(" selector_before="); b3_put_u64(row->selector_before);
    uart_puts(" selector_after="); b3_put_u64(row->selector_after);
    uart_puts(" eval_ops="); b3_put_u64(row->evaluator_ops);
    uart_puts(" eval_cells="); b3_put_u64(row->evaluator_cells);
    uart_puts(" eval_depth="); b3_put_u64(row->evaluator_depth);
    uart_puts(" before="); b3_put_metrics(&row->before);
    uart_puts(" after="); b3_put_metrics(&row->after);
    uart_puts("\r\n");
}

/* Keep the dedicated witness driver stable under the cross compiler. This
 * does not affect normal builds or any ResourceABI/runtime implementation. */
static __attribute__((noinline, optimize("O0"))) int b3_dispatch(ResourceSession *session, noun request,
                       uint32_t session_index, uint32_t operation,
                       uint32_t load_index, uint32_t core,
                       uint32_t expected_status, uint32_t expected_wire,
                       const ResourceResultView **view_out)
{
    const ResourceResultView *view = 0;
    B3Row *row = &b3_work_row;
    row->sequence = ++b3_sequence;
    row->session = session_index;
    row->operation = operation;
    row->load_index = load_index;
    row->core = core;
    row->sessions = M38_D8_B3_SESSIONS;
    row->cores = M38_D8_B3_CORES;
    row->selector_before = heap_persist_selector();
    noun_b3_metrics_begin_row();
    noun_b3_metrics_read(&row->before);
    nock_budget_set_limits(0, 0);
    M38Status status = m38_resource_session_dispatch(session, request, &view);
    row->status = status;
    row->view_present = view != 0;
    row->wire_status = view ? view->wire_status : 0u;
    row->selector_after = heap_persist_selector();
    row->evaluator_ops = nock_ops_used();
    row->evaluator_cells = nock_cells_used();
    row->evaluator_depth = nock_eval_stack_peak();
    noun_b3_metrics_read(&row->after);
    row->zero_residue = row->status != M38_STATUS_OK
        && row->view_present == 0u
        && row->before.persistent_cells_current == row->after.persistent_cells_current
        && row->before.scratch_cells_current == row->after.scratch_cells_current
        && row->before.atom_bytes_current == row->after.atom_bytes_current
        && row->before.atom_index_occupancy_current
            == row->after.atom_index_occupancy_current
        && row->selector_before == row->selector_after;
    b3_put_row(row);
    if (view_out) *view_out = view;
    return status == expected_status && row->wire_status == expected_wire
        && (status == M38_STATUS_OK ? view != 0 : view == 0)
        && (status == M38_STATUS_OK || row->zero_residue);
}

void m38_resource_b3_boot(void)
{
    noun input;
    uint32_t record_bytes[B3_CORE_COUNT], core_bytes[B3_CORE_COUNT];
    if (!b3_decode_pill(&input, record_bytes, core_bytes)) {
        uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
        return;
    }
    if (noun_tx_active()) noun_tx_abort();
    heap_scratch_reset();
    for (uint32_t i = 0; i < B3_CORE_COUNT; i++) b3_plans[i].type_count = 0;
    for (uint32_t i = 0; i < M38_D8_B3_CORES; i++) {
        noun core;
        if (!b3_core_noun(i, core_bytes[i], &core)
            || !b3_parse_plan(core, &b3_plans[i])) {
            uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
            return;
        }
        if (i == 1u) continue;
    }
    /* The plan is exported into scalar witness state before runtime init.
     * Drop those temporary cue roots so B3 measures only admitted runtime
     * state and per-operation allocations, not driver bookkeeping roots. */
    heap_persist_reset();
    heap_scratch_reset();
    SupervisorAdmissionEntry entries[B3_CORE_COUNT] = {
        {b3_jams[0][0], record_bytes[0], b3_jams[0][1], core_bytes[0]},
        {b3_jams[1][0], record_bytes[1], b3_jams[1][1], core_bytes[1]},
    };
    SupervisorAdmissionCatalog catalog;
    ResourceRuntime *runtime = 0;
    ResourceSession *sessions[2] = {0, 0};
    SessionCapability capabilities[2] = {0, 0};
    if (m38_supervisor_admission_catalog_make(&catalog, entries,
                                              M38_D8_B3_CORES)
            != M38_STATUS_OK
        || m38_resource_runtime_init(b3_control, sizeof(b3_control),
                                     b3_workspace, sizeof(b3_workspace),
                                     &runtime) != M38_STATUS_OK
        || m38_resource_session_init(runtime, b3_session_a, sizeof(b3_session_a),
                                     &catalog, &sessions[0], &capabilities[0])
            != M38_STATUS_OK
#if M38_D8_B3_SESSIONS == 2
        || m38_resource_session_init(runtime, b3_session_b, sizeof(b3_session_b),
                                     &catalog, &sessions[1], &capabilities[1])
            != M38_STATUS_OK
#endif
    ) {
        uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
        return;
    }
    (void)capabilities;

    noun_b3_metrics_reset();
    uart_puts("M38D8B3 v=1 case=s"); b3_put_u64(M38_D8_B3_SESSIONS);
    uart_puts("c"); b3_put_u64(M38_D8_B3_CORES); uart_puts("\r\n");

    B3Handle handles[2] = {0};
    for (uint32_t s = 0; s < M38_D8_B3_SESSIONS; s++) {
        for (uint32_t h = 0; h < B3_MAX_HANDLES; h++) {
            uint32_t core_index = M38_D8_B3_CORES == 1u ? 0u : (s + h) % 2u;
            noun core, request;
            if (!b3_core_noun(core_index, core_bytes[core_index], &core)
                || !b3_make_request(B3_OP_LOAD, core, &request)) {
                uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
                return;
            }
            const ResourceResultView *view = 0;
            if (!b3_dispatch(sessions[s], request, s + 1u, B3_OP_LOAD, h + 1u,
                             core_index + 1u, M38_STATUS_OK, B3_WIRE_LOAD,
                             &view)
                || !b3_handle_from_load(view, &handles[s])) {
                uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
                return;
            }
        }
        noun handle, stimulus, args, request;
        uint32_t core_index = M38_D8_B3_CORES == 1u ? 0u : (s + 7u) % 2u;
        if (!b3_handle_to_noun(&handles[s], &handle)
            || !b3_make_stimulus(&b3_plans[core_index], &stimulus)) {
            uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
            return;
        }
        noun poke_fields[2] = {handle, stimulus};
        if (!b3_build_list(poke_fields, 2, &args)
            || !b3_make_request(B3_OP_POKE, args, &request)) {
            uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
            return;
        }
        if (!b3_dispatch(sessions[s], request, s + 1u, B3_OP_POKE,
                         B3_MAX_HANDLES + 1u, core_index + 1u,
                         M38_STATUS_OK, B3_WIRE_POKE, 0)) {
            uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
            return;
        }
    }

    noun core, request;
    if (!b3_core_noun(0, core_bytes[0], &core)
        || !b3_make_request(B3_OP_LOAD, core, &request)) {
        uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
        return;
    }
    m38_resource_test_fail_next(runtime, M38_FAULT_COLLECTIVE_COMMIT);
    if (!b3_dispatch(sessions[0], request, 0u, B3_OP_LOAD, 0u, 1u,
                     M38_STATUS_COLLECTIVE_COMMIT, 0u, 0)) {
        uart_puts("M38D8B3 v=1 terminal=refuse\r\n");
        return;
    }
    uart_puts("M38D8B3 v=1 control=pass\r\n");
    uart_puts("M38D8B3 v=1 terminal=pass\r\n");
}
