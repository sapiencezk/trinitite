#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "noun.h"
#include "uart.h"

/*
 * M38-D1 native boundary.
 *
 * This file deliberately does not call the legacy PILL loader or recursive
 * decoder.  The
 * only untrusted bytes entering this target are decoded by cue_bounded_bytes,
 * and every noun which reaches Nock has already passed the complete numeric
 * M38-C grammar below.  Validation is allocation-free; scratch is the sole
 * staging area until the persistent root transaction commits.
 */
#define IMAGE_SCHEMA 1u
#define POLICY_MAX_OPS 2000000ULL
#define POLICY_MAX_CELLS 128000ULL
#define POLICY_MAX_STACK 1024ULL
#define QUEUE_LIMIT 8u
#define WORKLIST_LIMIT 32u
#define TRACE_LIMIT 128u
#define EXPR_DEPTH_LIMIT 32u
#define M38_D1_JAM_WORK_LIMIT 4000000ULL

#ifndef M38_D1_STATE_COPY_PROBE
#define M38_D1_STATE_COPY_PROBE 0
#endif
#ifndef M38_D1_REPEAT_REFUSAL_PROBE
#define M38_D1_REPEAT_REFUSAL_PROBE 0
#endif
#define M38_D1_REPEAT_COUNT 4u

#define M38_MAX_TYPES 8u
#define M38_MAX_EVENTS 8u
#define M38_MAX_VALUES 16u
#define M38_MAX_STATES 8u
#define M38_MAX_TRANSITIONS 16u
#define M38_MAX_ACTIONS 8u
#define M38_MAX_ALGORITHMS 8u
#define M38_MAX_INSTANCES 8u
#define M38_MAX_ROUTES 16u

#define TYPE_BOOL 1u
#define TYPE_UINT16 2u

#ifndef M38_D1_IMAGE_COPY_FAIL_AFTER
#define M38_D1_IMAGE_COPY_FAIL_AFTER (-1)
#endif
#ifndef M38_D1_STATE_COPY_FAIL_AFTER
#if M38_D1_STATE_COPY_PROBE
#define M38_D1_STATE_COPY_FAIL_AFTER 1
#else
#define M38_D1_STATE_COPY_FAIL_AFTER (-1)
#endif
#endif
#ifndef M38_D1_PROMOTION_FAIL
#define M38_D1_PROMOTION_FAIL 0
#endif

/* Frozen M38-B formula identities, represented as little-endian limbs. */
static const uint64_t M38C_DIAGNOSTIC_FORMULA_LIMBS[4] = {
    0xd0dbcb8ed417d899ULL, 0xed39139a5bf9f62dULL,
    0x824a2bfb780036efULL, 0xd450f368dbee147eULL,
};
static const uint64_t M38C_OPERATIONAL_FORMULA_LIMBS[4] = {
    0x88d98b77b6e1f6ccULL, 0x81bcc00131f69a66ULL,
    0x1db48566fdb303beULL, 0x74c92efa44caf596ULL,
};

typedef struct {
    uint32_t id;
    uint32_t direction;
    uint32_t with_count;
    uint32_t with_ids[M38_MAX_VALUES];
} m38_event_t;

typedef struct {
    uint32_t id;
    uint32_t direction;
    uint32_t type;
} m38_value_t;

typedef struct {
    uint32_t ordinal;
    uint32_t algorithm;
    uint32_t output_event;
} m38_action_t;

typedef struct {
    uint32_t id;
    uint32_t initial;
    uint32_t action_count;
    m38_action_t actions[M38_MAX_ACTIONS];
} m38_state_t;

typedef struct {
    uint32_t ordinal;
    uint32_t source;
    uint32_t destination;
    uint32_t event;
} m38_transition_t;

typedef struct {
    uint32_t id;
    uint32_t assignment_count;
} m38_algorithm_t;

typedef struct {
    uint32_t id;
    uint32_t event_count;
    uint32_t value_count;
    uint32_t state_count;
    uint32_t transition_count;
    uint32_t algorithm_count;
    m38_event_t events[M38_MAX_EVENTS];
    m38_value_t values[M38_MAX_VALUES];
    m38_state_t states[M38_MAX_STATES];
    m38_transition_t transitions[M38_MAX_TRANSITIONS];
    m38_algorithm_t algorithms[M38_MAX_ALGORITHMS];
} m38_type_t;

typedef struct {
    uint32_t type_count;
    uint32_t instance_count;
    m38_type_t types[M38_MAX_TYPES];
    uint32_t instance_types[M38_MAX_INSTANCES];
} m38_plan_t;

typedef struct {
    uint64_t work;
    uint64_t max_work;
} m38_validation_budget_t;

typedef struct {
    noun image;
    noun runtime_plan;
    noun base_plan;
    noun formula;
    noun state;
    noun stimuli;
    noun plan_identity;
    uint64_t mode;
    uint8_t image_digest[32];
    m38_plan_t plan;
} m38_image_t;

extern uint8_t __core0_stack_base[];
extern uint8_t __core0_stack_top[];
extern uint8_t _pill_embed_start[];
extern uint8_t _pill_embed_end[];

static void put_hex_byte(uint8_t value)
{
    static const char digits[] = "0123456789abcdef";
    uart_putc(digits[value >> 4]);
    uart_putc(digits[value & 0x0f]);
}

static void put_hex_u64(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4)
        uart_putc(digits[(value >> shift) & 0x0f]);
}

static uint64_t native_stack_hwm_words(void)
{
    volatile const uint64_t *cursor =
        (volatile const uint64_t *)(uintptr_t)__core0_stack_base;
    const uint64_t *top = (const uint64_t *)(uintptr_t)__core0_stack_top;
    while (cursor < top && *cursor == CORE0_STACK_PATTERN)
        cursor++;
    return (uint64_t)(top - (const uint64_t *)cursor);
}

static int digest_bytes(noun value, uint8_t digest[32],
                        jam_admission_budget_t *budget)
{
    const uint8_t *jammed;
    uint64_t length;
    if (jam_encode_bytes_identity_bounded(value, &jammed, &length, budget) != 0)
        return 0;
    blake3_hash(jammed, (size_t)length, digest);
    return 1;
}

static void put_digest_bytes(const uint8_t digest[32])
{
    /* Host noun_hash renders the little-endian digest as a hex integer. */
    for (int i = 31; i >= 0; i--)
        put_hex_byte(digest[i]);
}

static void put_digest(noun value)
{
    uint8_t digest[32];
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, M38_D1_JAM_WORK_LIMIT);
    if (!digest_bytes(value, digest, &budget)) {
        uart_puts("digest-error");
        return;
    }
    put_digest_bytes(digest);
}

static void put_allocator_receipt(uint64_t persist_before,
                                  uint64_t persist_hwm,
                                  uint64_t persist_after,
                                  uint64_t scratch_before,
                                  uint64_t scratch_hwm,
                                  uint64_t scratch_after,
                                  uint64_t atoms_before,
                                  uint64_t atoms_hwm,
                                  uint64_t atoms_after,
                                  uint64_t stack_words);

static int atom_tag(noun value, const uint8_t *bytes, size_t length)
{
    uint8_t got[64];
    if (length > sizeof got || !noun_is_atom(value))
        return 0;
    for (size_t i = 0; i < sizeof got; i++)
        got[i] = 0;
    if (noun_atom_read_fixed(value, got, sizeof got) == 0)
        return 0;
    for (size_t i = 0; i < length; i++)
        if (got[i] != bytes[i])
            return 0;
    for (size_t i = length; i < sizeof got; i++)
        if (got[i] != 0)
            return 0;
    return 1;
}

static int hash_atom_matches(noun value, const uint8_t expected[32])
{
    uint8_t got[32];
    if (!noun_is_atom(value) || noun_atom_read_fixed(value, got, sizeof got) == 0)
        return 0;
    for (unsigned i = 0; i < sizeof got; i++)
        if (got[i] != expected[i])
            return 0;
    return 1;
}

static int digest_field_matches(noun field, noun value,
                                jam_admission_budget_t *budget)
{
    uint8_t digest[32];
    return digest_bytes(value, digest, budget) && hash_atom_matches(field, digest);
}

static void limbs_to_bytes(const uint64_t limbs[4], uint8_t bytes[32])
{
    for (unsigned limb = 0; limb < 4; limb++)
        for (unsigned byte = 0; byte < 8; byte++)
            bytes[limb * 8 + byte] = (uint8_t)(limbs[limb] >> (byte * 8));
}

static int expected_formula_matches(noun value, uint64_t mode)
{
    uint8_t expected[32];
    limbs_to_bytes(mode == 0 ? M38C_DIAGNOSTIC_FORMULA_LIMBS
                             : M38C_OPERATIONAL_FORMULA_LIMBS, expected);
    return hash_atom_matches(value, expected);
}

/* Read exactly one proper numeric record.  No caller uses an unbounded field walk. */
static int record_exact(noun value, noun *fields, uint32_t count)
{
    noun current = value;
    for (uint32_t i = 0; i < count; i++) {
        if (!noun_is_cell(current))
            return 0;
        cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(current);
        fields[i] = cell->head;
        current = cell->tail;
    }
    return current == NOUN_ZERO;
}

static int list_collect(noun value, noun *items, uint32_t limit, uint32_t *count)
{
    noun current = value;
    uint32_t used = 0;
    while (current != NOUN_ZERO) {
        if (used >= limit || !noun_is_cell(current))
            return 0;
        cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(current);
        items[used++] = cell->head;
        current = cell->tail;
    }
    *count = used;
    return 1;
}

static int v_charge(m38_validation_budget_t *budget, uint64_t amount)
{
    if (amount > budget->max_work || budget->work > budget->max_work - amount)
        return 0;
    budget->work += amount;
    return 1;
}

static int direct_u(noun value, uint64_t maximum, uint32_t *out)
{
    if (!noun_is_direct(value) || direct_val(value) > maximum)
        return 0;
    *out = (uint32_t)direct_val(value);
    return 1;
}

static int typed_atom(noun type, noun raw)
{
    uint32_t code;
    if (!direct_u(type, TYPE_UINT16, &code) || !noun_is_direct(raw))
        return 0;
    if (code == TYPE_BOOL)
        return direct_val(raw) <= 1;
    return code == TYPE_UINT16 && direct_val(raw) <= 65535;
}

static const m38_type_t *find_type(const m38_plan_t *plan, uint32_t id)
{
    if (id == 0 || id > plan->type_count)
        return 0;
    return &plan->types[id - 1];
}

static const m38_value_t *find_value(const m38_type_t *type, uint32_t id)
{
    if (!type || id == 0 || id > type->value_count)
        return 0;
    return &type->values[id - 1];
}

static const m38_event_t *find_event(const m38_type_t *type, uint32_t id,
                                     uint32_t direction)
{
    if (!type || id == 0 || id > M38_MAX_EVENTS)
        return 0;
    for (uint32_t i = 0; i < type->event_count; i++)
        if (type->events[i].id == id && type->events[i].direction == direction)
            return &type->events[i];
    return 0;
}

static int validate_expr(noun expression, const m38_type_t *type,
                         uint32_t expected_type, uint32_t depth,
                         m38_validation_budget_t *budget)
{
    noun fields[5];
    uint32_t kind, expression_type;
    if (depth > EXPR_DEPTH_LIMIT || !v_charge(budget, 1)
        || !noun_is_cell(expression) || !record_exact(expression, fields, 3)) {
        /* Binary expressions have five fields, so retry that shape below. */
        if (depth > EXPR_DEPTH_LIMIT || !v_charge(budget, 1)
            || !noun_is_cell(expression) || !record_exact(expression, fields, 5))
            return 0;
        if (!direct_u(fields[0], 3, &kind) || kind != 3
            || !direct_u(fields[1], TYPE_UINT16, &expression_type)
            || expression_type != expected_type
            || !direct_u(fields[2], 4, &kind))
            return 0;
        uint32_t operator = kind;
        if (operator == 1) {
            if (expected_type != TYPE_UINT16)
                return 0;
        } else if (operator == 2 || operator == 3 || operator == 4) {
            if (expected_type != TYPE_BOOL)
                return 0;
        } else {
            return 0;
        }
        uint32_t child_type = operator == 1 ? TYPE_UINT16 :
                              (operator == 4 ? TYPE_BOOL : TYPE_UINT16);
        return validate_expr(fields[3], type, child_type, depth + 1, budget)
            && validate_expr(fields[4], type, child_type, depth + 1, budget);
    }

    if (!direct_u(fields[0], 3, &kind)
        || !direct_u(fields[1], TYPE_UINT16, &expression_type)
        || expression_type != expected_type)
        return 0;
    if (kind == 1) {
        uint32_t value_id;
        if (!direct_u(fields[2], M38_MAX_VALUES, &value_id))
            return 0;
        const m38_value_t *value = find_value(type, value_id);
        return value && value->type == expected_type;
    }
    if (kind == 2)
        return typed_atom(fields[1], fields[2]);
    return 0;
}

static int validate_type(noun value, uint32_t type_id,
                         m38_type_t *out, m38_validation_budget_t *budget)
{
    noun fields[6];
    noun items[M38_MAX_TRANSITIONS > M38_MAX_ALGORITHMS
                  ? M38_MAX_TRANSITIONS : M38_MAX_ALGORITHMS];
    uint32_t count;
    m38_type_t type = {0};
    type.id = type_id;
    if (!v_charge(budget, 1) || !record_exact(value, fields, 6)
        || !direct_u(fields[0], M38_MAX_TYPES, &type.id)
        || type.id != type_id)
        return 0;

    if (!list_collect(fields[1], items, M38_MAX_EVENTS, &count))
        return 0;
    type.event_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun event_fields[3];
        noun with_items[M38_MAX_VALUES];
        uint32_t id, direction;
        if (!record_exact(items[i], event_fields, 3))
            return 0;
        if (!direct_u(event_fields[0], M38_MAX_EVENTS, &id) || id == 0)
            return 0;
        if (!direct_u(event_fields[1], 1, &direction))
            return 0;
        if (!list_collect(event_fields[2], with_items, M38_MAX_VALUES,
                          &type.events[i].with_count))
            return 0;
        for (uint32_t k = 0; k < i; k++)
            if (type.events[k].id == id && type.events[k].direction == direction)
                return 0;
        type.events[i].id = id;
        type.events[i].direction = direction;
        for (uint32_t j = 0; j < type.events[i].with_count; j++) {
            uint32_t with_id;
            if (!direct_u(with_items[j], M38_MAX_VALUES, &with_id))
                return 0;
            type.events[i].with_ids[j] = with_id;
        }
    }

    if (!list_collect(fields[2], items, M38_MAX_VALUES, &count))
        return 0;
    type.value_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun value_fields[4];
        uint32_t id, direction, type_code;
        if (!record_exact(items[i], value_fields, 4)
            || !direct_u(value_fields[0], M38_MAX_VALUES, &id)
            || id != i + 1
            || !direct_u(value_fields[1], 2, &direction)
            || !direct_u(value_fields[2], TYPE_UINT16, &type_code)
            || (type_code != TYPE_BOOL && type_code != TYPE_UINT16)
            || !typed_atom(value_fields[2], value_fields[3]))
            return 0;
        type.values[i].id = id;
        type.values[i].direction = direction;
        type.values[i].type = type_code;
    }
    for (uint32_t i = 0; i < type.event_count; i++) {
        for (uint32_t j = 0; j < type.events[i].with_count; j++) {
            uint32_t id = type.events[i].with_ids[j];
            const m38_value_t *with = find_value(&type, id);
            if (!with || with->direction != type.events[i].direction)
                return 0;
            for (uint32_t k = 0; k < j; k++)
                if (type.events[i].with_ids[k] == id)
                    return 0;
        }
    }

    if (!list_collect(fields[3], items, M38_MAX_STATES, &count)
        || count == 0)
        return 0;
    type.state_count = count;
    uint32_t initial_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        noun state_fields[3];
        noun actions[M38_MAX_ACTIONS];
        uint32_t id, initial, action_count;
        if (!record_exact(items[i], state_fields, 3)
            || !direct_u(state_fields[0], M38_MAX_STATES, &id)
            || id != i + 1 || !direct_u(state_fields[1], 1, &initial)
            || initial != (i == 0)
            || !list_collect(state_fields[2], actions, M38_MAX_ACTIONS,
                              &action_count))
            return 0;
        initial_count += initial;
        type.states[i].id = id;
        type.states[i].initial = initial;
        type.states[i].action_count = action_count;
        for (uint32_t j = 0; j < action_count; j++) {
            noun action_fields[3];
            uint32_t ordinal, algorithm, output_event;
            if (!record_exact(actions[j], action_fields, 3)
                || !direct_u(action_fields[0], M38_MAX_ACTIONS, &ordinal)
                || ordinal != j + 1
                || !direct_u(action_fields[1], M38_MAX_ALGORITHMS, &algorithm)
                || !direct_u(action_fields[2], M38_MAX_EVENTS, &output_event)
                || (output_event != 0 && !find_event(&type, output_event, 1)))
                return 0;
            type.states[i].actions[j].ordinal = ordinal;
            type.states[i].actions[j].algorithm = algorithm;
            type.states[i].actions[j].output_event = output_event;
        }
    }

    if (!list_collect(fields[4], items, M38_MAX_TRANSITIONS, &count)
        || count == 0 || initial_count != 1)
        return 0;
    type.transition_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun transition_fields[5];
        uint32_t ordinal, source, destination, event;
        if (!record_exact(items[i], transition_fields, 5)
            || !direct_u(transition_fields[0], M38_MAX_TRANSITIONS, &ordinal)
            || ordinal != i + 1
            || !direct_u(transition_fields[1], M38_MAX_STATES, &source)
            || !direct_u(transition_fields[2], M38_MAX_STATES, &destination)
            || !direct_u(transition_fields[3], M38_MAX_EVENTS, &event)
            || source == 0 || destination == 0
            || source > type.state_count || destination > type.state_count
            || (event != 0 && !find_event(&type, event, 0))
            || !validate_expr(transition_fields[4], &type, TYPE_BOOL, 0, budget))
            return 0;
        type.transitions[i].ordinal = ordinal;
        type.transitions[i].source = source;
        type.transitions[i].destination = destination;
        type.transitions[i].event = event;
    }

    if (!list_collect(fields[5], items, M38_MAX_ALGORITHMS, &count))
        return 0;
    type.algorithm_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun algorithm_fields[2];
        noun assignments[M38_MAX_VALUES];
        uint32_t id, assignment_count;
        if (!record_exact(items[i], algorithm_fields, 2)
            || !direct_u(algorithm_fields[0], M38_MAX_ALGORITHMS, &id)
            || id != i + 1
            || !list_collect(algorithm_fields[1], assignments,
                              M38_MAX_VALUES, &assignment_count)
            || assignment_count == 0)
            return 0;
        type.algorithms[i].id = id;
        type.algorithms[i].assignment_count = assignment_count;
        for (uint32_t j = 0; j < assignment_count; j++) {
            noun assignment_fields[2];
            uint32_t value_id;
            const m38_value_t *target;
            if (!record_exact(assignments[j], assignment_fields, 2)
                || !direct_u(assignment_fields[0], M38_MAX_VALUES, &value_id)
                || !(target = find_value(&type, value_id))
                || target->direction == 0
                || !validate_expr(assignment_fields[1], &type, target->type,
                                  0, budget))
                return 0;
        }
    }
    for (uint32_t i = 0; i < type.state_count; i++)
        for (uint32_t j = 0; j < type.states[i].action_count; j++)
            if (type.states[i].actions[j].algorithm == 0
                || type.states[i].actions[j].algorithm > type.algorithm_count)
                return 0;
    *out = type;
    return 1;
}

static int validate_base_plan(noun value, noun expected_identity,
                              m38_plan_t *out, m38_validation_budget_t *budget)
{
    static const uint8_t plan_tag[] = "38-plan";
    noun fields[4];
    noun types[M38_MAX_TYPES];
    noun instances[M38_MAX_INSTANCES];
    noun routes[M38_MAX_ROUTES];
    uint32_t count;
    m38_plan_t plan = {0};
    if (!v_charge(budget, 1) || !noun_is_cell(value))
        return 0;
    cell_t *root = (cell_t *)(uintptr_t)cell_ptr(value);
    if (!atom_tag(root->head, plan_tag, sizeof plan_tag - 1)
        || !record_exact(root->tail, fields, 4)
        || !noun_eq(fields[0], expected_identity)
        || !list_collect(fields[1], types, M38_MAX_TYPES, &count)
        || count == 0)
        return 0;
    plan.type_count = count;
    for (uint32_t i = 0; i < count; i++)
        if (!validate_type(types[i], i + 1, &plan.types[i], budget))
            return 0;

    if (!list_collect(fields[2], instances, M38_MAX_INSTANCES, &count)
        || count == 0)
        return 0;
    plan.instance_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun instance_fields[2];
        uint32_t id, type_id;
        if (!record_exact(instances[i], instance_fields, 2)
            || !direct_u(instance_fields[0], M38_MAX_INSTANCES, &id)
            || id != i + 1
            || !direct_u(instance_fields[1], M38_MAX_TYPES, &type_id)
            || !find_type(&plan, type_id))
            return 0;
        plan.instance_types[i] = type_id;
    }

    if (!list_collect(fields[3], routes, M38_MAX_ROUTES, &count))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun route_fields[6];
        noun bindings[M38_MAX_VALUES];
        uint32_t ordinal, source, source_event, target, target_event;
        uint32_t binding_count;
        if (!record_exact(routes[i], route_fields, 6)
            || !direct_u(route_fields[0], M38_MAX_ROUTES, &ordinal)
            || ordinal != i + 1
            || !direct_u(route_fields[1], M38_MAX_INSTANCES, &source)
            || !direct_u(route_fields[2], M38_MAX_EVENTS, &source_event)
            || !direct_u(route_fields[3], M38_MAX_INSTANCES, &target)
            || !direct_u(route_fields[4], M38_MAX_EVENTS, &target_event)
            || source == 0 || target == 0 || source > plan.instance_count
            || target > plan.instance_count
            || !find_event(find_type(&plan, plan.instance_types[source - 1]),
                           source_event, 1)
            || !find_event(find_type(&plan, plan.instance_types[target - 1]),
                           target_event, 0)
            || !list_collect(route_fields[5], bindings, M38_MAX_VALUES,
                              &binding_count))
            return 0;
        const m38_type_t *source_type = find_type(&plan, plan.instance_types[source - 1]);
        const m38_type_t *target_type = find_type(&plan, plan.instance_types[target - 1]);
        const m38_event_t *source_port = find_event(source_type, source_event, 1);
        const m38_event_t *target_port = find_event(target_type, target_event, 0);
        if (binding_count != source_port->with_count
            || binding_count != target_port->with_count)
            return 0;
        for (uint32_t j = 0; j < binding_count; j++) {
            noun binding_fields[3];
            uint32_t source_value, target_value, type_code;
            if (!record_exact(bindings[j], binding_fields, 3)
                || !direct_u(binding_fields[0], M38_MAX_VALUES, &source_value)
                || !direct_u(binding_fields[1], M38_MAX_VALUES, &target_value)
                || !direct_u(binding_fields[2], TYPE_UINT16, &type_code))
                return 0;
            const m38_value_t *sv = find_value(source_type, source_value);
            const m38_value_t *tv = find_value(target_type, target_value);
            if (!sv || !tv || sv->type != tv->type || sv->type != type_code)
                return 0;
            int source_with = 0, target_with = 0;
            for (uint32_t k = 0; k < source_port->with_count; k++)
                source_with |= source_port->with_ids[k] == source_value;
            for (uint32_t k = 0; k < target_port->with_count; k++)
                target_with |= target_port->with_ids[k] == target_value;
            if (!source_with || !target_with)
                return 0;
            for (uint32_t k = 0; k < j; k++) {
                noun prior_fields[3];
                uint32_t prior_source, prior_target;
                if (!record_exact(bindings[k], prior_fields, 3)
                    || !direct_u(prior_fields[0], M38_MAX_VALUES, &prior_source)
                    || !direct_u(prior_fields[1], M38_MAX_VALUES, &prior_target)
                    || prior_source == source_value || prior_target == target_value)
                    return 0;
            }
        }
    }
    *out = plan;
    return 1;
}

static int validate_runtime_state(noun value, const m38_plan_t *plan,
                                  noun expected_identity,
                                  m38_validation_budget_t *budget)
{
    static const uint8_t state_tag[] = "38-state";
    noun fields[2];
    noun records[M38_MAX_INSTANCES];
    uint32_t count;
    if (!v_charge(budget, 1) || !noun_is_cell(value))
        return 0;
    cell_t *root = (cell_t *)(uintptr_t)cell_ptr(value);
    if (!atom_tag(root->head, state_tag, sizeof state_tag - 1)
        || !record_exact(root->tail, fields, 2)
        || !noun_eq(fields[0], expected_identity)
        || !list_collect(fields[1], records, M38_MAX_INSTANCES, &count)
        || count != plan->instance_count)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun record_fields[3];
        noun values[M38_MAX_VALUES];
        uint32_t instance_id, state_id, value_count;
        if (!record_exact(records[i], record_fields, 3)
            || !direct_u(record_fields[0], M38_MAX_INSTANCES, &instance_id)
            || instance_id != i + 1
            || !direct_u(record_fields[1], M38_MAX_STATES, &state_id))
            return 0;
        const m38_type_t *type = find_type(plan, plan->instance_types[i]);
        if (!type || state_id == 0 || state_id > type->state_count
            || !list_collect(record_fields[2], values, M38_MAX_VALUES, &value_count)
            || value_count != type->value_count)
            return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value_fields[3];
            uint32_t value_id, type_code;
            if (!record_exact(values[j], value_fields, 3)
                || !direct_u(value_fields[0], M38_MAX_VALUES, &value_id)
                || value_id != j + 1
                || !direct_u(value_fields[1], TYPE_UINT16, &type_code)
                || type_code != type->values[j].type
                || !typed_atom(value_fields[1], value_fields[2]))
                return 0;
        }
    }
    return 1;
}

static int validate_typed_values(noun value, const m38_type_t *type,
                                 const m38_event_t *event,
                                 m38_validation_budget_t *budget)
{
    noun values[M38_MAX_VALUES];
    uint32_t count;
    if (!list_collect(value, values, M38_MAX_VALUES, &count)
        || count != event->with_count)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun fields[3];
        uint32_t value_id, type_code;
        const m38_value_t *value_info;
        if (!record_exact(values[i], fields, 3)
            || !direct_u(fields[0], M38_MAX_VALUES, &value_id)
            || value_id != event->with_ids[i]
            || !direct_u(fields[1], TYPE_UINT16, &type_code)
            || !(value_info = find_value(type, value_id))
            || type_code != value_info->type
            || !typed_atom(fields[1], fields[2])
            || !v_charge(budget, 1))
            return 0;
    }
    return 1;
}

static int validate_stimuli(noun value, noun expected_identity,
                            const m38_plan_t *plan,
                            m38_validation_budget_t *budget)
{
    static const uint8_t stimulus_tag[] = "38-stimul";
    noun stimuli[QUEUE_LIMIT];
    uint32_t count;
    if (!list_collect(value, stimuli, QUEUE_LIMIT, &count))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun body_fields[4];
        uint32_t instance_id, event_id;
        if (!noun_is_cell(stimuli[i]))
            return 0;
        cell_t *stimulus = (cell_t *)(uintptr_t)cell_ptr(stimuli[i]);
        if (!atom_tag(stimulus->head, stimulus_tag, sizeof stimulus_tag - 1)
            || !record_exact(stimulus->tail, body_fields, 4)
            || !noun_eq(body_fields[0], expected_identity)
            || !direct_u(body_fields[1], M38_MAX_INSTANCES, &instance_id)
            || !direct_u(body_fields[2], M38_MAX_EVENTS, &event_id)
            || instance_id == 0 || instance_id > plan->instance_count)
            return 0;
        const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
        const m38_event_t *event = find_event(type, event_id, 0);
        if (!type || !event || !validate_typed_values(body_fields[3], type, event, budget))
            return 0;
    }
    return 1;
}

static int validate_observations(noun value, const m38_plan_t *plan,
                                 m38_validation_budget_t *budget)
{
    noun observations[TRACE_LIMIT];
    uint32_t count;
    if (!list_collect(value, observations, TRACE_LIMIT, &count))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun fields[2], event_fields[2];
        uint32_t instance_id, event_id;
        if (!record_exact(observations[i], fields, 2)
            || !direct_u(fields[0], M38_MAX_INSTANCES, &instance_id)
            || instance_id == 0 || instance_id > plan->instance_count
            || !record_exact(fields[1], event_fields, 2)
            || !direct_u(event_fields[0], M38_MAX_EVENTS, &event_id))
            return 0;
        const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
        const m38_event_t *event = find_event(type, event_id, 1);
        if (!type || !event || !validate_typed_values(event_fields[1], type, event, budget))
            return 0;
    }
    return 1;
}

static int validate_trace(noun value, const m38_plan_t *plan,
                          uint64_t mode, m38_validation_budget_t *budget)
{
    noun rows[TRACE_LIMIT];
    uint32_t count;
    if (!list_collect(value, rows, TRACE_LIMIT, &count))
        return 0;
    /* Operational mode intentionally publishes no diagnostic trace. */
    if (mode == 1 && count != 0)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun fields[7];
        uint32_t kind, instance_id, event_id, value_id, type_code;
        if (!noun_is_cell(rows[i]) || !v_charge(budget, 1))
            return 0;
        if (!record_exact(rows[i], fields, 6)
            || !direct_u(fields[0], 7, &kind)) {
            if (!record_exact(rows[i], fields, 7)
                || !direct_u(fields[0], 7, &kind) || kind != 7)
                return 0;
        }
        if (kind == 1) {
            uint32_t reason;
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &instance_id)
                || !direct_u(fields[2], M38_MAX_VALUES, &value_id)
                || !direct_u(fields[5], 2, &reason) || reason == 0
                || instance_id == 0 || value_id == 0
                || instance_id > plan->instance_count)
                return 0;
            const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
            const m38_value_t *value_info = find_value(type, value_id);
            if (!value_info || !typed_atom((noun)direct(value_info->type), fields[3])
                || !typed_atom((noun)direct(value_info->type), fields[4]))
                return 0;
        } else if (kind == 2 || kind == 6) {
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &instance_id)
                || !direct_u(fields[2], M38_MAX_EVENTS, &event_id)
                || instance_id == 0 || instance_id > plan->instance_count)
                return 0;
            const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
            const m38_event_t *event = find_event(type, event_id, kind == 2 ? 0 : 1);
            if (!event || !validate_typed_values(fields[3], type, event, budget)
                || !direct_u(fields[4], 0, &type_code)
                || !direct_u(fields[5], 0, &type_code))
                return 0;
        } else if (kind == 3) {
            uint32_t state_id;
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &instance_id)
                || !direct_u(fields[2], M38_MAX_EVENTS, &event_id)
                || !direct_u(fields[3], M38_MAX_STATES, &state_id)
                || !direct_u(fields[4], 0, &type_code)
                || !direct_u(fields[5], 0, &type_code)
                || instance_id == 0 || instance_id > plan->instance_count)
                return 0;
            const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
            if (!find_event(type, event_id, 0) || state_id == 0 || state_id > type->state_count)
                return 0;
        } else if (kind == 4) {
            uint32_t source, destination, ordinal;
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &instance_id)
                || !direct_u(fields[2], M38_MAX_EVENTS, &event_id)
                || !direct_u(fields[3], M38_MAX_STATES, &source)
                || !direct_u(fields[4], M38_MAX_STATES, &destination)
                || !direct_u(fields[5], M38_MAX_TRANSITIONS, &ordinal)
                || ordinal == 0 || instance_id == 0 || instance_id > plan->instance_count)
                return 0;
            const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
            if (!find_event(type, event_id, 0) || source == 0 || destination == 0
                || source > type->state_count || destination > type->state_count)
                return 0;
        } else if (kind == 5) {
            uint32_t state_id, algorithm_id, ordinal;
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &instance_id)
                || !direct_u(fields[2], 0, &type_code)
                || !direct_u(fields[3], M38_MAX_STATES, &state_id)
                || !direct_u(fields[4], M38_MAX_ALGORITHMS, &algorithm_id)
                || !direct_u(fields[5], M38_MAX_ACTIONS, &ordinal)
                || ordinal == 0 || instance_id == 0 || instance_id > plan->instance_count)
                return 0;
            const m38_type_t *type = find_type(plan, plan->instance_types[instance_id - 1]);
            if (state_id == 0 || state_id > type->state_count
                || algorithm_id == 0 || algorithm_id > type->algorithm_count)
                return 0;
        } else if (kind == 7) {
            uint32_t source_instance, target_instance, source_value, target_value;
            if (!direct_u(fields[1], M38_MAX_INSTANCES, &source_instance)
                || !direct_u(fields[2], M38_MAX_INSTANCES, &target_instance)
                || !direct_u(fields[3], M38_MAX_VALUES, &source_value)
                || !direct_u(fields[4], M38_MAX_VALUES, &target_value)
                || source_instance == 0 || target_instance == 0
                || source_instance > plan->instance_count || target_instance > plan->instance_count)
                return 0;
            const m38_type_t *source_type = find_type(plan, plan->instance_types[source_instance - 1]);
            const m38_type_t *target_type = find_type(plan, plan->instance_types[target_instance - 1]);
            const m38_value_t *sv = find_value(source_type, source_value);
            const m38_value_t *tv = find_value(target_type, target_value);
            if (!sv || !tv || sv->type != tv->type
                || !typed_atom((noun)direct(tv->type), fields[5])
                || !typed_atom((noun)direct(tv->type), fields[6]))
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

/* Returns 2 for a valid commit, 1 for a valid abort, and 0 for malformed. */
static int validate_product(noun product, const m38_image_t *image,
                            noun prior_state, noun *candidate_state,
                            noun *observations, uint8_t observation_digest[32],
                            m38_validation_budget_t *budget,
                            jam_admission_budget_t *jam_budget)
{
    static const uint8_t product_tag[] = "m38-product-v2";
    static const uint8_t commit_tag[] = "commit";
    static const uint8_t abort_tag[] = "abort";
    noun status_fields[2];
    noun fields[7];
    if (!noun_is_cell(product))
        return 0;
    cell_t *root = (cell_t *)(uintptr_t)cell_ptr(product);
    if (!atom_tag(root->head, product_tag, sizeof product_tag - 1)
        || !record_exact(root->tail, status_fields, 2)
        || !noun_eq(status_fields[0], image->plan_identity))
        return 0;
    if (atom_tag(status_fields[1], abort_tag, sizeof abort_tag - 1)) {
        noun abort_fields[5];
        uint32_t code;
        if (!record_exact(root->tail, abort_fields, 5)
            || !noun_eq(abort_fields[2], prior_state)
            || !direct_u(abort_fields[3], 6, &code) || code == 0
            || !direct_u(abort_fields[4], 0, &code))
            return 0;
        return 1;
    }
    if (!atom_tag(status_fields[1], commit_tag, sizeof commit_tag - 1)
        || !record_exact(root->tail, fields, 7))
        return 0;
    uint32_t queue_high, worklist;
    if (!validate_runtime_state(fields[2], &image->plan, image->plan_identity, budget)
        || !validate_observations(fields[3], &image->plan, budget)
        || !validate_trace(fields[4], &image->plan, image->mode, budget)
        || !direct_u(fields[5], QUEUE_LIMIT, &queue_high)
        || !direct_u(fields[6], WORKLIST_LIMIT, &worklist)
        || !digest_bytes(fields[3], observation_digest, jam_budget))
        return 0;
    (void)queue_high;
    (void)worklist;
    *candidate_state = fields[2];
    *observations = fields[3];
    return 2;
}

static int validate_image(noun image, m38_image_t *out,
                          jam_admission_budget_t *jam_budget)
{
    static const uint8_t image_tag[] = "m38-c-image";
    static const uint8_t runtime_tag[] = "m38-c-plan";
    noun outer_fields[2], body_fields[9], runtime_fields[4];
    uint32_t schema, mode, unused;
    m38_validation_budget_t budget = {0, POLICY_MAX_OPS};
    m38_image_t result = {0};
    if (!noun_is_cell(image))
        return 0;
    cell_t *image_root = (cell_t *)(uintptr_t)cell_ptr(image);
    if (!atom_tag(image_root->head, image_tag, sizeof image_tag - 1)
        || !record_exact(image_root->tail, outer_fields, 2)
        || !digest_field_matches(outer_fields[0], outer_fields[1], jam_budget)
        || !record_exact(outer_fields[1], body_fields, 9)
        || !direct_u(body_fields[0], IMAGE_SCHEMA, &schema)
        || schema != IMAGE_SCHEMA || !noun_is_cell(body_fields[1]))
        return 0;

    cell_t *runtime_root = (cell_t *)(uintptr_t)cell_ptr(body_fields[1]);
    if (!atom_tag(runtime_root->head, runtime_tag, sizeof runtime_tag - 1)
        || !record_exact(runtime_root->tail, runtime_fields, 4)
        || !digest_field_matches(body_fields[2], body_fields[1], jam_budget)
        || !noun_is_atom(runtime_fields[0])
        || !digest_field_matches(runtime_fields[3], runtime_fields[2], jam_budget)
        || !validate_base_plan(runtime_fields[1], runtime_fields[0],
                               &result.plan, &budget))
        return 0;
    result.image = image;
    result.plan_identity = runtime_fields[0];
    result.runtime_plan = body_fields[1];
    result.base_plan = runtime_fields[1];
    result.formula = body_fields[3];
    if (!digest_field_matches(body_fields[4], body_fields[3], jam_budget))
        return 0;
    noun bounds[3];
    if (!record_exact(body_fields[5], bounds, 3)
        || !direct_u(bounds[0], POLICY_MAX_OPS, &unused)
        || direct_val(bounds[0]) != POLICY_MAX_OPS
        || !direct_u(bounds[1], POLICY_MAX_CELLS, &unused)
        || direct_val(bounds[1]) != POLICY_MAX_CELLS
        || !direct_u(bounds[2], POLICY_MAX_STACK, &unused)
        || direct_val(bounds[2]) != POLICY_MAX_STACK
        || !direct_u(body_fields[6], 1, &mode)
        || !expected_formula_matches(body_fields[4], mode)
        || !validate_stimuli(body_fields[7], result.plan_identity, &result.plan, &budget)
        || !validate_runtime_state(body_fields[8], &result.plan, result.plan_identity, &budget))
        return 0;
    result.state = body_fields[8];
    result.stimuli = body_fields[7];
    result.mode = mode;
    if (budget.work > POLICY_MAX_OPS
        || !digest_bytes(image, result.image_digest, jam_budget))
        return 0;
    *out = result;
    return 1;
}

static int m38_pill_source(const volatile uint8_t **base, uint64_t *available)
{
    const volatile uint8_t *q = (const volatile uint8_t *)(uintptr_t)PILL_BASE;
    int any = 0;
    for (unsigned i = 0; i < 8; i++)
        any |= q[i] != 0;
    if (any) {
        *base = q;
        *available = 16ULL + PILL_SCRATCH_SIZE;
        return 1;
    }
    if (&_pill_embed_start[0] >= &_pill_embed_end[0])
        return 0;
    *base = (const volatile uint8_t *)_pill_embed_start;
    *available = (uint64_t)(_pill_embed_end - _pill_embed_start);
    return *available != 0;
}

static int m38_decode_image(noun *image)
{
    const volatile uint8_t *base;
    uint64_t available, length = 0;
    if (!m38_pill_source(&base, &available) || available < 16)
        return 0;
    for (unsigned i = 0; i < 8; i++)
        length |= (uint64_t)base[i] << (i * 8);
    if (length == 0 || length > PILL_SCRATCH_SIZE
        || length > cue_i2_limits.max_input_bytes
        || available < 16 || length > available - 16)
        return 0;
    if (base[8] > 1 || base[9] != 1 || base[10] != 0 || base[11] != 0
        || base[12] != 0 || base[13] != 0 || base[14] != 0 || base[15] != 0)
        return 0;
    cue_bounded_status_t status = cue_bounded_bytes(
        (const uint8_t *)(uintptr_t)(base + 16), length, &cue_i2_limits,
        HEAP_MODE_SCRATCH, image);
    return status == CUE_BOUNDED_OK;
}

static noun runtime_bounds(void)
{
    return alloc_cell(direct(QUEUE_LIMIT),
           alloc_cell(direct(WORKLIST_LIMIT),
           alloc_cell(direct(TRACE_LIMIT), NOUN_ZERO)));
}

static void put_allocator_receipt(uint64_t persist_before,
                                  uint64_t persist_hwm,
                                  uint64_t persist_after,
                                  uint64_t scratch_before,
                                  uint64_t scratch_hwm,
                                  uint64_t scratch_after,
                                  uint64_t atoms_before,
                                  uint64_t atoms_hwm,
                                  uint64_t atoms_after,
                                  uint64_t stack_words)
{
    uart_puts("M38C ALLOC persist=");
    put_hex_u64(persist_before); uart_putc('/'); put_hex_u64(persist_hwm);
    uart_putc('/'); put_hex_u64(persist_after); uart_puts(" scratch=");
    put_hex_u64(scratch_before); uart_putc('/'); put_hex_u64(scratch_hwm);
    uart_putc('/'); put_hex_u64(scratch_after); uart_puts(" atoms=");
    put_hex_u64(atoms_before); uart_putc('/'); put_hex_u64(atoms_hwm);
    uart_putc('/'); put_hex_u64(atoms_after); uart_puts(" stack_words=");
    put_hex_u64(stack_words); uart_puts("\r\n");
}

static void put_jam_budget_receipt(const char *phase,
                                   const jam_admission_budget_t *budget)
{
    uart_puts("M38C JAM phase="); uart_puts(phase); uart_puts(" work=");
    put_hex_u64(budget->work); uart_puts(" limit=");
    put_hex_u64(budget->max_work); uart_puts(" exhausted=");
    uart_putc(budget->exhausted ? '1' : '0'); uart_puts("\r\n");
}

static void terminal(const char *status)
{
    uart_puts("M38C TERMINAL status=");
    uart_puts(status);
    uart_puts("\r\n");
}

static void reject(const char *reason)
{
    uart_puts("M38C REFUSE ");
    uart_puts(reason);
    uart_puts("\r\n");
    terminal("refuse");
}

static int promote_image(noun candidate, m38_image_t *image,
                         jam_admission_budget_t *jam_budget,
                         uint64_t persist_before,
                         uint64_t scratch_before,
                         uint64_t atoms_before)
{
    noun promoted;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    noun_test_copy_fail_after(M38_D1_IMAGE_COPY_FAIL_AFTER);
    int copied = noun_copy_checked(candidate, &promoted);
    noun_test_copy_fail_after(-1);
    m38_image_t checked = {0};
    int valid = copied && validate_image(promoted, &checked, jam_budget);
    if (M38_D1_PROMOTION_FAIL)
        valid = 0;
    if (!valid) {
        uint64_t persist_hwm = heap_cells_used(HEAP_MODE_PERSIST);
        uint64_t scratch_hwm = heap_cells_used(HEAP_MODE_SCRATCH);
        uint64_t atoms_hwm = atom_store_bytes_used();
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        put_allocator_receipt(
            persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
            scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
            atoms_before, atoms_hwm, atom_store_bytes_used(),
            native_stack_hwm_words());
        return 0;
    }
    heap_persist_commit_tx();
    noun_tx_commit();
    heap_set_mode(HEAP_MODE_SCRATCH);
    heap_scratch_reset();
    *image = checked;
    return 1;
}

static int promote_live_roots(noun runtime_plan, noun formula, noun remaining,
                              noun candidate_state, noun *new_runtime,
                              noun *new_formula, noun *new_remaining,
                              noun *new_state)
{
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    noun_test_copy_fail_after(M38_D1_STATE_COPY_FAIL_AFTER);
    int copied = noun_copy_checked(runtime_plan, new_runtime)
        && noun_copy_checked(formula, new_formula)
        && noun_copy_checked(remaining, new_remaining)
        && noun_copy_checked(candidate_state, new_state);
    noun_test_copy_fail_after(-1);
    if (M38_D1_PROMOTION_FAIL)
        copied = 0;
    if (!copied) {
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        return 0;
    }
    heap_persist_commit_tx();
    noun_tx_commit();
    heap_set_mode(HEAP_MODE_SCRATCH);
    heap_scratch_reset();
    return 1;
}

#if M38_D1_STATE_COPY_PROBE
/* Test-only: force a partial live-root copy, then prove that both transactions
 * return to their exact pre-copy state.  The valid M38-C control is not used
 * as an execution workload because it intentionally reaches the frozen cell
 * cap before ordinary promotion. */
static int run_state_copy_probe(noun runtime_plan, noun formula,
                                noun remaining, noun current)
{
    uint64_t persist_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t selector_before = heap_persist_selector();
    uint64_t atoms_before = atom_store_bytes_used();
    uint64_t atom_slots_before = atom_store_index_occupancy();
    heap_set_mode(HEAP_MODE_SCRATCH);
    heap_scratch_reset();
    uint64_t scratch_before = heap_cells_used(HEAP_MODE_SCRATCH);
    if (!noun_tx_begin(HEAP_MODE_SCRATCH))
        return 0;
    noun scratch_marker;
    if (!alloc_cell_checked(NOUN_ONE, NOUN_ZERO, &scratch_marker)) {
        noun_tx_abort();
        heap_scratch_reset();
        return 0;
    }
    uint64_t scratch_hwm = heap_cells_used(HEAP_MODE_SCRATCH);
    noun before_runtime = runtime_plan;
    noun before_formula = formula;
    noun before_remaining = remaining;
    noun before_state = current;
    noun new_runtime = NOUN_ZERO, new_formula = NOUN_ZERO;
    noun new_remaining = NOUN_ZERO, new_state = NOUN_ZERO;
    noun_test_copy_mutations_reset();
    int copied = promote_live_roots(runtime_plan, formula, remaining, current,
                                    &new_runtime, &new_formula,
                                    &new_remaining, &new_state);
    uint64_t mutations = noun_test_copy_mutations();
    uint64_t persist_after = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t selector_after = heap_persist_selector();
    uint64_t scratch_after = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms_after = atom_store_bytes_used();
    uint64_t atom_slots_after = atom_store_index_occupancy();
    int roots_restored = runtime_plan == before_runtime
        && formula == before_formula && remaining == before_remaining
        && current == before_state;
    int restored = !copied && mutations != 0
        && selector_before == selector_after
        && persist_before == persist_after
        && atoms_before == atoms_after
        && atom_slots_before == atom_slots_after
        && scratch_after == scratch_before
        && roots_restored && !noun_tx_active();
    uart_puts("M38C STATE_PROBE copied="); uart_putc(copied ? '1' : '0');
    uart_puts(" mutations="); put_hex_u64(mutations);
    uart_puts(" selector="); put_hex_u64(selector_before); uart_putc('/');
    put_hex_u64(selector_after); uart_puts(" persist=");
    put_hex_u64(persist_before); uart_putc('/'); put_hex_u64(persist_after);
    uart_puts(" scratch="); put_hex_u64(scratch_before); uart_putc('/');
    put_hex_u64(scratch_hwm); uart_putc('/'); put_hex_u64(scratch_after);
    uart_puts(" atoms="); put_hex_u64(atoms_before); uart_putc('/');
    put_hex_u64(atoms_after); uart_puts(" slots=");
    put_hex_u64(atom_slots_before); uart_putc('/');
    put_hex_u64(atom_slots_after); uart_puts(" roots=");
    uart_putc(roots_restored ? '1' : '0'); uart_puts(" restored=");
    uart_putc(restored ? '1' : '0'); uart_puts("\r\n");
    return restored;
}
#endif

#if M38_D1_REPEAT_REFUSAL_PROBE
/* Test-only: repeat the same decoded collision refusal in one guest. */
static int run_repeated_refusal_probe(void)
{
    uint64_t persist_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t selector_before = heap_persist_selector();
    uint64_t atoms_before = atom_store_bytes_used();
    uint64_t atom_slots_before = atom_store_index_occupancy();
    uint64_t first_work = 0, last_work = 0;
    for (unsigned i = 0; i < M38_D1_REPEAT_COUNT; i++) {
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        noun candidate;
        if (!m38_decode_image(&candidate))
            return 0;
        jam_admission_budget_t jam_budget;
        jam_admission_budget_init(&jam_budget, M38_D1_JAM_WORK_LIMIT);
        m38_image_t image = {0};
        int valid = validate_image(candidate, &image, &jam_budget);
        if (valid || !jam_budget.exhausted) {
            if (noun_tx_active())
                noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            return 0;
        }
        if (i == 0)
            first_work = jam_budget.work;
        last_work = jam_budget.work;
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_PERSIST);
        heap_scratch_reset();
        if (heap_cells_used(HEAP_MODE_PERSIST) != persist_before
            || heap_persist_selector() != selector_before
            || atom_store_bytes_used() != atoms_before
            || atom_store_index_occupancy() != atom_slots_before
            || heap_cells_used(HEAP_MODE_SCRATCH) != 0)
            return 0;
    }
    jam_admission_budget_t evidence = {last_work, M38_D1_JAM_WORK_LIMIT, 1};
    put_jam_budget_receipt("repeat", &evidence);
    uart_puts("M38C REPEAT iterations="); put_hex_u64(M38_D1_REPEAT_COUNT);
    uart_puts(" persist="); put_hex_u64(persist_before); uart_putc('/');
    put_hex_u64(heap_cells_used(HEAP_MODE_PERSIST)); uart_puts(" selector=");
    put_hex_u64(selector_before); uart_putc('/');
    put_hex_u64(heap_persist_selector()); uart_puts(" scratch=");
    put_hex_u64(0); uart_putc('/'); put_hex_u64(heap_cells_used(HEAP_MODE_SCRATCH));
    uart_puts(" atoms="); put_hex_u64(atoms_before); uart_putc('/');
    put_hex_u64(atom_store_bytes_used()); uart_puts(" jam_work=");
    put_hex_u64(first_work); uart_putc('/'); put_hex_u64(last_work);
    uart_puts("\r\n");
    return first_work == last_work;
}
#endif

void m38_c_boot(void)
{
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        nock_budget_finish();
        /* No-op when the jump came from the evaluator; essential if a
         * checked promotion ever faults after flipping the semispace. */
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        reject(jumped == NOCK_ABORT_BUDGET ? "budget" : "native-crash");
        return;
    }

    uart_puts("M38C START\r\n");
    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);
#if M38_D1_REPEAT_REFUSAL_PROBE
    if (!run_repeated_refusal_probe()) {
        reject("repeat-refusal-probe");
        return;
    }
    terminal("test-pass");
    return;
#endif
    uint64_t admission_persist_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t admission_scratch_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t admission_atoms_before = atom_store_bytes_used();
    noun candidate;
    if (!m38_decode_image(&candidate)) {
        if (noun_tx_active())
            noun_tx_abort();
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_PERSIST);
        reject("image-decode");
        return;
    }
    m38_image_t image = {0};
    jam_admission_budget_t image_jam_budget;
    jam_admission_budget_init(&image_jam_budget, M38_D1_JAM_WORK_LIMIT);
    if (!validate_image(candidate, &image, &image_jam_budget)) {
        noun_tx_abort();
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_PERSIST);
        if (image_jam_budget.exhausted)
            put_jam_budget_receipt("image", &image_jam_budget);
        reject(image_jam_budget.exhausted ? "image-jam-budget" : "image-auth");
        return;
    }
    if (!promote_image(candidate, &image, &image_jam_budget,
                      admission_persist_before, admission_scratch_before,
                      admission_atoms_before)) {
        heap_set_mode(HEAP_MODE_PERSIST);
        if (image_jam_budget.exhausted)
            put_jam_budget_receipt("image", &image_jam_budget);
        reject("image-promotion");
        return;
    }

    noun runtime_plan = image.runtime_plan;
    noun formula = image.formula;
    volatile noun current = image.state;
    volatile noun remaining = image.stimuli;
    volatile unsigned ordinal = 0;

    uart_puts("M38C READY mode=");
    uart_putc(image.mode ? 'o' : 'd');
    uart_puts(" image=");
    put_digest_bytes(image.image_digest);
    uart_puts("\r\n");
    /* The fixed core stack also serves boot and admission.  Measure the
     * evaluator's incremental watermark so the image's 1,024-word policy is
     * enforced without confusing it with total native C-stack occupancy. */
    uint64_t evaluator_stack_baseline = native_stack_hwm_words();

#if M38_D1_STATE_COPY_PROBE
    if (!run_state_copy_probe(runtime_plan, formula, remaining, current)) {
        reject("state-copy-probe");
        return;
    }
    terminal("test-pass");
    return;
#endif

    while (remaining != NOUN_ZERO) {
        if (!noun_is_cell(remaining)) {
            reject("stimulus");
            return;
        }
        cell_t *remaining_cell = (cell_t *)(uintptr_t)cell_ptr(remaining);
        noun stimulus = remaining_cell->head;
        noun next_remaining = remaining_cell->tail;
        uint64_t persist_before = heap_cells_used(HEAP_MODE_PERSIST);
        uint64_t atoms_before = atom_store_bytes_used();
        heap_scratch_reset();
        heap_set_mode(HEAP_MODE_SCRATCH);
        uint64_t scratch_before = heap_cells_used(HEAP_MODE_SCRATCH);
        int slam_jump = setjmp(nock_abort);
        if (slam_jump != 0) {
            uint64_t ops = nock_ops_used();
            uint64_t cells = nock_cells_used();
            uint64_t persist_hwm = heap_cells_used(HEAP_MODE_PERSIST);
            uint64_t scratch_hwm = heap_cells_used(HEAP_MODE_SCRATCH);
            uint64_t atoms_hwm = atom_store_bytes_used();
            uint64_t stack_words = native_stack_hwm_words();
            nock_budget_finish();
            if (noun_tx_active())
                noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            put_allocator_receipt(
                persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
                scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
                atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
            if (stack_words >= evaluator_stack_baseline
                && stack_words - evaluator_stack_baseline > POLICY_MAX_STACK) {
                reject("stack-edge");
                return;
            }
            if (slam_jump == NOCK_ABORT_BUDGET) {
                uart_puts("M38C REFUSE cap-edge ops=");
                put_hex_u64(ops); uart_puts(" cells="); put_hex_u64(cells);
                uart_puts("\r\n");
                remaining = next_remaining;
                if (remaining != NOUN_ZERO)
                    continue;
                terminal("cap-edge");
            } else {
                reject("slam-crash");
            }
            return;
        }

        if (!noun_tx_begin(HEAP_MODE_SCRATCH)) {
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            reject("scratch-transaction");
            return;
        }
        noun subject = alloc_cell(runtime_plan,
                         alloc_cell(current,
                         alloc_cell(stimulus,
                         alloc_cell(runtime_bounds(), NOUN_ZERO))));
        nock_budget_set_limits(POLICY_MAX_OPS, POLICY_MAX_CELLS);
        noun product = nock(subject, formula);
        uint64_t ops = nock_ops_used();
        uint64_t cells = nock_cells_used();
        uint64_t persist_hwm = heap_cells_used(HEAP_MODE_PERSIST);
        uint64_t scratch_hwm = heap_cells_used(HEAP_MODE_SCRATCH);
        uint64_t atoms_hwm = atom_store_bytes_used();
        uint64_t stack_words = native_stack_hwm_words();
        nock_budget_finish();

        if (stack_words >= evaluator_stack_baseline
            && stack_words - evaluator_stack_baseline > POLICY_MAX_STACK) {
            noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            put_allocator_receipt(
                persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
                scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
                atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
            reject("stack-edge");
            return;
        }

        noun candidate_state = NOUN_ZERO;
        noun observations = NOUN_ZERO;
        uint8_t observations_digest[32];
        m38_validation_budget_t budget = {0, POLICY_MAX_OPS};
        jam_admission_budget_t product_jam_budget;
        jam_admission_budget_init(&product_jam_budget, M38_D1_JAM_WORK_LIMIT);
        int product_status = validate_product(product, &image, current,
                                              &candidate_state, &observations,
                                              observations_digest, &budget,
                                              &product_jam_budget);
        if (product_status == 0) {
            noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            put_allocator_receipt(
                persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
                scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
                atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
            if (product_jam_budget.exhausted)
                put_jam_budget_receipt("product", &product_jam_budget);
            reject(product_jam_budget.exhausted ? "product-jam-budget"
                                                : "atomic-refusal");
            return;
        }
        if (product_status == 1) {
            noun_tx_abort();
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            put_allocator_receipt(
                persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
                scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
                atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
            reject("product-abort");
            return;
        }

        noun new_runtime, new_formula, new_remaining, new_state;
        if (!promote_live_roots(runtime_plan, formula, next_remaining,
                                candidate_state, &new_runtime, &new_formula,
                                &new_remaining, &new_state)) {
            heap_set_mode(HEAP_MODE_PERSIST);
            heap_scratch_reset();
            put_allocator_receipt(
                persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
                scratch_before, scratch_hwm, heap_cells_used(HEAP_MODE_SCRATCH),
                atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
            reject("promotion");
            return;
        }
        runtime_plan = new_runtime;
        formula = new_formula;
        remaining = new_remaining;
        current = new_state;
        uint64_t promoted_persist = heap_cells_used(HEAP_MODE_PERSIST);
        if (promoted_persist > persist_hwm)
            persist_hwm = promoted_persist;
        uint64_t scratch_after = heap_cells_used(HEAP_MODE_SCRATCH);
        heap_set_mode(HEAP_MODE_PERSIST);
        put_allocator_receipt(
            persist_before, persist_hwm, heap_cells_used(HEAP_MODE_PERSIST),
            scratch_before, scratch_hwm, scratch_after,
            atoms_before, atoms_hwm, atom_store_bytes_used(), stack_words);
        uart_puts("M38C SLAM "); put_hex_u64((uint64_t)ordinal++);
        uart_puts(" status=commit ops="); put_hex_u64(ops);
        uart_puts(" cells="); put_hex_u64(cells); uart_puts(" state=");
        put_digest(current); uart_puts(" observations=");
        put_digest_bytes(observations_digest); uart_puts("\r\n");
    }
    uart_puts("M38C PASS\r\n");
    terminal("pass");
}
