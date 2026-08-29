#include <stddef.h>
#include "i2_admission_policy.h"
#include "blake3.h"
#include "uart.h"
#include "jam.h"
#include "memory.h"
#include "sha256.h"

#define I2_DEPLOYMENT_BINDING_LOCAL_ORDINAL 1u

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail)
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

#include "i2_admission_catalog.inc"

int i2_admission_program_known(const uint8_t program_hash[32])
{
    if (!program_hash)
        return 0;
    for (unsigned i = 0; i < I2_ADMISSION_CATALOG_COUNT; i++)
        if (bytes_eq(I2_ADMISSION_CATALOG[i].program_hash, program_hash, 32))
            return 1;
    return 0;
}

int i2_admission_match_header(const uint8_t program_hash[32],
                              const uint8_t executable_anchor[32],
                              const uint8_t pill_digest[32],
                              uint8_t capability)
{
    if (!program_hash || !executable_anchor || !pill_digest)
        return 0;
    for (unsigned i = 0; i < I2_ADMISSION_CATALOG_COUNT; i++) {
        const i2_admission_catalog_entry_t *entry = &I2_ADMISSION_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)
            && bytes_eq(entry->pill_digest, pill_digest, 32))
            return 1;
    }
    return 0;
}

int i2_admission_lookup(const uint8_t program_hash[32],
                        const uint8_t executable_anchor[32],
                        const uint8_t pill_digest[32],
                        uint8_t capability,
                        const uint8_t limits_hash[32],
                        const i2_admission_catalog_entry_t **out)
{
    if (!program_hash || !executable_anchor || !pill_digest || !limits_hash)
        return 0;
    const i2_admission_catalog_entry_t *found = 0;
    unsigned matches = 0;
    for (unsigned i = 0; i < I2_ADMISSION_CATALOG_COUNT; i++) {
        const i2_admission_catalog_entry_t *entry = &I2_ADMISSION_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)
            && bytes_eq(entry->pill_digest, pill_digest, 32)
            && bytes_eq(entry->limits_hash, limits_hash, 32)) {
            found = entry;
            matches++;
        }
    }
    if (matches != 1)
        return 0;
    if (out)
        *out = found;
    return 1;
}

int i2_admission_limits_hash(noun gate, uint8_t out[32])
{
    noun battery, sample, zero, state, tag, rest, header, state_tail;
    noun program, dynamic, versions, rid, generation, incarnation;
    noun battery_hash, program_hash, limits;
    const uint8_t *encoded;
    uint64_t encoded_len;
    if (!out)
        return 0;
    if (!take(gate, &battery, &sample)
        || !take(sample, &zero, &state)
        || !take(state, &tag, &rest)
        || !take(rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic)
        || !take(header, &versions, &rest)
        || !take(rest, &rid, &rest)
        || !take(rest, &generation, &rest)
        || !take(rest, &incarnation, &rest)
        || !take(rest, &battery_hash, &rest)
        || !take(rest, &program_hash, &limits)
        || jam_encode_bytes_checked(limits, &encoded, &encoded_len) != 0)
        return 0;
    blake3_hash(encoded, (size_t)encoded_len, out);
    return 1;
}

static int gate_limits(noun gate, noun *out)
{
    noun battery, sample, zero, state, tag, rest, header, dynamic;
    noun versions, resource, generation, incarnation, battery_hash;
    noun program_hash, limits;
    if (!out
        || !take(gate, &battery, &sample)
        || !take(sample, &zero, &state)
        || !take(state, &tag, &rest)
        || !take(rest, &header, &dynamic)
        || !take(header, &versions, &rest)
        || !take(rest, &resource, &rest)
        || !take(rest, &generation, &rest)
        || !take(rest, &incarnation, &rest)
        || !take(rest, &battery_hash, &rest)
        || !take(rest, &program_hash, &limits))
        return 0;
    *out = limits;
    return 1;
}

typedef struct {
    uint64_t cells;
    uint64_t depth;
    uint64_t atom_bytes;
} i2_noun_stats_t;

static int i2_noun_stats(noun n, uint64_t depth, i2_noun_stats_t *stats)
{
    if (!stats || depth > 256)
        return 0;
    if (!noun_is_cell(n)) {
        uint64_t bytes = 1;
        if (noun_is_direct(n)) {
            uint64_t value = direct_val(n);
            bytes = value == 0 ? 1 : (64 - __builtin_clzll(value) + 7) / 8;
        } else {
            atom_t *atom = atom_store_get(indirect_hash(n));
            if (!atom || atom->size > (UINT64_MAX / 8))
                return 0;
            bytes = atom->size * 8;
            while (bytes > 1
                   && ((const uint8_t *)atom->limbs)[bytes - 1] == 0)
                bytes--;
        }
        if (bytes > stats->atom_bytes)
            stats->atom_bytes = bytes;
        if (depth > stats->depth)
            stats->depth = depth;
        return 1;
    }
    noun head, tail;
    if (!take(n, &head, &tail))
        return 0;
    if (++stats->cells == 0)
        return 0;
    if (depth > stats->depth)
        stats->depth = depth;
    return i2_noun_stats(head, depth + 1, stats)
        && i2_noun_stats(tail, depth + 1, stats);
}

static int i2_list_count(noun list, uint64_t maximum, uint64_t *out)
{
    uint64_t count = 0;
    while (noun_is_cell(list)) {
        if (++count > maximum)
            return 0;
        noun ignored;
        if (!take(list, &ignored, &list))
            return 0;
    }
    if (list != NOUN_ZERO || !out)
        return 0;
    *out = count;
    return 1;
}

static int i2_body_formula_stats(noun declarations, i2_noun_stats_t *out)
{
    i2_noun_stats_t maximum = {0, 0, 0};
    while (noun_is_cell(declarations)) {
        noun declaration, rest, ignored, formula;
        i2_noun_stats_t current = {0, 0, 0};
        if (!take(declarations, &declaration, &declarations)
            || !take(declaration, &ignored, &rest)
            || !take(rest, &ignored, &rest)
            || !take(rest, &formula, &rest)
            || !i2_noun_stats(formula, 1, &current))
            return 0;
        if (current.cells > maximum.cells)
            maximum.cells = current.cells;
        if (current.depth > maximum.depth)
            maximum.depth = current.depth;
        if (current.atom_bytes > maximum.atom_bytes)
            maximum.atom_bytes = current.atom_bytes;
    }
    if (declarations != NOUN_ZERO || !out)
        return 0;
    *out = maximum;
    return 1;
}

/* Derive the M25 binding effective-limits noun from ordinary ResourceProgram
 * data.  The state header intentionally retains only the execution group;
 * the model group is the bounded static maximum of the wrapped program and
 * the host group is the fixed M11/M25 service envelope. */
static int i2_candidate_effective_limits(noun gate, noun *out)
{
    noun battery, sample, zero, state, state_tag, state_rest;
    noun header, state_tail, program, dynamic, program_tag, program_rest;
    noun base, projection_tables, schema, rest, types, fb_types, instances;
    noun connections, external, subscriptions, event_connections, data_connections;
    uint64_t counts[13] = {0};
    uint64_t model_values[16];
    uint64_t max_vars = 0, max_states = 0, max_transitions = 0;
    uint64_t max_predicates = 0, max_algorithms = 0, max_actions = 0;
    uint64_t max_formula_cells = 0, max_formula_depth = 0;
    uint64_t max_formula_atom_bytes = 0;
    i2_noun_stats_t program_stats = {0, 0, 0};

    if (!out
        || !take(gate, &battery, &sample)
        || !take(sample, &zero, &state) || zero != NOUN_ZERO
        || !take(state, &state_tag, &state_rest)
        || !take(state_rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic)
        || !take(program, &program_tag, &program_rest)
        || !noun_eq(program_tag, cord_from_bytes("i2-resource-program-v1", 23))
        || !take(program_rest, &base, &projection_tables)
        || !take(base, &program_tag, &rest)
        || !noun_eq(program_tag, cord_from_bytes("i2-program", 10))
        || !take(rest, &schema, &rest)
        || !take(rest, &types, &rest)
        || !take(rest, &fb_types, &rest)
        || !take(rest, &instances, &rest)
        || !take(rest, &connections, &rest)
        || !take(rest, &external, &subscriptions)
        || !take(connections, &event_connections, &data_connections)
        || !i2_list_count(types, 16, &counts[0])
        || !i2_list_count(fb_types, 32, &counts[1])
        || !i2_list_count(instances, 32, &counts[2])
        || !i2_list_count(event_connections, 64, &counts[3])
        || !i2_list_count(data_connections, 64, &counts[4])
        || !i2_list_count(external, 16, &counts[5])
        || !i2_list_count(subscriptions, 16, &counts[6])
        || !i2_noun_stats(base, 1, &program_stats))
        return 0;
    (void)battery;
    (void)state_tag;
    (void)header;
    (void)dynamic;
    (void)schema;
    (void)projection_tables;
    (void)counts[6];

    while (noun_is_cell(fb_types)) {
        noun entry, descriptor, kind, rest, interface;
        noun event_inputs, event_outputs, data_inputs, data_outputs, body;
        uint64_t value;
        if (!take(fb_types, &entry, &fb_types)
            || !take(entry, &value, &descriptor)
            || !take(descriptor, &kind, &rest)
            || !take(rest, &value, &rest)
            || !take(rest, &interface, &body)
            || !take(interface, &event_inputs, &rest)
            || !take(rest, &event_outputs, &rest)
            || !take(rest, &data_inputs, &data_outputs)
            || !i2_list_count(data_inputs, 32, &value)
            || !i2_list_count(data_outputs, 32, &counts[7]))
            return 0;
        if (value + counts[7] > max_vars)
            max_vars = value + counts[7];
        if (!noun_eq(kind, cord_from_bytes("bfb", 3)))
            continue;

        noun internal_vars, initial_state, states, transitions, predicates;
        noun actions, algorithms;
        if (!take(body, &internal_vars, &rest)
            || !take(rest, &initial_state, &rest)
            || !take(rest, &states, &rest)
            || !take(rest, &transitions, &rest)
            || !take(rest, &predicates, &rest)
            || !take(rest, &actions, &algorithms)
            || !i2_list_count(states, 64, &value))
            return 0;
        if (value > max_states)
            max_states = value;
        if (!i2_list_count(transitions, 256, &value))
            return 0;
        if (value > max_transitions)
            max_transitions = value;
        if (!i2_list_count(predicates, 256, &value))
            return 0;
        if (value > max_predicates)
            max_predicates = value;
        if (!i2_list_count(actions, 256, &value))
            return 0;
        if (value > max_actions)
            max_actions = value;
        if (!i2_list_count(algorithms, 256, &value))
            return 0;
        if (value > max_algorithms)
            max_algorithms = value;
        /* Both tables are proper lists; formulas are the third field of each
         * [id [symbol [formula [hash limit]]]] declaration. */
        i2_noun_stats_t formula_stats = {0, 0, 0};
        i2_noun_stats_t algorithm_stats = {0, 0, 0};
        if (!i2_body_formula_stats(predicates, &formula_stats)
            || !i2_body_formula_stats(algorithms, &algorithm_stats))
            return 0;
        if (algorithm_stats.cells > formula_stats.cells)
            formula_stats.cells = algorithm_stats.cells;
        if (algorithm_stats.depth > formula_stats.depth)
            formula_stats.depth = algorithm_stats.depth;
        if (algorithm_stats.atom_bytes > formula_stats.atom_bytes)
            formula_stats.atom_bytes = algorithm_stats.atom_bytes;
        (void)internal_vars;
        (void)initial_state;
        if (formula_stats.cells > max_formula_cells)
            max_formula_cells = formula_stats.cells;
        if (formula_stats.depth > max_formula_depth)
            max_formula_depth = formula_stats.depth;
        if (formula_stats.atom_bytes > max_formula_atom_bytes)
            max_formula_atom_bytes = formula_stats.atom_bytes;
    }
    if (fb_types != NOUN_ZERO || counts[2] == 0 || counts[2] > 16
        || counts[0] == 0 || counts[0] > 4 || counts[1] == 0 || counts[1] > 16
        || counts[3] > 32 || counts[4] > 32 || counts[5] > 1
        || program_stats.depth > 128 || max_vars > 16 || max_states > 24
        || max_transitions > 128 || max_predicates > 128
        || max_algorithms > 32 || max_actions > 32
        || max_formula_cells > 32768 || max_formula_depth > 256
        || max_formula_atom_bytes > 256)
        return 0;

    model_values[0] = program_stats.depth;
    model_values[1] = counts[0];
    model_values[2] = counts[1];
    model_values[3] = counts[2];
    model_values[4] = max_vars;
    model_values[5] = max_states;
    model_values[6] = max_transitions;
    model_values[7] = max_predicates;
    model_values[8] = max_algorithms;
    model_values[9] = max_actions;
    model_values[10] = counts[3];
    model_values[11] = counts[4];
    model_values[12] = counts[5];
    model_values[13] = max_formula_cells;
    model_values[14] = max_formula_depth;
    model_values[15] = max_formula_atom_bytes;
    for (unsigned i = 0; i < 16; i++)
        if (model_values[i] == 0)
            model_values[i] = 1;
    noun model, execution, host, tail, effective;
    tail = direct(model_values[15]);
    for (int i = 14; i >= 0; i--)
        if (!alloc_cell_checked(direct(model_values[i]), tail, &tail))
            return 0;
    if (!gate_limits(gate, &execution))
        return 0;
    static const uint64_t host_values[16] = {
        16, 16, 1, 1, 1, 65536, 1048576, 16384,
        100000, 100000, 64, 1000000, 10000, 1000000, 10000000, 1000000,
    };
    host = direct(host_values[15]);
    for (int i = 14; i >= 0; i--)
        if (!alloc_cell_checked(direct(host_values[i]), host, &host))
            return 0;
    model = tail;
    if (!alloc_cell_checked(execution, host, &effective)
        || !alloc_cell_checked(model, effective, out))
        return 0;
    return 1;
}

static int digest_atom(const uint8_t bytes[32], noun *out)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    if (!bytes || !out)
        return 0;
    for (unsigned i = 0; i < 32; i++)
        limbs[i >> 3] |= (uint64_t)bytes[i] << ((i & 7u) * 8u);
    return make_atom_checked(limbs, 4, out);
}

int i2_candidate_binding_digest(noun gate, uint64_t resource_id,
                                uint64_t generation,
                                const uint8_t package_hash[32],
                                const uint8_t battery_hash[32],
                                uint8_t out[32])
{
    noun schema, host_abi, package, battery, limits, tail, binding;
    const uint8_t *encoded;
    uint64_t encoded_len;
    if (!out || !package_hash || !battery_hash || resource_id == 0
        || generation == 0 || (resource_id >> 63) || (generation >> 63)
        || !i2_candidate_effective_limits(gate, &limits)
        || !digest_atom(package_hash, &package)
        || !digest_atom(battery_hash, &battery)
        || !alloc_cell_checked(direct(1), direct(3), &schema))
        return 0;
    /* DeploymentBinding.device is the retained local ordinal, not the IEC
     * Device identity. pack_binding() receives the same canonical (1,3) tuple for both
     * version fields, so its host Jam emits the second field as a backref. */
    host_abi = schema;

    /* Right-associated equivalent of host pack_binding():
     * [tag schema host_abi local-ordinal resource generation package battery limits 0]. */
    if (!alloc_cell_checked(limits, NOUN_ZERO, &tail)
        || !alloc_cell_checked(battery, tail, &tail)
        || !alloc_cell_checked(package, tail, &tail)
        || !alloc_cell_checked(direct(generation), tail, &tail)
        || !alloc_cell_checked(direct(resource_id), tail, &tail)
        || !alloc_cell_checked(direct(I2_DEPLOYMENT_BINDING_LOCAL_ORDINAL), tail, &tail)
        || !alloc_cell_checked(host_abi, tail, &tail)
        || !alloc_cell_checked(schema, tail, &tail)
        || !alloc_cell_checked(cord_from_bytes("i2-binding", 10), tail, &binding)
        || jam_encode_bytes_identity(binding, &encoded, &encoded_len) != 0
        || encoded_len == 0)
        return 0;
    sha256_hash(encoded, encoded_len, out);
    return 1;
}

int i2_admission_pill_digest(const uint8_t *base, uint64_t pill_bytes,
                             uint8_t out[32])
{
    if (!base || !out || pill_bytes == 0)
        return 0;
    blake3_hash(base, (size_t)pill_bytes, out);
    return 1;
}

int i2_admission_historical_refusal(const uint8_t program_hash[32])
{
    if (!program_hash)
        return 0;
    for (unsigned i = 0; i < I2_HISTORICAL_REFUSAL_COUNT; i++)
        if (bytes_eq(I2_HISTORICAL_REFUSAL_PROGRAMS[i], program_hash, 32))
            return 1;
    return 0;
}

void i2_admission_refuse_identity(const uint8_t program_hash[32])
{
    uart_puts("ADMISSION ENVELOPE MISMATCH");
    if (i2_admission_historical_refusal(program_hash))
        uart_puts(" HISTORICAL-REFUSAL");
    uart_puts("\r\n");
}

int i2_admission_identity_limits_match(const uint8_t program_hash[32],
                                       const uint8_t executable_anchor[32],
                                       uint8_t capability,
                                       const uint8_t limits_hash[32])
{
    if (!program_hash || !executable_anchor || !limits_hash)
        return 0;
    const i2_admission_catalog_entry_t *found = 0;
    unsigned matches = 0;
    for (unsigned i = 0; i < I2_ADMISSION_CATALOG_COUNT; i++) {
        const i2_admission_catalog_entry_t *entry = &I2_ADMISSION_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)) {
            found = entry;
            matches++;
        }
    }
    if (matches != 1 || !found)
        return 0;
    return bytes_eq(found->limits_hash, limits_hash, 32);
}
