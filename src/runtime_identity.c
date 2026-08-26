#include <stddef.h>
#include <stdint.h>
#include "runtime_identity.h"
#include "i2_admission_policy.h"
#include "bounded_cue.h"
#include "blake3.h"
#include "jam.h"
#include "memory.h"
#include "i2_admission_envelope.h"
#include "i2_admission_metrics.h"
#ifdef M26_DUPLEX
#include "m26_admission.h"
#endif
#ifdef M27_COMMISSION
#include "m27_admission.h"
#endif

#define PILL_I2_HEADER_SIZE (256u)
#define PILL_I2_MAX_BYTES   PILL_SCRATCH_SIZE
#define CORD_I2_STATE       0x65746174732d3269ULL

extern int noun_pill_shape;
extern uint32_t noun_pill_version;
extern uint8_t _pill_embed_start[];
extern uint8_t _pill_embed_end[];

static const uint8_t g_pill_magic[8] = {
    'I', '2', 'P', 'I', 'L', 'L', '2', 0
};
static const uint8_t g_identity_magic[8] = {
    'I', '2', 'R', 'I', 'D', 0, 0, 0
};
static const uint8_t g_identity_domain[8] = {
    'I', '2', 'R', 'I', 'D', 'v', '1', 0
};
static const uint8_t g_digital_out_request_grant_fingerprint[8] = {
    0x26, 0x48, 0x2a, 0xff, 0xfc, 0x96, 0x3f, 0x59
};
static const uint8_t g_m7_digital_out_request_grant_fingerprint[8] = {
    0x77, 0x3c, 0x4c, 0x79, 0xd7, 0xbb, 0x23, 0xd0
};
static const uint8_t g_closed_process_io_request_grant_fingerprint[8] = {
    0x79, 0x90, 0xcd, 0xd1, 0x04, 0x7d, 0xaa, 0xc3
};
static const uint8_t g_m8_executable_domain[11] = {
    'I', '2', 'M', '8', 'E', 'X', 'E', 'C', 'v', '1', 0
};
static const uint8_t g_m8_formula_domain[11] = {
    'I', '2', 'M', '8', 'F', 'O', 'R', 'M', 'v', '1', 0
};
#define M8_FORMULA_HASH_CACHE_CAP I2_FORMULA_CACHE_ENTRIES
static noun g_m8_formula_hash_keys[M8_FORMULA_HASH_CACHE_CAP];
static uint8_t g_m8_formula_hash_values[M8_FORMULA_HASH_CACHE_CAP][32];
static uint32_t g_m8_formula_hash_used;
static uint64_t g_m8_formula_nodes_current;
static runtime_identity_t g_live_identity;
static int g_live_identity_valid;
static uint8_t g_live_capability_profile;
static void identity_record(const runtime_identity_t *id,
                            uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE]);

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t out = 0;
    for (int i = 0; i < 8; i++)
        out |= (uint64_t)p[i] << (i * 8);
    return out;
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int bytes_nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    for (size_t i = 0; i < n; i++)
        v |= p[i];
    return v != 0;
}

int runtime_identity_parse(const uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE],
                           runtime_identity_t *out)
{
    if (!record || !out || !bytes_eq(record, g_identity_magic, 8)
        || le16(record + 8) != 1 || le16(record + 10) != 0)
        return 0;
    out->pill_container_version = le32(record + 12);
    uint16_t *pairs[] = {
        out->package_schema, out->kernel_kver, out->runtime_abi,
        out->host_abi, out->program_schema, out->algorithm_abi,
        out->formula_abi, out->deployment_schema
    };
    size_t off = 16;
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        pairs[i][0] = le16(record + off);
        pairs[i][1] = le16(record + off + 2);
        off += 4;
    }
    out->generation = le64(record + 48);
    for (size_t i = 0; i < 32; i++) {
        out->package_hash[i] = record[56 + i];
        out->battery_hash[i] = record[88 + i];
        out->program_hash[i] = record[120 + i];
    }
    return 1;
}

int runtime_identity_supported(const runtime_identity_t *id)
{
    if (!id || id->pill_container_version != 2 || id->generation == 0)
        return 0;
    const uint16_t *baseline_pairs[] = {
        id->package_schema, id->program_schema, id->algorithm_abi
    };
    for (size_t i = 0;
         i < sizeof(baseline_pairs) / sizeof(baseline_pairs[0]); i++)
        if (baseline_pairs[i][0] != 1 || baseline_pairs[i][1] != 0)
            return 0;
    int baseline_host = id->host_abi[0] == 1 && id->host_abi[1] == 0
        && id->deployment_schema[0] == 1
        && id->deployment_schema[1] == 0;
    int digital_host = id->host_abi[0] == 1 && id->host_abi[1] == 1
        && id->deployment_schema[0] == 1
        && id->deployment_schema[1] == 1;
    int m7_host = id->host_abi[0] == 1 && id->host_abi[1] == 2
        && id->deployment_schema[0] == 1
        && id->deployment_schema[1] == 2;
    int legacy = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 0
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 0;
    int origin_v1 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 1
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 1;
    int m7 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 2
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 2;
    int m16 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 3
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 3;
    int m17 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 4
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 4;
    int m18 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 5
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 5;
    int m19 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 6
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 6;
    int m20 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 7
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 7;
    int m21 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 8
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 8;
    int m25 = id->runtime_abi[0] == 1 && id->runtime_abi[1] == 9
        && id->formula_abi[0] == 1 && id->formula_abi[1] == 9;
    if (!legacy && !origin_v1 && !m7 && !m16 && !m17 && !m18 && !m19 && !m20 && !m21 && !m25)
        return 0;
    /* ABI families are paired products. Do not admit a valid runtime with a
     * host/deployment family from another product cut. The supervised 1.2
     * through 1.4 runtimes retain the exact host/deployment 1.2 family. */
    if (m7 || m16 || m17 || m18 || m19 || m20 || m21) {
        if (!m7_host) return 0;
    } else if (m25) {
        if (id->host_abi[0] != 1 || id->host_abi[1] != 3
            || id->deployment_schema[0] != 1 || id->deployment_schema[1] != 3)
            return 0;
    } else if (!baseline_host && !digital_host) {
        return 0;
    }
    if (id->kernel_kver[0] != 2 || id->kernel_kver[1] != 0)
        return 0;
    return bytes_nonzero(id->package_hash, 32)
        && bytes_nonzero(id->battery_hash, 32)
        && bytes_nonzero(id->program_hash, 32);
}

int runtime_identity_equal(const runtime_identity_t *a,
                           const runtime_identity_t *b)
{
    if (!a || !b)
        return 0;
    uint8_t ar[RUNTIME_IDENTITY_RECORD_SIZE];
    uint8_t br[RUNTIME_IDENTITY_RECORD_SIZE];
    if (!runtime_identity_supported(a) || !runtime_identity_supported(b))
        return 0;
    identity_record(a, ar);
    identity_record(b, br);
    return bytes_eq(ar, br, sizeof ar);
}

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n))
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int direct_is(noun n, uint64_t expected)
{
    return noun_is_direct(n) && direct_val(n) == expected;
}

static int version_is(noun n, uint16_t major, uint16_t minor)
{
    noun h, t;
    return take(n, &h, &t) && direct_is(h, major) && direct_is(t, minor);
}

#define M17_STATE_MAX_TYPES      4u
#define M17_STATE_MAX_FB_TYPES  16u
#define M17_STATE_MAX_INSTANCES 16u
#define M17_STATE_MAX_VARS      16u
#define M17_STATE_MAX_STATES    24u

static int m17_cord_is(noun n, const char *text)
{
    char buffer[16];
    size_t len = 0;
    while (text[len])
        len++;
    if (len + 1 > sizeof buffer || cord_to_cstr(n, buffer, sizeof buffer) != len)
        return 0;
    for (size_t i = 0; i < len; i++)
        if (buffer[i] != text[i])
            return 0;
    return 1;
}

static int m17_type_descriptor(noun types, noun wanted, noun *kind_out,
                               noun *width_out)
{
    for (unsigned count = 0;
         count < M17_STATE_MAX_TYPES && noun_is_cell(types); count++) {
        noun entry, tail, type_id, descriptor;
        if (!take(types, &entry, &tail)
            || !take(entry, &type_id, &descriptor)
            || !noun_is_direct(type_id) || direct_val(type_id) == 0)
            return 0;
        types = tail;
        if (!noun_eq(type_id, wanted))
            continue;
        noun elementary, rest, symbol, kind, width, limit;
        if (!take(descriptor, &elementary, &rest)
            || !m17_cord_is(elementary, "elementary")
            || !take(rest, &symbol, &rest)
            || !take(rest, &kind, &rest)
            || !take(rest, &width, &limit)
            || !noun_is_direct(width))
            return 0;
        (void)symbol;
        (void)limit;
        *kind_out = kind;
        *width_out = width;
        return 1;
    }
    return 0;
}

static int m17_typed_value(noun types, noun expected_type, noun value)
{
    noun actual_type, payload, kind, width;
    if (!take(value, &actual_type, &payload)
        || !noun_eq(actual_type, expected_type)
        || !m17_type_descriptor(types, expected_type, &kind, &width))
        return 0;
    if (direct_is(kind, 0x6c6f6f62ULL)) /* %bool */
        return direct_is(width, 1)
            && noun_is_direct(payload) && direct_val(payload) <= 1;
    if (direct_is(kind, 0x746e6975ULL)) /* %uint */
        return direct_is(width, 16)
            && noun_is_direct(payload) && direct_val(payload) <= 65535;
    if (direct_is(kind, 0x656d6974ULL)) { /* %time */
        uint8_t bytes[8];
        return direct_is(width, 64)
            && noun_atom_read_fixed(payload, bytes, sizeof bytes);
    }
    return 0;
}

static int m17_var_table(noun declarations, noun table, noun types)
{
    uint64_t last = 0;
    unsigned count = 0;
    while (noun_is_cell(declarations) && noun_is_cell(table)) {
        noun declaration, decl_tail, decl_id, decl_rest;
        noun symbol, type_rest, type_id, initial;
        noun value_entry, value_tail, value_id, value;
        if (++count > M17_STATE_MAX_VARS
            || !take(declarations, &declaration, &decl_tail)
            || !take(table, &value_entry, &value_tail)
            || !take(declaration, &decl_id, &decl_rest)
            || !noun_is_direct(decl_id) || direct_val(decl_id) <= last
            || !take(decl_rest, &symbol, &type_rest)
            || !take(type_rest, &type_id, &initial)
            || !noun_is_direct(type_id) || direct_val(type_id) == 0
            || !take(value_entry, &value_id, &value)
            || !noun_eq(value_id, decl_id)
            || !m17_typed_value(types, type_id, value))
            return 0;
        last = direct_val(decl_id);
        declarations = decl_tail;
        table = value_tail;
        (void)symbol;
        (void)initial;
    }
    return declarations == NOUN_ZERO && table == NOUN_ZERO;
}

static int m17_active_state(noun states, noun active)
{
    int found = 0;
    unsigned count = 0;
    while (noun_is_cell(states)) {
        noun declaration, tail, state_id, rest;
        if (++count > M17_STATE_MAX_STATES
            || !take(states, &declaration, &tail)
            || !take(declaration, &state_id, &rest)
            || !noun_is_direct(state_id) || direct_val(state_id) == 0)
            return 0;
        if (noun_eq(state_id, active))
            found = 1;
        states = tail;
    }
    return states == NOUN_ZERO && found;
}

static int m17_fb_descriptor(noun fb_types, noun wanted, noun *kind_out,
                             noun *interface_out, noun *body_out)
{
    for (unsigned count = 0;
         count < M17_STATE_MAX_FB_TYPES && noun_is_cell(fb_types); count++) {
        noun entry, tail, type_id, descriptor;
        if (!take(fb_types, &entry, &tail)
            || !take(entry, &type_id, &descriptor)
            || !noun_is_direct(type_id) || direct_val(type_id) == 0)
            return 0;
        fb_types = tail;
        if (!noun_eq(type_id, wanted))
            continue;
        noun kind, rest, symbol, interface, body;
        if (!take(descriptor, &kind, &rest)
            || !take(rest, &symbol, &rest)
            || !take(rest, &interface, &body))
            return 0;
        (void)symbol;
        *kind_out = kind;
        *interface_out = interface;
        *body_out = body;
        return 1;
    }
    return 0;
}

static int m17_instance_state(noun fb_kind, noun interface, noun fb_body,
                              noun state, noun types)
{
    noun event_inputs, rest, event_outputs, data_inputs, data_outputs;
    noun state_kind, state_rest, ignored, inputs, outputs;
    if (!take(interface, &event_inputs, &rest)
        || !take(rest, &event_outputs, &rest)
        || !take(rest, &data_inputs, &data_outputs)
        || !take(state, &state_kind, &state_rest))
        return 0;
    (void)event_inputs;
    (void)event_outputs;
    if (direct_is(fb_kind, 0x626662ULL)) { /* %bfb */
        noun active, internals, initial, states;
        if (!m17_cord_is(state_kind, "bfb-state")
            || !take(state_rest, &active, &rest)
            || !noun_is_direct(active) || direct_val(active) == 0
            || !take(rest, &inputs, &rest)
            || !take(rest, &outputs, &internals)
            || !take(fb_body, &ignored, &rest)
            || !take(rest, &initial, &rest)
            || !take(rest, &states, &rest)
            || !m17_active_state(states, active)
            || !m17_var_table(data_inputs, inputs, types)
            || !m17_var_table(data_outputs, outputs, types)
            || !m17_var_table(ignored, internals, types))
            return 0;
        (void)initial;
        return 1;
    }
    if (direct_is(fb_kind, 0x626665ULL)) { /* %efb */
        if (!m17_cord_is(state_kind, "efb-state"))
            return 0;
    } else if (direct_is(fb_kind, 0x62666973ULL)) { /* %sifb */
        if (!m17_cord_is(state_kind, "sifb-state"))
            return 0;
    } else {
        return 0;
    }
    return take(state_rest, &ignored, &rest)
        && take(rest, &inputs, &outputs)
        && m17_var_table(data_inputs, inputs, types)
        && m17_var_table(data_outputs, outputs, types);
}

static int m17_instance_states(noun program, noun states)
{
    noun tag, rest, schema, types, fb_types, instances;
    if (!take(program, &tag, &rest) || !m17_cord_is(tag, "i2-program")
        || !take(rest, &schema, &rest)
        || !take(rest, &types, &rest)
        || !take(rest, &fb_types, &rest)
        || !take(rest, &instances, &rest))
        return 0;
    (void)schema;
    uint64_t last = 0;
    unsigned count = 0;
    while (noun_is_cell(instances) && noun_is_cell(states)) {
        noun instance_entry, instance_tail, instance_id, instance_body;
        noun symbol, type_rest, fb_type_id, parameters;
        noun state_entry, state_tail, state_id, state_body;
        noun fb_kind, interface, fb_body;
        if (++count > M17_STATE_MAX_INSTANCES
            || !take(instances, &instance_entry, &instance_tail)
            || !take(states, &state_entry, &state_tail)
            || !take(instance_entry, &instance_id, &instance_body)
            || !noun_is_direct(instance_id)
            || direct_val(instance_id) <= last
            || !take(instance_body, &symbol, &type_rest)
            || !take(type_rest, &fb_type_id, &parameters)
            || !noun_is_direct(fb_type_id) || direct_val(fb_type_id) == 0
            || !take(state_entry, &state_id, &state_body)
            || !noun_eq(state_id, instance_id)
            || !m17_fb_descriptor(
                fb_types, fb_type_id, &fb_kind, &interface, &fb_body)
            || !m17_instance_state(
                fb_kind, interface, fb_body, state_body, types))
            return 0;
        last = direct_val(instance_id);
        instances = instance_tail;
        states = state_tail;
        (void)symbol;
        (void)parameters;
    }
    return count != 0 && instances == NOUN_ZERO && states == NOUN_ZERO;
}

/* ABI-1.7 binds an ordinary flat ResourceProgram together with compiler-
 * derived immutable execution tables.  The wrapper identity remains the
 * program identity; this narrow projection is only for the retained flat
 * instance-state shape checker. */
static int m20_or_m21_base_program(noun program, noun *base_out)
{
    noun tag, rest, base, tables;
    if (!take(program, &tag, &rest)
        || (!m17_cord_is(tag, "i2-m20-program")
            && !m17_cord_is(tag, "i2-m21-program")
            && !m17_cord_is(tag, "i2-m25-program")
#ifdef M26_DUPLEX
            && !m17_cord_is(tag, "i2-m26-program")
#endif
#ifdef M27_COMMISSION
            && !m17_cord_is(tag, "i2-m27-program")
#endif
            )
        || !take(rest, &base, &tables) || !noun_is_cell(tables))
        return 0;
    *base_out = base;
    return 1;
}

static int atom_matches_hash(noun n, const uint8_t expected[32])
{
    uint8_t actual[32];
    return noun_atom_read_fixed(n, actual, sizeof actual)
        && bytes_eq(actual, expected, sizeof actual);
}

static int noun_matches_hash(noun n, const uint8_t expected[32])
{
    const uint8_t *encoded;
    uint64_t encoded_len;
    uint8_t actual[32];
    if (jam_encode_bytes_checked(n, &encoded, &encoded_len) != 0)
        return 0;
    blake3_hash(encoded, (size_t)encoded_len, actual);
    return bytes_eq(actual, expected, sizeof actual);
}

static int jam_program_identity(noun program, const uint8_t **encoded,
                                uint64_t *encoded_len)
{
    noun copy;
    /* Gate cue may share program cells with the header. Copy the subgraph
     * so pointer-key jam matches the host's standalone program jam. */
    if (!noun_copy_checked(program, &copy))
        return -1;
    return jam_encode_bytes_identity(copy, encoded, encoded_len);
}

static int noun_matches_identity_hash(noun n, const uint8_t expected[32])
{
    const uint8_t *encoded;
    uint64_t encoded_len;
    uint8_t actual[32];
    if (jam_program_identity(n, &encoded, &encoded_len) != 0)
        return 0;
    blake3_hash(encoded, (size_t)encoded_len, actual);
    return bytes_eq(actual, expected, sizeof actual);
}

static int m8_formula_merkle(noun n, uint8_t out[32], uint32_t depth)
{
    g_m8_formula_nodes_current++;
    i2_admission_metrics_max(
        &g_i2_admission_metrics.formula_nodes_hwm,
        g_m8_formula_nodes_current);
    if (depth > 512)
        return 0;
    if (!noun_is_cell(n)) {
        uint8_t atom[256];
        uint8_t payload[sizeof g_m8_formula_domain + 1 + 8 + sizeof atom];
        size_t len = 0;
        if (!noun_atom_read_fixed(n, atom, sizeof atom))
            return 0;
        if (noun_is_direct(n)) {
            uint64_t value = direct_val(n);
            len = value == 0 ? 1 : (size_t)((64 - __builtin_clzll(value) + 7) / 8);
        } else {
            atom_t *stored = atom_store_get(indirect_hash(n));
            if (!stored)
                return 0;
            len = (size_t)stored->size * 8;
            while (len > 1 && atom[len - 1] == 0)
                len--;
        }
        size_t off = 0;
        for (size_t i = 0; i < sizeof g_m8_formula_domain; i++)
            payload[off++] = g_m8_formula_domain[i];
        payload[off++] = 0;
        for (size_t i = 0; i < 8; i++)
            payload[off++] = (uint8_t)(len >> (i * 8));
        for (size_t i = 0; i < len; i++)
            payload[off++] = atom[i];
        blake3_hash(payload, off, out);
        return 1;
    }

    uint32_t slot = (uint32_t)(((uintptr_t)n >> 4)
        & (M8_FORMULA_HASH_CACHE_CAP - 1));
    for (uint32_t probe = 0; probe < M8_FORMULA_HASH_CACHE_CAP; probe++) {
        i2_admission_metrics_max(
            &g_i2_admission_metrics.formula_probe_hwm,
            (uint64_t)probe + 1u);
        uint32_t at = (slot + probe) & (M8_FORMULA_HASH_CACHE_CAP - 1);
        if (g_m8_formula_hash_keys[at] == n) {
            for (size_t i = 0; i < 32; i++)
                out[i] = g_m8_formula_hash_values[at][i];
            return 1;
        }
        if (g_m8_formula_hash_keys[at] == NOUN_ZERO) {
            if (g_m8_formula_hash_used >= I2_FORMULA_CACHE_ADMITTED)
                return 0;
            noun h, t;
            if (!take(n, &h, &t))
                return 0;
            uint8_t left[32], right[32], payload[sizeof g_m8_formula_domain + 1 + 64];
            if (!m8_formula_merkle(h, left, depth + 1)
                || !m8_formula_merkle(t, right, depth + 1))
                return 0;
            size_t off = 0;
            for (size_t i = 0; i < sizeof g_m8_formula_domain; i++)
                payload[off++] = g_m8_formula_domain[i];
            payload[off++] = 1;
            for (size_t i = 0; i < 32; i++) payload[off++] = left[i];
            for (size_t i = 0; i < 32; i++) payload[off++] = right[i];
            blake3_hash(payload, off, out);
            g_m8_formula_hash_keys[at] = n;
            for (size_t i = 0; i < 32; i++)
                g_m8_formula_hash_values[at][i] = out[i];
            g_m8_formula_hash_used++;
            i2_admission_metrics_max(
                &g_i2_admission_metrics.formula_cache_entries_hwm,
                g_m8_formula_hash_used);
            return 1;
        }
    }
    return 0;
}

/* Selector 3 keeps the RuntimeIdentity record shape but binds the actual
 * battery, normalized program, and specialized formula through one digest.
 * Component hashes are computed from the live nouns immediately before this
 * fixed-size digest is compared; this is an executable identity, not a
 * header-only assertion. */
static int m8_executable_matches(noun battery, noun program, noun formula,
                                 const uint8_t expected[32])
{
    const uint8_t *encoded;
    uint64_t encoded_len;
    uint8_t input[11 + 32 * 3];
    uint8_t component[32];
    size_t off = sizeof g_m8_executable_domain;
    for (uint32_t i = 0; i < M8_FORMULA_HASH_CACHE_CAP; i++)
        g_m8_formula_hash_keys[i] = NOUN_ZERO;
    g_m8_formula_hash_used = 0;
    g_m8_formula_nodes_current = 0;
    g_i2_admission_metrics.formula_passes++;
    g_i2_admission_metrics.formula_clear_count++;
    g_i2_admission_metrics.formula_clear_bytes +=
        sizeof g_m8_formula_hash_keys;
    for (int i = 0; i < 3; i++) {
        noun value = i == 0 ? battery : i == 1 ? program : formula;
        if (i == 2) {
            if (!m8_formula_merkle(value, component, 0))
                return 0;
        } else {
            int jammed = i == 0
                ? jam_encode_bytes_checked(value, &encoded, &encoded_len)
                : jam_program_identity(value, &encoded, &encoded_len);
            if (jammed != 0)
                return 0;
            blake3_hash(encoded, (size_t)encoded_len, component);
        }
        for (size_t j = 0; j < sizeof component; j++)
            input[off + j] = component[j];
        off += sizeof component;
    }
    for (size_t i = 0; i < sizeof g_m8_executable_domain; i++)
        input[i] = g_m8_executable_domain[i];
    uint8_t actual[32];
    blake3_hash(input, sizeof input, actual);
    return bytes_eq(actual, expected, sizeof actual);
}

static int gate_take_program_formula(noun gate, noun *battery_out,
                                     noun *program_out, noun *formula_out)
{
    noun battery, sample, zero, state, tag, rest, header, state_tail;
    noun program, dynamic, instance_states, formula;
    if (!take(gate, &battery, &sample)
        || !take(sample, &zero, &state)
        || !take(state, &tag, &rest)
        || !take(rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic)
        || !take(dynamic, &instance_states, &formula))
        return 0;
    if (battery_out)
        *battery_out = battery;
    if (program_out)
        *program_out = program;
    if (formula_out)
        *formula_out = formula;
    return 1;
}

static int validate_gate_common(noun gate, const runtime_identity_t *id,
                                uint64_t *incarnation_out,
                                int check_executable)
{
    noun battery, sample, zero, state;
    noun tag, state_rest, header, state_tail, program, dynamic;
    if (!runtime_identity_supported(id))
        return 0;
    if (!take(gate, &battery, &sample)
        || !take(sample, &zero, &state) || !direct_is(zero, 0))
        return 0;
    if (!take(state, &tag, &state_rest)
        || !direct_is(tag, CORD_I2_STATE))
        return 0;
    if (!take(state_rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic))
        return 0;

    noun versions, rest, rid, generation, incarnation;
    noun battery_hash, program_hash, limits;
    if (!take(header, &versions, &rest)
        || !take(rest, &rid, &rest)
        || !take(rest, &generation, &rest)
        || !take(rest, &incarnation, &rest)
        || !take(rest, &battery_hash, &rest)
        || !take(rest, &program_hash, &limits)
        || !noun_is_direct(rid) || direct_val(rid) == 0
        || !direct_is(generation, id->generation)
        || !noun_is_direct(incarnation) || direct_val(incarnation) == 0
        || !atom_matches_hash(battery_hash, id->battery_hash)
        || !atom_matches_hash(program_hash, id->program_hash))
        return 0;

    noun instance_states = NOUN_ZERO;
    if (i2_admission_program_known(id->program_hash)
        || m25_admission_program_known(id->program_hash)
#ifdef M26_DUPLEX
#ifdef M27_COMMISSION
        || m27_admission_program_known(id->program_hash)
#else
        || m26_admission_program_known(id->program_hash)
#endif
#endif
    ) {
        noun formula;
        if (!take(dynamic, &instance_states, &formula)
            || !noun_matches_hash(battery, id->battery_hash)
            || !noun_is_cell(instance_states))
            return 0;
        if (check_executable
            && (!noun_matches_identity_hash(program, id->program_hash)
                || !m8_executable_matches(
                    battery, program, formula, id->package_hash)))
            return 0;
    }

    noun kver, rv_rest, runtime_abi, program_schema, algorithm_abi;
    if (!take(versions, &kver, &rv_rest)
        || !take(rv_rest, &runtime_abi, &rv_rest)
        || !take(rv_rest, &program_schema, &algorithm_abi)
        || !version_is(kver, id->kernel_kver[0], id->kernel_kver[1])
        || !version_is(runtime_abi, id->runtime_abi[0], id->runtime_abi[1])
        || !version_is(program_schema, id->program_schema[0],
                       id->program_schema[1])
        || !version_is(algorithm_abi, id->algorithm_abi[0],
                       id->algorithm_abi[1]))
        return 0;
    noun instance_program = program;
    if (id->runtime_abi[0] == 1
        && (id->runtime_abi[1] == 7 || id->runtime_abi[1] == 8
            || id->runtime_abi[1] == 9)
        && !m20_or_m21_base_program(program, &instance_program))
        return 0;
    if (id->runtime_abi[0] == 1
        && (id->runtime_abi[1] == 4 || id->runtime_abi[1] == 5
            || id->runtime_abi[1] == 6 || id->runtime_abi[1] == 7
            || id->runtime_abi[1] == 8 || id->runtime_abi[1] == 9)
        && !m17_instance_states(instance_program, instance_states))
        return 0;
    if (incarnation_out)
        *incarnation_out = direct_val(incarnation);
    return 1;
}

int runtime_identity_validate_gate(noun gate, const runtime_identity_t *id,
                                   uint64_t *incarnation_out)
{
    return validate_gate_common(gate, id, incarnation_out, 1);
}

int runtime_identity_validate_gate_header(
    noun gate, const runtime_identity_t *id, uint64_t *incarnation_out)
{
    return validate_gate_common(gate, id, incarnation_out, 0);
}

int runtime_identity_meanings_match(noun live_gate, noun admitted_gate)
{
    noun live_prog, live_form, adm_prog, adm_form;
    uint8_t live_d[32], adm_d[32];
    if (!gate_take_program_formula(live_gate, 0, &live_prog, &live_form)
        || !gate_take_program_formula(admitted_gate, 0, &adm_prog, &adm_form)
        || !m8_formula_merkle(live_prog, live_d, 0)
        || !m8_formula_merkle(adm_prog, adm_d, 0)
        || !bytes_eq(live_d, adm_d, sizeof live_d)
        || !m8_formula_merkle(live_form, live_d, 0)
        || !m8_formula_merkle(adm_form, adm_d, 0)
        || !bytes_eq(live_d, adm_d, sizeof live_d))
        return 0;
    return 1;
}

int runtime_identity_validate_closed_process_io_gate(
    noun gate, const runtime_identity_t *id, uint64_t *incarnation_out)
{
    uint64_t incarnation = 0;
    if (!runtime_identity_validate_gate(gate, id, &incarnation))
        return 0;
    noun battery, sample, zero, state, tag, rest, header, state_tail;
    noun program, dynamic;
    const uint8_t *encoded;
    uint64_t encoded_len;
    uint8_t actual[32];
    if (!i2_admission_program_known(id->program_hash)
        || !take(gate, &battery, &sample)
        || !take(sample, &zero, &state)
        || !take(state, &tag, &rest)
        || !take(rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic)
        || jam_program_identity(program, &encoded, &encoded_len) != 0) {
        return 0;
    }
    blake3_hash(encoded, (size_t)encoded_len, actual);
    if (!bytes_eq(actual, id->program_hash, sizeof actual))
        return 0;
    if (incarnation_out)
        *incarnation_out = incarnation;
    return 1;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}

static void identity_record(const runtime_identity_t *id,
                            uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE])
{
    for (size_t i = 0; i < RUNTIME_IDENTITY_RECORD_SIZE; i++)
        record[i] = 0;
    for (int i = 0; i < 8; i++)
        record[i] = g_identity_magic[i];
    put16(record + 8, 1);
    put16(record + 10, 0);
    put32(record + 12, id->pill_container_version);
    const uint16_t *pairs[] = {
        id->package_schema, id->kernel_kver, id->runtime_abi,
        id->host_abi, id->program_schema, id->algorithm_abi,
        id->formula_abi, id->deployment_schema
    };
    size_t off = 16;
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        put16(record + off, pairs[i][0]);
        put16(record + off + 2, pairs[i][1]);
        off += 4;
    }
    put64(record + 48, id->generation);
    for (size_t i = 0; i < 32; i++) {
        record[56 + i] = id->package_hash[i];
        record[88 + i] = id->battery_hash[i];
        record[120 + i] = id->program_hash[i];
    }
}

int runtime_identity_to_noun(const runtime_identity_t *id, noun *out)
{
    uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE];
    uint64_t limbs[RUNTIME_IDENTITY_RECORD_SIZE / 8];
    noun atom;
    if (!runtime_identity_supported(id) || !out)
        return 0;
    identity_record(id, record);
    for (size_t i = 0; i < sizeof(limbs) / sizeof(limbs[0]); i++)
        limbs[i] = le64(record + i * 8);
    if (!make_atom_checked(limbs, sizeof(limbs) / sizeof(limbs[0]), &atom)
        || !alloc_cell_checked(direct(RUNTIME_IDENTITY_RECORD_SIZE), atom, out))
        return 0;
    return 1;
}

int runtime_identity_from_noun(noun n, runtime_identity_t *out)
{
    noun length, atom;
    uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE];
    return take(n, &length, &atom)
        && direct_is(length, RUNTIME_IDENTITY_RECORD_SIZE)
        && noun_is_atom(atom)
        && noun_atom_read_fixed(atom, record, sizeof record)
        && runtime_identity_parse(record, out)
        && runtime_identity_supported(out);
}

int runtime_identity_live(void)
{
    return g_live_identity_valid;
}

const runtime_identity_t *runtime_identity_get(void)
{
    return g_live_identity_valid ? &g_live_identity : 0;
}

uint8_t runtime_identity_capability_profile(void)
{
    return g_live_identity_valid
        ? g_live_capability_profile : RUNTIME_CAPABILITY_PROFILE_NONE;
}

void runtime_identity_set(const runtime_identity_t *identity)
{
    if (!identity)
        return;
    g_live_identity = *identity;
    g_live_identity_valid = 1;
    /* A raw identity record never carries capability authorization. PILL2
     * admission sets the exact profile only after gate validation succeeds. */
    g_live_capability_profile = RUNTIME_CAPABILITY_PROFILE_NONE;
}

void runtime_identity_set_capability_profile(uint8_t profile)
{
    if (g_live_identity_valid)
        g_live_capability_profile = profile;
}

void runtime_identity_clear(void)
{
    g_live_identity_valid = 0;
    g_live_capability_profile = RUNTIME_CAPABILITY_PROFILE_NONE;
}

static const volatile uint8_t *pill_base(uint64_t *available)
{
    const volatile uint8_t *q =
        (const volatile uint8_t *)(uintptr_t)PILL_BASE;
    int any = 0;
    for (int i = 0; i < 8; i++)
        any |= q[i];
    if (any) {
        *available = PILL_I2_HEADER_SIZE + PILL_I2_MAX_BYTES;
        return q;
    }
    if (&_pill_embed_start[0] >= &_pill_embed_end[0]) {
        *available = 0;
        return 0;
    }
    *available = (uint64_t)(_pill_embed_end - _pill_embed_start);
    return (const volatile uint8_t *)_pill_embed_start;
}

pill_i2_status_t pill_i2_validate_buffer(const uint8_t *base,
                                         uint64_t available,
                                         int heap_mode,
                                         noun *gate_out,
                                         runtime_identity_t *identity_out,
                                         uint8_t *capability_out)
{
    if (!gate_out || !base || available < 8)
        return PILL_I2_ABSENT;
    uint8_t magic[8];
    for (int i = 0; i < 8; i++)
        magic[i] = base[i];
    if (!bytes_eq(magic, g_pill_magic, 8))
        return PILL_I2_NOT_I2;
    if (available < PILL_I2_HEADER_SIZE)
        return PILL_I2_HEADER;

    uint8_t header[PILL_I2_HEADER_SIZE];
    for (size_t i = 0; i < sizeof header; i++)
        header[i] = base[i];
    if (le16(header + 8) != 2 || le16(header + 10) != 0)
        return PILL_I2_VERSION;
    if (le32(header + 12) != PILL_I2_HEADER_SIZE || header[24] != 1)
        return PILL_I2_HEADER;
    for (int i = 26; i < 32; i++)
        if (header[i] != 0)
            return PILL_I2_HEADER;
    uint64_t len = le64(header + 16);
    if (len == 0 || len > PILL_I2_MAX_BYTES
        || available < PILL_I2_HEADER_SIZE + len)
        return PILL_I2_LENGTH;

    const uint8_t *payload =
        (const uint8_t *)(uintptr_t)(base + PILL_I2_HEADER_SIZE);
    uint8_t digest[32];
    blake3_hash(payload, (size_t)len, digest);
    if (!bytes_eq(digest, header + 32, 32))
        return PILL_I2_DIGEST;

    uint8_t identity_input[8 + RUNTIME_IDENTITY_RECORD_SIZE];
    for (int i = 0; i < 8; i++)
        identity_input[i] = g_identity_domain[i];
    for (size_t i = 0; i < RUNTIME_IDENTITY_RECORD_SIZE; i++)
        identity_input[8 + i] = header[64 + i];
    blake3_hash(identity_input, sizeof identity_input, digest);
    if (!bytes_eq(digest, header + 216, 32))
        return PILL_I2_DIGEST;

    runtime_identity_t identity;
    if (!runtime_identity_parse(header + 64, &identity)
        || !runtime_identity_supported(&identity))
        return PILL_I2_IDENTITY;
    int digital_identity =
        identity.host_abi[0] == 1 && identity.host_abi[1] == 1
        && identity.deployment_schema[0] == 1
        && identity.deployment_schema[1] == 1;
    int m7_digital_identity =
        identity.host_abi[0] == 1 && identity.host_abi[1] == 2
        && identity.deployment_schema[0] == 1
        && identity.deployment_schema[1] == 2;
    uint8_t capability_profile = header[25];
    int closed_io = 0;
    int static_resource = m7_digital_identity
        && capability_profile == RUNTIME_CAPABILITY_PROFILE_STATIC_RESOURCE;
    int m25_identity = identity.host_abi[0] == 1 && identity.host_abi[1] == 3
        && identity.deployment_schema[0] == 1
        && identity.deployment_schema[1] == 3
        && capability_profile == RUNTIME_CAPABILITY_PROFILE_M25;
#ifdef M26_DUPLEX
    int m26_identity = m25_identity
#ifdef M27_COMMISSION
        && m27_admission_program_known(identity.program_hash);
#else
        && m26_admission_program_known(identity.program_hash);
#endif
#endif
    if (digital_identity || m7_digital_identity || m25_identity) {
        closed_io = m7_digital_identity
            && capability_profile == RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO;
        static const uint8_t static_resource_fingerprint[8] = {
            0x54, 0x98, 0xab, 0xc7, 0x4f, 0xb5, 0x98, 0x33
        };
        static const uint8_t m25_fingerprint[8] = {
            0x1f, 0x4e, 0x4d, 0x25, 0x3a, 0x65, 0x74, 0x68
        };
        const uint8_t *fingerprint = static_resource
            ? static_resource_fingerprint : closed_io
            ? g_closed_process_io_request_grant_fingerprint
            : m25_identity ? m25_fingerprint
            : digital_identity ? g_digital_out_request_grant_fingerprint
                               : g_m7_digital_out_request_grant_fingerprint;
        uint8_t expected_profile = static_resource
            ? RUNTIME_CAPABILITY_PROFILE_STATIC_RESOURCE : closed_io
            ? RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO
            : m25_identity ? RUNTIME_CAPABILITY_PROFILE_M25
            : digital_identity ? RUNTIME_CAPABILITY_PROFILE_DIGITAL_OUT
                               : RUNTIME_CAPABILITY_PROFILE_M7_DIGITAL_OUT;
        if (capability_profile != expected_profile
            || !bytes_eq(header + 248, fingerprint, 8))
            return PILL_I2_IDENTITY;
        if (closed_io || static_resource || m25_identity) {
            uint8_t pill_digest[32];
            uint64_t pill_bytes = PILL_I2_HEADER_SIZE + len;
            int header_admitted = !i2_admission_pill_digest(base, pill_bytes, pill_digest)
                ? 0
#ifdef M26_DUPLEX
#ifdef M27_COMMISSION
                : m26_identity
                ? m27_admission_lookup(identity.program_hash, identity.package_hash,
                                       pill_digest, 0, 0)
#else
                : m26_identity
                ? m26_admission_lookup(identity.program_hash, identity.package_hash,
                                       pill_digest, 0, 0)
#endif
#endif
                : m25_identity
                ? m25_admission_lookup(identity.program_hash, identity.package_hash,
                                       pill_digest, 0, 0)
                : i2_admission_match_header(
                    identity.program_hash, identity.package_hash,
                    pill_digest, capability_profile);
            if (!header_admitted) {
                i2_admission_refuse_identity(identity.program_hash);
                return PILL_I2_IDENTITY;
            }
        }
    } else if (capability_profile != RUNTIME_CAPABILITY_PROFILE_NONE
               || bytes_nonzero(header + 248, 8)) {
        return PILL_I2_IDENTITY;
    }

    noun gate;
    cue_bounded_status_t cue_status = cue_bounded_bytes(
        payload, len, &cue_i2_limits, heap_mode, &gate);
    if (cue_status != CUE_BOUNDED_OK)
        return cue_status == CUE_BOUNDED_ALLOC
            ? PILL_I2_ALLOC : PILL_I2_CUE;
    if (closed_io || static_resource || m25_identity) {
        uint8_t limits_hash[32];
        uint8_t pill_digest[32];
        uint64_t pill_bytes = PILL_I2_HEADER_SIZE + len;
        const i2_admission_catalog_entry_t *entry = 0;
        int admitted = !i2_admission_limits_hash(gate, limits_hash)
            || !i2_admission_pill_digest(base, pill_bytes, pill_digest)
            ? 0
#ifdef M26_DUPLEX
#ifdef M27_COMMISSION
            : m26_identity
            ? m27_admission_lookup(identity.program_hash, identity.package_hash,
                                   pill_digest, limits_hash, &entry)
#else
            : m26_identity
            ? m26_admission_lookup(identity.program_hash, identity.package_hash,
                                   pill_digest, limits_hash, &entry)
#endif
#endif
            : m25_identity
            ? m25_admission_lookup(identity.program_hash, identity.package_hash,
                                   pill_digest, limits_hash, &entry)
            : i2_admission_lookup(identity.program_hash, identity.package_hash,
                                  pill_digest, capability_profile, limits_hash, &entry);
        if (!admitted) {
            i2_admission_refuse_identity(identity.program_hash);
            noun_tx_abort();
            return PILL_I2_IDENTITY;
        }
    }
    int gate_ok = closed_io
        ? runtime_identity_validate_closed_process_io_gate(
            gate, &identity, 0)
        : runtime_identity_validate_gate(gate, &identity, 0);
    if (!gate_ok) {
        noun_tx_abort();
        return PILL_I2_GATE;
    }
    *gate_out = gate;
    if (identity_out)
        *identity_out = identity;
    if (capability_out)
        *capability_out = capability_profile;
    return PILL_I2_OK;
}

pill_i2_status_t pill_i2_load(noun *gate_out)
{
    uint64_t available;
    const volatile uint8_t *base = pill_base(&available);
    pill_i2_status_t status = pill_i2_validate_buffer(
        (const uint8_t *)(uintptr_t)base, available,
        HEAP_MODE_PERSIST, gate_out, &g_live_identity,
        &g_live_capability_profile);
    if (status != PILL_I2_OK)
        return status;
    noun_tx_commit();
    g_live_identity_valid = 1;
    noun_pill_shape = 1;
    noun_pill_version = 2;
    return PILL_I2_OK;
}

pill_i2_status_t pill_i2_load_candidate(noun *gate_out,
                                        runtime_identity_t *identity_out,
                                        uint8_t *capability_out)
{
    uint64_t available;
    const volatile uint8_t *base = pill_base(&available);
    return pill_i2_validate_buffer(
        (const uint8_t *)(uintptr_t)base, available, HEAP_MODE_PERSIST,
        gate_out, identity_out, capability_out);
}

const char *pill_i2_status_name(pill_i2_status_t status)
{
    static const char *names[] = {
        "ok", "legacy", "absent", "header", "version", "length", "digest",
        "identity", "cue", "gate", "alloc"
    };
    if ((unsigned)status >= sizeof(names) / sizeof(names[0]))
        return "unknown";
    return names[status];
}
