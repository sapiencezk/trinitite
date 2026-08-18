#include <stddef.h>
#include <stdint.h>
#include "runtime_identity.h"
#include "i2_admission_policy.h"
#include "bounded_cue.h"
#include "blake3.h"
#include "jam.h"
#include "memory.h"

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
#ifdef I2_M11
/* M11 specialized formulas have ~35k unique cells; 32k open-addressing
 * fills and m8_formula_merkle returns 0, so a valid PILL is GATE-rejected. */
#define M8_FORMULA_HASH_CACHE_CAP 65536u
#else
#define M8_FORMULA_HASH_CACHE_CAP 32768u
#endif
static noun g_m8_formula_hash_keys[M8_FORMULA_HASH_CACHE_CAP];
static uint8_t g_m8_formula_hash_values[M8_FORMULA_HASH_CACHE_CAP][32];
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
    if (!legacy && !origin_v1 && !m7)
        return 0;
    /* ABI families are paired products. Do not admit a valid runtime with a
     * host/deployment family from another product cut. M7's supervisor then
     * has one exact (1,2) identity rather than relying on a second validator
     * to reject mixed combinations later. */
    if (m7) {
        if (!m7_host) return 0;
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
        uint32_t at = (slot + probe) & (M8_FORMULA_HASH_CACHE_CAP - 1);
        if (g_m8_formula_hash_keys[at] == n) {
            for (size_t i = 0; i < 32; i++)
                out[i] = g_m8_formula_hash_values[at][i];
            return 1;
        }
        if (g_m8_formula_hash_keys[at] == NOUN_ZERO) {
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

int runtime_identity_validate_gate(noun gate, const runtime_identity_t *id,
                                   uint64_t *incarnation_out)
{
    noun battery, sample, zero, state;
    noun tag, state_rest, header, state_tail, program, dynamic;
    (void)battery;
    (void)program;
    (void)dynamic;
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

    if (i2_admission_program_known(id->program_hash)) {
        noun instance_states, formula;
        if (!take(dynamic, &instance_states, &formula)
            || !noun_matches_hash(battery, id->battery_hash)
            || !noun_matches_identity_hash(program, id->program_hash)
            || !noun_is_cell(instance_states)
            || !m8_executable_matches(
                battery, program, formula, id->package_hash))
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
    if (incarnation_out)
        *incarnation_out = direct_val(incarnation);
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
    if (digital_identity || m7_digital_identity) {
        closed_io = m7_digital_identity
            && capability_profile == RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO;
        const uint8_t *fingerprint = closed_io
            ? g_closed_process_io_request_grant_fingerprint
            : digital_identity ? g_digital_out_request_grant_fingerprint
                               : g_m7_digital_out_request_grant_fingerprint;
        uint8_t expected_profile = closed_io
            ? RUNTIME_CAPABILITY_PROFILE_CLOSED_PROCESS_IO
            : digital_identity ? RUNTIME_CAPABILITY_PROFILE_DIGITAL_OUT
                               : RUNTIME_CAPABILITY_PROFILE_M7_DIGITAL_OUT;
        if (capability_profile != expected_profile
            || !bytes_eq(header + 248, fingerprint, 8))
            return PILL_I2_IDENTITY;
        if (closed_io) {
            uint8_t pill_digest[32];
            uint64_t pill_bytes = PILL_I2_HEADER_SIZE + len;
            if (!i2_admission_pill_digest(base, pill_bytes, pill_digest)
                || !i2_admission_match_header(
                    identity.program_hash, identity.package_hash,
                    pill_digest, capability_profile))
                return PILL_I2_IDENTITY;
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
    if (closed_io) {
        uint8_t limits_hash[32];
        uint8_t pill_digest[32];
        uint64_t pill_bytes = PILL_I2_HEADER_SIZE + len;
        if (!i2_admission_limits_hash(gate, limits_hash)
            || !i2_admission_pill_digest(base, pill_bytes, pill_digest)
            || !i2_admission_lookup(
                identity.program_hash, identity.package_hash,
                pill_digest, capability_profile, limits_hash, 0)) {
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
