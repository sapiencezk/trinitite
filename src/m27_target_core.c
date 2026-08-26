#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "jam.h"
#include "m26_target_core.h"
#include "m27_aethernet_native.h"
#include "m27_target_core.h"
#include "i2_admission_policy.h"
#include "memory.h"
#include "noun.h"
#include "runtime_identity.h"
#include "sha256.h"

/* M27 is a fixed node-22 commissioning authority, not a deployment
 * framework.  The target retains only this one stage and the metadata below;
 * successor PILL bytes arrive through the management profile. */
#define M27_STAGE_BYTES 32768u
#define M27_CHUNK_BYTES 384u
#define M27_MAX_CHUNKS 86u
#define M27_MAX_PAYLOAD 512u
#define M27_HEADER_BYTES 128u
#define M27_CACHE_ENTRIES 96u
#define M27_LEASE_SECONDS 5u
#define M27_RATE_LIMIT 64u

#define M27_WIRE_MAJOR 0u
#define M27_WIRE_MINOR 1u
#define M27_PROFILE 2u
#define M27_KIND_REQUEST 2u
#define M27_KIND_RESPONSE 3u
#define M27_KEY_ID 2u
#define M27_EPOCH 1u
#define M27_MANAGER 33u
#define M27_TARGET 22u

static const uint8_t M27_PSK[] =
    "m27-management-development-key-0123456789";
static const uint8_t M27_BINDING[16] = {
    0x8a,0x75,0xfd,0x90,0xf0,0x28,0xc7,0x0a,
    0xfc,0xd4,0x41,0x92,0x3a,0x7b,0xa7,0x43,
};
/* Filled from the canonical schema digest in tools/i2/m27_wire.py. */
static const uint8_t M27_SCHEMA[32] = {
    0x5e,0x29,0x02,0x6d,0x3e,0x60,0x86,0x1b,
    0xe1,0x0d,0xf2,0x26,0xa3,0x5f,0xa5,0xf5,
    0xac,0x17,0x40,0xa6,0xef,0x90,0x34,0xd0,
    0x6f,0x02,0xc3,0x20,0x58,0x72,0xb2,0x3b,
};

/* RuntimeIdentity and catalog hashes use little-endian atom bytes. */
static const uint8_t M27_A_PROGRAM[32] = {
    0x77,0x0b,0x73,0x7b,0x49,0x4c,0xbb,0xdc,0x14,0x1c,0xa1,0x4d,0x2e,0xf4,0xd1,0xcc,
    0xa0,0xef,0xaa,0x2f,0xc1,0x16,0xba,0x2c,0xb0,0x91,0x44,0x52,0x75,0xc8,0x67,0x45,
};
static const uint8_t M27_A_ANCHOR[32] = {
    0x96,0x9c,0x64,0x82,0xa8,0xa0,0xa2,0x22,0x29,0x41,0x83,0xc4,0xee,0xce,0x6f,0xc8,
    0x0c,0xe8,0x93,0x98,0x7e,0x74,0x38,0x64,0x18,0x5e,0x66,0x41,0xcc,0x1e,0x52,0xed,
};
static const uint8_t M27_B_PROGRAM[32] = {
    0x07,0x0e,0xc6,0x3b,0xa6,0x4e,0x9d,0x09,0xed,0xb2,0xd0,0xff,0xf3,0x34,0x97,0x1d,
    0x67,0x65,0x51,0xa7,0x66,0x05,0x1b,0x4b,0x9e,0x18,0xc4,0x5d,0x92,0x81,0x50,0xe7,
};
static const uint8_t M27_B_ANCHOR[32] = {
    0x1f,0x6e,0xa9,0x98,0x27,0x2f,0xcd,0x5d,0x3f,0xc9,0x54,0x14,0x2a,0x5d,0x66,0x87,
    0x99,0x43,0xba,0x19,0x5f,0xbb,0xc3,0xc3,0xb6,0xae,0xc6,0xa0,0x50,0x49,0x7d,0x4d,
};
static const uint8_t M27_B_PILL_SHA256[32] = {
    0x14,0x68,0x74,0x24,0xb5,0x57,0xca,0xb0,0x2f,0x23,0xdd,0xc0,0x5b,0x01,0x29,0xac,
    0x56,0xed,0x37,0x77,0x9b,0xef,0x9d,0x40,0x2f,0x1a,0x38,0x7a,0x05,0xc3,0x56,0xc7,
};
static const uint8_t M27_B_PILL_BLAKE3[32] = {
    0xee,0x9e,0xd9,0xdf,0x7b,0xe5,0x8f,0xb3,0x07,0x08,0xe9,0x02,0x73,0xf5,0x07,0x50,
    0x16,0x66,0x2c,0xb4,0xad,0x73,0x73,0xce,0xb3,0x23,0x67,0xf5,0x9d,0x55,0xa7,0xdf,
};
static const uint8_t M27_AUTHORITY_DIGEST[32] = {
    0x24,0xc5,0x35,0x09,0x3d,0x08,0x76,0x42,0xf6,0xd4,0xbc,0x23,0xb4,0xec,0xc7,0xa1,
    0xa2,0x38,0x46,0xb7,0x1c,0x8d,0xf5,0x67,0x37,0xe0,0xae,0x12,0x4e,0xf3,0x52,0x56,
};
static const uint8_t M27_LIMITS[32] = {
    0x98,0x8e,0x70,0x63,0x12,0x2b,0xfe,0x48,0x49,0xad,0xc9,0xdd,0xe1,0x24,0xc9,0x36,
    0x45,0x2f,0x1f,0x6a,0x51,0xa3,0xdf,0xb2,0xd0,0x87,0x3a,0x25,0x21,0xe1,0x58,0x3b,
};
static const uint8_t M27_BATTERY[32] = {
    0x57,0x42,0x2c,0x15,0xa7,0x72,0xc6,0x11,0x44,0x3e,0x5a,0x28,0x40,0x68,0x94,0xf7,
    0xa4,0x5a,0xcf,0x2f,0x21,0xea,0x38,0x3e,0x68,0x8f,0x06,0x03,0x67,0x67,0xc2,0x20,
};

typedef enum { M27_RUNNING = 1, M27_STOPPED = 2, M27_IDLE = 3 } m27_lifecycle_t;
typedef enum { M27_DONE = 1, M27_REJECTED = 2, M27_FAILED = 3 } m27_result_t;
typedef enum {
    M27_OP_STATUS = 1, M27_OP_STOP, M27_OP_BEGIN, M27_OP_CHUNK,
    M27_OP_SEAL, M27_OP_ACTIVATE, M27_OP_CANCEL, M27_OP_START,
} m27_op_t;

typedef struct {
    uint64_t request_id;
    m27_op_t op;
    uint64_t deployment;
    uint64_t total;
    uint64_t offset;
    uint32_t data_len;
    uint8_t data[M27_CHUNK_BYTES];
    uint8_t pill_sha256[32];
    uint8_t authority[32];
} m27_request_t;

typedef struct {
    int used;
    uint64_t request_id;
    uint8_t digest[32];
    uint16_t payload_len;
    uint8_t payload[M27_MAX_PAYLOAD];
} m27_cache_entry_t;

static uint8_t g_stage[M27_STAGE_BYTES] __attribute__((aligned(16)));
static uint64_t g_stage_id, g_stage_total, g_stage_received, g_stage_chunks;
static uint64_t g_lease_deadline;
static int g_stage_open, g_stage_sealed;
static uint8_t g_stage_pill_sha256[32];
static m27_lifecycle_t g_lifecycle;
static int g_selected_b, g_terminal, g_initialized, g_response_pending;
static noun g_management_tag;
static uint64_t g_generation, g_terminal_deployment;
static uint64_t g_request_high_water, g_response_sequence;
static uint64_t g_rate_start, g_rate_count;
static m27_cache_entry_t g_cache[M27_CACHE_ENTRIES];
static uint8_t g_checkpoint_valid, g_checkpoint_selected, g_checkpoint_terminal;
static m27_lifecycle_t g_checkpoint_lifecycle;
static uint64_t g_checkpoint_generation, g_checkpoint_deployment;

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head; *tail = c->tail;
    return 1;
}

static int direct_is(noun n, uint64_t value)
{
    return noun_is_direct(n) && direct_val(n) == value;
}

static int pair(noun a, noun b, noun *out)
{
    return out && alloc_cell_checked(a, b, out);
}

static int equal_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static uint64_t header_u64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value = (value << 8) | p[i];
    return value;
}

static uint64_t counter_now(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static uint64_t counter_freq(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value ? value : 54000000ULL;
}

static int cord_is(noun n, const char *text)
{
    char value[24]; size_t len = 0;
    while (text[len] && len + 1 < sizeof value) len++;
    return text[len] == 0 && cord_to_cstr(n, value, sizeof value) == len
        && equal_bytes((const uint8_t *)value, (const uint8_t *)text, len);
}

static int atom_bytes(noun n, uint8_t *out, size_t max, size_t len)
{
    if (!out || len == 0 || len > max || !noun_atom_read_fixed(n, out, len))
        return 0;
    return 1;
}

static int decode_request(const uint8_t *header, const uint8_t *payload,
                          uint32_t payload_len, m27_request_t *out)
{
    if (!header || !payload || !out || payload_len == 0
        || payload_len > M27_MAX_PAYLOAD) return 0;
    if (header[0] != 'A' || header[1] != 'E' || header[2] != 'T' || header[3] != '0'
        || header[4] != M27_WIRE_MAJOR || header[5] != M27_WIRE_MINOR
        || header[6] != M27_PROFILE || header[7] != M27_KIND_REQUEST) return 0;
    if (((uint16_t)header[8] << 8 | header[9]) != M27_HEADER_BYTES
        || ((uint16_t)header[10] << 8 | header[11]) != payload_len) return 0;
    if (header_u64(header + 12) != M27_MANAGER
        || header_u64(header + 20) != M27_TARGET) return 0;
    if (!equal_bytes(header + 28, M27_BINDING, sizeof M27_BINDING)) return 0;
    if (!equal_bytes(header + 44, M27_SCHEMA, sizeof M27_SCHEMA)) return 0;
    if (header[76] != 0 || header[77] != 0 || header[78] != 0
        || header[79] != M27_KEY_ID) return 0;
    for (unsigned i = 80; i < 87; i++)
        if (header[i] != 0) return 0;
    if (header[87] != M27_EPOCH) return 0;
    if (header_u64(header + 88) == 0 || header_u64(header + 88) == UINT64_MAX) return 0;
    uint8_t auth_input[M27_HEADER_BYTES + M27_MAX_PAYLOAD];
    for (unsigned i = 0; i < M27_HEADER_BYTES; i++)
        auth_input[i] = i >= 96 ? 0 : header[i];
    for (uint32_t i = 0; i < payload_len; i++) auth_input[M27_HEADER_BYTES + i] = payload[i];
    uint8_t expected[32];
    hmac_sha256(M27_PSK, sizeof M27_PSK - 1u,
                auth_input, M27_HEADER_BYTES + payload_len, expected);
    if (!equal_bytes(expected, header + 96, 32)) return 0;

    noun root;
    if (cue_bounded_bytes(payload, payload_len, &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &root) != CUE_BOUNDED_OK)
        return 0;
    const uint8_t *canonical; uint64_t canonical_len;
    if (jam_encode_bytes_identity(root, &canonical, &canonical_len) != 0
        || canonical_len != payload_len
        || !equal_bytes(canonical, payload, payload_len)) return 0;
    noun tag, rest, version, request_id, body, operation, operation_payload;
    if (!take(root, &tag, &rest) || !cord_is(tag, "aethernet-management")
        || !take(rest, &version, &rest) || !direct_is(version, 1)
        || !take(rest, &request_id, &body) || !noun_is_direct(request_id)
        || direct_val(request_id) == 0 || !take(body, &operation, &operation_payload)) return 0;
    out->request_id = direct_val(request_id);
    out->op = 0; out->deployment = out->total = out->offset = 0;
    out->data_len = 0;
    if (cord_is(operation, "status") && operation_payload == NOUN_ZERO) out->op = M27_OP_STATUS;
    else if (cord_is(operation, "resource-stop") && operation_payload == NOUN_ZERO) out->op = M27_OP_STOP;
    else if (cord_is(operation, "resource-start") && operation_payload == NOUN_ZERO) out->op = M27_OP_START;
    else if (cord_is(operation, "install-seal") || cord_is(operation, "install-activate")
             || cord_is(operation, "install-cancel")) {
        if (!noun_is_direct(operation_payload) || direct_val(operation_payload) == 0) return 0;
        out->deployment = direct_val(operation_payload);
        out->op = cord_is(operation, "install-seal") ? M27_OP_SEAL
            : cord_is(operation, "install-activate") ? M27_OP_ACTIVATE : M27_OP_CANCEL;
    } else if (cord_is(operation, "install-begin")) {
        noun deployment, tail, total, pill, authority;
        if (!take(operation_payload, &deployment, &tail) || !take(tail, &total, &tail)
            || !take(tail, &pill, &authority)
            || !noun_is_direct(deployment) || direct_val(deployment) == 0
            || !noun_is_direct(total)
            || !atom_bytes(pill, out->pill_sha256, 32, 32)
            || !atom_bytes(authority, out->authority, 32, 32)) return 0;
        out->deployment = direct_val(deployment); out->total = direct_val(total);
        out->op = M27_OP_BEGIN;
    } else if (cord_is(operation, "install-chunk")) {
        noun deployment, tail, offset, length, atom_tail, atom, zero;
        if (!take(operation_payload, &deployment, &tail) || !take(tail, &offset, &tail)
            || !take(tail, &length, &atom_tail) || !take(atom_tail, &atom, &zero)
            || !noun_is_direct(deployment) || direct_val(deployment) == 0
            || !noun_is_direct(offset) || !noun_is_direct(length)
            || direct_val(length) == 0 || direct_val(length) > M27_CHUNK_BYTES
            || zero != NOUN_ZERO
            || !atom_bytes(atom, out->data, sizeof out->data, direct_val(length))) return 0;
        out->deployment = direct_val(deployment); out->offset = direct_val(offset);
        out->data_len = (uint32_t)direct_val(length); out->op = M27_OP_CHUNK;
    } else return 0;
    return out->op != 0;
}

static int status_body(m27_lifecycle_t lifecycle, int selected_b,
                       uint64_t generation, uint64_t deployment,
                       uint64_t received, uint64_t chunks, int terminal,
                       noun *out)
{
    noun values[8], tail;
    values[0] = direct(lifecycle); values[1] = direct(selected_b ? 1 : 0);
    values[2] = direct(generation);
    values[3] = direct(lifecycle == M27_STOPPED || lifecycle == M27_IDLE ? 1 : 0);
    values[4] = direct(deployment); values[5] = direct(received);
    values[6] = direct(chunks); values[7] = direct(terminal ? 1 : 0);
    /* The product status noun is an eight-field nested tuple, not a proper
       list.  Its final field is the value itself, with no extra terminator. */
    tail = values[7];
    for (int i = 6; i >= 0; i--) if (!pair(values[i], tail, &tail)) return 0;
    *out = tail; return 1;
}

static int response_payload(uint64_t request_id, m27_result_t result,
                            noun body, uint8_t out[M27_MAX_PAYLOAD], uint16_t *len_out,
                            int post_activation)
{
    if (!noun_tx_begin(HEAP_MODE_SCRATCH)) return 0;
    noun response, tail, operation, request, version, tag;
    tag = g_management_tag;
    operation = result == M27_DONE ? cord_from_bytes("done", 4)
        : result == M27_FAILED ? cord_from_bytes("failed", 6)
        : cord_from_bytes("rejected", 8);
    if (!pair(operation, body, &tail) || !pair(direct(request_id), tail, &request)
        || !pair(direct(1), request, &version) || !pair(tag, version, &response)) {
        noun_tx_abort();
        return 0;
    }
    (void)post_activation;
    const uint8_t *encoded; uint64_t encoded_len;
    if (jam_encode_bytes_identity(response, &encoded, &encoded_len) != 0
        || encoded_len == 0 || encoded_len > M27_MAX_PAYLOAD) {
        noun_tx_abort(); return 0;
    }
    for (uint64_t i = 0; i < encoded_len; i++) out[i] = encoded[i];
    noun_tx_abort();
    *len_out = (uint16_t)encoded_len; return 1;
}

static int response_frame(const uint8_t *payload, uint16_t payload_len,
                          uint8_t out[M27_HEADER_BYTES + M27_MAX_PAYLOAD],
                          uint32_t *len_out)
{
    for (unsigned i = 0; i < M27_HEADER_BYTES; i++) out[i] = 0;
    out[0]='A'; out[1]='E'; out[2]='T'; out[3]='0';
    out[4]=M27_WIRE_MAJOR; out[5]=M27_WIRE_MINOR; out[6]=M27_PROFILE; out[7]=M27_KIND_RESPONSE;
    out[8]=0; out[9]=M27_HEADER_BYTES; out[10]=(uint8_t)(payload_len >> 8); out[11]=(uint8_t)payload_len;
    for (unsigned i = 0; i < 8; i++) {
        out[12+i] = (uint8_t)((uint64_t)M27_TARGET >> (56u - i * 8u));
        out[20+i] = (uint8_t)((uint64_t)M27_MANAGER >> (56u - i * 8u));
    }
    for (unsigned i = 0; i < 16; i++) out[28+i] = M27_BINDING[i];
    for (unsigned i = 0; i < 32; i++) out[44+i] = M27_SCHEMA[i];
    out[79] = M27_KEY_ID; out[87] = M27_EPOCH;
    uint64_t sequence = g_response_sequence;
    for (unsigned i = 0; i < 8; i++) out[88+i] = (uint8_t)(sequence >> (56u - i * 8u));
    for (unsigned i = 0; i < payload_len; i++) out[M27_HEADER_BYTES+i] = payload[i];
    uint8_t auth[32];
    hmac_sha256(M27_PSK, sizeof M27_PSK - 1u,
                out, M27_HEADER_BYTES + payload_len, auth);
    for (unsigned i = 0; i < 32; i++) out[96+i] = auth[i];
    *len_out = M27_HEADER_BYTES + payload_len;
    return 1;
}

static int cache_find(uint64_t request_id, const uint8_t digest[32])
{
    for (unsigned i = 0; i < M27_CACHE_ENTRIES; i++)
        if (g_cache[i].used && g_cache[i].request_id == request_id)
            return equal_bytes(g_cache[i].digest, digest, 32) ? (int)i : -2;
    return -1;
}

static int cache_store(uint64_t request_id, const uint8_t digest[32],
                       const uint8_t *payload, uint16_t payload_len)
{
    for (unsigned i = 0; i < M27_CACHE_ENTRIES; i++) if (!g_cache[i].used) {
        g_cache[i].used = 1; g_cache[i].request_id = request_id;
        for (unsigned j = 0; j < 32; j++) g_cache[i].digest[j] = digest[j];
        g_cache[i].payload_len = payload_len;
        for (unsigned j = 0; j < payload_len; j++) g_cache[i].payload[j] = payload[j];
        return 1;
    }
    return 0;
}

static int cache_available(void)
{
    for (unsigned i = 0; i < M27_CACHE_ENTRIES; i++)
        if (!g_cache[i].used) return 1;
    return 0;
}

static int accept_sequence(uint64_t sequence)
{
    if (sequence <= g_request_high_water || sequence == UINT64_MAX) return 0;
    uint64_t now = counter_now(), freq = counter_freq();
    if (g_rate_start == 0 || now - g_rate_start >= freq)
        g_rate_start = now, g_rate_count = 0;
    if (g_rate_count >= M27_RATE_LIMIT) return 0;
    g_rate_count++;
    g_request_high_water = sequence;
    return 1;
}

static int make_status_payload(uint64_t request_id, uint8_t out[M27_MAX_PAYLOAD],
                               uint16_t *len, m27_lifecycle_t lifecycle,
                               int selected_b, uint64_t generation,
                               uint64_t deployment, uint64_t received,
                               uint64_t chunks, int terminal)
{
    noun body;
    if (!status_body(lifecycle, selected_b, generation, deployment,
                     received, chunks, terminal, &body)) return 0;
    return response_payload(request_id, M27_DONE, body, out, len, 0);
}

static void discard_stage(void)
{
    for (uint64_t i = 0; i < M27_STAGE_BYTES; i++) g_stage[i] = 0;
    g_stage_id = g_stage_total = g_stage_received = g_stage_chunks = 0;
    g_lease_deadline = 0; g_stage_open = g_stage_sealed = 0;
    for (unsigned i = 0; i < 32; i++) g_stage_pill_sha256[i] = 0;
}

static int begin_install(const m27_request_t *request)
{
    if (g_lifecycle != M27_STOPPED || g_selected_b || g_stage_open
        || request->deployment != 27 || request->total != 22206
        || !equal_bytes(request->pill_sha256, M27_B_PILL_SHA256, 32)
        || !equal_bytes(request->authority, M27_AUTHORITY_DIGEST, 32)) return 0;
    g_stage_id = request->deployment; g_stage_total = request->total;
    g_stage_received = g_stage_chunks = 0; g_stage_open = 1; g_stage_sealed = 0;
    for (unsigned i = 0; i < 32; i++) g_stage_pill_sha256[i] = request->pill_sha256[i];
    g_lease_deadline = counter_now() + counter_freq() * M27_LEASE_SECONDS;
    return 1;
}

static int chunk_install(const m27_request_t *request)
{
    if (!g_stage_open || g_stage_sealed || request->deployment != g_stage_id
        || request->data_len == 0 || request->data_len > M27_CHUNK_BYTES) return 0;
    if (request->offset < g_stage_received) {
        if (request->offset + request->data_len > g_stage_received) return 0;
        return equal_bytes(g_stage + request->offset, request->data, request->data_len);
    }
    if (request->offset != g_stage_received || g_stage_chunks >= M27_MAX_CHUNKS
        || request->data_len > g_stage_total - g_stage_received) return 0;
    for (uint32_t i = 0; i < request->data_len; i++) g_stage[g_stage_received+i] = request->data[i];
    g_stage_received += request->data_len; g_stage_chunks++;
    g_lease_deadline = counter_now() + counter_freq() * M27_LEASE_SECONDS;
    return 1;
}

static int seal_install(const m27_request_t *request)
{
    if (!g_stage_open || g_stage_sealed || request->deployment != g_stage_id
        || g_stage_received != g_stage_total || g_lifecycle != M27_STOPPED) return 0;
    uint8_t sha[32], b3[32];
    sha256_hash(g_stage, g_stage_total, sha); blake3_hash(g_stage, g_stage_total, b3);
    if (!equal_bytes(sha, M27_B_PILL_SHA256, 32)
        || !equal_bytes(b3, M27_B_PILL_BLAKE3, 32)) return 0;
    g_stage_sealed = 1; return 1;
}

static int activate_install(const m27_request_t *request,
                            uint8_t reserved[M27_MAX_PAYLOAD], uint16_t *reserved_len)
{
    if (!g_stage_open || !g_stage_sealed || request->deployment != g_stage_id
        || g_lifecycle != M27_STOPPED || g_selected_b || g_terminal
        || g_stage_received != g_stage_total) return 0;
    /* Reserve the only response shape before candidate cue/validation starts;
     * response allocation cannot become a post-commit activation failure. */
    if (!make_status_payload(request->request_id, reserved, reserved_len,
                             M27_IDLE, 1, 2, 0, 0, 0, 1)) return 0;
    noun candidate_gate, prepared;
    runtime_identity_t identity;
    uint8_t capability;
    if (pill_i2_validate_buffer(g_stage, g_stage_total, HEAP_MODE_PERSIST,
                                &candidate_gate, &identity, &capability) != PILL_I2_OK
        || capability != RUNTIME_CAPABILITY_PROFILE_M25
        || identity.runtime_abi[0] != 1 || identity.runtime_abi[1] != 9
        || identity.formula_abi[0] != 1 || identity.formula_abi[1] != 9
        || identity.host_abi[0] != 1 || identity.host_abi[1] != 3
        || identity.deployment_schema[0] != 1 || identity.deployment_schema[1] != 3
        || identity.generation != 2
        || !equal_bytes(identity.program_hash, M27_B_PROGRAM, 32)
        || !equal_bytes(identity.package_hash, M27_B_ANCHOR, 32)
        || !equal_bytes(identity.battery_hash, M27_BATTERY, 32)
        || !equal_bytes(g_stage_pill_sha256, M27_B_PILL_SHA256, 32)
        ) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    uint8_t limits_hash[32];
    if (!i2_admission_limits_hash(candidate_gate, limits_hash)
        || !equal_bytes(limits_hash, M27_LIMITS, 32)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    if (m26_target_prepare_gate(candidate_gate, &identity, capability, &prepared) != 0) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    noun_tx_commit();
    heap_persist_commit_tx();
    /* Assignment-only commit suffix: the new data gate and M27 authority
     * state become visible together. */
    m26_target_publish_gate(prepared, &identity, capability);
    g_selected_b = 1; g_generation = 2; g_lifecycle = M27_IDLE;
    g_terminal = 1; g_terminal_deployment = request->deployment;
    discard_stage();
    return 1;
}

static int execute_request(const m27_request_t *request,
                           uint8_t response[M27_MAX_PAYLOAD], uint16_t *response_len)
{
    m27_result_t result = M27_REJECTED; noun body = NOUN_ZERO;
    if (request->op == M27_OP_STATUS) {
        if (!status_body(g_lifecycle, g_selected_b, g_generation,
                         g_stage_open ? g_stage_id : g_terminal_deployment,
                         g_stage_open ? g_stage_received : 0,
                         g_stage_open ? g_stage_chunks : 0, g_terminal, &body)) return 0;
        result = M27_DONE;
    } else if (request->op == M27_OP_STOP) {
        if (m26_target_set_running(0) == 0) { g_lifecycle = M27_STOPPED; result = M27_DONE; }
        if (result == M27_DONE && !status_body(g_lifecycle, g_selected_b, g_generation,
                                               g_stage_id, g_stage_received, g_stage_chunks,
                                               g_terminal, &body)) return 0;
    } else if (request->op == M27_OP_BEGIN) {
        if (begin_install(request)) { result = M27_DONE; body = NOUN_ZERO; }
    } else if (request->op == M27_OP_CHUNK) {
        if (chunk_install(request)) { result = M27_DONE; body = NOUN_ZERO; }
    } else if (request->op == M27_OP_SEAL) {
        if (seal_install(request)) { result = M27_DONE; body = NOUN_ZERO; }
    } else if (request->op == M27_OP_ACTIVATE) {
        if (activate_install(request, response, response_len)) return 1;
    } else if (request->op == M27_OP_CANCEL) {
        if (g_stage_open && request->deployment == g_stage_id) {
            discard_stage(); result = M27_DONE;
            if (!status_body(g_lifecycle, g_selected_b, g_generation, 0, 0, 0,
                             g_terminal, &body)) return 0;
        }
    } else if (request->op == M27_OP_START) {
        if (g_selected_b && (g_lifecycle == M27_IDLE || g_lifecycle == M27_STOPPED)
            && m26_target_init() == 0 && m27_native_init() == 0
            && m26_target_set_running(1) == 0) {
            g_lifecycle = M27_RUNNING; result = M27_DONE;
            if (!status_body(g_lifecycle, g_selected_b, g_generation, 0, 0, 0,
                             g_terminal, &body)) return 0;
        }
    }
    return response_payload(request->request_id, result, body,
                            response, response_len, 0);
}

static int send_response(uint64_t request_id, const uint8_t *payload,
                         uint16_t payload_len)
{
    uint8_t frame[M27_HEADER_BYTES + M27_MAX_PAYLOAD]; uint32_t frame_len;
    if (g_response_sequence == UINT64_MAX
        || !response_frame(payload, payload_len, frame, &frame_len)) return 0;
    m27_native_status_t status = m27_native_send(frame, frame_len);
    if (status != M27_NATIVE_OK) { g_response_pending = 1; return 0; }
    g_response_sequence++;
    (void)request_id;
    return 1;
}

int m27_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile)
{
    if (!identity || capability_profile != RUNTIME_CAPABILITY_PROFILE_M25
        || identity->generation != 1 || !equal_bytes(identity->program_hash, M27_A_PROGRAM, 32)
        || !equal_bytes(identity->package_hash, M27_A_ANCHOR, 32)) return -1;
    (void)gate;
    discard_stage();
    for (unsigned i = 0; i < M27_CACHE_ENTRIES; i++) g_cache[i].used = 0;
    g_lifecycle = M27_RUNNING; g_selected_b = 0; g_terminal = 0;
    g_management_tag = cord_from_bytes("aethernet-management", 20);
    if (!noun_is_atom(g_management_tag)) return -1;
    g_generation = 1; g_terminal_deployment = 0; g_initialized = 0;
    g_response_pending = 0; g_request_high_water = 0; g_response_sequence = 1;
    g_rate_start = g_rate_count = 0; g_checkpoint_valid = 0;
    return 0;
}

int m27_target_service_tick(void)
{
    if (!g_initialized) {
        if (!m26_target_native_ready()) {
            return 0;
        }
        if (m27_native_init() != 0) {
            return 0;
        }
        g_initialized = 1;
    }
    if (g_stage_open && g_lease_deadline && counter_now() >= g_lease_deadline)
        discard_stage();
    m27_native_datagram_t datagram;
    m27_native_status_t native_status = m27_native_receive(&datagram);
    if (native_status != M27_NATIVE_OK) {
        return 0;
    }
    if (g_response_pending) return 0;
    uint8_t digest[32]; sha256_hash(datagram.payload, datagram.payload_len, digest);
    m27_request_t request;
    if (!decode_request(datagram.header, datagram.payload, datagram.payload_len, &request)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    /* Parsing is a scratch-only admission phase. Every operation below owns
     * its own bounded transaction, and activation's candidate transaction is
     * never nested inside the decoded request. */
    if (noun_tx_active()) noun_tx_abort();
    uint64_t sequence = 0;
    for (unsigned i = 0; i < 8; i++) sequence = (sequence << 8) | datagram.header[88+i];
    int cached = cache_find(request.request_id, digest);
    uint8_t response[M27_MAX_PAYLOAD]; uint16_t response_len = 0;
    if (!accept_sequence(sequence)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    if (cached >= 0) {
        for (unsigned i = 0; i < g_cache[cached].payload_len; i++) response[i] = g_cache[cached].payload[i];
        response_len = g_cache[cached].payload_len;
    } else if (cached == -2) {
        if (!response_payload(request.request_id, M27_REJECTED, NOUN_ZERO,
                              response, &response_len, 0)) { noun_tx_abort(); return 0; }
    } else {
        if (!cache_available()) {
            if (noun_tx_active()) noun_tx_abort();
            return 0;
        }
        if (!execute_request(&request, response, &response_len)) {
            if (noun_tx_active()) noun_tx_abort();
            return 0;
        }
        if (!cache_store(request.request_id, digest, response, response_len)) {
            if (noun_tx_active()) noun_tx_abort();
            return 0;
        }
    }
    if (noun_tx_active()) noun_tx_abort();
    int sent = send_response(request.request_id, response, response_len);
    return sent ? 1 : 0;
}

int m27_target_checkpoint_capture(void)
{
    if (g_stage_open || g_response_pending || g_checkpoint_valid
        || m26_target_checkpoint_capture() != 0) return -1;
    g_checkpoint_selected = (uint8_t)g_selected_b;
    g_checkpoint_terminal = (uint8_t)g_terminal;
    g_checkpoint_lifecycle = g_lifecycle;
    g_checkpoint_generation = g_generation; g_checkpoint_deployment = g_terminal_deployment;
    g_checkpoint_valid = 1; return 0;
}

int m27_target_checkpoint_restore(void)
{
    if (!g_checkpoint_valid || g_stage_open || g_response_pending
        || m26_target_checkpoint_restore() != 0) return -1;
    g_selected_b = g_checkpoint_selected; g_terminal = g_checkpoint_terminal;
    g_generation = g_checkpoint_generation; g_terminal_deployment = g_checkpoint_deployment;
    g_lifecycle = g_checkpoint_lifecycle;
    return 0;
}

uint64_t m27_target_selected(void) { return g_selected_b ? 1 : 0; }
uint64_t m27_target_generation(void) { return g_generation; }
uint64_t m27_target_terminal(void) { return g_terminal ? 1 : 0; }
