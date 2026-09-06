#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "jam.h"
#include "m38_resource_core_descriptor.h"
#include "m38_resource_runtime.h"
#include "memory.h"
#include "nock.h"
#include "sha256.h"
#include "setjmp.h"

/*
 * M38-D8 Wave A.
 *
 * This translation unit is intentionally independent of the historical
 * m38_resource_abi_target.c D5/D7 seam.  The only authority accepted here is
 * the exact ResourceCore Jam paired with its exact SessionAdmissionRecord.
 * Session state lives in caller-owned opaque storage; the platform noun heap,
 * atom store, scratch heap, and Nock abort point remain one serialized
 * ResourceRuntime domain.
 */

#define RESOURCE_RUNTIME_CONTROL_BYTES       (64u * 1024u)
#define RESOURCE_RUNTIME_WORKSPACE_BYTES     (4u * 1024u * 1024u)
#define RESOURCE_RUNTIME_BYTES               (RESOURCE_RUNTIME_CONTROL_BYTES + RESOURCE_RUNTIME_WORKSPACE_BYTES)
#define RESOURCE_SESSION_BYTES               (2u * 1024u * 1024u)
#define RESOURCE_STORAGE_ALIGNMENT           64u
#define RESOURCE_MAX_ADMISSION_ENTRIES       2u
#define RESOURCE_MAX_LIVE_HANDLES            8u
#define RESOURCE_MAX_REGISTERED_SESSIONS     2u
#define RESOURCE_MAX_CORE_JAM_BYTES          (128u * 1024u)
#define RESOURCE_MAX_RECORD_JAM_BYTES        (128u * 1024u)
#define RESOURCE_MAX_CUE_DEPTH               256u
#define RESOURCE_MAX_CELLS                    128000u
#define RESOURCE_MAX_NODES                    131072u
#define RESOURCE_MAX_PLAN_TYPES               8u
#define RESOURCE_MAX_PLAN_EVENTS              16u
#define RESOURCE_MAX_PLAN_VALUES              16u
#define RESOURCE_MAX_PLAN_STATES              8u
#define RESOURCE_MAX_PLAN_INSTANCES           8u
#define RESOURCE_MAX_VALUES                    16u
#define RESOURCE_MAX_SNAPSHOT_NONCE            0xFFFFFFFFULL

#define RESOURCE_RUNTIME_PLAN_TAG             0x6e616c702d3833ULL
#define RESOURCE_RUNTIME_STATE_TAG            0x65746174732d3833ULL
#define RESOURCE_RUNTIME_STIMULUS_TAG         0x6c756d6974732d3833ULL
#define RESOURCE_RUNTIME_QUEUE_LIMIT          8u
#define RESOURCE_RUNTIME_WORKLIST_LIMIT       32u
#define RESOURCE_RUNTIME_TRACE_LIMIT          128u

#define RESOURCE_SAFETY_SEEN_OFFSET           0u
#define RESOURCE_SAFETY_COLOR_OFFSET          (RESOURCE_MAX_NODES * sizeof(uint32_t))
#define RESOURCE_SAFETY_STACK_OFFSET          (RESOURCE_SAFETY_COLOR_OFFSET + RESOURCE_MAX_NODES)
#define RESOURCE_SAFETY_DEPTH_OFFSET          (RESOURCE_SAFETY_STACK_OFFSET + RESOURCE_MAX_NODES * sizeof(noun))
#define RESOURCE_SAFETY_WORK_OFFSET           (RESOURCE_SAFETY_DEPTH_OFFSET + RESOURCE_MAX_NODES * sizeof(uint32_t))
#define RESOURCE_SAFETY_WORK_BYTES            (RESOURCE_RUNTIME_WORKSPACE_BYTES - RESOURCE_SAFETY_WORK_OFFSET)

#define RESOURCE_OP_LOAD                      1u
#define RESOURCE_OP_POKE                      2u
#define RESOURCE_OP_PEEK                      3u
#define RESOURCE_OP_SNAPSHOT                  4u
#define RESOURCE_OP_RESTORE                   5u

#define RESOURCE_WIRE_LOADED                  1u
#define RESOURCE_WIRE_POKE                    2u
#define RESOURCE_WIRE_PEEK                    3u
#define RESOURCE_WIRE_SNAPSHOT                4u
#define RESOURCE_WIRE_RESTORE                 5u
#define RESOURCE_WIRE_REFUSE                  255u

#define RESOURCE_REASON_INVALID_REQUEST       1u
#define RESOURCE_REASON_UNKNOWN_CORE          2u
#define RESOURCE_REASON_BAD_HANDLE            3u
#define RESOURCE_REASON_BAD_STIMULUS          4u
#define RESOURCE_REASON_BAD_SELECTOR          5u
#define RESOURCE_REASON_BAD_SNAPSHOT          6u
#define RESOURCE_REASON_CONSTRUCTION          7u
#define RESOURCE_REASON_CORE_FAILURE          8u
#define RESOURCE_REASON_NO_SLOT               9u

static const char RESOURCE_REQUEST_TAG[] = "m38-resource-abi-v1-request";
static const char RESOURCE_REQUEST_SCHEMA[] = "m38-resource-abi-v1-request-schema-v1";
static const char RESOURCE_RESULT_TAG[] = "m38-resource-abi-v1-result";
static const char RESOURCE_RESULT_SCHEMA[] = "m38-resource-abi-v1-result-schema-v1";
static const char RESOURCE_STIMULUS_TAG[] = "m38-resource-abi-v1-numeric-stimulus";
static const char RESOURCE_STIMULUS_SCHEMA[] = "m38-resource-abi-v1-numeric-stimulus-schema-v1";
static const char RESOURCE_SELECTOR_TAG[] = "m38-resource-abi-v1-numeric-selector";
static const char RESOURCE_SELECTOR_SCHEMA[] = "m38-resource-abi-v1-numeric-selector-schema-v1";
static const char RESOURCE_STATE_TAG[] = "m38-resource-abi-v1-numeric-state";
static const char RESOURCE_STATE_SCHEMA[] = "m38-resource-abi-v1-numeric-state-schema-v1";
static const char RESOURCE_INSTANCE_TAG[] = "m38-resource-abi-v1-instance-state";
static const char RESOURCE_INSTANCE_SCHEMA[] = "m38-resource-abi-v1-instance-state-schema-v1";
static const char RESOURCE_VALUE_TAG[] = "m38-resource-abi-v1-numeric-value";
static const char RESOURCE_VALUE_SCHEMA[] = "m38-resource-abi-v1-numeric-value-schema-v1";
static const char RESOURCE_EFFECTS_TAG[] = "m38-resource-abi-v1-numeric-effects";
static const char RESOURCE_EFFECTS_SCHEMA[] = "m38-resource-abi-v1-numeric-effects-schema-v1";
static const char RESOURCE_OBSERVATIONS_TAG[] = "m38-resource-abi-v1-numeric-observations";
static const char RESOURCE_OBSERVATIONS_SCHEMA[] = "m38-resource-abi-v1-numeric-observations-schema-v1";
static const char RESOURCE_OBSERVATION_TAG[] = "m38-resource-abi-v1-numeric-observation";
static const char RESOURCE_OBSERVATION_SCHEMA[] = "m38-resource-abi-v1-numeric-observation-schema-v1";
static const char RESOURCE_METRICS_TAG[] = "m38-resource-abi-v1-numeric-metrics";
static const char RESOURCE_METRICS_SCHEMA[] = "m38-resource-abi-v1-numeric-metrics-schema-v1";
static const char RESOURCE_RECEIPT_TAG[] = "m38-resource-abi-v1-restore-receipt";
static const char RESOURCE_RECEIPT_SCHEMA[] = "m38-resource-abi-v1-restore-receipt-schema-v1";
static const char RESOURCE_REFUSAL_TAG[] = "m38-resource-abi-v1-refusal-reason";
static const char RESOURCE_REFUSAL_SCHEMA[] = "m38-resource-abi-v1-refusal-reason-schema-v1";
static const char RESOURCE_ZERO_TAG[] = "m38-resource-abi-v1-zero-state";
static const char RESOURCE_ZERO_SCHEMA[] = "m38-resource-abi-v1-zero-state-schema-v1";
static const char RESOURCE_RECORD_TAG[] = "m38-resource-abi-v1-session-admission-record";
static const char RESOURCE_RECORD_SCHEMA[] = "m38-resource-abi-v1-session-admission-record-schema-v1";
static const char RESOURCE_ADMISSION_DOMAIN[] = "1499kernel:i2:m38:resource-abi-v1:session-admission-record:v1";
static const char RESOURCE_CORE_DOMAIN[] = "1499kernel:i2:m38-d0-r3:resource-core:v3";
static const char RESOURCE_FORMULA_DOMAIN[] = "1499kernel:i2:m38-d0-r3:formula:v3";
static const char RESOURCE_PAYLOAD_DOMAIN[] = "1499kernel:i2:m38-d0-r3:resource-payload:v3";
static const char RESOURCE_PROFILE_ID[] = "1499kernel-i2-m38-numeric-execution-profile-v1-bounded";

static const char *const RESOURCE_BINDING_NAMES[15] = {
    "ResourceABIRequest", "ResourceABIResult", "NumericValue",
    "NumericStimulus", "NumericSelector", "NumericState",
    "NumericInstanceState", "NumericEffects", "NumericEffect",
    "NumericObservations", "NumericObservation", "NumericMetrics",
    "RestoreReceipt", "RefusalReason", "ZeroState"
};
static const char *const RESOURCE_BINDING_TAGS[15] = {
    "m38-resource-abi-v1-request", "m38-resource-abi-v1-result",
    "m38-resource-abi-v1-numeric-value", "m38-resource-abi-v1-numeric-stimulus",
    "m38-resource-abi-v1-numeric-selector", "m38-resource-abi-v1-numeric-state",
    "m38-resource-abi-v1-instance-state", "m38-resource-abi-v1-numeric-effects",
    "m38-resource-abi-v1-numeric-effect", "m38-resource-abi-v1-numeric-observations",
    "m38-resource-abi-v1-numeric-observation", "m38-resource-abi-v1-numeric-metrics",
    "m38-resource-abi-v1-restore-receipt", "m38-resource-abi-v1-refusal-reason",
    "m38-resource-abi-v1-zero-state"
};
static const char *const RESOURCE_BINDING_SCHEMAS[15] = {
    "m38-resource-abi-v1-request-schema-v1", "m38-resource-abi-v1-result-schema-v1",
    "m38-resource-abi-v1-numeric-value-schema-v1", "m38-resource-abi-v1-numeric-stimulus-schema-v1",
    "m38-resource-abi-v1-numeric-selector-schema-v1", "m38-resource-abi-v1-numeric-state-schema-v1",
    "m38-resource-abi-v1-instance-state-schema-v1", "m38-resource-abi-v1-numeric-effects-schema-v1",
    "m38-resource-abi-v1-numeric-effect-schema-v1", "m38-resource-abi-v1-numeric-observations-schema-v1",
    "m38-resource-abi-v1-numeric-observation-schema-v1", "m38-resource-abi-v1-numeric-metrics-schema-v1",
    "m38-resource-abi-v1-restore-receipt-schema-v1", "m38-resource-abi-v1-refusal-reason-schema-v1",
    "m38-resource-abi-v1-zero-state-schema-v1"
};
static const char *const RESOURCE_NESTED_SCHEMAS[13] = {
    "m38-resource-abi-v1-numeric-value-schema-v1",
    "m38-resource-abi-v1-numeric-stimulus-schema-v1",
    "m38-resource-abi-v1-numeric-selector-schema-v1",
    "m38-resource-abi-v1-numeric-state-schema-v1",
    "m38-resource-abi-v1-instance-state-schema-v1",
    "m38-resource-abi-v1-numeric-effects-schema-v1",
    "m38-resource-abi-v1-numeric-effect-schema-v1",
    "m38-resource-abi-v1-numeric-observations-schema-v1",
    "m38-resource-abi-v1-numeric-observation-schema-v1",
    "m38-resource-abi-v1-numeric-metrics-schema-v1",
    "m38-resource-abi-v1-restore-receipt-schema-v1",
    "m38-resource-abi-v1-refusal-reason-schema-v1",
    "m38-resource-abi-v1-zero-state-schema-v1"
};

#define RESOURCE_CORE_IDS m38_resource_core_ids
#define RESOURCE_BATTERY_IDS m38_resource_battery_ids
#define RESOURCE_PAYLOAD_IDS m38_resource_payload_ids
#define RESOURCE_ADMISSION_IDS m38_resource_admission_ids

typedef struct WavePlanType {
    uint32_t id;
    uint32_t value_count;
    uint32_t state_id;
    uint32_t value_ids[RESOURCE_MAX_PLAN_VALUES];
    uint32_t value_types[RESOURCE_MAX_PLAN_VALUES];
    uint32_t value_initials[RESOURCE_MAX_PLAN_VALUES];
    uint32_t event_count;
    uint32_t event_ids[RESOURCE_MAX_PLAN_EVENTS];
    uint32_t event_value_counts[RESOURCE_MAX_PLAN_EVENTS];
    uint32_t event_value_ids[RESOURCE_MAX_PLAN_EVENTS][RESOURCE_MAX_PLAN_VALUES];
    uint32_t state_count;
} WavePlanType;

typedef struct WavePlan {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t instance_types[RESOURCE_MAX_PLAN_INSTANCES];
    WavePlanType types[RESOURCE_MAX_PLAN_TYPES];
    noun formula;
    noun payload;
} WavePlan;

typedef struct WaveCacheEntry {
    uint8_t valid;
    uint8_t core_id[32];
    uint8_t payload_id[32];
    noun core;
    noun payload;
    WavePlan plan;
} WaveCacheEntry;

typedef struct WaveSlot {
    uint8_t used;
    uint8_t catalog_index;
    uint8_t reserved[2];
    uint64_t generation;
    uint64_t snapshot_nonce;
    noun handle_root;
    noun state_root;
    noun snapshot_root;
    uint32_t state_ids[RESOURCE_MAX_PLAN_INSTANCES];
    uint32_t state_values[RESOURCE_MAX_PLAN_INSTANCES][RESOURCE_MAX_PLAN_VALUES];
} WaveSlot;

typedef struct WaveCatalogCopy {
    uint8_t valid;
    uint8_t core_id[32];
    uint8_t battery_id[32];
    uint8_t payload_id[32];
    uint8_t admission_id[32];
    uint32_t core_jam_bytes;
    uint8_t core_jam[RESOURCE_MAX_CORE_JAM_BYTES];
    noun core;
} WaveCatalogCopy;

struct ResourceSession {
    uint32_t magic;
    uint8_t state; /* 1=bound, 2=closed */
    uint8_t registry_index;
    uint8_t in_flight;
    uint8_t reserved;
    ResourceRuntime *runtime;
    SessionCapability capability;
    WaveCatalogCopy catalog[RESOURCE_MAX_ADMISSION_ENTRIES];
    WaveCacheEntry cache[RESOURCE_MAX_ADMISSION_ENTRIES];
    WaveSlot slots[RESOURCE_MAX_LIVE_HANDLES];
    noun primary_root;
    noun refusal_root;
    ResourceResultView primary_view;
    ResourceResultView refusal_view;
    uint64_t primary_generation;
    uint64_t refusal_generation;
    uint64_t session_transaction_id;
    uint64_t parse_count;
};

struct ResourceRuntime {
    uint32_t magic;
    uint8_t state; /* 1=initializing, 2=idle, 3=dispatching, 4=lifecycle */
    uint8_t broker_owner;
    uint8_t session_count;
    uint8_t reserved;
    void *control_storage;
    void *workspace;
    uint64_t next_capability;
    uint64_t broker_transaction_id;
    uint64_t promoted_root_count;
    M38FaultPoint next_fault;
    ResourceSession *sessions[RESOURCE_MAX_REGISTERED_SESSIONS];
};

#define RESOURCE_RUNTIME_MAGIC  0x52333857u
#define RESOURCE_SESSION_MAGIC  0x53333857u

/* The singleton lease is runtime ownership, not session/catalog/slot state. */
static ResourceRuntime *g_wave_runtime_lease;

static size_t wave_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static void wave_zero(void *p, size_t n)
{
    __builtin_memset(p, 0, n);
}

static void wave_copy(void *dst, const void *src, size_t n)
{
    __builtin_memcpy(dst, src, n);
}

static int wave_bytes_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static int wave_range_overlap(const void *a, size_t an,
                              const void *b, size_t bn)
{
    uintptr_t aa = (uintptr_t)a, bb = (uintptr_t)b;
    if (an == 0 || bn == 0) return 0;
    if (aa > UINTPTR_MAX - an || bb > UINTPTR_MAX - bn) return 1;
    return aa < bb + bn && bb < aa + an;
}

static noun wave_cord(const char *s)
{
    return cord_from_bytes(s, wave_strlen(s));
}

static int wave_atom_bytes(noun n, uint8_t *out, size_t nbytes)
{
    return noun_is_atom(n) && noun_atom_read_fixed(n, out, nbytes);
}

static int wave_atom_text(noun n, const char *s)
{
    uint8_t bytes[256];
    size_t len = wave_strlen(s);
    if (len >= sizeof(bytes) || !wave_atom_bytes(n, bytes, sizeof(bytes)))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] != (uint8_t)s[i]) return 0;
    for (size_t i = len; i < sizeof(bytes); i++)
        if (bytes[i] != 0) return 0;
    return 1;
}

static int wave_pair(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n)) return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

static int wave_record(noun n, noun *out, uint32_t count)
{
    noun cur = n;
    for (uint32_t i = 0; i < count; i++) {
        if (!wave_pair(cur, &out[i], &cur)) return 0;
    }
    return cur == NOUN_ZERO;
}

static int wave_list(noun n, noun *out, uint32_t limit, uint32_t *count)
{
    noun cur = n;
    uint32_t used = 0;
    while (cur != NOUN_ZERO) {
        if (used == limit || !wave_pair(cur, &out[used], &cur)) return 0;
        used++;
    }
    *count = used;
    return 1;
}

static int wave_u(noun n, uint64_t max, uint32_t *out)
{
    if (!noun_is_direct(n) || direct_val(n) > max) return 0;
    *out = (uint32_t)direct_val(n);
    return 1;
}

static int wave_build_list(const noun *items, uint32_t count, noun *out)
{
    noun result = NOUN_ZERO;
    for (uint32_t i = count; i != 0; i--) {
        noun next;
        if (!alloc_cell_checked(items[i - 1], result, &next)) return 0;
        result = next;
    }
    *out = result;
    return 1;
}

static int wave_build_record(const noun *items, uint32_t count, noun *out)
{
    return wave_build_list(items, count, out);
}

static int wave_build_tagged(const char *tag, const char *schema,
                             const noun *fields, uint32_t count, noun *out)
{
    noun row[1 + RESOURCE_MAX_VALUES];
    if (count >= 1 + RESOURCE_MAX_VALUES) return 0;
    row[0] = wave_cord(schema);
    for (uint32_t i = 0; i < count; i++) row[i + 1] = fields[i];
    noun body;
    if (!wave_build_record(row, count + 1, &body)) return 0;
    noun result;
    if (!alloc_cell_checked(wave_cord(tag), body, &result)) return 0;
    *out = result;
    return 1;
}

static int wave_digest_atom(const uint8_t digest[32], noun *out)
{
    uint64_t limbs[4] = {0, 0, 0, 0};
    for (uint32_t i = 0; i < 4; i++)
        for (uint32_t j = 0; j < 8; j++)
            limbs[i] |= (uint64_t)digest[i * 8 + j] << (j * 8);
    return make_atom_checked(limbs, 4, out);
}

static int wave_capability_atom(SessionCapability value, noun *out)
{
    if (value <= 0x7FFFFFFFFFFFFFFFULL) {
        *out = direct(value);
        return 1;
    }
    uint64_t limbs[1] = {value};
    return make_atom_checked(limbs, 1, out);
}

static int wave_capability_value(noun value, SessionCapability *out)
{
    uint8_t bytes[8] = {0};
    if (!wave_atom_bytes(value, bytes, sizeof(bytes))) return 0;
    uint64_t result = 0;
    for (uint32_t i = 0; i < 8; i++) result |= (uint64_t)bytes[i] << (8u * i);
    if (result == 0) return 0;
    *out = result;
    return 1;
}

static int wave_u64(noun value, uint64_t max, uint64_t *out)
{
    uint8_t bytes[8] = {0};
    if (!out || !wave_atom_bytes(value, bytes, sizeof(bytes))) return 0;
    uint64_t result = 0;
    for (uint32_t i = 0; i < 8; i++)
        result |= (uint64_t)bytes[i] << (8u * i);
    if (result > max) return 0;
    *out = result;
    return 1;
}

static int wave_u64_atom(uint64_t value, noun *out)
{
    if (!out) return 0;
    if (value <= 0x7FFFFFFFFFFFFFFFULL) {
        *out = direct(value);
        return 1;
    }
    return make_atom_checked(&value, 1, out);
}

/* A slot whose next generation would be UINT64_MAX is retired.  This keeps
 * the maximum value from becoming a reusable live generation and makes every
 * stale handle fail closed even after repeated reset/reload cycles. */
static int wave_generation_advance(uint64_t current, uint64_t *next)
{
    if (!next || current == 0 || current >= UINT64_MAX - 1u) {
        if (next) *next = 0;
        return 0;
    }
    *next = current + 1u;
    return 1;
}

/* Result views are externally observable.  Unlike a slot generation, a
 * result generation may start at zero, but it must never wrap to a value that
 * could make a newer view indistinguishable from an older one. */
static int wave_result_generation_advance(uint64_t current, uint64_t *next)
{
    if (!next || current == UINT64_MAX) {
        if (next) *next = 0;
        return 0;
    }
    *next = current + 1u;
    return 1;
}

static int wave_domain_digest(ResourceRuntime *runtime, noun value,
                              const char *domain, uint8_t digest[32])
{
    const uint8_t *jammed;
    uint64_t jam_bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(value, &jammed, &jam_bytes, &budget) != 0
        || jam_bytes > RESOURCE_MAX_CORE_JAM_BYTES)
        return 0;
    size_t domain_bytes = wave_strlen(domain);
    if (domain_bytes + 1u + jam_bytes > RESOURCE_SAFETY_WORK_BYTES)
        return 0;
    uint8_t *preimage = (uint8_t *)runtime->workspace + RESOURCE_SAFETY_WORK_OFFSET;
    for (size_t i = 0; i < domain_bytes; i++) preimage[i] = (uint8_t)domain[i];
    preimage[domain_bytes] = 0;
    for (uint64_t i = 0; i < jam_bytes; i++) preimage[domain_bytes + 1u + i] = jammed[i];
    uint8_t raw[32];
    blake3_hash(preimage, domain_bytes + 1u + (size_t)jam_bytes, raw);
    for (uint32_t i = 0; i < 32; i++) digest[i] = raw[31u - i];
    return 1;
}

static int wave_cell_active(noun n)
{
    if (!noun_is_cell(n)) return 0;
    uintptr_t address = (uintptr_t)cell_ptr(n);
    uint64_t selector = heap_persist_selector();
    uintptr_t persist_base = (uintptr_t)(HEAP_BASE + selector * HEAP_PERSIST_HALF);
    uintptr_t persist_end = persist_base + heap_cells_used(HEAP_MODE_PERSIST) * sizeof(cell_t);
    uintptr_t scratch_base = (uintptr_t)HEAP_SCRATCH_BASE;
    uintptr_t scratch_end = scratch_base + heap_cells_used(HEAP_MODE_SCRATCH) * sizeof(cell_t);
    if ((address & (sizeof(uint64_t) - 1u)) != 0 || address > UINTPTR_MAX - sizeof(cell_t))
        return 0;
    return (address >= persist_base && address + sizeof(cell_t) <= persist_end)
        || (address >= scratch_base && address + sizeof(cell_t) <= scratch_end);
}

static int wave_safety_slot(uint32_t *keys, uint8_t *colors, uint32_t key,
                            uint32_t *slot, int *found)
{
    uint32_t h = key * 2654435761u;
    for (uint32_t probe = 0; probe < RESOURCE_MAX_NODES; probe++) {
        uint32_t i = (h + probe) & (RESOURCE_MAX_NODES - 1u);
        if (keys[i] == 0) {
            keys[i] = key;
            colors[i] = 0;
            *slot = i;
            *found = 0;
            return 1;
        }
        if (keys[i] == key) {
            *slot = i;
            *found = 1;
            return 1;
        }
    }
    return 0;
}

/* Iterative, color-marked DFS.  A gray edge is a cycle; a black edge is
 * ordinary noun sharing and is allowed.  Every indirect atom is resolved in
 * the atom store before any content operation. */
static int wave_safe_noun(ResourceRuntime *runtime, noun root)
{
    uint8_t *workspace = (uint8_t *)runtime->workspace;
    uint32_t *keys = (uint32_t *)(workspace + RESOURCE_SAFETY_SEEN_OFFSET);
    uint8_t *colors = workspace + RESOURCE_SAFETY_COLOR_OFFSET;
    noun *stack = (noun *)(workspace + RESOURCE_SAFETY_STACK_OFFSET);
    uint32_t *depths = (uint32_t *)(workspace + RESOURCE_SAFETY_DEPTH_OFFSET);
    uint8_t *phases = workspace + RESOURCE_SAFETY_WORK_OFFSET;
    wave_zero(keys, RESOURCE_MAX_NODES * sizeof(uint32_t));
    wave_zero(colors, RESOURCE_MAX_NODES);

    uint32_t top = 0, nodes = 0, cells = 0;
    stack[top] = root;
    depths[top] = 0;
    phases[top] = 0;
    top++;
    while (top != 0) {
        uint32_t index = top - 1u;
        noun n = stack[index];
        uint32_t depth = depths[index];
        if (!noun_is_cell(n)) {
            if (noun_is_indirect(n) && atom_store_get(indirect_hash(n)) == 0)
                return 0;
            if (++nodes > RESOURCE_MAX_NODES) return 0;
            top--;
            continue;
        }
        if (!wave_cell_active(n) || depth > RESOURCE_MAX_CUE_DEPTH)
            return 0;
        uint32_t slot;
        int found;
        if (!wave_safety_slot(keys, colors, cell_ptr(n), &slot, &found)) return 0;
        if (!found) {
            if (++nodes > RESOURCE_MAX_NODES || ++cells > RESOURCE_MAX_CELLS) return 0;
            colors[slot] = 1;
        } else if (colors[slot] == 2) {
            top--;
            continue;
        } else if (colors[slot] == 1 && phases[index] == 0) {
            return 0;
        }
        cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
        if (phases[index] == 0) {
            phases[index] = 1;
            if (top == RESOURCE_MAX_NODES) return 0;
            stack[top] = c->head;
            depths[top] = depth + 1u;
            phases[top] = 0;
            top++;
        } else if (phases[index] == 1) {
            phases[index] = 2;
            if (top == RESOURCE_MAX_NODES) return 0;
            stack[top] = c->tail;
            depths[top] = depth + 1u;
            phases[top] = 0;
            top++;
        } else {
            colors[slot] = 2;
            top--;
        }
    }
    return 1;
}

static int wave_identity(noun value, const uint8_t expected[32])
{
    uint8_t got[32];
    return wave_atom_bytes(value, got, sizeof(got))
        && wave_bytes_equal(got, expected, sizeof(got));
}

static int wave_forward_binding(noun value, uint32_t expected)
{
    noun fields[3];
    uint32_t count;
    return wave_list(value, fields, 3, &count) && count == 3
        && wave_atom_text(fields[0], RESOURCE_BINDING_NAMES[expected])
        && wave_atom_text(fields[1], RESOURCE_BINDING_TAGS[expected])
        && wave_atom_text(fields[2], RESOURCE_BINDING_SCHEMAS[expected]);
}

static int wave_record_validate(ResourceRuntime *runtime,
                                const SupervisorAdmissionEntry *entry,
                                noun record, uint32_t *catalog_index,
                                uint8_t admission_id[32])
{
    noun tag, body, fields[11];
    if (!wave_pair(record, &tag, &body)
        || !wave_atom_text(tag, RESOURCE_RECORD_TAG)
        || !wave_record(body, fields, 11)
        || !wave_atom_text(fields[0], RESOURCE_RECORD_SCHEMA)) {
        return 0;
    }
    uint8_t core_id[32];
    uint32_t index = 0xFFFFFFFFu;
    if (!wave_atom_bytes(fields[1], core_id, sizeof(core_id))) return 0;
    for (uint32_t i = 0; i < M38_RESOURCE_CORE_COUNT; i++)
        if (wave_bytes_equal(core_id, RESOURCE_CORE_IDS[i], sizeof(core_id))) index = i;
    if (index >= M38_RESOURCE_CORE_COUNT || !m38_resource_core_admitted(index)) return 0;
    uint32_t core_bytes;
    if (!wave_u(fields[2], RESOURCE_MAX_CORE_JAM_BYTES, &core_bytes)
        || core_bytes != entry->resource_core_jam_bytes
        || core_bytes == 0)
        return 0;
    uint8_t sha[32];
    sha256_hash(entry->resource_core_jam, entry->resource_core_jam_bytes, sha);
    if (!wave_identity(fields[3], sha)
        || !wave_identity(fields[4], RESOURCE_BATTERY_IDS[index])
        || !wave_identity(fields[5], RESOURCE_PAYLOAD_IDS[index])) return 0;
    noun bindings[15], supported[2], nested[13], limits[3];
    uint32_t count;
    if (!wave_list(fields[6], bindings, 15, &count) || count != 15) return 0;
    for (uint32_t i = 0; i < count; i++)
        if (!wave_forward_binding(bindings[i], i)) return 0;
    const M38ResourceCoreDescriptor *descriptor = m38_resource_core_descriptor(index);
    if (!descriptor || !wave_atom_text(fields[7], descriptor->profile_id)
        || !wave_list(fields[8], supported, 2, &count) || count != 2)
        return 0;
    for (uint32_t i = 0; i < 2; i++) {
        noun sf[3];
        if (!wave_record(supported[i], sf, 3)
            || !wave_atom_text(sf[0], i == 0 ? "BOOL" : "UINT16")
            || !wave_u(sf[1], 2, &core_bytes) || core_bytes != i + 1u
            || !wave_u(sf[2], i == 0 ? 1 : 65535, &core_bytes))
            return 0;
    }
    if (!wave_list(fields[9], nested, 13, &count) || count != 13) return 0;
    for (uint32_t i = 0; i < 13; i++)
        if (!wave_atom_text(nested[i], RESOURCE_NESTED_SCHEMAS[i])) return 0;
    if (!wave_list(fields[10], limits, 3, &count) || count != 3
        || !wave_u(limits[0], 2000000, &core_bytes) || core_bytes != 2000000u
        || !wave_u(limits[1], 128000, &core_bytes) || core_bytes != 128000u
        || !wave_u(limits[2], 1024, &core_bytes) || core_bytes != 1024u)
        return 0;

    const uint8_t *canonical;
    uint64_t canonical_bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(record, &canonical, &canonical_bytes, &budget) != 0
        || canonical_bytes > RESOURCE_MAX_RECORD_JAM_BYTES)
        return 0;
    size_t domain_bytes = wave_strlen(RESOURCE_ADMISSION_DOMAIN);
    if (domain_bytes + canonical_bytes > RESOURCE_SAFETY_WORK_BYTES) return 0;
    uint8_t *preimage = (uint8_t *)runtime->workspace + RESOURCE_SAFETY_WORK_OFFSET;
    for (size_t i = 0; i < domain_bytes; i++) preimage[i] = (uint8_t)RESOURCE_ADMISSION_DOMAIN[i];
    for (uint64_t i = 0; i < canonical_bytes; i++) preimage[domain_bytes + i] = canonical[i];
    sha256_hash(preimage, domain_bytes + (size_t)canonical_bytes, admission_id);
    if (!wave_bytes_equal(admission_id, RESOURCE_ADMISSION_IDS[index], 32)) return 0;
    *catalog_index = index;
    return 1;
}

static WavePlanType *wave_plan_type(WavePlan *plan, uint32_t id)
{
    return id >= 1 && id <= plan->type_count ? &plan->types[id - 1u] : 0;
}

static int wave_parse_plan(noun core, WavePlan *out)
{
    noun formula, payload, payload_tag, payload_body, pf[2], semantic[5];
    noun types[RESOURCE_MAX_PLAN_TYPES], instances[RESOURCE_MAX_PLAN_INSTANCES];
    uint32_t type_count, instance_count;
    if (!wave_pair(core, &formula, &payload)
        || !wave_pair(payload, &payload_tag, &payload_body)
        || !wave_atom_text(payload_tag, "m38-d0-r2-resource-payload")
        || !wave_record(payload_body, pf, 2)
        || !wave_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
        || !wave_record(pf[1], semantic, 5)
        || !wave_list(semantic[0], types, RESOURCE_MAX_PLAN_TYPES, &type_count)
        || !wave_list(semantic[1], instances, RESOURCE_MAX_PLAN_INSTANCES, &instance_count)
        || type_count == 0 || instance_count == 0)
        return 0;
    WavePlan plan = {0};
    plan.type_count = type_count;
    plan.instance_count = instance_count;
    plan.formula = formula;
    plan.payload = payload;
    for (uint32_t i = 0; i < type_count; i++) {
        noun tf[6], events[RESOURCE_MAX_PLAN_EVENTS], values[RESOURCE_MAX_PLAN_VALUES];
        noun states[RESOURCE_MAX_PLAN_STATES];
        uint32_t event_count, value_count, state_count;
        WavePlanType *type = &plan.types[i];
        if (!wave_record(types[i], tf, 6)
            || !wave_u(tf[0], RESOURCE_MAX_PLAN_TYPES, &type->id)
            || type->id != i + 1u
            || !wave_list(tf[1], events, RESOURCE_MAX_PLAN_EVENTS, &event_count)
            || !wave_list(tf[2], values, RESOURCE_MAX_PLAN_VALUES, &value_count)
            || !wave_list(tf[3], states, RESOURCE_MAX_PLAN_STATES, &state_count)
            || value_count == 0 || state_count == 0)
            return 0;
        type->event_count = event_count;
        for (uint32_t j = 0; j < event_count; j++) {
            noun ef[3];
            noun event_values[RESOURCE_MAX_PLAN_VALUES];
            uint32_t direction, event_value_count;
            if (!wave_record(events[j], ef, 3)
                || !wave_u(ef[0], 0xFFFF, &type->event_ids[j])
                || type->event_ids[j] == 0
                || !wave_u(ef[1], 2, &direction)
                || !wave_list(ef[2], event_values, RESOURCE_MAX_PLAN_VALUES,
                              &event_value_count))
                return 0;
            type->event_value_counts[j] = event_value_count;
            for (uint32_t k = 0; k < event_value_count; k++)
                if (!wave_u(event_values[k], RESOURCE_MAX_PLAN_VALUES,
                            &type->event_value_ids[j][k])
                    || type->event_value_ids[j][k] == 0)
                    return 0;
        }
        type->value_count = value_count;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[4];
            if (!wave_record(values[j], vf, 4)
                || !wave_u(vf[0], RESOURCE_MAX_PLAN_VALUES, &type->value_ids[j])
                || type->value_ids[j] != j + 1u
                || !wave_u(vf[2], 2, &type->value_types[j])
                || (type->value_types[j] != 1 && type->value_types[j] != 2)
                || !wave_u(vf[3], type->value_types[j] == 1 ? 1 : 65535,
                           &type->value_initials[j]))
                return 0;
        }
        type->state_count = state_count;
        uint32_t initial_states = 0;
        for (uint32_t j = 0; j < state_count; j++) {
            noun sf[3];
            uint32_t id, initial;
            if (!wave_record(states[j], sf, 3)
                || !wave_u(sf[0], RESOURCE_MAX_PLAN_STATES, &id)
                || id != j + 1u || !wave_u(sf[1], 1, &initial))
                return 0;
            if (initial != 0) {
                initial_states++;
                type->state_id = id;
            }
        }
        if (initial_states != 1 || type->state_id == 0) return 0;
    }
    for (uint32_t i = 0; i < instance_count; i++) {
        noun inf[2];
        uint32_t id, type_id;
        if (!wave_record(instances[i], inf, 2)
            || !wave_u(inf[0], RESOURCE_MAX_PLAN_INSTANCES, &id)
            || id != i + 1u || !wave_u(inf[1], RESOURCE_MAX_PLAN_TYPES, &type_id)
            || wave_plan_type(&plan, type_id) == 0)
            return 0;
        plan.instance_types[i] = type_id;
    }
    *out = plan;
    return 1;
}

static int wave_core_validate(ResourceRuntime *runtime, noun core,
                              const uint8_t expected_id[32],
                              const uint8_t expected_battery[32],
                              const uint8_t expected_payload[32],
                              const uint8_t *expected_jam, size_t expected_jam_bytes,
                              WavePlan *plan)
{
    noun formula, payload;
    if (!wave_pair(core, &formula, &payload) || !wave_parse_plan(core, plan)) return 0;
    uint8_t digest[32];
    if (!wave_domain_digest(runtime, formula, RESOURCE_FORMULA_DOMAIN, digest)
        || !wave_bytes_equal(digest, expected_battery, sizeof(digest))
        || !wave_domain_digest(runtime, payload, RESOURCE_PAYLOAD_DOMAIN, digest)
        || !wave_bytes_equal(digest, expected_payload, sizeof(digest))
        || !wave_domain_digest(runtime, core, RESOURCE_CORE_DOMAIN, digest)
        || !wave_bytes_equal(digest, expected_id, sizeof(digest))) return 0;
    const uint8_t *canonical;
    uint64_t canonical_bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    int jam_status = jam_encode_bytes_identity_bounded(core, &canonical,
                                                       &canonical_bytes, &budget);
    return jam_status == 0 && canonical_bytes == expected_jam_bytes
        && wave_bytes_equal(canonical, expected_jam, expected_jam_bytes);
}

typedef struct WavePreflightEntry {
    uint32_t catalog_index;
    uint32_t core_jam_bytes;
    uint8_t core_id[32];
    uint8_t battery_id[32];
    uint8_t payload_id[32];
    uint8_t admission_id[32];
    WavePlan plan;
} WavePreflightEntry;

typedef struct WaveRootCopies {
    noun catalog[RESOURCE_MAX_ADMISSION_ENTRIES];
    noun cache_core[RESOURCE_MAX_ADMISSION_ENTRIES];
    noun cache_formula[RESOURCE_MAX_ADMISSION_ENTRIES];
    noun cache_payload[RESOURCE_MAX_ADMISSION_ENTRIES];
    noun state[RESOURCE_MAX_LIVE_HANDLES];
    noun snapshot[RESOURCE_MAX_LIVE_HANDLES];
    noun handle[RESOURCE_MAX_LIVE_HANDLES];
    noun primary;
    noun refusal;
} WaveRootCopies;

static int wave_runtime_valid(ResourceRuntime *runtime)
{
    return runtime != 0 && runtime == g_wave_runtime_lease
        && runtime->magic == RESOURCE_RUNTIME_MAGIC
        && runtime->state != 0;
}

static int wave_session_valid(ResourceSession *session)
{
    return session != 0 && session->magic == RESOURCE_SESSION_MAGIC
        && session->runtime == g_wave_runtime_lease
        && session->state != 0;
}

static void wave_broker_release(ResourceRuntime *runtime)
{
    runtime->broker_owner = 0;
    runtime->state = 2;
}

static M38Status wave_fault_status(M38FaultPoint fault)
{
    switch (fault) {
    case M38_FAULT_BROKER_BEGIN: return M38_STATUS_BROKER_BEGIN;
    case M38_FAULT_CUE_CACHE_INSERT: return M38_STATUS_CUE_CACHE_INSERT;
    case M38_FAULT_SLOT_PUBLICATION: return M38_STATUS_SLOT_PUBLICATION;
    case M38_FAULT_EVALUATOR_ABORT: return M38_STATUS_EVALUATOR_ABORT;
    case M38_FAULT_ATOM_RESULT_STAGING: return M38_STATUS_ATOM_RESULT_STAGING;
    case M38_FAULT_COLLECTIVE_COMMIT: return M38_STATUS_COLLECTIVE_COMMIT;
    case M38_FAULT_RESTORE_COMMIT: return M38_STATUS_RESTORE_COMMIT;
    default: return M38_STATUS_INTERNAL;
    }
}

static M38Status wave_take_fault(ResourceRuntime *runtime, M38FaultPoint point)
{
    if (runtime->next_fault == point) {
        runtime->next_fault = M38_FAULT_NONE;
        return wave_fault_status(point);
    }
    return M38_STATUS_OK;
}

static int wave_copy_root(noun source, noun *destination)
{
    if (source == NOUN_ZERO) {
        *destination = NOUN_ZERO;
        return 1;
    }
    return noun_copy_checked(source, destination);
}

static int wave_copy_registered_roots(ResourceRuntime *runtime,
                                      WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS])
{
    int previous_mode = heap_get_mode();
    wave_zero(copies, sizeof(WaveRootCopies) * RESOURCE_MAX_REGISTERED_SESSIONS);
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(session->catalog[j].core, &copies[i].catalog[j])) goto fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(session->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(session->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(session->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (!wave_copy_root(session->slots[j].handle_root, &copies[i].handle[j])) goto fail;
            if (!wave_copy_root(session->slots[j].state_root, &copies[i].state[j])) goto fail;
            if (!wave_copy_root(session->slots[j].snapshot_root, &copies[i].snapshot[j])) goto fail;
        }
        if (!wave_copy_root(session->primary_root, &copies[i].primary)) goto fail;
        if (!wave_copy_root(session->refusal_root, &copies[i].refusal)) goto fail;
    }
    heap_persist_commit_tx();
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            session->catalog[j].core = copies[i].catalog[j];
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            session->cache[j].core = copies[i].cache_core[j];
            session->cache[j].plan.formula = copies[i].cache_formula[j];
            session->cache[j].plan.payload = copies[i].cache_payload[j];
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            session->slots[j].handle_root = copies[i].handle[j];
            session->slots[j].state_root = copies[i].state[j];
            session->slots[j].snapshot_root = copies[i].snapshot[j];
        }
        session->primary_root = copies[i].primary;
        session->refusal_root = copies[i].refusal;
    }
    runtime->promoted_root_count++;
    heap_set_mode(previous_mode);
    return 1;
fail:
    heap_persist_abort_tx();
    heap_set_mode(previous_mode);
    return 0;
}

static int wave_preflight_entry(ResourceRuntime *runtime,
                                const SupervisorAdmissionEntry *entry,
                                WavePreflightEntry *out)
{
    noun record;
    uint32_t index;
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (cue_bounded_bytes(entry->record_jam, entry->record_jam_bytes,
                          &cue_i2_limits, HEAP_MODE_SCRATCH, &record) != CUE_BOUNDED_OK)
        return 0;
    if (!wave_record_validate(runtime, entry, record, &index, out->admission_id)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    const uint8_t *canonical;
    uint64_t canonical_bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(record, &canonical, &canonical_bytes, &budget) != 0
        || canonical_bytes != entry->record_jam_bytes
        || !wave_bytes_equal(canonical, entry->record_jam, canonical_bytes)) {
        noun_tx_abort();
        return 0;
    }
    noun_tx_abort();

    noun core;
    if (cue_bounded_bytes(entry->resource_core_jam, entry->resource_core_jam_bytes,
                          &cue_i2_limits, HEAP_MODE_SCRATCH, &core) != CUE_BOUNDED_OK)
        return 0;
    if (!wave_safe_noun(runtime, core)
        || !wave_core_validate(runtime, core, RESOURCE_CORE_IDS[index],
                               RESOURCE_BATTERY_IDS[index], RESOURCE_PAYLOAD_IDS[index],
                               entry->resource_core_jam, entry->resource_core_jam_bytes,
                               &out->plan)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    out->catalog_index = index;
    out->core_jam_bytes = (uint32_t)entry->resource_core_jam_bytes;
    for (uint32_t i = 0; i < 32; i++) {
        out->core_id[i] = RESOURCE_CORE_IDS[index][i];
        out->battery_id[i] = RESOURCE_BATTERY_IDS[index][i];
        out->payload_id[i] = RESOURCE_PAYLOAD_IDS[index][i];
    }
    noun_tx_abort();
    return 1;
}

static M38Status wave_catalog_preflight(ResourceRuntime *runtime,
                                        const SupervisorAdmissionCatalog *catalog,
                                        WavePreflightEntry out[RESOURCE_MAX_ADMISSION_ENTRIES])
{
    if (!catalog || !catalog->entries || catalog->entry_count == 0
        || catalog->entry_count > RESOURCE_MAX_ADMISSION_ENTRIES)
        return M38_STATUS_CATALOG_INVALID;
    for (uint32_t i = 0; i < catalog->entry_count; i++) {
        const SupervisorAdmissionEntry *entry = &catalog->entries[i];
        if (!entry->record_jam || !entry->resource_core_jam
            || entry->record_jam_bytes == 0 || entry->resource_core_jam_bytes == 0
            || entry->record_jam_bytes > RESOURCE_MAX_RECORD_JAM_BYTES
            || entry->resource_core_jam_bytes > RESOURCE_MAX_CORE_JAM_BYTES)
            return M38_STATUS_CATALOG_BOUNDS;
        if (!wave_preflight_entry(runtime, entry, &out[i]))
            return M38_STATUS_CATALOG_INVALID;
        for (uint32_t j = 0; j < i; j++) {
            if (out[j].catalog_index == out[i].catalog_index)
                return M38_STATUS_CATALOG_DUPLICATE;
        }
    }
    return M38_STATUS_OK;
}

size_t m38_resource_runtime_storage_bytes(void) { return RESOURCE_RUNTIME_BYTES; }
size_t m38_resource_runtime_control_storage_bytes(void) { return RESOURCE_RUNTIME_CONTROL_BYTES; }
size_t m38_resource_runtime_init_workspace_bytes(void) { return RESOURCE_RUNTIME_WORKSPACE_BYTES; }
size_t m38_resource_runtime_storage_alignment(void) { return RESOURCE_STORAGE_ALIGNMENT; }
size_t m38_resource_session_storage_bytes(void) { return RESOURCE_SESSION_BYTES; }
size_t m38_resource_session_storage_alignment(void) { return RESOURCE_STORAGE_ALIGNMENT; }

M38Status m38_supervisor_admission_catalog_make(
    SupervisorAdmissionCatalog *out_catalog,
    const SupervisorAdmissionEntry *entries, uint32_t entry_count)
{
    if (!out_catalog) return M38_STATUS_INVALID_ARGUMENT;
    out_catalog->entries = 0;
    out_catalog->entry_count = 0;
    if (!entries || entry_count == 0 || entry_count > RESOURCE_MAX_ADMISSION_ENTRIES)
        return M38_STATUS_CATALOG_INVALID;
    if (wave_range_overlap(out_catalog, sizeof(*out_catalog), entries,
                           entry_count * sizeof(*entries)))
        return M38_STATUS_STORAGE_OVERLAP;
    for (uint32_t i = 0; i < entry_count; i++) {
        if (!entries[i].record_jam || !entries[i].resource_core_jam
            || entries[i].record_jam_bytes == 0 || entries[i].resource_core_jam_bytes == 0)
            return M38_STATUS_CATALOG_BOUNDS;
        if (entries[i].record_jam_bytes > RESOURCE_MAX_RECORD_JAM_BYTES
            || entries[i].resource_core_jam_bytes > RESOURCE_MAX_CORE_JAM_BYTES)
            return M38_STATUS_CATALOG_BOUNDS;
        if (wave_range_overlap(out_catalog, sizeof(*out_catalog),
                               entries[i].record_jam, entries[i].record_jam_bytes)
            || wave_range_overlap(out_catalog, sizeof(*out_catalog),
                                  entries[i].resource_core_jam,
                                  entries[i].resource_core_jam_bytes))
            return M38_STATUS_STORAGE_OVERLAP;
        if (wave_range_overlap(entries, entry_count * sizeof(*entries),
                               entries[i].record_jam, entries[i].record_jam_bytes)
            || wave_range_overlap(entries, entry_count * sizeof(*entries),
                                  entries[i].resource_core_jam,
                                  entries[i].resource_core_jam_bytes))
            return M38_STATUS_STORAGE_OVERLAP;
        for (uint32_t j = 0; j < i; j++) {
            if (wave_range_overlap(entries[i].record_jam, entries[i].record_jam_bytes,
                                   entries[j].record_jam, entries[j].record_jam_bytes)
                || wave_range_overlap(entries[i].record_jam, entries[i].record_jam_bytes,
                                      entries[j].resource_core_jam,
                                      entries[j].resource_core_jam_bytes)
                || wave_range_overlap(entries[i].resource_core_jam,
                                      entries[i].resource_core_jam_bytes,
                                      entries[j].record_jam,
                                      entries[j].record_jam_bytes)
                || wave_range_overlap(entries[i].resource_core_jam,
                                      entries[i].resource_core_jam_bytes,
                                      entries[j].resource_core_jam,
                                      entries[j].resource_core_jam_bytes))
                return M38_STATUS_STORAGE_OVERLAP;
            if (entries[i].resource_core_jam_bytes == entries[j].resource_core_jam_bytes
                && wave_bytes_equal(entries[i].resource_core_jam,
                                     entries[j].resource_core_jam,
                                     entries[i].resource_core_jam_bytes))
                return M38_STATUS_CATALOG_DUPLICATE;
        }
    }
    out_catalog->entries = entries;
    out_catalog->entry_count = entry_count;
    return M38_STATUS_OK;
}

static void wave_apply_root_copies(ResourceRuntime *runtime,
                                   WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS])
{
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            session->catalog[j].core = copies[i].catalog[j];
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            session->cache[j].core = copies[i].cache_core[j];
            session->cache[j].plan.formula = copies[i].cache_formula[j];
            session->cache[j].plan.payload = copies[i].cache_payload[j];
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            session->slots[j].handle_root = copies[i].handle[j];
            session->slots[j].state_root = copies[i].state[j];
            session->slots[j].snapshot_root = copies[i].snapshot[j];
        }
        session->primary_root = copies[i].primary;
        session->refusal_root = copies[i].refusal;
    }
}

static int wave_promote_registration(ResourceRuntime *runtime,
                                     const SupervisorAdmissionCatalog *catalog,
                                     const WavePreflightEntry pre[RESOURCE_MAX_ADMISSION_ENTRIES],
                                     noun new_cores[RESOURCE_MAX_ADMISSION_ENTRIES])
{
    WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS];
    wave_zero(copies, sizeof(copies));
    wave_zero(new_cores, sizeof(noun) * RESOURCE_MAX_ADMISSION_ENTRIES);
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(session->catalog[j].core, &copies[i].catalog[j])) goto fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(session->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(session->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(session->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (!wave_copy_root(session->slots[j].handle_root, &copies[i].handle[j])) goto fail;
            if (!wave_copy_root(session->slots[j].state_root, &copies[i].state[j])) goto fail;
            if (!wave_copy_root(session->slots[j].snapshot_root, &copies[i].snapshot[j])) goto fail;
        }
        if (!wave_copy_root(session->primary_root, &copies[i].primary)) goto fail;
        if (!wave_copy_root(session->refusal_root, &copies[i].refusal)) goto fail;
    }
    for (uint32_t i = 0; i < catalog->entry_count; i++) {
        if (cue_bounded_bytes(catalog->entries[i].resource_core_jam,
                              catalog->entries[i].resource_core_jam_bytes,
                              &cue_i2_limits, HEAP_MODE_PERSIST, &new_cores[i]) != CUE_BOUNDED_OK)
            goto fail;
        WavePlan persisted_plan;
        if (!wave_safe_noun(runtime, new_cores[i])
            || !wave_core_validate(runtime, new_cores[i], RESOURCE_CORE_IDS[pre[i].catalog_index],
                                   RESOURCE_BATTERY_IDS[pre[i].catalog_index],
                                   RESOURCE_PAYLOAD_IDS[pre[i].catalog_index],
                                   catalog->entries[i].resource_core_jam,
                                   catalog->entries[i].resource_core_jam_bytes,
                                   &persisted_plan)) {
            if (noun_tx_active()) noun_tx_abort();
            goto fail;
        }
        noun_tx_commit();
    }
    heap_persist_commit_tx();
    wave_apply_root_copies(runtime, copies);
    runtime->promoted_root_count++;
    heap_set_mode(HEAP_MODE_SCRATCH);
    return 1;
fail:
    if (noun_tx_active()) noun_tx_abort();
    heap_persist_abort_tx();
    heap_set_mode(HEAP_MODE_SCRATCH);
    return 0;
}

static int wave_catalog_aliases_storage(const SupervisorAdmissionCatalog *catalog,
                                        const void *storage, size_t storage_bytes,
                                        ResourceRuntime *runtime)
{
    if (wave_range_overlap(catalog, sizeof(*catalog), storage, storage_bytes)
        || wave_range_overlap(catalog->entries,
                              catalog->entry_count * sizeof(*catalog->entries),
                              storage, storage_bytes)
        || wave_range_overlap(catalog, sizeof(*catalog), runtime->control_storage,
                              RESOURCE_RUNTIME_CONTROL_BYTES)
        || wave_range_overlap(catalog, sizeof(*catalog), runtime->workspace,
                              RESOURCE_RUNTIME_WORKSPACE_BYTES)
        || wave_range_overlap(catalog->entries,
                              catalog->entry_count * sizeof(*catalog->entries),
                              runtime->control_storage, RESOURCE_RUNTIME_CONTROL_BYTES)
        || wave_range_overlap(catalog->entries,
                              catalog->entry_count * sizeof(*catalog->entries),
                              runtime->workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES))
        return 1;
    for (uint32_t i = 0; i < catalog->entry_count; i++)
        if (wave_range_overlap(catalog->entries[i].record_jam,
                               catalog->entries[i].record_jam_bytes,
                               storage, storage_bytes)
            || wave_range_overlap(catalog->entries[i].resource_core_jam,
                                  catalog->entries[i].resource_core_jam_bytes,
                                  storage, storage_bytes)
            || wave_range_overlap(catalog->entries[i].record_jam,
                                  catalog->entries[i].record_jam_bytes,
                                  runtime->control_storage, RESOURCE_RUNTIME_CONTROL_BYTES)
            || wave_range_overlap(catalog->entries[i].resource_core_jam,
                                  catalog->entries[i].resource_core_jam_bytes,
                                  runtime->control_storage, RESOURCE_RUNTIME_CONTROL_BYTES)
            || wave_range_overlap(catalog->entries[i].record_jam,
                                  catalog->entries[i].record_jam_bytes,
                                  runtime->workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES)
            || wave_range_overlap(catalog->entries[i].resource_core_jam,
                                  catalog->entries[i].resource_core_jam_bytes,
                                  runtime->workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES))
            return 1;
    return 0;
}

M38Status m38_resource_session_init(
    ResourceRuntime *runtime,
    void *storage, size_t storage_bytes,
    const SupervisorAdmissionCatalog *catalog,
    ResourceSession **out_session, SessionCapability *out_capability)
{
    if (!out_session || !out_capability) return M38_STATUS_INVALID_ARGUMENT;
    *out_session = 0;
    *out_capability = 0;
    if (!runtime || !storage || !catalog) return M38_STATUS_INVALID_ARGUMENT;
    if (wave_range_overlap(out_session, sizeof(*out_session),
                           out_capability, sizeof(*out_capability))
        || wave_range_overlap(out_session, sizeof(*out_session), storage, storage_bytes)
        || wave_range_overlap(out_capability, sizeof(*out_capability), storage, storage_bytes))
        return M38_STATUS_STORAGE_OVERLAP;
    if (!wave_runtime_valid(runtime)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (storage_bytes < RESOURCE_SESSION_BYTES) return M38_STATUS_STORAGE_TOO_SMALL;
    if (((uintptr_t)storage & (RESOURCE_STORAGE_ALIGNMENT - 1u)) != 0)
        return M38_STATUS_STORAGE_MISALIGNED;
    if (catalog->entry_count == 0 || catalog->entry_count > RESOURCE_MAX_ADMISSION_ENTRIES
        || !catalog->entries)
        return M38_STATUS_CATALOG_INVALID;
    if (wave_catalog_aliases_storage(catalog, storage, RESOURCE_SESSION_BYTES, runtime))
        return M38_STATUS_STORAGE_OVERLAP;
    if (wave_range_overlap(storage, RESOURCE_SESSION_BYTES,
                           runtime->control_storage, RESOURCE_RUNTIME_CONTROL_BYTES)
        || wave_range_overlap(storage, RESOURCE_SESSION_BYTES,
                              runtime->workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES))
        return M38_STATUS_STORAGE_OVERLAP;
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *live = runtime->sessions[i];
        if (live && live->state == 1
            && wave_range_overlap(live, RESOURCE_SESSION_BYTES, storage, RESOURCE_SESSION_BYTES))
            return M38_STATUS_SESSION_BUSY;
    }
    if (runtime->broker_owner != 0 || runtime->state == 3)
        return M38_STATUS_RUNTIME_BUSY;
    if (runtime->session_count >= RESOURCE_MAX_REGISTERED_SESSIONS)
        return M38_STATUS_SESSION_REGISTRY_FULL;
    runtime->broker_owner = 3;
    runtime->state = 4;

    WavePreflightEntry pre[RESOURCE_MAX_ADMISSION_ENTRIES] = {{0}};
    M38Status preflight = wave_catalog_preflight(runtime, catalog, pre);
    if (preflight != M38_STATUS_OK) {
        wave_broker_release(runtime);
        return preflight;
    }
    if (runtime->next_capability == UINT64_MAX) {
        wave_broker_release(runtime);
        return M38_STATUS_CAPABILITY_EXHAUSTED;
    }
    SessionCapability capability = runtime->next_capability + 1u;
    /* Issuance is staged before the fallible collective copy.  A failed
     * registration therefore consumes the capability and it can never wrap
     * or be reused. */
    runtime->next_capability = capability;
    noun new_cores[RESOURCE_MAX_ADMISSION_ENTRIES];
    if (!wave_promote_registration(runtime, catalog, pre, new_cores)) {
        wave_broker_release(runtime);
        return M38_STATUS_COLLECTIVE_COMMIT;
    }
    uint32_t registry_index = 0;
    while (registry_index < RESOURCE_MAX_REGISTERED_SESSIONS
           && runtime->sessions[registry_index] != 0)
        registry_index++;
    if (registry_index >= RESOURCE_MAX_REGISTERED_SESSIONS) {
        wave_broker_release(runtime);
        return M38_STATUS_SESSION_REGISTRY_FULL;
    }
    ResourceSession *session = (ResourceSession *)storage;
    wave_zero(session, sizeof(*session));
    session->magic = RESOURCE_SESSION_MAGIC;
    session->state = 1;
    session->registry_index = (uint8_t)registry_index;
    session->runtime = runtime;
    session->capability = capability;
    session->session_transaction_id = ++runtime->broker_transaction_id;
    for (uint32_t i = 0; i < catalog->entry_count; i++) {
        WaveCatalogCopy *copy = &session->catalog[pre[i].catalog_index];
        copy->valid = 1;
        copy->core = new_cores[i];
        copy->core_jam_bytes = pre[i].core_jam_bytes;
        wave_copy(copy->core_jam, catalog->entries[i].resource_core_jam, pre[i].core_jam_bytes);
        for (uint32_t j = 0; j < 32; j++) copy->core_id[j] = pre[i].core_id[j];
        for (uint32_t j = 0; j < 32; j++) copy->battery_id[j] = pre[i].battery_id[j];
        for (uint32_t j = 0; j < 32; j++) copy->payload_id[j] = pre[i].payload_id[j];
        for (uint32_t j = 0; j < 32; j++) copy->admission_id[j] = pre[i].admission_id[j];
        if (!wave_parse_plan(copy->core, &session->cache[pre[i].catalog_index].plan)) {
            /* The same core was validated before commit; this is an internal
             * invariant failure, and no session has been published yet. */
            wave_broker_release(runtime);
            return M38_STATUS_INTERNAL;
        }
    }
    for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++)
        session->slots[i].generation = 1;
    runtime->sessions[registry_index] = session;
    runtime->session_count++;
    wave_broker_release(runtime);
    *out_session = session;
    *out_capability = capability;
    return M38_STATUS_OK;
}

M38Status m38_resource_runtime_init(
    void *control_storage, size_t control_storage_bytes,
    void *init_workspace, size_t init_workspace_bytes,
    ResourceRuntime **out_runtime)
{
    if (!out_runtime) return M38_STATUS_INVALID_ARGUMENT;
    *out_runtime = 0;
    if (g_wave_runtime_lease) return M38_STATUS_RUNTIME_ALREADY_INITIALIZED;
    if (!control_storage || !init_workspace) return M38_STATUS_INVALID_ARGUMENT;
    if (control_storage_bytes < RESOURCE_RUNTIME_CONTROL_BYTES
        || init_workspace_bytes < RESOURCE_RUNTIME_WORKSPACE_BYTES)
        return M38_STATUS_STORAGE_TOO_SMALL;
    if (((uintptr_t)control_storage & (RESOURCE_STORAGE_ALIGNMENT - 1u)) != 0
        || ((uintptr_t)init_workspace & (RESOURCE_STORAGE_ALIGNMENT - 1u)) != 0)
        return M38_STATUS_STORAGE_MISALIGNED;
    if (wave_range_overlap(control_storage, RESOURCE_RUNTIME_CONTROL_BYTES,
                           init_workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES)
        || wave_range_overlap(out_runtime, sizeof(*out_runtime),
                              control_storage, RESOURCE_RUNTIME_CONTROL_BYTES)
        || wave_range_overlap(out_runtime, sizeof(*out_runtime),
                              init_workspace, RESOURCE_RUNTIME_WORKSPACE_BYTES))
        return M38_STATUS_STORAGE_OVERLAP;
    ResourceRuntime *runtime = (ResourceRuntime *)control_storage;
    wave_zero(runtime, sizeof(*runtime));
    runtime->magic = RESOURCE_RUNTIME_MAGIC;
    runtime->state = 1;
    runtime->control_storage = control_storage;
    runtime->workspace = init_workspace;
    runtime->next_capability = 0;
    g_wave_runtime_lease = runtime;
    runtime->state = 2;
    *out_runtime = runtime;
    return M38_STATUS_OK;
}

void m38_resource_test_fail_next(ResourceRuntime *runtime, M38FaultPoint fault)
{
    if (wave_runtime_valid(runtime)) runtime->next_fault = fault;
}

static int wave_handle_build(const ResourceSession *session, uint32_t slot,
                             uint64_t generation, uint32_t catalog_index,
                             noun *out)
{
    noun fields[4], admission;
    if (catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !wave_digest_atom(session->catalog[catalog_index].admission_id, &admission))
        return 0;
    if (!wave_capability_atom(session->capability, &fields[0])
        || !wave_u64_atom(generation, &fields[2])) return 0;
    fields[1] = direct(slot);
    fields[3] = admission;
    return wave_build_record(fields, 4, out);
}

static int wave_value_build(uint32_t id, uint32_t type, uint32_t value, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(value)};
    return wave_build_tagged(RESOURCE_VALUE_TAG, RESOURCE_VALUE_SCHEMA, fields, 3, out);
}

static int wave_state_build(const ResourceSession *session, const WavePlan *plan,
                            uint32_t catalog_index, const WaveSlot *slot,
                            noun *out)
{
    noun instances[RESOURCE_MAX_PLAN_INSTANCES];
    for (uint32_t i = plan->instance_count; i != 0; i--) {
        uint32_t instance = i - 1u;
        WavePlanType *type = (WavePlanType *)&plan->types[plan->instance_types[instance] - 1u];
        noun values[RESOURCE_MAX_PLAN_VALUES];
        for (uint32_t j = type->value_count; j != 0; j--) {
            uint32_t value = j - 1u;
            if (!wave_value_build(type->value_ids[value], type->value_types[value],
                                  slot->state_values[instance][value], &values[value]))
                return 0;
        }
        noun value_list;
        if (!wave_build_list(values, type->value_count, &value_list)) return 0;
        noun instance_fields[3] = {direct(instance + 1u), direct(slot->state_ids[instance]), value_list};
        if (!wave_build_tagged(RESOURCE_INSTANCE_TAG, RESOURCE_INSTANCE_SCHEMA,
                               instance_fields, 3, &instances[instance]))
            return 0;
    }
    noun instance_list;
    if (!wave_build_list(instances, plan->instance_count, &instance_list)) return 0;
    noun admission;
    if (!wave_digest_atom(session->catalog[catalog_index].admission_id, &admission)) return 0;
    noun fields[3] = {admission, wave_cord(RESOURCE_PROFILE_ID), instance_list};
    return wave_build_tagged(RESOURCE_STATE_TAG, RESOURCE_STATE_SCHEMA, fields, 3, out);
}

static int wave_zero_state_build(noun *out)
{
    noun fields[1] = {NOUN_ZERO};
    return wave_build_tagged(RESOURCE_ZERO_TAG, RESOURCE_ZERO_SCHEMA, fields, 1, out);
}

static int wave_refusal_build(uint32_t reason, noun *out)
{
    noun reason_fields[2] = {direct(reason), wave_cord("resource refusal")};
    noun reason_noun;
    noun zero_state;
    noun body_fields[2];
    if (!wave_build_tagged(RESOURCE_REFUSAL_TAG, RESOURCE_REFUSAL_SCHEMA,
                           reason_fields, 2, &reason_noun)
        || !wave_zero_state_build(&zero_state))
        return 0;
    body_fields[0] = reason_noun;
    body_fields[1] = zero_state;
    noun body;
    if (!wave_build_record(body_fields, 2, &body)) return 0;
    noun result_fields[2] = {direct(RESOURCE_WIRE_REFUSE), body};
    return wave_build_tagged(RESOURCE_RESULT_TAG, RESOURCE_RESULT_SCHEMA,
                              result_fields, 2, out);
}

static int wave_empty_effects(noun *out)
{
    noun fields[1] = {NOUN_ZERO};
    return wave_build_tagged(RESOURCE_EFFECTS_TAG, RESOURCE_EFFECTS_SCHEMA, fields, 1, out);
}

static int wave_empty_observations(noun *out)
{
    noun fields[1] = {NOUN_ZERO};
    return wave_build_tagged(RESOURCE_OBSERVATIONS_TAG, RESOURCE_OBSERVATIONS_SCHEMA, fields, 1, out);
}

static int wave_metrics_build(uint64_t ops, uint64_t cells, uint64_t stack, noun *out)
{
    noun fields[5] = {direct(ops), direct(cells), direct(stack), direct(0), direct(0)};
    return wave_build_tagged(RESOURCE_METRICS_TAG, RESOURCE_METRICS_SCHEMA, fields, 5, out);
}

static int wave_result_build(uint32_t status, noun body, noun *out)
{
    noun fields[2] = {direct(status), body};
    return wave_build_tagged(RESOURCE_RESULT_TAG, RESOURCE_RESULT_SCHEMA, fields, 2, out);
}

static int wave_handle_decode(const ResourceSession *session, noun value,
                              uint32_t *slot_out)
{
    noun fields[4];
    uint32_t slot;
    uint64_t generation;
    SessionCapability capability;
    if (!wave_record(value, fields, 4)
        || !wave_capability_value(fields[0], &capability)
        || capability != session->capability
        || !wave_u(fields[1], RESOURCE_MAX_LIVE_HANDLES, &slot)
        || slot == 0
        || !wave_u64(fields[2], UINT64_MAX, &generation)
        || generation == 0
        || session->slots[slot - 1u].catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[session->slots[slot - 1u].catalog_index].valid
        || !wave_identity(fields[3], session->catalog[session->slots[slot - 1u].catalog_index].admission_id)
        || !session->slots[slot - 1u].used
        || session->slots[slot - 1u].generation != generation)
        return 0;
    *slot_out = slot - 1u;
    return 1;
}

static int wave_plan_has_event(const WavePlan *plan, uint32_t event_id)
{
    for (uint32_t i = 0; i < plan->type_count; i++)
        for (uint32_t j = 0; j < plan->types[i].event_count; j++)
            if (plan->types[i].event_ids[j] == event_id) return 1;
    return 0;
}

static int wave_stimulus_validate(const WavePlan *plan, noun stimulus)
{
    noun tag, body, fields[3], values[16];
    uint32_t count, event;
    if (!wave_pair(stimulus, &tag, &body)
        || !wave_atom_text(tag, RESOURCE_STIMULUS_TAG)
        || !wave_record(body, fields, 3)
        || !wave_atom_text(fields[0], RESOURCE_STIMULUS_SCHEMA)
        || !wave_u(fields[1], 0xFFFF, &event) || event == 0
        || !wave_plan_has_event(plan, event)
        || !wave_list(fields[2], values, RESOURCE_MAX_VALUES, &count))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun vf[4];
        uint32_t id, type, raw;
        if (!wave_pair(values[i], &tag, &body)
            || !wave_atom_text(tag, RESOURCE_VALUE_TAG)
            || !wave_record(body, vf, 4)
            || !wave_atom_text(vf[0], RESOURCE_VALUE_SCHEMA)
            || !wave_u(vf[1], 0xFFFF, &id) || id == 0
            || !wave_u(vf[2], 2, &type) || (type != 1 && type != 2)
            || !wave_u(vf[3], type == 1 ? 1 : 65535, &raw))
            return 0;
    }
    return 1;
}

static int wave_selector_validate(const WavePlan *plan, noun selector,
                                  uint32_t *target_out)
{
    noun tag, body, fields[2];
    uint32_t target;
    if (!wave_pair(selector, &tag, &body)
        || !wave_atom_text(tag, RESOURCE_SELECTOR_TAG)
        || !wave_record(body, fields, 2)
        || !wave_atom_text(fields[0], RESOURCE_SELECTOR_SCHEMA)
        || !wave_u(fields[1], 0xFFFF, &target) || target == 0)
        return 0;
    for (uint32_t i = 0; i < plan->type_count; i++)
        for (uint32_t j = 0; j < plan->types[i].value_count; j++)
            if (plan->types[i].value_ids[j] == target) {
                *target_out = target;
                return 1;
            }
    return 0;
}

typedef struct WaveRequest {
    uint32_t operation;
    noun first;
    noun second;
} WaveRequest;

static int wave_request_decode(noun request, WaveRequest *out)
{
    noun tag, body, fields[3], args[2];
    if (!wave_pair(request, &tag, &body)
        || !wave_atom_text(tag, RESOURCE_REQUEST_TAG)
        || !wave_record(body, fields, 3)
        || !wave_atom_text(fields[0], RESOURCE_REQUEST_SCHEMA)
        || !wave_u(fields[1], RESOURCE_OP_RESTORE, &out->operation))
        return 0;
    out->first = NOUN_ZERO;
    out->second = NOUN_ZERO;
    if (out->operation == RESOURCE_OP_LOAD || out->operation == RESOURCE_OP_SNAPSHOT) {
        out->first = fields[2];
        return 1;
    }
    if (!wave_record(fields[2], args, 2)) return 0;
    out->first = args[0];
    out->second = args[1];
    return 1;
}

static int wave_core_index(ResourceRuntime *runtime, ResourceSession *session,
                           noun core, uint32_t *index_out)
{
    const uint8_t *canonical;
    uint64_t bytes;
    uint8_t identity[32];
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(core, &canonical, &bytes, &budget) != 0
        || bytes == 0 || bytes > RESOURCE_MAX_CORE_JAM_BYTES)
        return 0;
    if (!wave_domain_digest(runtime, core, RESOURCE_CORE_DOMAIN, identity)) return 0;
    for (uint32_t i = 0; i < RESOURCE_MAX_ADMISSION_ENTRIES; i++) {
        WaveCatalogCopy *entry = &session->catalog[i];
        if (entry->valid && bytes == entry->core_jam_bytes
            && wave_bytes_equal(canonical, entry->core_jam, bytes)
            && wave_bytes_equal(identity, entry->core_id, sizeof(identity))) {
            *index_out = i;
            return 1;
        }
    }
    return 0;
}

static int wave_find_value(const WavePlan *plan, uint32_t id,
                           uint32_t *type_out, uint32_t *value_out)
{
    for (uint32_t i = 0; i < plan->type_count; i++)
        for (uint32_t j = 0; j < plan->types[i].value_count; j++)
            if (plan->types[i].value_ids[j] == id) {
                if (type_out) *type_out = plan->types[i].value_types[j];
                if (value_out) *value_out = plan->types[i].value_initials[j];
                return 1;
            }
    return 0;
}

static int wave_observation_build(const WavePlan *plan, uint32_t target,
                                  noun *out)
{
    uint32_t type, value;
    if (!wave_find_value(plan, target, &type, &value)) return 0;
    noun typed;
    if (!wave_value_build(target, type, value, &typed)) return 0;
    noun values;
    if (!wave_build_list(&typed, 1, &values)) return 0;
    noun fields[2] = {direct(1), values};
    return wave_build_tagged(RESOURCE_OBSERVATION_TAG, RESOURCE_OBSERVATION_SCHEMA,
                             fields, 2, out);
}

static int wave_snapshot_build(const ResourceSession *session,
                               const WavePlan *plan, uint32_t slot_index,
                               const WaveSlot *source_slot,
                               noun *state_out, noun *handle_out,
                               noun *snapshot_out)
{
    const WaveSlot *slot = source_slot ? source_slot : &session->slots[slot_index];
    if (!wave_handle_build(session, slot_index + 1u, slot->generation,
                           slot->catalog_index, handle_out)
        || !wave_state_build(session, plan, slot->catalog_index, slot, state_out))
        return 0;
    noun nonce;
    if (!wave_u64_atom(slot->snapshot_nonce, &nonce)) return 0;
    noun fields[3] = {*handle_out, *state_out, nonce};
    return wave_build_record(fields, 3, snapshot_out);
}

static int wave_snapshot_apply(const ResourceSession *session, const WavePlan *plan,
                               noun snapshot, uint32_t slot_index, WaveSlot *out_slot)
{
    noun fields[3], state_tag, state_body, state_fields[4];
    if (slot_index >= RESOURCE_MAX_LIVE_HANDLES || !session->slots[slot_index].used
        || session->slots[slot_index].catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[session->slots[slot_index].catalog_index].valid) return 0;
    uint32_t catalog_index = session->slots[slot_index].catalog_index;
    if (!wave_record(snapshot, fields, 3)
        || !wave_pair(fields[1], &state_tag, &state_body)
        || !wave_atom_text(state_tag, RESOURCE_STATE_TAG)
        || !wave_record(state_body, state_fields, 4)
        || !wave_atom_text(state_fields[0], RESOURCE_STATE_SCHEMA)
        || !wave_identity(state_fields[1], session->catalog[catalog_index].admission_id)
        || !wave_atom_text(state_fields[2], RESOURCE_PROFILE_ID)) return 0;
    uint32_t decoded_slot;
    uint64_t snapshot_nonce;
    if (!wave_handle_decode(session, fields[0], &decoded_slot)
        || decoded_slot != slot_index
        || !wave_u64(fields[2], UINT64_MAX, &snapshot_nonce)
        || snapshot_nonce != session->slots[slot_index].snapshot_nonce
        || !noun_eq(snapshot, session->slots[slot_index].snapshot_root))
        return 0;
    noun instances[RESOURCE_MAX_PLAN_INSTANCES];
    uint32_t instance_count;
    if (!wave_list(state_fields[3], instances, RESOURCE_MAX_PLAN_INSTANCES, &instance_count)
        || instance_count != plan->instance_count) return 0;
    WaveSlot candidate = session->slots[slot_index];
    uint8_t seen[RESOURCE_MAX_PLAN_INSTANCES] = {0};
    for (uint32_t i = 0; i < instance_count; i++) {
        noun instance_tag, instance_body, instance_fields[4];
        uint32_t instance, state_id, value_count;
        if (!wave_pair(instances[i], &instance_tag, &instance_body)
            || !wave_atom_text(instance_tag, RESOURCE_INSTANCE_TAG)
            || !wave_record(instance_body, instance_fields, 4)
            || !wave_atom_text(instance_fields[0], RESOURCE_INSTANCE_SCHEMA)
            || !wave_u(instance_fields[1], RESOURCE_MAX_PLAN_INSTANCES, &instance)
            || instance == 0 || instance > plan->instance_count || seen[instance - 1u]
            || !wave_u(instance_fields[2], RESOURCE_MAX_PLAN_STATES, &state_id)) return 0;
        uint32_t instance_index = instance - 1u;
        const WavePlanType *type = &plan->types[plan->instance_types[instance_index] - 1u];
        if (state_id == 0 || state_id > type->state_count) return 0;
        noun values[RESOURCE_MAX_PLAN_VALUES];
        if (!wave_list(instance_fields[3], values, RESOURCE_MAX_PLAN_VALUES, &value_count)
            || value_count != type->value_count) return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value_tag, value_body, value_fields[4];
            uint32_t value_id, value_type, raw;
            if (!wave_pair(values[j], &value_tag, &value_body)
                || !wave_atom_text(value_tag, RESOURCE_VALUE_TAG)
                || !wave_record(value_body, value_fields, 4)
                || !wave_atom_text(value_fields[0], RESOURCE_VALUE_SCHEMA)
                || !wave_u(value_fields[1], RESOURCE_MAX_PLAN_VALUES, &value_id)
                || value_id != type->value_ids[j]
                || !wave_u(value_fields[2], 2, &value_type)
                || value_type != type->value_types[j]
                || !wave_u(value_fields[3], value_type == 1 ? 1 : 65535, &raw)) return 0;
            candidate.state_values[instance_index][j] = raw;
        }
        candidate.state_ids[instance_index] = state_id;
        seen[instance_index] = 1;
    }
    for (uint32_t i = 0; i < instance_count; i++) if (!seen[i]) return 0;
    if (out_slot) *out_slot = candidate;
    return 1;
}

static int wave_promote_operation(ResourceRuntime *runtime, ResourceSession *session,
                                  uint32_t slot_index, const WaveSlot *staged_slot,
                                  noun staged_handle, noun staged_state,
                                  noun staged_snapshot, noun staged_result,
                                  ResultOwner owner, uint8_t wire_status,
                                  M38Status *failure)
{
    WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS];
    noun handle_copy = NOUN_ZERO, state_copy = NOUN_ZERO;
    noun snapshot_copy = NOUN_ZERO, result_copy = NOUN_ZERO;
    uint64_t next_result_generation;
    if (owner != M38_RESULT_OWNER_PRIMARY && owner != M38_RESULT_OWNER_REFUSAL) {
        *failure = M38_STATUS_SLOT_PUBLICATION;
        return 0;
    }
    if (!wave_result_generation_advance(
            owner == M38_RESULT_OWNER_PRIMARY ? session->primary_generation
                                               : session->refusal_generation,
            &next_result_generation)) {
        *failure = M38_STATUS_SLOT_PUBLICATION;
        return 0;
    }
    wave_zero(copies, sizeof(copies));
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        ResourceSession *other = runtime->sessions[i];
        if (!other || other->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(other->catalog[j].core, &copies[i].catalog[j])) goto collective_fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(other->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(other->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(other->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto collective_fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (!wave_copy_root(other->slots[j].handle_root, &copies[i].handle[j])) goto collective_fail;
            if (!wave_copy_root(other->slots[j].state_root, &copies[i].state[j])) goto collective_fail;
            if (!wave_copy_root(other->slots[j].snapshot_root, &copies[i].snapshot[j])) goto collective_fail;
        }
        if (!wave_copy_root(other->primary_root, &copies[i].primary)) goto collective_fail;
        if (!wave_copy_root(other->refusal_root, &copies[i].refusal)) goto collective_fail;
    }
    if (!wave_copy_root(staged_handle, &handle_copy)
        || !wave_copy_root(staged_state, &state_copy)
        || !wave_copy_root(staged_snapshot, &snapshot_copy)
        || !wave_copy_root(staged_result, &result_copy))
        goto collective_fail;
    heap_persist_commit_tx();
    wave_apply_root_copies(runtime, copies);
    if (owner == M38_RESULT_OWNER_PRIMARY)
        session->primary_root = result_copy;
    else
        session->refusal_root = result_copy;
    if (staged_slot) {
        /* A staged slot is a value copy made before the persist flip.  Roots
         * omitted by this operation must come from the freshly copied live
         * slot, not from that stale pre-flip value copy. */
        noun preserved_handle = session->slots[slot_index].handle_root;
        noun preserved_state = session->slots[slot_index].state_root;
        noun preserved_snapshot = session->slots[slot_index].snapshot_root;
        session->slots[slot_index] = *staged_slot;
        session->slots[slot_index].handle_root =
            staged_handle != NOUN_ZERO ? handle_copy : preserved_handle;
        session->slots[slot_index].state_root =
            staged_state != NOUN_ZERO ? state_copy : preserved_state;
        session->slots[slot_index].snapshot_root =
            staged_snapshot != NOUN_ZERO ? snapshot_copy : preserved_snapshot;
    }
    if (owner == M38_RESULT_OWNER_PRIMARY) {
        session->primary_generation = next_result_generation;
        session->primary_view.root_slot = &session->primary_root;
        session->primary_view.handle_slot = staged_slot ? &session->slots[slot_index].handle_root : 0;
        session->primary_view.generation = session->primary_generation;
        session->primary_view.wire_status = wire_status;
        session->primary_view.owner = M38_RESULT_OWNER_PRIMARY;
    } else {
        session->refusal_generation = next_result_generation;
        session->refusal_view.root_slot = &session->refusal_root;
        session->refusal_view.handle_slot = 0;
        session->refusal_view.generation = session->refusal_generation;
        session->refusal_view.wire_status = wire_status;
        session->refusal_view.owner = M38_RESULT_OWNER_REFUSAL;
    }
    runtime->promoted_root_count++;
    *failure = M38_STATUS_OK;
    heap_set_mode(HEAP_MODE_SCRATCH);
    return 1;
collective_fail:
    heap_persist_abort_tx();
    *failure = M38_STATUS_COLLECTIVE_COMMIT;
    heap_set_mode(HEAP_MODE_SCRATCH);
    return 0;
}

static M38Status wave_publish_refusal(ResourceRuntime *runtime, ResourceSession *session,
                                      uint32_t reason,
                                      const ResourceResultView **out_view)
{
    noun result;
    M38Status failure = M38_STATUS_OK;
    if (!wave_refusal_build(reason, &result)) return M38_STATUS_ATOM_RESULT_STAGING;
    if (!wave_promote_operation(runtime, session, 0, 0, NOUN_ZERO, NOUN_ZERO,
                                NOUN_ZERO, result, M38_RESULT_OWNER_REFUSAL,
                                RESOURCE_WIRE_REFUSE, &failure))
        return failure;
    *out_view = &session->refusal_view;
    return M38_STATUS_OK;
}

static int wave_plan_for_slot(ResourceSession *session, uint32_t slot_index,
                              WavePlan **out)
{
    if (slot_index >= RESOURCE_MAX_LIVE_HANDLES || !session->slots[slot_index].used)
        return 0;
    uint32_t catalog_index = session->slots[slot_index].catalog_index;
    if (catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[catalog_index].valid)
        return 0;
    WaveCacheEntry *cache = &session->cache[catalog_index];
    if (!cache->valid) return 0;
    *out = &cache->plan;
    return 1;
}

static int wave_runtime_state_build(const ResourceSession *session,
                                    const WavePlan *plan, uint32_t catalog_index,
                                    const WaveSlot *slot, noun *out)
{
    noun rows[RESOURCE_MAX_PLAN_INSTANCES];
    noun identity;
    if (!wave_digest_atom(session->catalog[catalog_index].payload_id, &identity)) return 0;
    for (uint32_t i = plan->instance_count; i != 0; i--) {
        uint32_t instance = i - 1u;
        const WavePlanType *type = &plan->types[plan->instance_types[instance] - 1u];
        noun values[RESOURCE_MAX_PLAN_VALUES];
        for (uint32_t j = type->value_count; j != 0; j--) {
            uint32_t value = j - 1u;
            noun fields[3] = {direct(type->value_ids[value]),
                              direct(type->value_types[value]),
                              direct(slot->state_values[instance][value])};
            if (!wave_build_record(fields, 3, &values[value])) return 0;
        }
        noun value_list;
        if (!wave_build_list(values, type->value_count, &value_list)) return 0;
        noun fields[3] = {direct(instance + 1u), direct(slot->state_ids[instance]), value_list};
        if (!wave_build_record(fields, 3, &rows[instance])) return 0;
    }
    noun row_list, fields[2], body;
    if (!wave_build_list(rows, plan->instance_count, &row_list)) return 0;
    fields[0] = identity;
    fields[1] = row_list;
    if (!wave_build_record(fields, 2, &body)) return 0;
    return alloc_cell_checked(direct(RESOURCE_RUNTIME_STATE_TAG), body, out);
}

static int wave_runtime_stimulus_build(const ResourceSession *session,
                                       const WavePlan *plan, uint32_t catalog_index,
                                       noun stimulus, noun *out)
{
    noun tag, body, fields[3], values[RESOURCE_MAX_PLAN_VALUES];
    uint32_t value_count, event;
    if (!wave_pair(stimulus, &tag, &body)
        || !wave_record(body, fields, 3)
        || !wave_u(fields[1], 0xFFFF, &event)
        || !wave_list(fields[2], values, RESOURCE_MAX_PLAN_VALUES, &value_count)) return 0;
    uint32_t type_index = RESOURCE_MAX_PLAN_TYPES;
    uint32_t event_index = RESOURCE_MAX_PLAN_EVENTS;
    for (uint32_t i = 0; i < plan->type_count; i++) {
        for (uint32_t j = 0; j < plan->types[i].event_count; j++) {
            if (plan->types[i].event_ids[j] == event) {
                type_index = i;
                event_index = j;
                break;
            }
        }
        if (type_index != RESOURCE_MAX_PLAN_TYPES) break;
    }
    if (type_index == RESOURCE_MAX_PLAN_TYPES) return 0;
    uint32_t instance = RESOURCE_MAX_PLAN_INSTANCES;
    for (uint32_t i = 0; i < plan->instance_count; i++)
        if (plan->instance_types[i] == type_index + 1u) {
            instance = i;
            break;
        }
    if (instance == RESOURCE_MAX_PLAN_INSTANCES
        || value_count != plan->types[type_index].event_value_counts[event_index]) return 0;

    noun runtime_values[RESOURCE_MAX_PLAN_VALUES];
    for (uint32_t i = 0; i < value_count; i++) {
        noun value_tag, value_body, value_fields[4];
        if (!wave_pair(values[i], &value_tag, &value_body)
            || !wave_atom_text(value_tag, RESOURCE_VALUE_TAG)
            || !wave_record(value_body, value_fields, 4)) return 0;
        uint32_t value_id;
        if (!wave_u(value_fields[1], RESOURCE_MAX_PLAN_VALUES, &value_id)
            || value_id != plan->types[type_index].event_value_ids[event_index][i]) return 0;
        noun runtime_fields[3] = {value_fields[1], value_fields[2], value_fields[3]};
        if (!wave_build_record(runtime_fields, 3, &runtime_values[i])) return 0;
    }
    noun runtime_value_list, identity, runtime_fields[4], runtime_body;
    if (!wave_build_list(runtime_values, value_count, &runtime_value_list)
        || !wave_digest_atom(session->catalog[catalog_index].payload_id, &identity)) return 0;
    runtime_fields[0] = identity;
    runtime_fields[1] = direct(instance + 1u);
    runtime_fields[2] = direct(event);
    runtime_fields[3] = runtime_value_list;
    if (!wave_build_record(runtime_fields, 4, &runtime_body)) return 0;
    return alloc_cell_checked(wave_cord("38-stimul"), runtime_body, out);
}

static int wave_runtime_bounds_build(noun *out)
{
    noun fields[3] = {direct(RESOURCE_RUNTIME_QUEUE_LIMIT),
                      direct(RESOURCE_RUNTIME_WORKLIST_LIMIT),
                      direct(RESOURCE_RUNTIME_TRACE_LIMIT)};
    noun limits;
    return wave_build_record(fields, 3, &limits)
        && alloc_cell_checked(limits, NOUN_ZERO, out);
}

static M38Status wave_evaluate_poke(ResourceSession *session, const WavePlan *plan,
                                    uint32_t catalog_index, const WaveSlot *slot,
                                    noun stimulus, noun *product,
                                    uint64_t *ops_out, uint64_t *cells_out,
                                    uint64_t *stack_out)
{
    noun runtime_state, runtime_stimulus, bounds, tail, subject;
    if (!wave_runtime_state_build(session, plan, catalog_index, slot, &runtime_state)
        || !wave_runtime_stimulus_build(session, plan, catalog_index, stimulus,
                                        &runtime_stimulus)
        || !wave_runtime_bounds_build(&bounds)
        || !alloc_cell_checked(runtime_stimulus, bounds, &tail)
        || !alloc_cell_checked(runtime_state, tail, &tail)
        || !alloc_cell_checked(plan->payload, tail, &subject))
        return M38_STATUS_INTERNAL;

    nock_budget_set_limits(2000000ULL, 128000ULL);
    nock_eval_stack_set_limit(1024ULL);
    jmp_buf saved_abort;
    __builtin_memcpy(saved_abort, nock_abort, sizeof saved_abort);
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        *ops_out = nock_ops_used();
        *cells_out = nock_cells_used();
        *stack_out = nock_eval_stack_peak();
        nock_budget_finish();
        __builtin_memcpy(nock_abort, saved_abort, sizeof saved_abort);
        return M38_STATUS_EVALUATOR_ABORT;
    }
    noun evaluated = nock(subject, plan->formula);
    *ops_out = nock_ops_used();
    *cells_out = nock_cells_used();
    *stack_out = nock_eval_stack_peak();
    nock_budget_finish();
    __builtin_memcpy(nock_abort, saved_abort, sizeof saved_abort);
    *product = evaluated;
    return M38_STATUS_OK;
}

static int wave_runtime_product_commit(const ResourceSession *session,
                                       const WavePlan *plan, uint32_t catalog_index,
                                       noun product, WaveSlot *slot)
{
    noun tag, body, fields[7];
    if (!wave_pair(product, &tag, &body)
        || !wave_atom_text(tag, "m38-product-v2")
        || !wave_record(body, fields, 7)
        || !wave_identity(fields[0], session->catalog[catalog_index].payload_id)
        || !wave_atom_text(fields[1], "commit")) return 0;
    noun observations[32], trace[128];
    uint32_t observation_count, trace_count;
    if (!wave_list(fields[3], observations, 32, &observation_count)
        || !wave_list(fields[4], trace, 128, &trace_count)) return 0;

    noun state_tag, state_body, state_fields[2], rows[RESOURCE_MAX_PLAN_INSTANCES];
    uint32_t row_count;
    if (!wave_pair(fields[2], &state_tag, &state_body)
        || !noun_is_direct(state_tag) || direct_val(state_tag) != RESOURCE_RUNTIME_STATE_TAG
        || !wave_record(state_body, state_fields, 2)
        || !wave_identity(state_fields[0], session->catalog[catalog_index].payload_id)
        || !wave_list(state_fields[1], rows, RESOURCE_MAX_PLAN_INSTANCES, &row_count)
        || row_count != plan->instance_count) return 0;

    WaveSlot candidate = *slot;
    uint8_t seen[RESOURCE_MAX_PLAN_INSTANCES] = {0};
    for (uint32_t i = 0; i < row_count; i++) {
        noun row_fields[3], values[RESOURCE_MAX_PLAN_VALUES];
        uint32_t instance, state_id, value_count;
        if (!wave_record(rows[i], row_fields, 3)
            || !wave_u(row_fields[0], RESOURCE_MAX_PLAN_INSTANCES, &instance)
            || instance == 0 || instance > plan->instance_count || seen[instance - 1u]
            || !wave_u(row_fields[1], RESOURCE_MAX_PLAN_STATES, &state_id)
            || state_id == 0
            || !wave_list(row_fields[2], values, RESOURCE_MAX_PLAN_VALUES, &value_count)) return 0;
        uint32_t instance_index = instance - 1u;
        const WavePlanType *type = &plan->types[plan->instance_types[instance_index] - 1u];
        if (state_id > type->state_count || value_count != type->value_count) return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value_fields[3];
            uint32_t value_id, value_type, raw;
            if (!wave_record(values[j], value_fields, 3)
                || !wave_u(value_fields[0], RESOURCE_MAX_PLAN_VALUES, &value_id)
                || value_id != type->value_ids[j]
                || !wave_u(value_fields[1], 2, &value_type)
                || value_type != type->value_types[j]
                || !wave_u(value_fields[2], value_type == 1 ? 1 : 65535, &raw)) return 0;
            candidate.state_values[instance_index][j] = raw;
        }
        candidate.state_ids[instance_index] = state_id;
        seen[instance_index] = 1;
    }
    for (uint32_t i = 0; i < row_count; i++) if (!seen[i]) return 0;
    *slot = candidate;
    return 1;
}

static int wave_poke_result(ResourceSession *session, uint32_t slot_index,
                            const WavePlan *plan, noun stimulus,
                            WaveSlot *staged_slot, noun *state_out,
                            noun *result_out, M38Status *evaluation_status)
{
    noun effects, observations, metrics, body, product = NOUN_ZERO;
    uint64_t ops = 0, cells = 0, stack = 0;
    *evaluation_status = M38_STATUS_OK;
    if (!wave_stimulus_validate(plan, stimulus)) return 0;
    M38Status evaluation = wave_evaluate_poke(
        session, plan, staged_slot->catalog_index, staged_slot,
        stimulus, &product, &ops, &cells, &stack);
    if (evaluation != M38_STATUS_OK) {
        *evaluation_status = evaluation;
        return 0;
    }
    if (!wave_runtime_product_commit(session, plan, staged_slot->catalog_index,
                                     product, staged_slot)
        || !wave_state_build(session, plan, staged_slot->catalog_index, staged_slot, state_out)
        || !wave_empty_effects(&effects)
        || !wave_empty_observations(&observations)
        || !wave_metrics_build(ops, cells, stack, &metrics)) {
        *evaluation_status = M38_STATUS_EVALUATOR_ABORT;
        return 0;
    }
    noun body_fields[4] = {*state_out, effects, observations, metrics};
    if (!wave_build_record(body_fields, 4, &body)
        || !wave_result_build(RESOURCE_WIRE_POKE, body, result_out))
        return 0;
    (void)slot_index;
    return 1;
}

static M38Status wave_dispatch_operation(ResourceRuntime *runtime,
                                         ResourceSession *session,
                                         const WaveRequest *request,
                                         const ResourceResultView **out_view)
{
    uint32_t slot_index = 0;
    WavePlan *plan = 0;
    WaveSlot staged_slot;
    noun handle = NOUN_ZERO, state = NOUN_ZERO;
    noun snapshot = NOUN_ZERO, result = NOUN_ZERO;
    uint8_t wire_status = RESOURCE_WIRE_REFUSE;
    ResultOwner owner = M38_RESULT_OWNER_REFUSAL;
    uint32_t refusal_reason = RESOURCE_REASON_INVALID_REQUEST;
    uint64_t parse_before = session->parse_count;

    if (request->operation < RESOURCE_OP_LOAD || request->operation > RESOURCE_OP_RESTORE)
        goto refuse;

    if (request->operation == RESOURCE_OP_LOAD) {
        uint32_t catalog_index;
        if (!wave_core_index(runtime, session, request->first, &catalog_index)) {
            refusal_reason = RESOURCE_REASON_UNKNOWN_CORE;
            goto refuse;
        }
        WaveCacheEntry *cache = &session->cache[catalog_index];
        WavePlan staged_plan = cache->plan;
        if (!cache->valid) {
            if (wave_take_fault(runtime, M38_FAULT_CUE_CACHE_INSERT) != M38_STATUS_OK)
                return M38_STATUS_CUE_CACHE_INSERT;
            if (!wave_parse_plan(session->catalog[catalog_index].core, &staged_plan)) {
                refusal_reason = RESOURCE_REASON_CORE_FAILURE;
                goto refuse;
            }
        }
        uint32_t free_slot = RESOURCE_MAX_LIVE_HANDLES;
        for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++)
            if (!session->slots[i].used && session->slots[i].generation != 0) {
                free_slot = i;
                break;
            }
        if (free_slot == RESOURCE_MAX_LIVE_HANDLES) {
            refusal_reason = RESOURCE_REASON_NO_SLOT;
            goto refuse;
        }
        staged_slot = session->slots[free_slot];
        staged_slot.used = 1;
        staged_slot.catalog_index = (uint8_t)catalog_index;
        if (staged_slot.generation == 0) staged_slot.generation = 1;
        staged_slot.snapshot_nonce = 0;
        staged_slot.handle_root = NOUN_ZERO;
        staged_slot.state_root = NOUN_ZERO;
        staged_slot.snapshot_root = NOUN_ZERO;
        for (uint32_t i = 0; i < staged_plan.instance_count; i++) {
            WavePlanType *type = &staged_plan.types[staged_plan.instance_types[i] - 1u];
            staged_slot.state_ids[i] = type->state_id;
            for (uint32_t j = 0; j < type->value_count; j++)
                staged_slot.state_values[i][j] = type->value_initials[j];
        }
        if (!wave_handle_build(session, free_slot + 1u, staged_slot.generation,
                                catalog_index, &handle)
            || !wave_state_build(session, &staged_plan, catalog_index,
                                 &staged_slot, &state)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        noun body_fields[2] = {handle, state};
        noun body;
        if (!wave_build_record(body_fields, 2, &body)
            || !wave_result_build(RESOURCE_WIRE_LOADED, body, &result)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        staged_slot.handle_root = handle;
        staged_slot.state_root = state;
        wire_status = RESOURCE_WIRE_LOADED;
        owner = M38_RESULT_OWNER_PRIMARY;
        M38Status failure;
        if (wave_take_fault(runtime, M38_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
            return M38_STATUS_ATOM_RESULT_STAGING;
        if (wave_take_fault(runtime, M38_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
            return M38_STATUS_COLLECTIVE_COMMIT;
        if (!wave_promote_operation(runtime, session, free_slot, &staged_slot,
                                    handle, state, NOUN_ZERO, result, owner,
                                    wire_status, &failure))
            return failure;
        if (!cache->valid) {
            noun persisted_formula, persisted_payload;
            if (!wave_pair(session->catalog[catalog_index].core,
                           &persisted_formula, &persisted_payload))
                return M38_STATUS_INTERNAL;
            cache->plan = staged_plan;
            cache->plan.formula = persisted_formula;
            cache->plan.payload = persisted_payload;
            cache->valid = 1;
            if (session->parse_count == parse_before) session->parse_count++;
        }
        *out_view = &session->primary_view;
        return M38_STATUS_OK;
    }

    if (request->operation == RESOURCE_OP_SNAPSHOT) {
        if (!wave_handle_decode(session, request->first, &slot_index)
            || !wave_plan_for_slot(session, slot_index, &plan)) {
            refusal_reason = RESOURCE_REASON_BAD_HANDLE;
            goto refuse;
        }
        staged_slot = session->slots[slot_index];
        if (staged_slot.snapshot_nonce == RESOURCE_MAX_SNAPSHOT_NONCE) {
            refusal_reason = RESOURCE_REASON_BAD_SNAPSHOT;
            goto refuse;
        }
        staged_slot.snapshot_nonce++;
        if (!wave_snapshot_build(session, plan, slot_index, &staged_slot,
                                 &state, &handle, &snapshot)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        if (!wave_result_build(RESOURCE_WIRE_SNAPSHOT, snapshot, &result)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        staged_slot.snapshot_root = snapshot;
        wire_status = RESOURCE_WIRE_SNAPSHOT;
        owner = M38_RESULT_OWNER_PRIMARY;
        goto publish;
    }

    if (!wave_handle_decode(session, request->first, &slot_index)
        || !wave_plan_for_slot(session, slot_index, &plan)) {
        refusal_reason = RESOURCE_REASON_BAD_HANDLE;
        goto refuse;
    }
    staged_slot = session->slots[slot_index];
    if (request->operation == RESOURCE_OP_POKE) {
        M38Status evaluation_status = M38_STATUS_OK;
        if (wave_take_fault(runtime, M38_FAULT_EVALUATOR_ABORT) != M38_STATUS_OK)
            return M38_STATUS_EVALUATOR_ABORT;
        if (!wave_poke_result(session, slot_index, plan, request->second,
                              &staged_slot, &state, &result, &evaluation_status)) {
            if (evaluation_status != M38_STATUS_OK) return evaluation_status;
            refusal_reason = RESOURCE_REASON_BAD_STIMULUS;
            goto refuse;
        }
        staged_slot.state_root = state;
        wire_status = RESOURCE_WIRE_POKE;
        owner = M38_RESULT_OWNER_PRIMARY;
        goto publish;
    }
    if (request->operation == RESOURCE_OP_PEEK) {
        uint32_t target;
        if (!wave_selector_validate(plan, request->second, &target)) {
            refusal_reason = RESOURCE_REASON_BAD_SELECTOR;
            goto refuse;
        }
        noun observation, body;
        if (!wave_observation_build(plan, target, &observation)
            || !wave_build_record((noun[2]){request->second, observation}, 2, &body)
            || !wave_result_build(RESOURCE_WIRE_PEEK, body, &result)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        wire_status = RESOURCE_WIRE_PEEK;
        owner = M38_RESULT_OWNER_PRIMARY;
        goto publish;
    }
    if (request->operation == RESOURCE_OP_RESTORE) {
        if (!wave_snapshot_apply(session, plan, request->second, slot_index, &staged_slot)
            || !wave_state_build(session, plan, staged_slot.catalog_index,
                                 &staged_slot, &state)
            || !wave_handle_build(session, slot_index + 1u, staged_slot.generation,
                                  staged_slot.catalog_index, &handle)) {
            refusal_reason = RESOURCE_REASON_BAD_SNAPSHOT;
            goto refuse;
        }
        noun receipt_fields[2] = {handle, direct(staged_slot.snapshot_nonce)};
        noun receipt;
        if (!wave_build_tagged(RESOURCE_RECEIPT_TAG, RESOURCE_RECEIPT_SCHEMA,
                               receipt_fields, 2, &receipt)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        noun body_fields[3] = {handle, state, receipt}, body;
        if (!wave_build_record(body_fields, 3, &body)
            || !wave_result_build(RESOURCE_WIRE_RESTORE, body, &result)) {
            refusal_reason = RESOURCE_REASON_CONSTRUCTION;
            goto refuse;
        }
        staged_slot.state_root = state;
        wire_status = RESOURCE_WIRE_RESTORE;
        owner = M38_RESULT_OWNER_PRIMARY;
        if (wave_take_fault(runtime, M38_FAULT_RESTORE_COMMIT) != M38_STATUS_OK)
            return M38_STATUS_RESTORE_COMMIT;
        goto publish;
    }
    return M38_STATUS_REQUEST_INVALID;

publish: {
        M38Status failure;
        if (wave_take_fault(runtime, M38_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
            return M38_STATUS_ATOM_RESULT_STAGING;
        if (wave_take_fault(runtime, M38_FAULT_SLOT_PUBLICATION) != M38_STATUS_OK)
            return M38_STATUS_SLOT_PUBLICATION;
        if (wave_take_fault(runtime, M38_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
            return M38_STATUS_COLLECTIVE_COMMIT;
        if (!wave_promote_operation(runtime, session, slot_index, &staged_slot,
                                    handle, state, snapshot, result, owner,
                                    wire_status, &failure))
            return failure;
        *out_view = &session->primary_view;
        return M38_STATUS_OK;
    }
refuse:
    if (wave_take_fault(runtime, M38_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
        return M38_STATUS_ATOM_RESULT_STAGING;
    if (wave_take_fault(runtime, M38_FAULT_SLOT_PUBLICATION) != M38_STATUS_OK)
        return M38_STATUS_SLOT_PUBLICATION;
    if (wave_take_fault(runtime, M38_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
        return M38_STATUS_COLLECTIVE_COMMIT;
    return wave_publish_refusal(runtime, session, refusal_reason, out_view);
}

M38Status m38_resource_session_dispatch(ResourceSession *session, noun request,
                                        const ResourceResultView **out_view)
{
    if (!out_view) return M38_STATUS_INVALID_ARGUMENT;
    *out_view = 0;
    if (!wave_session_valid(session)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    ResourceRuntime *runtime = session->runtime;
    if (session->state == 2) return M38_STATUS_SESSION_CLOSED;
    if (session->in_flight) return M38_STATUS_SESSION_BUSY;
    if (runtime->broker_owner != 0 || runtime->state != 2)
        return M38_STATUS_RUNTIME_BUSY;
    if (!wave_safe_noun(runtime, request)) return M38_STATUS_REQUEST_INVALID;
    WaveRequest decoded = {0};
    /* Safety failure is a C-boundary error.  A safely traversable noun that
     * merely misses the ResourceABI grammar is an ordinary wire refusal. */
    if (!wave_request_decode(request, &decoded)) decoded.operation = 0;
    M38Status broker_fault = wave_take_fault(runtime, M38_FAULT_BROKER_BEGIN);
    if (broker_fault != M38_STATUS_OK) return broker_fault;
    runtime->broker_owner = (uint8_t)(session->registry_index + 1u);
    runtime->state = 3;
    session->in_flight = 1;
    session->session_transaction_id = ++runtime->broker_transaction_id;
    uint64_t scratch_mark = heap_scratch_mark();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!noun_tx_begin(HEAP_MODE_SCRATCH)) {
        session->in_flight = 0;
        wave_broker_release(runtime);
        return M38_STATUS_INTERNAL;
    }
    M38Status status = wave_dispatch_operation(runtime, session, &decoded, out_view);
    if (status != M38_STATUS_OK) {
        noun_tx_abort();
        (void)heap_scratch_rewind(scratch_mark);
        *out_view = 0;
    } else {
        noun_tx_commit();
    }
    session->in_flight = 0;
    wave_broker_release(runtime);
    (void)heap_scratch_rewind(scratch_mark);
    return status;
}

static M38Status wave_lifecycle_begin(ResourceRuntime *runtime,
                                      ResourceSession *session)
{
    if (!wave_runtime_valid(runtime)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (!wave_session_valid(session) || session->runtime != runtime)
        return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (session->state == 2) return M38_STATUS_SESSION_CLOSED;
    if (session->in_flight) return M38_STATUS_SESSION_BUSY;
    if (runtime->broker_owner != 0 || runtime->state == 3)
        return M38_STATUS_RUNTIME_BUSY;
    runtime->broker_owner = 3;
    runtime->state = 4;
    return M38_STATUS_OK;
}

M38Status m38_resource_session_reset(ResourceRuntime *runtime,
                                     ResourceSession *session)
{
    M38Status status = wave_lifecycle_begin(runtime, session);
    if (status != M38_STATUS_OK) return status;
    if (wave_take_fault(runtime, M38_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK) {
        wave_broker_release(runtime);
        return M38_STATUS_COLLECTIVE_COMMIT;
    }
    WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS];
    if (!wave_copy_registered_roots(runtime, copies)) {
        wave_broker_release(runtime);
        return M38_STATUS_COLLECTIVE_COMMIT;
    }
    uint64_t next_primary_generation, next_refusal_generation;
    if (!wave_result_generation_advance(session->primary_generation,
                                        &next_primary_generation)
        || !wave_result_generation_advance(session->refusal_generation,
                                           &next_refusal_generation)) {
        wave_broker_release(runtime);
        return M38_STATUS_SLOT_PUBLICATION;
    }
    session->primary_root = NOUN_ZERO;
    session->refusal_root = NOUN_ZERO;
    session->primary_generation = next_primary_generation;
    session->refusal_generation = next_refusal_generation;
    session->primary_view.root_slot = &session->primary_root;
    session->primary_view.handle_slot = 0;
    session->primary_view.generation = session->primary_generation;
    session->primary_view.wire_status = 0;
    session->primary_view.owner = M38_RESULT_OWNER_NONE;
    session->refusal_view.root_slot = &session->refusal_root;
    session->refusal_view.handle_slot = 0;
    session->refusal_view.generation = session->refusal_generation;
    session->refusal_view.wire_status = 0;
    session->refusal_view.owner = M38_RESULT_OWNER_NONE;
    for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++) {
        session->slots[i].used = 0;
        (void)wave_generation_advance(session->slots[i].generation,
                                      &session->slots[i].generation);
        session->slots[i].snapshot_nonce = 0;
        session->slots[i].handle_root = NOUN_ZERO;
        session->slots[i].state_root = NOUN_ZERO;
        session->slots[i].snapshot_root = NOUN_ZERO;
    }
    session->session_transaction_id = ++runtime->broker_transaction_id;
    wave_broker_release(runtime);
    return M38_STATUS_OK;
}

M38Status m38_resource_session_dispose(ResourceRuntime *runtime,
                                       ResourceSession *session)
{
    M38Status status = wave_lifecycle_begin(runtime, session);
    if (status != M38_STATUS_OK) return status;
    if (wave_take_fault(runtime, M38_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK) {
        wave_broker_release(runtime);
        return M38_STATUS_COLLECTIVE_COMMIT;
    }
    WaveRootCopies copies[RESOURCE_MAX_REGISTERED_SESSIONS];
    if (!wave_copy_registered_roots(runtime, copies)) {
        wave_broker_release(runtime);
        return M38_STATUS_COLLECTIVE_COMMIT;
    }
    uint64_t next_primary_generation, next_refusal_generation;
    if (!wave_result_generation_advance(session->primary_generation,
                                        &next_primary_generation)
        || !wave_result_generation_advance(session->refusal_generation,
                                           &next_refusal_generation)) {
        wave_broker_release(runtime);
        return M38_STATUS_SLOT_PUBLICATION;
    }
    uint32_t index = session->registry_index;
    runtime->sessions[index] = 0;
    if (runtime->session_count != 0) runtime->session_count--;
    session->state = 2;
    session->in_flight = 0;
    session->capability = 0;
    wave_zero(session->catalog, sizeof(session->catalog));
    wave_zero(session->cache, sizeof(session->cache));
    wave_zero(session->slots, sizeof(session->slots));
    session->primary_root = NOUN_ZERO;
    session->refusal_root = NOUN_ZERO;
    session->primary_view.root_slot = &session->primary_root;
    session->primary_view.handle_slot = 0;
    session->primary_generation = next_primary_generation;
    session->primary_view.generation = session->primary_generation;
    session->primary_view.wire_status = 0;
    session->primary_view.owner = M38_RESULT_OWNER_NONE;
    session->refusal_view.root_slot = &session->refusal_root;
    session->refusal_view.handle_slot = 0;
    session->refusal_generation = next_refusal_generation;
    session->refusal_view.generation = session->refusal_generation;
    session->refusal_view.wire_status = 0;
    session->refusal_view.owner = M38_RESULT_OWNER_NONE;
    session->session_transaction_id = ++runtime->broker_transaction_id;
    wave_broker_release(runtime);
    return M38_STATUS_OK;
}

_Static_assert(sizeof(ResourceRuntime) <= RESOURCE_RUNTIME_CONTROL_BYTES,
               "ResourceRuntime exceeds its fixed control reservation");
_Static_assert(sizeof(ResourceSession) <= RESOURCE_SESSION_BYTES,
               "ResourceSession exceeds its fixed storage reservation");
