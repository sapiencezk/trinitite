#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "jam.h"
#include "m38_resource_core_descriptor.h"
#include "m38_resource_runtime.h"
#if defined(M44_TWO_RESOURCE)
#include "m44_resource_transaction.h"
#endif
#include "memory.h"
#include "nock.h"
#include "sha256.h"
#include "setjmp.h"
#include "m38_resource_wave_b_qualification.h"

#if defined(M38_D8_WAVE_B_TEST_CONTROLS)
#include "m38_resource_test_controls.h"
#endif
#if defined(M38_D8_WAVE_B_B0)
#include "m38_resource_b0_observability.h"
#endif
#if defined(M38_D8_WAVE_B_B2)
#include "m38_resource_b2_observability.h"
#endif
#if defined(M38_D8_WAVE_B_B3)
#include "m38_resource_b3_observability.h"
#endif

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
#if defined(M46_LIVE_REPLACEMENT)
#define RESOURCE_SESSION_BYTES (1024u * 1024u)
#else
#define RESOURCE_SESSION_BYTES (2u * 1024u * 1024u)
#endif
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
#define RESOURCE_MAX_BOUNDARIES               128u
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
static const char RESOURCE_EFFECT_TAG[] = "m38-resource-abi-v1-numeric-effect";
static const char RESOURCE_EFFECT_SCHEMA[] = "m38-resource-abi-v1-numeric-effect-schema-v1";
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
static const char RESOURCE_PROFILE[] = "1499kernel-i2-m38-numeric-execution-profile-v1-bounded";
/* M41 is an explicit successor scalar profile. The old admission and value
 * schemas keep their exact BOOL/UINT16 meaning. Arithmetic remains Nock. */
static const char M41_PROFILE[] = "1499kernel-i2-m41-numeric-execution-profile-v1-int16";
static const char M41_RECORD_TAG[] = "m41-resource-session-admission-record";
static const char M41_RECORD_SCHEMA[] = "m41-resource-session-admission-record-schema-v1";
static const char M41_ADMISSION_DOMAIN[] = "1499kernel:i2:m41:session-admission-record:v1";
static const char M41_VALUE_SCHEMA[] = "m41-numeric-value-schema-v1";
static const char M41_PAYLOAD_SCHEMA[] = "m41-resource-payload-schema-v1";

/* Private fault vocabulary.  The public runtime header has no fault setter;
 * Wave B test builds translate their test-only enum at the boundary below. */
typedef enum WaveFaultPoint {
    WAVE_FAULT_NONE = 0,
    WAVE_FAULT_BROKER_BEGIN,
    WAVE_FAULT_CUE_CACHE_INSERT,
    WAVE_FAULT_SLOT_PUBLICATION,
    WAVE_FAULT_EVALUATOR_ABORT,
    WAVE_FAULT_ATOM_RESULT_STAGING,
    WAVE_FAULT_COLLECTIVE_COMMIT,
    WAVE_FAULT_RESTORE_COMMIT,
} WaveFaultPoint;

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

typedef struct WavePlanType {
    uint32_t id;
    uint32_t value_count;
    uint32_t state_id;
    uint32_t value_ids[RESOURCE_MAX_PLAN_VALUES];
    uint32_t value_types[RESOURCE_MAX_PLAN_VALUES];
    uint32_t value_initials[RESOURCE_MAX_PLAN_VALUES];
    uint32_t event_count;
    uint32_t event_ids[RESOURCE_MAX_PLAN_EVENTS];
    uint32_t event_directions[RESOURCE_MAX_PLAN_EVENTS];
    uint32_t event_value_counts[RESOURCE_MAX_PLAN_EVENTS];
    uint32_t event_value_ids[RESOURCE_MAX_PLAN_EVENTS][RESOURCE_MAX_PLAN_VALUES];
    uint32_t state_count;
} WavePlanType;

typedef struct WaveEndpoint {
    uint32_t instance; /* zero based */
    uint32_t event;    /* index in the type's all-event table */
} WaveEndpoint;

typedef struct WavePlan {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t scalar_count; /* 2 for frozen D8, 3 for the explicit M41 profile */
    uint32_t instance_types[RESOURCE_MAX_PLAN_INSTANCES];
    WavePlanType types[RESOURCE_MAX_PLAN_TYPES];
    uint32_t boundary_counts[2]; /* ingress, egress */
    WaveEndpoint boundaries[2][RESOURCE_MAX_BOUNDARIES];
    noun formula;
    noun payload;
} WavePlan;

typedef struct WaveCacheEntry {
    uint8_t valid;
    const M38ResourceCoreDescriptor *descriptor;
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

#if defined(M44_TWO_RESOURCE)
typedef struct WaveM44Group {
    uint32_t index[2];
    WaveSlot slots[2];
} WaveM44Group;
#endif

typedef struct WaveCatalogCopy {
    uint8_t valid;
    M38ResourceCoreDescriptor descriptor_storage;
    const M38ResourceCoreDescriptor *descriptor;
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
#if defined(M44_TWO_RESOURCE)
    const void *m44_owner;
    const M44PublicationHooks *m44_hooks;
    const WaveM44Group *m44_group;
#if defined(M46_LIVE_REPLACEMENT)
    ResourceSession *m46_source;
#endif
    uint8_t m44_call_active;
#if defined(M44_G0_TEST_CONTROLS)
    uint8_t m44_test_fault;
#endif
#endif
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
    uint8_t next_fault;
    ResourceSession *sessions[RESOURCE_MAX_REGISTERED_SESSIONS];
};

#define RESOURCE_RUNTIME_MAGIC  0x52333857u
#define RESOURCE_SESSION_MAGIC  0x53333857u

/* The singleton lease is runtime ownership, not session/catalog/slot state. */
static ResourceRuntime *g_wave_runtime_lease;

#if defined(M38_D8_WAVE_B_B2)
static uint64_t b2_live_roots(const ResourceRuntime *runtime)
{
    uint64_t count = 0;
    if (!runtime) return 0;
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        const ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            if (session->catalog[j].core != NOUN_ZERO) count++;
            if (session->cache[j].valid) {
                if (session->cache[j].core != NOUN_ZERO) count++;
                if (session->cache[j].plan.formula != NOUN_ZERO) count++;
                if (session->cache[j].plan.payload != NOUN_ZERO) count++;
            }
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (session->slots[j].handle_root != NOUN_ZERO) count++;
            if (session->slots[j].state_root != NOUN_ZERO) count++;
            if (session->slots[j].snapshot_root != NOUN_ZERO) count++;
        }
        if (session->primary_root != NOUN_ZERO) count++;
        if (session->refusal_root != NOUN_ZERO) count++;
    }
    return count;
}

static void b2_zero(void *pointer, size_t bytes)
{
    uint8_t *raw = (uint8_t *)pointer;
    for (size_t i = 0; i < bytes; i++) raw[i] = 0;
}
#endif

#if defined(M38_D8_WAVE_B_B0)
static M38B0Record g_b0_work_record;
static M38B0Record g_b0_last_record;
static uint32_t g_b0_sequence;
static uint8_t g_b0_has_record;
static uint8_t g_b0_active;
static uint64_t g_b0_safety_traversals;
static uint64_t g_b0_request_decodes;
static noun g_b0_primary_roots_before[RESOURCE_MAX_REGISTERED_SESSIONS];
static noun g_b0_refusal_roots_before[RESOURCE_MAX_REGISTERED_SESSIONS];
static void b0_note_safety_traversal(void);
static void b0_note_request_decode(void);

static void b0_zero(void *p, size_t n)
{
    uint8_t *bytes = (uint8_t *)p;
    for (size_t i = 0; i < n; i++) bytes[i] = 0;
}

static void b0_memory_point(M38B0MemoryPoint *out)
{
    out->persistent_cells = heap_cells_used(HEAP_MODE_PERSIST);
    out->persistent_bytes = out->persistent_cells * sizeof(cell_t);
    out->scratch_cells = heap_cells_used(HEAP_MODE_SCRATCH);
    out->scratch_bytes = out->scratch_cells * sizeof(cell_t);
    out->atom_bytes = atom_store_bytes_used();
    out->atom_index_occupancy = atom_store_index_occupancy();
    out->atom_index_probe_depth = atom_store_probe_hwm();
}

static void b0_peak_sample(void)
{
    if (!g_b0_active) return;
    M38B0MemoryPoint now;
    b0_memory_point(&now);
#define B0_MAX_FIELD(name) \
    if (now.name > g_b0_work_record.peak.name) g_b0_work_record.peak.name = now.name
    B0_MAX_FIELD(persistent_cells);
    B0_MAX_FIELD(persistent_bytes);
    B0_MAX_FIELD(scratch_cells);
    B0_MAX_FIELD(scratch_bytes);
    B0_MAX_FIELD(atom_bytes);
    B0_MAX_FIELD(atom_index_occupancy);
    B0_MAX_FIELD(atom_index_probe_depth);
#undef B0_MAX_FIELD
}

static uint64_t b0_live_roots(const ResourceRuntime *runtime)
{
    uint64_t count = 0;
    if (!runtime) return 0;
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        const ResourceSession *session = runtime->sessions[i];
        if (!session || session->state != 1) continue;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            if (session->catalog[j].core != NOUN_ZERO) count++;
            if (session->cache[j].valid) {
                if (session->cache[j].core != NOUN_ZERO) count++;
                if (session->cache[j].plan.formula != NOUN_ZERO) count++;
                if (session->cache[j].plan.payload != NOUN_ZERO) count++;
            }
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (session->slots[j].handle_root != NOUN_ZERO) count++;
            if (session->slots[j].state_root != NOUN_ZERO) count++;
            if (session->slots[j].snapshot_root != NOUN_ZERO) count++;
        }
        if (session->primary_root != NOUN_ZERO) count++;
        if (session->refusal_root != NOUN_ZERO) count++;
    }
    return count;
}

static void b0_generations(uint64_t *primary_a, uint64_t *refusal_a,
                           uint64_t *primary_b, uint64_t *refusal_b,
                           const ResourceRuntime *runtime)
{
    *primary_a = *refusal_a = *primary_b = *refusal_b = 0;
    if (!runtime) return;
    ResourceSession *a = runtime->sessions[0];
    ResourceSession *b = runtime->sessions[1];
    if (a && a->state == 1) {
        *primary_a = a->primary_generation;
        *refusal_a = a->refusal_generation;
    }
    if (b && b->state == 1) {
        *primary_b = b->primary_generation;
        *refusal_b = b->refusal_generation;
    }
}
#endif

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
#if defined(M38_D8_WAVE_B_B0)
        if (g_b0_active) b0_note_safety_traversal();
#endif
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

static int wave_forward_binding(noun value, uint32_t expected, int signed_profile)
{
    noun fields[3];
    uint32_t count;
    return wave_list(value, fields, 3, &count) && count == 3
        && wave_atom_text(fields[0], RESOURCE_BINDING_NAMES[expected])
        && wave_atom_text(fields[1], RESOURCE_BINDING_TAGS[expected])
        && wave_atom_text(fields[2], signed_profile && expected == 2
                          ? M41_VALUE_SCHEMA : RESOURCE_BINDING_SCHEMAS[expected]);
}

static int wave_record_validate(ResourceRuntime *runtime,
                                const SupervisorAdmissionEntry *entry,
                                noun record,
                                M38ResourceCoreDescriptor *descriptor_out)
{
    noun tag, body, fields[11];
    if (!wave_pair(record, &tag, &body)) return 0;
    int signed_profile = wave_atom_text(tag, M41_RECORD_TAG);
    if ((!signed_profile && !wave_atom_text(tag, RESOURCE_RECORD_TAG))
        || !wave_record(body, fields, 11)
        || !wave_atom_text(fields[0], signed_profile ? M41_RECORD_SCHEMA : RESOURCE_RECORD_SCHEMA)) {
        return 0;
    }
    M38ResourceCoreDescriptor descriptor = {0};
    if (!wave_atom_bytes(fields[1], descriptor.core_id, 32)
        || !wave_atom_bytes(fields[4], descriptor.battery_id, 32)
        || !wave_atom_bytes(fields[5], descriptor.payload_id, 32)) return 0;
    descriptor.profile_id = signed_profile ? M41_PROFILE : RESOURCE_PROFILE;
    uint32_t core_bytes;
    if (!wave_u(fields[2], RESOURCE_MAX_CORE_JAM_BYTES, &core_bytes)
        || core_bytes != entry->resource_core_jam_bytes
        || core_bytes == 0)
        return 0;
    uint8_t sha[32];
    sha256_hash(entry->resource_core_jam, entry->resource_core_jam_bytes, sha);
    if (!wave_identity(fields[3], sha)) return 0;
    noun bindings[15], supported[3], nested[13], limits[3];
    uint32_t count;
    if (!wave_list(fields[6], bindings, 15, &count) || count != 15) return 0;
    for (uint32_t i = 0; i < count; i++)
        if (!wave_forward_binding(bindings[i], i, signed_profile)) return 0;
    uint32_t scalar_count = signed_profile ? 3u : 2u;
    if (!wave_atom_text(fields[7], descriptor.profile_id)
        || !wave_list(fields[8], supported, scalar_count, &count) || count != scalar_count)
        return 0;
    for (uint32_t i = 0; i < scalar_count; i++) {
        noun sf[3];
        if (!wave_record(supported[i], sf, 3)
            || !wave_atom_text(sf[0], i == 0 ? "BOOL" : i == 1 ? "UINT16" : "INT16")
            || !wave_u(sf[1], scalar_count, &core_bytes) || core_bytes != i + 1u
            || !wave_u(sf[2], i == 0 ? 1 : 65535, &core_bytes)
            || core_bytes != (i == 0 ? 1u : 65535u))
            return 0;
    }
    if (!wave_list(fields[9], nested, 13, &count) || count != 13) return 0;
    for (uint32_t i = 0; i < 13; i++)
        if (!wave_atom_text(nested[i], signed_profile && i == 0
                            ? M41_VALUE_SCHEMA : RESOURCE_NESTED_SCHEMAS[i])) return 0;
    if (!wave_list(fields[10], limits, 3, &count) || count != 3
        || !wave_u(limits[0], 2000000, &core_bytes) || core_bytes != 2000000u
        || !wave_u(limits[1], 128000, &core_bytes) || core_bytes != 128000u
        || !wave_u(limits[2], 1024, &core_bytes) || core_bytes != 1024u)
        return 0;

    const uint8_t *canonical;
    uint64_t canonical_bytes;
    uint8_t admission_id[32];
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, 2000000ULL);
    if (jam_encode_bytes_identity_bounded(record, &canonical, &canonical_bytes, &budget) != 0
        || canonical_bytes > RESOURCE_MAX_RECORD_JAM_BYTES)
        return 0;
    const char *admission_domain = signed_profile ? M41_ADMISSION_DOMAIN : RESOURCE_ADMISSION_DOMAIN;
    size_t domain_bytes = wave_strlen(admission_domain);
    if (domain_bytes + canonical_bytes > RESOURCE_SAFETY_WORK_BYTES) return 0;
    uint8_t *preimage = (uint8_t *)runtime->workspace + RESOURCE_SAFETY_WORK_OFFSET;
    for (size_t i = 0; i < domain_bytes; i++) preimage[i] = (uint8_t)admission_domain[i];
    for (uint64_t i = 0; i < canonical_bytes; i++) preimage[domain_bytes + i] = canonical[i];
    sha256_hash(preimage, domain_bytes + (size_t)canonical_bytes, admission_id);
    wave_copy(descriptor.admission_id, admission_id, sizeof(admission_id));
    *descriptor_out = descriptor;
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
        || (!wave_atom_text(pf[0], "m38-d0-r2-resource-payload-schema-v2")
            && !wave_atom_text(pf[0], M41_PAYLOAD_SCHEMA))
        || !wave_record(pf[1], semantic, 5)
        || !wave_list(semantic[0], types, RESOURCE_MAX_PLAN_TYPES, &type_count)
        || !wave_list(semantic[1], instances, RESOURCE_MAX_PLAN_INSTANCES, &instance_count)
        || type_count == 0 || instance_count == 0)
        return 0;
    WavePlan plan = {0};
    plan.scalar_count = wave_atom_text(pf[0], M41_PAYLOAD_SCHEMA) ? 3u : 2u;
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
                || type->event_ids[j] != j + 1u
                || !wave_u(ef[1], 2, &direction)
                || !wave_list(ef[2], event_values, RESOURCE_MAX_PLAN_VALUES,
                              &event_value_count))
                return 0;
            type->event_value_counts[j] = event_value_count;
            type->event_directions[j] = direction;
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
                || !wave_u(vf[2], plan.scalar_count, &type->value_types[j])
                || type->value_types[j] == 0
                || !wave_u(vf[3], type->value_types[j] == 1 ? 1 : 65535,
                           &type->value_initials[j]))
                return 0;
        }
        for (uint32_t j = 0; j < event_count; j++)
            for (uint32_t k = 0; k < type->event_value_counts[j]; k++) {
                if (type->event_value_ids[j][k] > value_count) return 0;
                for (uint32_t l = 0; l < k; l++)
                    if (type->event_value_ids[j][k] == type->event_value_ids[j][l]) return 0;
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
    /* Boundary rows are part of the admitted payload, never inferred from a
     * first matching FB type. Globally qualified codes preserve instance
     * identity even when several instances share one type. */
    for (uint32_t direction = 0; direction < 2; direction++) {
        noun endpoints[RESOURCE_MAX_BOUNDARIES];
        uint32_t count;
        if (!wave_list(semantic[3 + direction], endpoints, RESOURCE_MAX_BOUNDARIES, &count)) return 0;
        plan.boundary_counts[direction] = count;
        for (uint32_t i = 0; i < count; i++) {
            noun ef[3], values[RESOURCE_MAX_PLAN_VALUES];
            uint32_t instance, code, value_count;
            if (!wave_record(endpoints[i], ef, 3)
                || !wave_u(ef[0], plan.instance_count, &instance) || instance == 0
                || !wave_u(ef[1], 65535, &code)
                || code / 1024u != instance || code % 1024u == 0
                || !wave_list(ef[2], values, RESOURCE_MAX_PLAN_VALUES, &value_count)) return 0;
            WavePlanType *type = &plan.types[plan.instance_types[instance - 1u] - 1u];
            uint32_t event = code % 1024u - 1u;
            if (event >= type->event_count || type->event_directions[event] != direction
                || value_count != type->event_value_counts[event]) return 0;
            for (uint32_t j = 0; j < value_count; j++) {
                noun vf[2];
                uint32_t id, kind, local = type->event_value_ids[event][j];
                if (!wave_record(values[j], vf, 2) || !wave_u(vf[0], 65535, &id)
                    || id != instance * 1024u + local
                    || !wave_u(vf[1], plan.scalar_count, &kind) || kind != type->value_types[local - 1u]) return 0;
            }
            for (uint32_t j = 0; j < i; j++)
                if (plan.boundaries[direction][j].instance == instance - 1u
                    && plan.boundaries[direction][j].event == event) return 0;
            plan.boundaries[direction][i] = (WaveEndpoint){instance - 1u, event};
        }
    }
    *out = plan;
    return 1;
}

static int wave_core_validate(ResourceRuntime *runtime, noun core,
                              const M38ResourceCoreDescriptor *descriptor,
                              const uint8_t *expected_jam, size_t expected_jam_bytes,
                              WavePlan *plan)
{
    noun formula, payload;
    if (!wave_pair(core, &formula, &payload) || !wave_parse_plan(core, plan)) return 0;
    if (descriptor->profile_id != (plan->scalar_count == 3 ? M41_PROFILE : RESOURCE_PROFILE))
        return 0;
    uint8_t digest[32];
    if (!wave_domain_digest(runtime, formula, RESOURCE_FORMULA_DOMAIN, digest)
        || !wave_bytes_equal(digest, descriptor->battery_id, sizeof(digest))
        || !wave_domain_digest(runtime, payload, RESOURCE_PAYLOAD_DOMAIN, digest)
        || !wave_bytes_equal(digest, descriptor->payload_id, sizeof(digest))
        || !wave_domain_digest(runtime, core, RESOURCE_CORE_DOMAIN, digest)
        || !wave_bytes_equal(digest, descriptor->core_id, sizeof(digest))) return 0;
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
    M38ResourceCoreDescriptor descriptor;
    uint32_t core_jam_bytes;
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

#if defined(M38_D8_WAVE_B_B0)
static void b0_begin(ResourceSession *session)
{
    b0_zero(&g_b0_work_record, sizeof(g_b0_work_record));
    g_b0_active = 1;
    g_b0_safety_traversals = 0;
    g_b0_request_decodes = 0;
    b0_zero(g_b0_primary_roots_before, sizeof(g_b0_primary_roots_before));
    b0_zero(g_b0_refusal_roots_before, sizeof(g_b0_refusal_roots_before));
    noun_b0_copy_metrics_reset();
    nock_b0_metrics_reset();
    g_b0_work_record.schema_version = M38_B0_SCHEMA_VERSION;
    g_b0_work_record.image_identity = M38_B0_IMAGE_ID;
    g_b0_work_record.contract_identity = M38_B0_CONTRACT_ID;
    if (wave_session_valid(session)) {
        ResourceRuntime *runtime = session->runtime;
        g_b0_work_record.session_id = (uint8_t)(session->registry_index + 1u);
        g_b0_work_record.resource_core_parse_count_before = session->parse_count;
        g_b0_work_record.registered_sessions_before = runtime->session_count;
        g_b0_work_record.live_roots_before = b0_live_roots(runtime);
        g_b0_work_record.semispace_before = (uint8_t)heap_persist_selector();
        for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
            ResourceSession *other = runtime->sessions[i];
            g_b0_primary_roots_before[i] = other ? other->primary_root : NOUN_ZERO;
            g_b0_refusal_roots_before[i] = other ? other->refusal_root : NOUN_ZERO;
        }
        b0_generations(&g_b0_work_record.primary_generation_a_before,
                       &g_b0_work_record.refusal_generation_a_before,
                       &g_b0_work_record.primary_generation_b_before,
                       &g_b0_work_record.refusal_generation_b_before, runtime);
    }
    b0_memory_point(&g_b0_work_record.before);
    g_b0_work_record.peak = g_b0_work_record.before;
    g_b0_work_record.scratch_entry_mark = heap_scratch_mark();
}

static void b0_finish(M38Status status, const ResourceResultView **out_view)
{
    if (!g_b0_active) return;
    ResourceRuntime *runtime = 0;
    if (g_wave_runtime_lease && g_wave_runtime_lease->state != 0)
        runtime = g_wave_runtime_lease;
    b0_peak_sample();
    b0_memory_point(&g_b0_work_record.after);
    g_b0_work_record.scratch_final_mark = heap_scratch_mark();
    g_b0_work_record.scratch_rewound =
        g_b0_work_record.scratch_final_mark == g_b0_work_record.scratch_entry_mark;
    g_b0_work_record.semispace_after = runtime ? (uint8_t)heap_persist_selector() : 0;
    g_b0_work_record.registered_sessions_after = runtime ? runtime->session_count : 0;
    g_b0_work_record.live_roots_after = b0_live_roots(runtime);
    g_b0_work_record.promotion_delta =
        g_b0_work_record.semispace_after != g_b0_work_record.semispace_before;
    if (runtime) {
        ResourceSession *session = g_b0_work_record.session_id == 0 ? 0
            : runtime->sessions[g_b0_work_record.session_id - 1u];
        g_b0_work_record.resource_core_parse_count_after = session ? session->parse_count : 0;
        b0_generations(&g_b0_work_record.primary_generation_a_after,
                       &g_b0_work_record.refusal_generation_a_after,
                       &g_b0_work_record.primary_generation_b_after,
                       &g_b0_work_record.refusal_generation_b_after, runtime);
    }
    g_b0_work_record.final_status = (uint32_t)status;
    g_b0_work_record.view_published = out_view && *out_view ? 1u : 0u;
    g_b0_work_record.semantic_roots_preserved = 0u;
    if (status != M38_STATUS_OK && runtime
        && g_b0_work_record.semispace_after == g_b0_work_record.semispace_before) {
        g_b0_work_record.semantic_roots_preserved = 1u;
        for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
            ResourceSession *other = runtime->sessions[i];
            if (!other || other->primary_root != g_b0_primary_roots_before[i]
                || other->refusal_root != g_b0_refusal_roots_before[i])
                g_b0_work_record.semantic_roots_preserved = 0u;
        }
    }
    g_b0_work_record.wire_status =
        (status == M38_STATUS_OK && out_view && *out_view) ? (*out_view)->wire_status : 0;
    g_b0_work_record.evaluator_ops = nock_ops_used();
    g_b0_work_record.evaluator_cells = nock_cells_used();
    g_b0_work_record.evaluator_peak_depth = nock_eval_stack_peak();
    g_b0_work_record.evaluator_aborted = nock_budget_abort_reason() != 0;
    g_b0_work_record.request_safety_traversal_count = g_b0_safety_traversals;
    g_b0_work_record.request_decode_count = g_b0_request_decodes;
    g_b0_work_record.copied_session_a_cells = noun_b0_copy_cells(M38_B0_COPY_SESSION_A);
    g_b0_work_record.copied_session_b_cells = noun_b0_copy_cells(M38_B0_COPY_SESSION_B);
    g_b0_work_record.copied_staged_cells = noun_b0_copy_cells(M38_B0_COPY_STAGED);
    g_b0_work_record.copy_map_passes = noun_b0_copy_passes();
    g_b0_work_record.copy_map_clear_bytes = noun_b0_copy_clear_bytes();
    g_b0_work_record.copy_map_peak_entries = noun_b0_copy_peak_entries();
    g_b0_work_record.copy_map_peak_probe_depth = noun_b0_copy_peak_probe_depth();
    g_b0_work_record.sequence = g_b0_sequence == UINT32_MAX ? UINT32_MAX : ++g_b0_sequence;
    g_b0_last_record = g_b0_work_record;
    g_b0_has_record = 1;
    g_b0_active = 0;
}

void m38_resource_b0_reset(void)
{
    b0_zero(&g_b0_work_record, sizeof(g_b0_work_record));
    b0_zero(&g_b0_last_record, sizeof(g_b0_last_record));
    g_b0_sequence = 0;
    g_b0_has_record = 0;
    g_b0_active = 0;
}

int m38_resource_b0_read(M38B0Record *out)
{
    if (!out || !g_b0_has_record) return 0;
    *out = g_b0_last_record;
    g_b0_has_record = 0;
    return 1;
}

static void b0_note_safety_traversal(void) { g_b0_safety_traversals++; }
static void b0_note_request_decode(void) { g_b0_request_decodes++; }
static void b0_set_operation(uint32_t operation)
{
    g_b0_work_record.operation = operation <= M38_B0_OP_RESTORE ? (uint8_t)operation : 0;
}
#endif

static void wave_broker_release(ResourceRuntime *runtime)
{
    runtime->broker_owner = 0;
    runtime->state = 2;
}

static M38Status wave_fault_status(WaveFaultPoint fault)
{
    switch (fault) {
    case WAVE_FAULT_BROKER_BEGIN: return M38_STATUS_BROKER_BEGIN;
    case WAVE_FAULT_CUE_CACHE_INSERT: return M38_STATUS_CUE_CACHE_INSERT;
    case WAVE_FAULT_SLOT_PUBLICATION: return M38_STATUS_SLOT_PUBLICATION;
    case WAVE_FAULT_EVALUATOR_ABORT: return M38_STATUS_EVALUATOR_ABORT;
    case WAVE_FAULT_ATOM_RESULT_STAGING: return M38_STATUS_ATOM_RESULT_STAGING;
    case WAVE_FAULT_COLLECTIVE_COMMIT: return M38_STATUS_COLLECTIVE_COMMIT;
    case WAVE_FAULT_RESTORE_COMMIT: return M38_STATUS_RESTORE_COMMIT;
    default: return M38_STATUS_INTERNAL;
    }
}

static M38Status wave_take_fault(ResourceRuntime *runtime, WaveFaultPoint point)
{
    if (runtime->next_fault == (uint8_t)point) {
        runtime->next_fault = (uint8_t)WAVE_FAULT_NONE;
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
#if defined(M38_D8_WAVE_B_B0)
        noun_b0_copy_domain_set((M38B0CopyDomain)(i + 1u));
#endif
#if defined(M38_D8_WAVE_B_B3)
        noun_b3_copy_domain_set((M38B3CopyDomain)(i + 1u));
#endif
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(session->catalog[j].core, &copies[i].catalog[j])) goto fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            /* An empty execution-cache entry owns no roots.  Do not copy
             * whatever happens to be in its zeroed/stale payload fields as
             * though admission authority had already become executable. */
            if (!session->cache[j].valid) continue;
            if (!wave_copy_root(session->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(session->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(session->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto fail;
        }
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
            if (session->cache[j].valid) {
                session->cache[j].core = copies[i].cache_core[j];
                session->cache[j].plan.formula = copies[i].cache_formula[j];
                session->cache[j].plan.payload = copies[i].cache_payload[j];
            } else {
                session->cache[j].core = NOUN_ZERO;
                session->cache[j].plan.formula = NOUN_ZERO;
                session->cache[j].plan.payload = NOUN_ZERO;
            }
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
    M38ResourceCoreDescriptor descriptor;
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (cue_bounded_bytes(entry->record_jam, entry->record_jam_bytes,
                          &cue_i2_limits, HEAP_MODE_SCRATCH, &record) != CUE_BOUNDED_OK)
        return 0;
    if (!wave_record_validate(runtime, entry, record, &descriptor)) {
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
        || !wave_core_validate(runtime, core, &descriptor,
                               entry->resource_core_jam, entry->resource_core_jam_bytes,
                               &out->plan)) {
        if (noun_tx_active()) noun_tx_abort();
        return 0;
    }
    out->descriptor = descriptor;
    out->core_jam_bytes = (uint32_t)entry->resource_core_jam_bytes;
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
            if (wave_bytes_equal(out[j].descriptor.core_id,
                                 out[i].descriptor.core_id, 32))
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
            if (session->cache[j].valid) {
                session->cache[j].core = copies[i].cache_core[j];
                session->cache[j].plan.formula = copies[i].cache_formula[j];
                session->cache[j].plan.payload = copies[i].cache_payload[j];
            } else {
                session->cache[j].core = NOUN_ZERO;
                session->cache[j].plan.formula = NOUN_ZERO;
                session->cache[j].plan.payload = NOUN_ZERO;
            }
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
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            if (!session->cache[j].valid) continue;
            if (!wave_copy_root(session->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(session->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(session->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto fail;
        }
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
            || !wave_core_validate(runtime, new_cores[i], &pre[i].descriptor,
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
        WaveCatalogCopy *copy = &session->catalog[i];
        copy->valid = 1;
        copy->descriptor_storage = pre[i].descriptor;
        copy->descriptor = &copy->descriptor_storage;
        copy->core = new_cores[i];
        copy->core_jam_bytes = pre[i].core_jam_bytes;
        wave_copy(copy->core_jam, catalog->entries[i].resource_core_jam, pre[i].core_jam_bytes);
        /* Admission validation proves the catalog/core authority.  The
         * execution plan is deliberately decoded only by the first LOAD,
         * where cache, slot, and result publish as one operation. */
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

#if defined(M38_D8_WAVE_B_TEST_CONTROLS)
void m38_resource_test_fail_next(ResourceRuntime *runtime, M38FaultPoint fault)
{
    if (wave_runtime_valid(runtime) && fault >= M38_FAULT_NONE
        && fault <= M38_FAULT_RESTORE_COMMIT)
        runtime->next_fault = (uint8_t)fault;
}
#endif

#if defined(M38_D8_WAVE_B_B2)
void m38_resource_b2_snapshot(M38B2Snapshot *out)
{
    if (!out) return;
    b2_zero(out, sizeof(*out));
    ResourceRuntime *runtime = g_wave_runtime_lease;
    out->persist_selector = heap_persist_selector();
    out->persistent_cells = heap_cells_used(HEAP_MODE_PERSIST);
    out->scratch_cells = heap_cells_used(HEAP_MODE_SCRATCH);
    out->atom_bytes = atom_store_bytes_used();
    out->atom_index_occupancy = atom_store_index_occupancy();
    out->atom_index_probe_depth = atom_store_probe_hwm();
    out->scratch_mark = heap_scratch_mark();
    out->noun_transaction_active = noun_tx_active();
    out->evaluator_ops = nock_ops_used();
    out->evaluator_cells = nock_cells_used();
    out->evaluator_peak_depth = nock_eval_stack_peak();
    out->evaluator_abort_reason = nock_budget_abort_reason();
    if (!wave_runtime_valid(runtime)) return;
    out->runtime_state = runtime->state;
    out->broker_owner = runtime->broker_owner;
    out->session_count = runtime->session_count;
    out->next_capability = runtime->next_capability;
    out->broker_transaction_id = runtime->broker_transaction_id;
    out->promoted_root_count = runtime->promoted_root_count;
    out->next_fault = runtime->next_fault;
    out->live_roots = b2_live_roots(runtime);
    for (uint32_t i = 0; i < RESOURCE_MAX_REGISTERED_SESSIONS; i++) {
        const ResourceSession *session = runtime->sessions[i];
        M38B2SessionSnapshot *copy = &out->sessions[i];
        if (!session) continue;
        copy->state = session->state;
        copy->in_flight = session->in_flight;
        copy->registry_index = session->registry_index;
        copy->capability = session->capability;
        copy->primary_root = session->primary_root;
        copy->refusal_root = session->refusal_root;
        copy->primary_view_root_slot = (uint64_t)(uintptr_t)session->primary_view.root_slot;
        copy->refusal_view_root_slot = (uint64_t)(uintptr_t)session->refusal_view.root_slot;
        copy->primary_view_generation = session->primary_view.generation;
        copy->refusal_view_generation = session->refusal_view.generation;
        copy->primary_view_wire = session->primary_view.wire_status;
        copy->refusal_view_wire = session->refusal_view.wire_status;
        copy->primary_view_owner = session->primary_view.owner;
        copy->refusal_view_owner = session->refusal_view.owner;
        copy->parse_count = session->parse_count;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            if (session->catalog[j].valid) copy->catalog_valid_mask |= UINT64_C(1) << j;
            if (session->cache[j].valid) copy->cache_valid_mask |= UINT64_C(1) << j;
            copy->catalog_roots[j] = session->catalog[j].core;
            copy->cache_roots[j] = session->cache[j].core;
            copy->cache_formula_roots[j] = session->cache[j].plan.formula;
            copy->cache_payload_roots[j] = session->cache[j].plan.payload;
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            const WaveSlot *slot = &session->slots[j];
            if (slot->used) copy->slot_used_mask |= UINT64_C(1) << j;
            copy->slot_catalog[j] = slot->catalog_index;
            copy->slot_generation[j] = slot->generation;
            copy->slot_snapshot_nonce[j] = slot->snapshot_nonce;
            copy->slot_handle_roots[j] = slot->handle_root;
            copy->slot_state_roots[j] = slot->state_root;
            copy->slot_snapshot_roots[j] = slot->snapshot_root;
        }
    }
}

void m38_resource_test_invalidate_cache(ResourceSession *session,
                                        uint32_t catalog_index)
{
    if (wave_session_valid(session)
        && catalog_index < RESOURCE_MAX_ADMISSION_ENTRIES)
        session->cache[catalog_index].valid = 0;
}

void m38_resource_test_hold_runtime_busy(ResourceRuntime *runtime)
{
    if (!wave_runtime_valid(runtime)) return;
    runtime->broker_owner = 3;
    runtime->state = 3;
}

void m38_resource_test_hold_session_busy(ResourceSession *session)
{
    if (wave_session_valid(session)) session->in_flight = 1;
}

void m38_resource_test_release_busy(ResourceRuntime *runtime,
                                    ResourceSession *session)
{
    if (wave_runtime_valid(runtime)) {
        runtime->broker_owner = 0;
        runtime->state = 2;
    }
    if (wave_session_valid(session)) session->in_flight = 0;
}
#endif

static int wave_handle_build(const ResourceSession *session, uint32_t slot,
                             uint64_t generation, uint32_t catalog_index,
                             noun *out)
{
    noun fields[4], admission;
    if (catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[catalog_index].descriptor
        || !wave_digest_atom(session->catalog[catalog_index].descriptor->admission_id,
                             &admission))
        return 0;
    if (!wave_capability_atom(session->capability, &fields[0])
        || !wave_u64_atom(generation, &fields[2])) return 0;
    fields[1] = direct(slot);
    fields[3] = admission;
    return wave_build_record(fields, 4, out);
}

static const char *wave_value_schema(const WavePlan *plan)
{
    return plan->scalar_count == 3 ? M41_VALUE_SCHEMA : RESOURCE_VALUE_SCHEMA;
}

static int wave_value_build(const WavePlan *plan, uint32_t id, uint32_t type, uint32_t value, noun *out)
{
    noun fields[3] = {direct(id), direct(type), direct(value)};
    return wave_build_tagged(RESOURCE_VALUE_TAG, wave_value_schema(plan), fields, 3, out);
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
            if (!wave_value_build(plan, type->value_ids[value], type->value_types[value],
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
    if (catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[catalog_index].descriptor
        || !wave_digest_atom(session->catalog[catalog_index].descriptor->admission_id,
                             &admission)) return 0;
    noun fields[3] = {admission,
                      wave_cord(session->catalog[catalog_index].descriptor->profile_id),
                      instance_list};
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

static int wave_outputs_build(const WavePlan *plan, noun source,
                               noun *effects_out, noun *observations_out)
{
    noun rows[32], effects[32], observations[32];
    uint32_t count;
    if (!wave_list(source, rows, 32, &count)) return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun instance_n, tail, event_n, values_n, values[RESOURCE_MAX_PLAN_VALUES];
        uint32_t instance, output, count_values;
        if (!wave_pair(rows[i], &instance_n, &tail)
            || !wave_pair(tail, &event_n, &values_n)
            || !wave_u(instance_n, plan->instance_count, &instance) || instance == 0
            || !wave_u(event_n, RESOURCE_MAX_PLAN_EVENTS, &output) || output == 0
            || !wave_list(values_n, values, RESOURCE_MAX_PLAN_VALUES, &count_values)) return 0;
        const WavePlanType *type = &plan->types[plan->instance_types[instance - 1u] - 1u];
        uint32_t ordinal = 0, event = type->event_count;
        for (uint32_t j = 0; j < type->event_count; j++)
            if (type->event_directions[j] == 1 && ++ordinal == output) { event = j; break; }
        if (event == type->event_count || count_values != type->event_value_counts[event]) return 0;
        uint32_t admitted = 0;
        for (uint32_t j = 0; j < plan->boundary_counts[1]; j++)
            if (plan->boundaries[1][j].instance == instance - 1u
                && plan->boundaries[1][j].event == event) admitted++;
        if (admitted != 1) return 0;
        noun typed[RESOURCE_MAX_PLAN_VALUES];
        for (uint32_t j = 0; j < count_values; j++) {
            noun vf[3];
            uint32_t id, kind, raw, local = type->event_value_ids[event][j];
            if (!wave_record(values[j], vf, 3) || !wave_u(vf[0], RESOURCE_MAX_PLAN_VALUES, &id)
                || id != local || !wave_u(vf[1], plan->scalar_count, &kind)
                || kind != type->value_types[local - 1u]
                || !wave_u(vf[2], kind == 1 ? 1 : 65535, &raw)
                || !wave_value_build(plan, instance * 1024u + local, kind, raw, &typed[j])) return 0;
        }
        noun list;
        if (!wave_build_list(typed, count_values, &list)) return 0;
        noun fields[2] = {direct(instance * 1024u + event + 1u), list};
        if (!wave_build_tagged(RESOURCE_EFFECT_TAG, RESOURCE_EFFECT_SCHEMA, fields, 2, &effects[i])
            || !wave_build_tagged(RESOURCE_OBSERVATION_TAG, RESOURCE_OBSERVATION_SCHEMA,
                                  fields, 2, &observations[i])) return 0;
    }
    noun list;
    if (!wave_build_list(effects, count, &list)
        || !wave_build_tagged(RESOURCE_EFFECTS_TAG, RESOURCE_EFFECTS_SCHEMA, &list, 1, effects_out)
        || !wave_build_list(observations, count, &list)
        || !wave_build_tagged(RESOURCE_OBSERVATIONS_TAG, RESOURCE_OBSERVATIONS_SCHEMA,
                              &list, 1, observations_out)) return 0;
    return 1;
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
        || !session->catalog[session->slots[slot - 1u].catalog_index].descriptor
        || !wave_identity(fields[3], session->catalog[session->slots[slot - 1u].catalog_index].descriptor->admission_id)
        || !session->slots[slot - 1u].used
        || session->slots[slot - 1u].generation != generation)
        return 0;
    *slot_out = slot - 1u;
    return 1;
}

/* Local codes are retained only for a unique external endpoint, for the
 * historical D8 callers. Forward callers use the qualified code. */
static int wave_ingress(const WavePlan *plan, uint32_t code, WaveEndpoint *out)
{
    uint32_t matches = 0;
    for (uint32_t i = 0; i < plan->boundary_counts[0]; i++) {
        WaveEndpoint endpoint = plan->boundaries[0][i];
        uint32_t local = endpoint.event + 1u;
        if (code == (endpoint.instance + 1u) * 1024u + local
            || (code < 1024u && code == local)) {
            *out = endpoint;
            matches++;
        }
    }
    return matches == 1;
}

static int wave_stimulus_validate(const WavePlan *plan, noun stimulus)
{
    noun tag, body, fields[3], values[RESOURCE_MAX_VALUES];
    uint32_t count, event;
    WaveEndpoint endpoint;
    if (!wave_pair(stimulus, &tag, &body)
        || !wave_atom_text(tag, RESOURCE_STIMULUS_TAG)
        || !wave_record(body, fields, 3)
        || !wave_atom_text(fields[0], RESOURCE_STIMULUS_SCHEMA)
        || !wave_u(fields[1], 0xFFFF, &event) || event == 0
        || !wave_ingress(plan, event, &endpoint)
        || !wave_list(fields[2], values, RESOURCE_MAX_VALUES, &count)) return 0;
    const WavePlanType *type = &plan->types[plan->instance_types[endpoint.instance] - 1u];
    if (count != type->event_value_counts[endpoint.event]) return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun vf[4];
        uint32_t id, kind, raw, local = type->event_value_ids[endpoint.event][i];
        uint32_t expected = event < 1024u ? local : (endpoint.instance + 1u) * 1024u + local;
        if (!wave_pair(values[i], &tag, &body)
            || !wave_atom_text(tag, RESOURCE_VALUE_TAG)
            || !wave_record(body, vf, 4)
            || !wave_atom_text(vf[0], wave_value_schema(plan))
            || !wave_u(vf[1], 0xFFFF, &id) || id != expected
            || !wave_u(vf[2], plan->scalar_count, &kind) || kind != type->value_types[local - 1u]
            || !wave_u(vf[3], kind == 1 ? 1 : 65535, &raw)) return 0;
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
    uint32_t instance = target < 1024u ? 0u : target / 1024u - 1u;
    uint32_t local = target < 1024u ? target : target % 1024u;
    if (instance >= plan->instance_count || local == 0
        || local > plan->types[plan->instance_types[instance] - 1u].value_count) return 0;
    *target_out = target;
    return 1;
}

typedef struct WaveRequest {
    uint32_t operation;
    noun first;
    noun second;
} WaveRequest;

static int wave_request_decode(noun request, WaveRequest *out)
{
#if defined(M38_D8_WAVE_B_B0)
    if (g_b0_active) b0_note_request_decode();
#endif
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
        if (entry->valid && entry->descriptor && bytes == entry->core_jam_bytes
            && wave_bytes_equal(canonical, entry->core_jam, bytes)
            && wave_bytes_equal(identity, entry->descriptor->core_id, sizeof(identity))) {
            *index_out = i;
            return 1;
        }
    }
    return 0;
}

static int wave_observation_build(const WavePlan *plan, const WaveSlot *slot,
                                  uint32_t target, noun *out)
{
    uint32_t instance = target < 1024u ? 0u : target / 1024u - 1u;
    uint32_t local = target < 1024u ? target : target % 1024u;
    if (instance >= plan->instance_count || local == 0) return 0;
    const WavePlanType *type = &plan->types[plan->instance_types[instance] - 1u];
    if (local > type->value_count) return 0;
    noun typed, values;
    if (!wave_value_build(plan, target, type->value_types[local - 1u],
                          slot->state_values[instance][local - 1u], &typed)
        || !wave_build_list(&typed, 1, &values)) return 0;
    noun fields[2] = {direct(target), values};
    return wave_build_tagged(RESOURCE_OBSERVATION_TAG, RESOURCE_OBSERVATION_SCHEMA, fields, 2, out);
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
        || !session->catalog[catalog_index].descriptor
        || !wave_identity(state_fields[1], session->catalog[catalog_index].descriptor->admission_id)
        || !wave_atom_text(state_fields[2], session->catalog[catalog_index].descriptor->profile_id)) return 0;
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
                || !wave_atom_text(value_fields[0], wave_value_schema(plan))
                || !wave_u(value_fields[1], RESOURCE_MAX_PLAN_VALUES, &value_id)
                || value_id != type->value_ids[j]
                || !wave_u(value_fields[2], plan->scalar_count, &value_type)
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

#if defined(M46_LIVE_REPLACEMENT)
static void m46_close_fixed(ResourceSession *session);
#endif
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
    uint64_t next_result_generation = 0;
#if defined(M44_TWO_RESOURCE)
    const M44PublicationHooks *hooks = session->m44_hooks;
    const WaveM44Group *group = session->m44_group;
    noun group_handles[2], group_states[2], group_snapshots[2];
    int participant = hooks && (wire_status == RESOURCE_WIRE_POKE || group
                                || owner == M38_RESULT_OWNER_NONE);
    if (owner == M38_RESULT_OWNER_NONE && !participant) {
        *failure = M38_STATUS_SLOT_PUBLICATION;
        return 0;
    }
    if (participant && !hooks->prepare(hooks->context, staged_result)) {
        *failure = M38_STATUS_SLOT_PUBLICATION;
        return 0;
    }
    if (owner != M38_RESULT_OWNER_NONE)
#endif
    if (owner != M38_RESULT_OWNER_PRIMARY && owner != M38_RESULT_OWNER_REFUSAL) {
        *failure = M38_STATUS_SLOT_PUBLICATION;
        return 0;
    }
#if defined(M44_TWO_RESOURCE)
    if (owner != M38_RESULT_OWNER_NONE)
#endif
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
#if defined(M38_D8_WAVE_B_B0)
        noun_b0_copy_domain_set((M38B0CopyDomain)(i + 1u));
#endif
#if defined(M38_D8_WAVE_B_B3)
        noun_b3_copy_domain_set((M38B3CopyDomain)(i + 1u));
#endif
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++)
            if (!wave_copy_root(other->catalog[j].core, &copies[i].catalog[j])) goto collective_fail;
        for (uint32_t j = 0; j < RESOURCE_MAX_ADMISSION_ENTRIES; j++) {
            if (!other->cache[j].valid) continue;
            if (!wave_copy_root(other->cache[j].core, &copies[i].cache_core[j])
                || !wave_copy_root(other->cache[j].plan.formula,
                                   &copies[i].cache_formula[j])
                || !wave_copy_root(other->cache[j].plan.payload,
                                   &copies[i].cache_payload[j])) goto collective_fail;
        }
        for (uint32_t j = 0; j < RESOURCE_MAX_LIVE_HANDLES; j++) {
            if (!wave_copy_root(other->slots[j].handle_root, &copies[i].handle[j])) goto collective_fail;
            if (!wave_copy_root(other->slots[j].state_root, &copies[i].state[j])) goto collective_fail;
            if (!wave_copy_root(other->slots[j].snapshot_root, &copies[i].snapshot[j])) goto collective_fail;
        }
        if (!wave_copy_root(other->primary_root, &copies[i].primary)) goto collective_fail;
        if (!wave_copy_root(other->refusal_root, &copies[i].refusal)) goto collective_fail;
    }
 #if defined(M38_D8_WAVE_B_B0)
    noun_b0_copy_domain_set(M38_B0_COPY_STAGED);
#endif
#if defined(M38_D8_WAVE_B_B3)
    noun_b3_copy_domain_set(M38_B3_COPY_STAGED);
#endif
    if (!wave_copy_root(staged_handle, &handle_copy)
        || !wave_copy_root(staged_state, &state_copy)
        || !wave_copy_root(staged_snapshot, &snapshot_copy)
        || !wave_copy_root(staged_result, &result_copy))
        goto collective_fail;
#if defined(M44_TWO_RESOURCE)
    if (group) {
        for (uint32_t i = 0; i < 2; i++) {
            if (!wave_copy_root(group->slots[i].handle_root, &group_handles[i])
                || !wave_copy_root(group->slots[i].state_root, &group_states[i])
                || !wave_copy_root(group->slots[i].snapshot_root, &group_snapshots[i]))
                goto collective_fail;
#if defined(M44_G0_TEST_CONTROLS)
            if (i == 0 && session->m44_test_fault == 2) {
                session->m44_test_fault = 0;
                goto collective_fail;
            }
#endif
        }
    }
#if defined(M44_G0_TEST_CONTROLS)
    if (session->m44_test_fault == 1) {
        session->m44_test_fault = 0;
        goto collective_fail;
    }
#endif
#endif
#if defined(M38_D8_WAVE_B_B0)
    b0_peak_sample();
#endif
    heap_persist_commit_tx();
    wave_apply_root_copies(runtime, copies);
    if (owner == M38_RESULT_OWNER_PRIMARY)
        session->primary_root = result_copy;
    else if (owner == M38_RESULT_OWNER_REFUSAL)
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
        session->primary_view.generation = session->primary_generation;
        session->primary_view.wire_status = wire_status;
        session->primary_view.owner = M38_RESULT_OWNER_PRIMARY;
    } else if (owner == M38_RESULT_OWNER_REFUSAL) {
        session->refusal_generation = next_result_generation;
        session->refusal_view.root_slot = &session->refusal_root;
        session->refusal_view.generation = session->refusal_generation;
        session->refusal_view.wire_status = wire_status;
        session->refusal_view.owner = M38_RESULT_OWNER_REFUSAL;
    }
#if defined(M44_TWO_RESOURCE)
    if (group) {
        for (uint32_t i = 0; i < 2; i++) {
            session->slots[group->index[i]] = group->slots[i];
            session->slots[group->index[i]].handle_root = group_handles[i];
            session->slots[group->index[i]].state_root = group_states[i];
            session->slots[group->index[i]].snapshot_root = group_snapshots[i];
        }
    }
#if defined(M46_LIVE_REPLACEMENT)
    if (session->m46_source) m46_close_fixed(session->m46_source);
#endif
    if (participant) hooks->commit(hooks->context);
#endif
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
    if (catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[catalog_index].descriptor
        || !wave_digest_atom(session->catalog[catalog_index].descriptor->payload_id, &identity)) return 0;
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
    WaveEndpoint endpoint;
    if (!wave_ingress(plan, event, &endpoint)) return 0;
    uint32_t instance = endpoint.instance;
    uint32_t type_index = plan->instance_types[instance] - 1u;
    uint32_t event_index = endpoint.event;
    if (value_count != plan->types[type_index].event_value_counts[event_index]) return 0;

    noun runtime_values[RESOURCE_MAX_PLAN_VALUES];
    for (uint32_t i = 0; i < value_count; i++) {
        noun value_tag, value_body, value_fields[4];
        if (!wave_pair(values[i], &value_tag, &value_body)
            || !wave_atom_text(value_tag, RESOURCE_VALUE_TAG)
            || !wave_record(value_body, value_fields, 4)) return 0;
        uint32_t value_id;
        uint32_t local = plan->types[type_index].event_value_ids[event_index][i];
        uint32_t expected = event < 1024u ? local : (instance + 1u) * 1024u + local;
        if (!wave_u(value_fields[1], 65535, &value_id) || value_id != expected) return 0;
        noun runtime_fields[3] = {direct(local), value_fields[2], value_fields[3]};
        if (!wave_build_record(runtime_fields, 3, &runtime_values[i])) return 0;
    }
    noun runtime_value_list, identity, runtime_fields[4], runtime_body;
    if (!wave_build_list(runtime_values, value_count, &runtime_value_list)
        || catalog_index >= RESOURCE_MAX_ADMISSION_ENTRIES
        || !session->catalog[catalog_index].descriptor
        || !wave_digest_atom(session->catalog[catalog_index].descriptor->payload_id, &identity)) return 0;
    runtime_fields[0] = identity;
    runtime_fields[1] = direct(instance + 1u);
    runtime_fields[2] = direct(event_index + 1u);
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
                                       noun product, WaveSlot *slot, noun *effects, noun *observations_out)
{
    noun tag, body, fields[7];
    if (!wave_pair(product, &tag, &body)
        || !wave_atom_text(tag, "m38-product-v2")
        || !wave_record(body, fields, 7)
        || !session->catalog[catalog_index].descriptor
        || !wave_identity(fields[0], session->catalog[catalog_index].descriptor->payload_id)
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
        || !wave_identity(state_fields[0], session->catalog[catalog_index].descriptor->payload_id)
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
                || !wave_u(value_fields[1], plan->scalar_count, &value_type)
                || value_type != type->value_types[j]
                || !wave_u(value_fields[2], value_type == 1 ? 1 : 65535, &raw)) return 0;
            candidate.state_values[instance_index][j] = raw;
        }
        candidate.state_ids[instance_index] = state_id;
        seen[instance_index] = 1;
    }
    for (uint32_t i = 0; i < row_count; i++) if (!seen[i]) return 0;
    if (!wave_outputs_build(plan, fields[3], effects, observations_out)) return 0;
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
                                     product, staged_slot, &effects, &observations)
        || !wave_state_build(session, plan, staged_slot->catalog_index, staged_slot, state_out)
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
        int cache_insert = !cache->valid;
        if (cache_insert) {
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
        /* All decode/construction work is staged above.  This is the real
         * first-LOAD cache-insertion commit gate: an injected failure leaves
         * the empty execution cache, slot table, and result roots untouched. */
        if (cache_insert
            && wave_take_fault(runtime, WAVE_FAULT_CUE_CACHE_INSERT) != M38_STATUS_OK)
            return M38_STATUS_CUE_CACHE_INSERT;
        if (wave_take_fault(runtime, WAVE_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
            return M38_STATUS_ATOM_RESULT_STAGING;
        if (wave_take_fault(runtime, WAVE_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
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
        if (wave_take_fault(runtime, WAVE_FAULT_EVALUATOR_ABORT) != M38_STATUS_OK)
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
        if (!wave_observation_build(plan, &session->slots[slot_index], target, &observation)
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
        if (wave_take_fault(runtime, WAVE_FAULT_RESTORE_COMMIT) != M38_STATUS_OK)
            return M38_STATUS_RESTORE_COMMIT;
        goto publish;
    }
    return M38_STATUS_REQUEST_INVALID;

publish: {
        M38Status failure;
        if (wave_take_fault(runtime, WAVE_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
            return M38_STATUS_ATOM_RESULT_STAGING;
        if (wave_take_fault(runtime, WAVE_FAULT_SLOT_PUBLICATION) != M38_STATUS_OK)
            return M38_STATUS_SLOT_PUBLICATION;
        if (wave_take_fault(runtime, WAVE_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
            return M38_STATUS_COLLECTIVE_COMMIT;
        if (!wave_promote_operation(runtime, session, slot_index, &staged_slot,
                                    handle, state, snapshot, result, owner,
                                    wire_status, &failure))
            return failure;
        *out_view = &session->primary_view;
        return M38_STATUS_OK;
    }
refuse:
    if (wave_take_fault(runtime, WAVE_FAULT_ATOM_RESULT_STAGING) != M38_STATUS_OK)
        return M38_STATUS_ATOM_RESULT_STAGING;
    if (wave_take_fault(runtime, WAVE_FAULT_SLOT_PUBLICATION) != M38_STATUS_OK)
        return M38_STATUS_SLOT_PUBLICATION;
    if (wave_take_fault(runtime, WAVE_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK)
        return M38_STATUS_COLLECTIVE_COMMIT;
    return wave_publish_refusal(runtime, session, refusal_reason, out_view);
}

M38Status m38_resource_session_dispatch(ResourceSession *session, noun request,
                                        const ResourceResultView **out_view)
{
#if defined(M38_D8_WAVE_B_B0)
#define B0_DISPATCH_RETURN(value) do { \
        M38Status b0_status = (value); \
        b0_finish(b0_status, out_view); \
        return b0_status; \
    } while (0)
    b0_begin(session);
#else
#define B0_DISPATCH_RETURN(value) return (value)
#endif
    if (!out_view) B0_DISPATCH_RETURN(M38_STATUS_INVALID_ARGUMENT);
    *out_view = 0;
    if (!wave_session_valid(session)) B0_DISPATCH_RETURN(M38_STATUS_RUNTIME_UNINITIALIZED);
    ResourceRuntime *runtime = session->runtime;
    if (session->state == 2) B0_DISPATCH_RETURN(M38_STATUS_SESSION_CLOSED);
#if defined(M44_TWO_RESOURCE)
    if (session->m44_owner && !session->m44_call_active)
        B0_DISPATCH_RETURN(M38_STATUS_SESSION_BUSY);
#endif
    if (session->in_flight) B0_DISPATCH_RETURN(M38_STATUS_SESSION_BUSY);
    if (runtime->broker_owner != 0 || runtime->state != 2)
        B0_DISPATCH_RETURN(M38_STATUS_RUNTIME_BUSY);
    if (!wave_safe_noun(runtime, request)) B0_DISPATCH_RETURN(M38_STATUS_REQUEST_INVALID);
    WaveRequest decoded = {0};
    /* Safety failure is a C-boundary error.  A safely traversable noun that
     * merely misses the ResourceABI grammar is an ordinary wire refusal. */
    if (!wave_request_decode(request, &decoded)) decoded.operation = 0;
#if defined(M38_D8_WAVE_B_B0)
    b0_set_operation(decoded.operation);
#endif
    M38Status broker_fault = wave_take_fault(runtime, WAVE_FAULT_BROKER_BEGIN);
    if (broker_fault != M38_STATUS_OK) B0_DISPATCH_RETURN(broker_fault);
    runtime->broker_owner = (uint8_t)(session->registry_index + 1u);
    runtime->state = 3;
    session->in_flight = 1;
    session->session_transaction_id = ++runtime->broker_transaction_id;
    uint64_t scratch_mark = heap_scratch_mark();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!noun_tx_begin(HEAP_MODE_SCRATCH)) {
        session->in_flight = 0;
        wave_broker_release(runtime);
        B0_DISPATCH_RETURN(M38_STATUS_INTERNAL);
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
    B0_DISPATCH_RETURN(status);
#undef B0_DISPATCH_RETURN
}

#if defined(M44_TWO_RESOURCE)
static M38Status m44_access(ResourceSession *session, const void *owner)
{
    if (!wave_session_valid(session)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (session->state != 1) return M38_STATUS_SESSION_CLOSED;
    if (!owner || session->m44_owner != owner) return M38_STATUS_SESSION_BUSY;
    if (session->m44_call_active || session->in_flight) return M38_STATUS_SESSION_BUSY;
    if (session->runtime->broker_owner || session->runtime->state != 2)
        return M38_STATUS_RUNTIME_BUSY;
    return M38_STATUS_OK;
}

static int m44_hooks_valid(const M44PublicationHooks *hooks)
{
    return hooks && hooks->prepare && hooks->commit;
}

M38Status m44_resource_claim(ResourceSession *session, const void *owner, const noun handles[2])
{
    if (!wave_session_valid(session)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (!owner || !handles) return M38_STATUS_INVALID_ARGUMENT;
    if (session->state != 1) return M38_STATUS_SESSION_CLOSED;
    if (session->m44_owner || session->in_flight) return M38_STATUS_SESSION_BUSY;
    if (session->runtime->broker_owner || session->runtime->state != 2)
        return M38_STATUS_RUNTIME_BUSY;
    uint32_t count = 0;
    for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++)
        if (session->slots[i].used) count++;
    if (count != 2) return M38_STATUS_INVALID_ARGUMENT;
    uint32_t indices[2];
    for (uint32_t i = 0; i < 2; i++)
        if (!wave_safe_noun(session->runtime, handles[i])
            || !wave_handle_decode(session, handles[i], &indices[i])
            || indices[i] != i) return M38_STATUS_REQUEST_INVALID;
    session->m44_owner = owner;
    return M38_STATUS_OK;
}

M38Status m44_resource_dispatch(ResourceSession *session, const void *owner,
    noun request, const M44PublicationHooks *hooks, const ResourceResultView **out_view)
{
    if (!out_view) return M38_STATUS_INVALID_ARGUMENT;
    *out_view = 0;
    M38Status status = m44_access(session, owner);
    if (status != M38_STATUS_OK) return status;
    WaveRequest decoded = {0};
    if (!wave_safe_noun(session->runtime, request) || !wave_request_decode(request, &decoded)
        || (decoded.operation != RESOURCE_OP_POKE && decoded.operation != RESOURCE_OP_PEEK)
        || (decoded.operation == RESOURCE_OP_POKE && !m44_hooks_valid(hooks)))
        return M38_STATUS_REQUEST_INVALID;
    session->m44_hooks = hooks;
    session->m44_call_active = 1;
    status = m38_resource_session_dispatch(session, request, out_view);
    session->m44_call_active = 0;
    session->m44_hooks = 0;
    return status;
}

typedef enum {
    M44_GROUP_METADATA = -1,
    M44_GROUP_CAPTURE = 0,
    M44_GROUP_RESTORE_SNAPSHOT = 1,
#if defined(M45_MANAGED_LIFECYCLE)
    M45_GROUP_INITIALIZE_ADMITTED = 2,
#if defined(M46_LIVE_REPLACEMENT)
    M46_GROUP_REBIND = 3,
#endif
#endif
} M44GroupOperation;

static M38Status m44_group_staged(ResourceSession *session, M44GroupOperation group_operation,
    const noun handles[2], const noun snapshots[2], const ResourceResultView **out_view)
{
    WaveM44Group group;
    noun results[2];
    for (uint32_t i = 0; i < 2; i++) {
        WavePlan *plan;
        if (!wave_handle_decode(session, handles[i], &group.index[i])
            || !wave_plan_for_slot(session, group.index[i], &plan)
            || (i && group.index[0] == group.index[1])) return M38_STATUS_REQUEST_INVALID;
        WaveSlot *slot = &group.slots[i];
        *slot = session->slots[group.index[i]];
        noun handle, state, body;
        if (!group_operation) {
            if (slot->snapshot_nonce == RESOURCE_MAX_SNAPSHOT_NONCE)
                return M38_STATUS_REQUEST_INVALID;
            slot->snapshot_nonce++;
            if (!wave_snapshot_build(session, plan, group.index[i], slot,
                                      &state, &handle, &slot->snapshot_root)
                || !wave_result_build(RESOURCE_WIRE_SNAPSHOT, slot->snapshot_root, &results[i]))
                return M38_STATUS_ATOM_RESULT_STAGING;
        } else {
#if defined(M45_MANAGED_LIFECYCLE)
#if defined(M46_LIVE_REPLACEMENT)
            if (group_operation == M46_GROUP_REBIND) {
                WaveSlot *old = &session->m46_source->slots[i];
                wave_copy(slot->state_ids, old->state_ids, sizeof(slot->state_ids));
                wave_copy(slot->state_values, old->state_values, sizeof(slot->state_values));
                slot->snapshot_root = NOUN_ZERO;
                slot->snapshot_nonce = 0;
                /* Validate the latest logical image, not a staging-time copy. */
                for (uint32_t j=0;j<plan->instance_count;j++) {
                    const WavePlanType *type=&plan->types[plan->instance_types[j]-1u];
                    if (!slot->state_ids[j] || slot->state_ids[j]>type->state_count)
                        return M38_STATUS_REQUEST_INVALID;
                    for (uint32_t k=0;k<type->value_count;k++)
                        if (slot->state_values[j][k]>(type->value_types[k]==1 ? 1u : 65535u))
                            return M38_STATUS_REQUEST_INVALID;
                }
            } else
#endif
            if (group_operation == M45_GROUP_INITIALIZE_ADMITTED) {
                if (slot->snapshot_nonce == RESOURCE_MAX_SNAPSHOT_NONCE)
                    return M38_STATUS_REQUEST_INVALID;
                slot->snapshot_nonce++;
                slot->snapshot_root = NOUN_ZERO;
                /* These are the explicit canonical initializer fields used by
                 * LOAD, authenticated at admission. C copies that image; it
                 * does not choose defaults, run ECC, or execute entry actions. */
                for (uint32_t j = 0; j < plan->instance_count; j++) {
                    const WavePlanType *type = &plan->types[plan->instance_types[j] - 1u];
                    slot->state_ids[j] = type->state_id;
                    for (uint32_t k = 0; k < type->value_count; k++)
                        slot->state_values[j][k] = type->value_initials[k];
                }
            } else
#endif
            if (!wave_snapshot_apply(session, plan, snapshots[i], group.index[i], slot))
                return M38_STATUS_REQUEST_INVALID;
            if (!wave_state_build(session, plan, slot->catalog_index, slot, &state)
                || !wave_handle_build(session, group.index[i] + 1u, slot->generation,
                                      slot->catalog_index, &handle)) return M38_STATUS_ATOM_RESULT_STAGING;
            noun receipt, receipt_fields[2] = {handle, direct(slot->snapshot_nonce)};
            if (!wave_build_tagged(RESOURCE_RECEIPT_TAG, RESOURCE_RECEIPT_SCHEMA,
                                   receipt_fields, 2, &receipt)
                || !wave_build_record((noun[3]){handle, state, receipt}, 3, &body)
                || !wave_result_build(RESOURCE_WIRE_RESTORE, body, &results[i]))
                return M38_STATUS_ATOM_RESULT_STAGING;
        }
        slot->handle_root = handle;
        slot->state_root = state;
    }
    noun body, result;
    if (!wave_build_list(results, 2, &body)
        || !alloc_cell_checked(wave_cord("m44-resource-group-v1"), body, &result))
        return M38_STATUS_ATOM_RESULT_STAGING;
    M38Status status;
    session->m44_group = &group;
    int committed = wave_promote_operation(session->runtime, session, 0, 0,
        NOUN_ZERO, NOUN_ZERO, NOUN_ZERO, result, M38_RESULT_OWNER_PRIMARY,
        group_operation ? RESOURCE_WIRE_RESTORE : RESOURCE_WIRE_SNAPSHOT, &status);
    session->m44_group = 0;
    if (committed) *out_view = &session->primary_view;
    return status;
}

/* A single broker envelope owns all temporary nouns and both candidates. */
static M38Status m44_group_operation(ResourceSession *session, const void *owner,
    M44GroupOperation group_operation, const noun handles[2], const noun snapshots[2],
    const M44PublicationHooks *hooks, const ResourceResultView **out_view)
{
    if (out_view) *out_view = 0;
    M38Status status = m44_access(session, owner);
    if (status != M38_STATUS_OK) return status;
    if (!m44_hooks_valid(hooks) || group_operation < M44_GROUP_METADATA || group_operation >
#if defined(M46_LIVE_REPLACEMENT)
        3
#elif defined(M45_MANAGED_LIFECYCLE)
        2
#else
        1
#endif
       )
        return M38_STATUS_INVALID_ARGUMENT;
    ResourceRuntime *runtime = session->runtime;
    if (group_operation >= 0) {
        if (!out_view || !handles || (
#if defined(M45_MANAGED_LIFECYCLE)
            group_operation == M44_GROUP_RESTORE_SNAPSHOT
#else
            group_operation
#endif
            && !snapshots)) return M38_STATUS_INVALID_ARGUMENT;
        for (uint32_t i = 0; i < 2; i++)
            if (!wave_safe_noun(runtime, handles[i])
                || (
#if defined(M45_MANAGED_LIFECYCLE)
                    group_operation == M44_GROUP_RESTORE_SNAPSHOT
#else
                    group_operation
#endif
                    && !wave_safe_noun(runtime, snapshots[i]))) return M38_STATUS_REQUEST_INVALID;
    }
    status = wave_take_fault(runtime, WAVE_FAULT_BROKER_BEGIN);
    if (status != M38_STATUS_OK) return status;
    runtime->broker_owner = (uint8_t)(session->registry_index + 1u);
    runtime->state = 3;
    session->in_flight = session->m44_call_active = 1;
    session->m44_hooks = hooks;
    session->session_transaction_id = ++runtime->broker_transaction_id;
    uint64_t mark = heap_scratch_mark();
    heap_set_mode(HEAP_MODE_SCRATCH);
    if (!noun_tx_begin(HEAP_MODE_SCRATCH)) status = M38_STATUS_INTERNAL;
    else {
        if (group_operation < 0) {
            (void)wave_promote_operation(runtime, session, 0, 0, NOUN_ZERO,
                NOUN_ZERO, NOUN_ZERO, NOUN_ZERO, M38_RESULT_OWNER_NONE, 0, &status);
        } else status = m44_group_staged(session, group_operation, handles, snapshots, out_view);
        if (status == M38_STATUS_OK) noun_tx_commit();
        else noun_tx_abort();
    }
    session->m44_hooks = 0;
    session->m44_group = 0;
    session->in_flight = session->m44_call_active = 0;
    wave_broker_release(runtime);
    (void)heap_scratch_rewind(mark);
    return status;
}

M38Status m44_resource_group(ResourceSession *session, const void *owner,
    int restore, const noun handles[2], const noun snapshots[2],
    const M44PublicationHooks *hooks, const ResourceResultView **out_view)
{
    if (restore != 0 && restore != 1) {
        if (out_view) *out_view = 0;
        return M38_STATUS_INVALID_ARGUMENT;
    }
    return m44_group_operation(session, owner, (M44GroupOperation)restore, handles, snapshots, hooks, out_view);
}

M38Status m44_resource_publish(ResourceSession *session, const void *owner,
    const M44PublicationHooks *hooks)
{
    return m44_group_operation(session, owner, M44_GROUP_METADATA, 0, 0, hooks, 0);
}

#if defined(M45_MANAGED_LIFECYCLE)
M38Status m45_resource_reinitialize(ResourceSession *session, const void *owner,
    const noun handles[2], const M44PublicationHooks *hooks,
    const ResourceResultView **out_view)
{
    return m44_group_operation(session, owner, M45_GROUP_INITIALIZE_ADMITTED, handles, 0, hooks, out_view);
}
#endif

#if defined(M46_LIVE_REPLACEMENT)
/* No allocation and no release-to-public interval. Retired storage is reusable
 * only after this closed session has left the registry. Its unreachable noun
 * cells are reclaimed by the next ordinary collective promotion. */
static void m46_close_fixed(ResourceSession *session) {
  ResourceRuntime *runtime = session->runtime;
  runtime->sessions[session->registry_index] = 0;
  runtime->session_count--;
  session->state = 2;
  session->capability = 0;
  /* Closed/unregistered storage contributes no roots. Clearing the bounded
   * catalog and slot arrays belongs to the next session initialization. */
  session->primary_root = session->refusal_root = NOUN_ZERO;
  session->primary_view.owner = session->refusal_view.owner =
      M38_RESULT_OWNER_NONE;
}

static int m46_payload_compatible(noun a, noun b) {
  noun at, ab, bt, bb, af[2], bf[2], as[5], bs[5];
  noun ats[8], bts[8];
  uint32_t ac, bc;
  if (!wave_pair(a, &at, &ab) || !wave_pair(b, &bt, &bb) || !noun_eq(at, bt) ||
      !wave_record(ab, af, 2) || !wave_record(bb, bf, 2) ||
      !noun_eq(af[0], bf[0]) || !wave_record(af[1], as, 5) ||
      !wave_record(bf[1], bs, 5) || !wave_list(as[0], ats, 8, &ac) ||
      !wave_list(bs[0], bts, 8, &bc) || ac != bc)
    return 0;
  for (uint32_t i = 1; i < 5; i++)
    if (!noun_eq(as[i], bs[i]))
      return 0;
  for (uint32_t i = 0; i < ac; i++) {
    noun ax[6], bx[6];
    if (!wave_record(ats[i], ax, 6) || !wave_record(bts[i], bx, 6))
      return 0;
    for (uint32_t j = 0; j < 5; j++)
      if (!noun_eq(ax[j], bx[j]))
        return 0;
    noun al = ax[5], bl = bx[5], ah, bh, ar[2], br[2];
    while (al != NOUN_ZERO && bl != NOUN_ZERO) {
      if (!wave_pair(al, &ah, &al) || !wave_pair(bl, &bh, &bl) ||
          !wave_record(ah, ar, 2) || !wave_record(bh, br, 2) ||
          !noun_eq(ar[0], br[0]))
        return 0;
    }
    if (al != bl)
      return 0;
  }
  return 1;
}

M38Status m46_resource_diagnostics(ResourceSession *session, const void *owner,
                                   M46ResourceDiagnostics *out) {
  if (!out)
    return M38_STATUS_INVALID_ARGUMENT;
  M38Status status = m44_access(session, owner);
  if (status != M38_STATUS_OK)
    return status;
  *out = (M46ResourceDiagnostics){
      session->runtime->session_count, session->runtime->next_capability,
      RESOURCE_SESSION_BYTES, sizeof(ResourceSession)};
  return M38_STATUS_OK;
}

M38Status m46_validate_replacement_pair(ResourceSession *old,
                                  ResourceSession *candidate,
                                  const void *owner) {
  M38Status s = m44_access(old, owner);
  if (s)
    return s;
  s = m44_access(candidate, owner);
  if (s)
    return s;
  if (old == candidate || old->runtime != candidate->runtime)
    return M38_STATUS_INVALID_ARGUMENT;
  /* Retirement is infallible only after both registry memberships and the
   * two-session ownership bound have been checked before any copying. */
  ResourceRuntime *runtime = old->runtime;
  if (runtime->session_count != 2 ||
      old->registry_index >= RESOURCE_MAX_REGISTERED_SESSIONS ||
      candidate->registry_index >= RESOURCE_MAX_REGISTERED_SESSIONS ||
      runtime->sessions[old->registry_index] != old ||
      runtime->sessions[candidate->registry_index] != candidate)
    return M38_STATUS_INTERNAL;
  for (uint32_t i = 0; i < 2; i++) {
    WavePlan *a, *b;
    if (!wave_plan_for_slot(old, i, &a) ||
        !wave_plan_for_slot(candidate, i, &b) ||
        !m46_payload_compatible(a->payload, b->payload))
      return M38_STATUS_REQUEST_INVALID;
  }
  return M38_STATUS_OK;
}
M38Status m46_resource_cancel(ResourceSession *session, const void *owner) {
  M38Status status = m44_access(session, owner);
  if (status != M38_STATUS_OK)
    return status;
  ResourceRuntime *runtime = session->runtime;
  if (!runtime->session_count ||
      session->registry_index >= RESOURCE_MAX_REGISTERED_SESSIONS ||
      runtime->sessions[session->registry_index] != session)
    return M38_STATUS_INTERNAL;
  m46_close_fixed(session);
  return M38_STATUS_OK;
}
M38Status m46_resource_discard_unclaimed(ResourceSession *session) {
  if (!wave_session_valid(session))
    return M38_STATUS_INVALID_ARGUMENT;
  if (session->state == 2)
    return M38_STATUS_OK;
  if (session->m44_owner || session->in_flight)
    return M38_STATUS_SESSION_BUSY;
  ResourceRuntime *runtime = session->runtime;
  if (!wave_runtime_valid(runtime) || runtime->state != 2 || runtime->broker_owner || noun_tx_active())
    return M38_STATUS_RUNTIME_BUSY;
  if (!runtime->session_count || session->registry_index >= RESOURCE_MAX_REGISTERED_SESSIONS ||
      runtime->sessions[session->registry_index] != session)
    return M38_STATUS_INTERNAL;
  m46_close_fixed(session);
  return M38_STATUS_OK;
}
M38Status m46_resource_rebind(ResourceSession *old, ResourceSession *candidate,
                              const void *owner, const noun handles[2],
                              const M44PublicationHooks *hooks,
                              const ResourceResultView **out_view) {
  if (out_view)
    *out_view = 0;
  M38Status s = m46_validate_replacement_pair(old, candidate, owner);
  if (s)
    return s;
  candidate->m46_source = old;
  s = m44_group_operation(candidate, owner, M46_GROUP_REBIND, handles, 0, hooks,
                          out_view);
  candidate->m46_source = 0;
  return s;
}
#endif

M38Status m44_resource_inspect(ResourceSession *session, const void *owner,
    M44ResourceInspection *out)
{
    M38Status status = m44_access(session, owner);
    if (status != M38_STATUS_OK) return status;
    if (!out) return M38_STATUS_INVALID_ARGUMENT;
    M44ResourceInspection candidate = {0};
    uint32_t slots[2];
    uint32_t count = 0;
    for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++) {
        if (!session->slots[i].used) continue;
        if (count == 2) return M38_STATUS_INTERNAL;
        slots[count++] = i;
    }
    if (count != 2) return M38_STATUS_INTERNAL;
    candidate.capability = session->capability;
    for (uint32_t i = 0; i < 2; i++) {
        WavePlan *plan;
        if (!wave_plan_for_slot(session, slots[i], &plan))
            return M38_STATUS_REQUEST_INVALID;
        const WaveSlot *slot = &session->slots[slots[i]];
        candidate.generations[i] = slot->generation;
        candidate.snapshot_nonces[i] = slot->snapshot_nonce;
        candidate.instance_counts[i] = plan->instance_count;
        for (uint32_t j = 0; j < plan->instance_count; j++) {
            const WavePlanType *type = &plan->types[plan->instance_types[j] - 1u];
            M44InstanceInspection *instance = &candidate.instances[i][j];
            instance->active = slot->state_ids[j];
            instance->value_count = type->value_count;
            for (uint32_t k = 0; k < type->value_count; k++) {
                instance->types[k] = type->value_types[k];
                instance->values[k] = slot->state_values[j][k];
            }
        }
    }
    *out = candidate;
    return M38_STATUS_OK;
}

#if defined(M44_G0_TEST_CONTROLS)
void m44_resource_test_fail_publication(ResourceSession *session, uint32_t point)
{
    if (wave_session_valid(session) && session->in_flight && point <= 2)
        session->m44_test_fault = (uint8_t)point;
}
#if defined(M45_MANAGED_LIFECYCLE)
M38Status m45_resource_test_control(ResourceSession *session, const void *owner,
    uint32_t point)
{
    M38Status status = m44_access(session, owner);
    if (status != M38_STATUS_OK) return status;
    if (point == 1) session->runtime->next_fault = WAVE_FAULT_BROKER_BEGIN;
    else if (point == 2) {
        for (uint32_t i = 0; i < RESOURCE_MAX_LIVE_HANDLES; i++)
            if (session->slots[i].used)
                session->slots[i].snapshot_nonce = RESOURCE_MAX_SNAPSHOT_NONCE;
    } else return M38_STATUS_INVALID_ARGUMENT;
    return M38_STATUS_OK;
}
#endif
#endif
#endif

static M38Status wave_lifecycle_begin(ResourceRuntime *runtime,
                                      ResourceSession *session)
{
    if (!wave_runtime_valid(runtime)) return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (!wave_session_valid(session) || session->runtime != runtime)
        return M38_STATUS_RUNTIME_UNINITIALIZED;
    if (session->state == 2) return M38_STATUS_SESSION_CLOSED;
#if defined(M44_TWO_RESOURCE)
    if (session->m44_owner) return M38_STATUS_SESSION_BUSY;
#endif
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
    if (wave_take_fault(runtime, WAVE_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK) {
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
    session->primary_view.generation = session->primary_generation;
    session->primary_view.wire_status = 0;
    session->primary_view.owner = M38_RESULT_OWNER_NONE;
    session->refusal_view.root_slot = &session->refusal_root;
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
    if (wave_take_fault(runtime, WAVE_FAULT_COLLECTIVE_COMMIT) != M38_STATUS_OK) {
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
    session->primary_generation = next_primary_generation;
    session->primary_view.generation = session->primary_generation;
    session->primary_view.wire_status = 0;
    session->primary_view.owner = M38_RESULT_OWNER_NONE;
    session->refusal_view.root_slot = &session->refusal_root;
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
