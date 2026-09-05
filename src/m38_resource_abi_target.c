#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "bounded_cue.h"
#include "jam.h"
#include "memory.h"
#include "nock.h"
#include "noun.h"
#include "sha256.h"
#include "uart.h"
#include "setjmp.h"

/*
 * M38-D5 native ResourceABI.
 *
 * The public native boundary is exactly d0_dispatch(): it accepts one
 * ABI-REQUEST noun and returns one ABI-RESULT noun.  The boot routine below is
 * only a deterministic QEMU witness that drives the five public operations.
 * The evaluator is the existing Trinitite Nock evaluator; this file owns only
 * the D0 codec, catalog, slot table, and publication transaction.
 */

#define D5_POLICY_MAX_OPS       2000000ULL
#define D5_POLICY_MAX_CELLS     128000ULL
#define D5_POLICY_MAX_STACK     1024ULL
#define D5_QUEUE_LIMIT          8u
#define D5_WORKLIST_LIMIT       32u
#define D5_TRACE_LIMIT          128u
#define D5_MAX_TYPES             8u
#define D5_MAX_EVENTS            8u
#define D5_MAX_VALUES           16u
#define D5_MAX_STATES             8u
#define D5_MAX_TRANSITIONS      16u
#define D5_MAX_ACTIONS            8u
#define D5_MAX_ALGORITHMS         8u
#define D5_MAX_INSTANCES          8u
#define D5_MAX_ROUTES            16u
#define D5_MAX_WITH              16u
#define D5_MAX_EFFECTS           32u
#define D5_MAX_OBSERVATIONS      32u
#define D5_MAX_IDENTITY_BYTES   256u
#define D5_JAM_WORK_LIMIT   2000000ULL
#define D5_CATALOG_CAPACITY       8u
#define D5_CATALOG_KNOWN_COUNT    2u
#define D5_SLOT_COUNT              8u
#define D5_MAX_GENERATION 0xFFFFFFFFULL
#define D5_RESULT_CELL_CAPACITY    32768u
#define D5_NESTED_RESULT_CELL_CAPACITY 64u
#define D5_RESULT_DEPTH_MAX         256u
#define D5_WITNESS_RETRY_PILL_OFFSET 0x01000000ULL
#define D7_RETRY_PILL_OFFSET         0x02000000ULL

#if defined(M38_D8_NATIVE)
#define D8_RAW_CATALOG_RESERVATION   (4u * 1024u * 1024u)
#define D8_RECORD_COUNT              2u
#define D8_FAULT_NONE                0u
#define D8_FAULT_DECODE_VALIDATION   1u
#define D8_FAULT_RAW_CATALOG_COPY   2u
#define D8_FAULT_PERSISTENT_COPY    3u
#define D8_FAULT_SCRATCH_ALLOCATION 4u
#define D8_FAULT_ATOM_DATA_INDEX    5u
#define D8_FAULT_RESULT_STAGING     6u
#define D8_FAULT_PUBLICATION        7u
#define D8_MAX_PLACEMENT_FAULT      D8_FAULT_PUBLICATION
#endif


#define D5_TYPE_BOOL              1u
#define D5_TYPE_UINT16            2u

#define D5_OP_LOAD                1u
#define D5_OP_POKE                2u
#define D5_OP_PEEK                3u
#define D5_OP_SNAPSHOT            4u
#define D5_OP_RESTORE             5u

#define D5_STATUS_LOAD             1u
#define D5_STATUS_POKE             2u
#define D5_STATUS_PEEK             3u
#define D5_STATUS_SNAPSHOT         4u
#define D5_STATUS_RESTORE          5u
#define D5_STATUS_REFUSE         255u

#define D5_STATE_INITIALIZED       1u
#define D5_STATE_NEXT              2u

/* Frozen D0-R2 domains and labels.  Long labels are constructed as atoms,
 * never used as caller-provided markers or selectors. */
#if defined(M38_D7_NATIVE)
static const char D5_CORE_DOMAIN[] =
    "1499kernel:i2:m38-d0-r3:resource-core:v3";
#else
static const char D5_CORE_DOMAIN[] =
    "1499kernel:i2:m38-d0-r2:resource-core:v2";
#endif
#if defined(M38_D8_NATIVE)
static const char D8_FORMULA_DOMAIN[] =
    "1499kernel:i2:m38-d0-r3:formula:v3";
static const char D8_INPUT_TAG[] = "m38-d8-placement-input-v1";
static const char D8_INPUT_SCHEMA[] =
    "1499kernel-i2-m38-d8-placement-input-v1";
#endif
static const char D5_SNAPSHOT_DOMAIN[] =
    "1499kernel:i2:m38-d4:latest-snapshot:v1";
static const char D5_BYTE_ORDER[] =
    "little-endian-digest-byte-0-is-atom-lsb";

/* D0 labels. */
static const char TAG_IDENTITY[] = "m38-d0-r2-identity";
static const char TAG_IDENTITY_SCHEMA[] = "m38-d0-r2-identity-schema-v2";
static const char TAG_PAYLOAD[] = "m38-d0-r2-resource-payload";
static const char TAG_PAYLOAD_SCHEMA[] = "m38-d0-r2-resource-payload-schema-v2";
static const char TAG_ADMISSION[] = "m38-d0-r2-resource-admission";
static const char TAG_ADMISSION_SCHEMA[] = "m38-d0-r2-resource-admission-schema-v2";
static const char TAG_BINDING[] = "m38-d0-r2-application-binding";
static const char TAG_BINDING_SCHEMA[] = "m38-d0-r2-application-binding-schema-v2";
static const char TAG_REQUEST[] = "m38-d0-r2-abi-request";
static const char TAG_REQUEST_SCHEMA[] = "m38-d0-r2-abi-request-schema-v2";
static const char TAG_RESULT[] = "m38-d0-r2-abi-result";
static const char TAG_RESULT_SCHEMA[] = "m38-d0-r2-abi-result-schema-v2";
static const char TAG_HANDLE[] = "m38-d0-r2-handle";
static const char TAG_HANDLE_SCHEMA[] = "m38-d0-r2-handle-schema-v2";
static const char TAG_STATE[] = "m38-d0-r2-state";
static const char TAG_STATE_SCHEMA[] = "m38-d0-r2-state-schema-v2";
static const char TAG_STIMULUS[] = "m38-d0-r2-stimulus";
static const char TAG_STIMULUS_SCHEMA[] = "m38-d0-r2-stimulus-schema-v2";
static const char TAG_EFFECTS[] = "m38-d0-r2-effects";
static const char TAG_EFFECTS_SCHEMA[] = "m38-d0-r2-effects-schema-v2";
static const char TAG_EFFECT_EMISSION[] = "m38-d0-r2-effect-emission";
static const char TAG_EFFECT_EMISSION_SCHEMA[] = "m38-d0-r2-effect-emission-schema-v2";
static const char TAG_OBSERVATIONS[] = "m38-d0-r2-observations";
static const char TAG_OBSERVATIONS_SCHEMA[] = "m38-d0-r2-observations-schema-v2";
static const char TAG_OBSERVATION[] = "m38-d0-r2-observation";
static const char TAG_OBSERVATION_SCHEMA[] = "m38-d0-r2-observation-schema-v2";
static const char TAG_METRICS[] = "m38-d0-r2-metrics";
static const char TAG_METRICS_SCHEMA[] = "m38-d0-r2-metrics-schema-v2";
static const char TAG_REASON[] = "m38-d0-r2-refusal-reason";
static const char TAG_REASON_SCHEMA[] = "m38-d0-r2-refusal-reason-schema-v2";
static const char TAG_SELECTOR[] = "m38-d0-r2-selector";
static const char TAG_SELECTOR_SCHEMA[] = "m38-d0-r2-selector-schema-v2";
static const char TAG_SNAPSHOT[] = "m38-d0-r2-snapshot";
static const char TAG_SNAPSHOT_SCHEMA[] = "m38-d0-r2-snapshot-schema-v2";
static const char TAG_RECEIPT[] = "m38-d0-r2-restore-receipt";
static const char TAG_RECEIPT_SCHEMA[] = "m38-d0-r2-restore-receipt-schema-v2";

/* Neutral D7/R5 compatibility-witness nouns.  These atoms are transport
 * labels only; they do not contain an application name, source path, compiler
 * plan, or deployment selector. */
static const char D7_INPUT_TAG[] = "m38-d7-native-input-v1";
static const char D7_INPUT_SCHEMA[] = "1499kernel-i2-m38-d7-native-input-v1";
static const char D7_REQUEST_TAG[] = "m38-d7-native-request-v1";
static const char D7_REQUEST_SCHEMA[] = "1499kernel-i2-m38-d7-native-request-v1";
static const char D7_HANDLE_TAG[] = "m38-d7-resource-handle-v1";
static const char D7_HANDLE_SCHEMA[] = "1499kernel-i2-m38-d7-resource-handle-v1";
static const char D7_SELECTOR_TAG[] = "m38-d7-resource-selector-v1";
static const char D7_SELECTOR_SCHEMA[] = "1499kernel-i2-m38-d7-resource-selector-v1";
static const char D7_SNAPSHOT_TAG[] = "m38-d7-resource-snapshot-v1";
static const char D7_SNAPSHOT_SCHEMA[] = "1499kernel-i2-m38-d7-resource-snapshot-v1";
static const char D7_CONTROL_TAG[] = "m38-d7-compatibility-witness-control-v1";
static const char D7_CONTROL_SCHEMA[] =
    "1499kernel-i2-m38-d7-compatibility-witness-control-v1";
static const char D7_PAYLOAD_DOMAIN[] =
    "1499kernel:i2:m38-d0-r3:resource-payload:v3";
static const char D7_EXECUTION_ABI[] =
    "1499kernel-i2-m38-d6-r5-execution-abi-v1";
static const char D7_DESCRIPTOR_TAG[] = "m38-d6-r5-descriptor";
static const char D7_DESCRIPTOR_SCHEMA[] =
    "1499kernel-i2-m38-d6-r5-core-execution-descriptor-v1";
static const char D7_POLICY_TAG[] = "m38-d6-r5-policy-witness";
static const char D7_POLICY_SCHEMA[] =
    "1499kernel-i2-m38-d6-r5-runtime-policy-witness-v1";
static const char D7_STATE_TAG[] = "m38-d6-r5-state";
static const char D7_STATE_SCHEMA[] =
    "1499kernel-i2-m38-d6-r5-runtime-state-v1";
static const char D7_INGRESS_TAG[] = "m38-d6-r5-ingress";
static const char D7_INGRESS_SCHEMA[] =
    "1499kernel-i2-m38-d6-r5-runtime-ingress-v1";
static const char D7_R5_SNAPSHOT_TAG[] = "m38-d6-r5-snapshot";
static const char D7_R5_SNAPSHOT_SCHEMA[] =
    "1499kernel-i2-m38-d6-r5-runtime-snapshot-v1";
#if defined(M38_D7_NATIVE)
static int d7_layout_digest(noun core, uint8_t digest[32]);
#endif

/* M38-B runtime atoms are the exact numeric atoms used by m38_nock.py. */
#define RUNTIME_PLAN_TAG     0x6e616c702d3833ULL
#define RUNTIME_STATE_TAG    0x65746174732d3833ULL
#define RUNTIME_STIMULUS_TAG_PREFIX "38-stimul"

#if defined(M38_D7_NATIVE)
/* The D7 finite authority record is declared below, alongside the core
 * identity table used by the common parser. */
#else
static const uint8_t FORMULA_ID[32] = {
    0xb6,0x7a,0x4a,0x69,0xf3,0xff,0x12,0x25,
    0xc7,0x4e,0x1f,0x33,0x30,0xe8,0x95,0x7a,
    0xa6,0x7b,0x94,0x4c,0x8f,0xb9,0x4e,0xe5,
    0x3b,0x85,0xa4,0x54,0x0b,0x09,0x89,0x87
};
#endif
#if defined(M38_D7_NATIVE)
/* One finite authority record binds each reviewed core to its formula.  The
 * native witness deliberately has no independent positional core/formula
 * tables that could drift apart. */
typedef struct {
    uint8_t core_id[32];
    uint8_t formula_id[32];
} d7_authority_t;
static const d7_authority_t D7_AUTHORITIES[2] = {
    {{0x4e,0x2d,0x08,0x3b,0x69,0x3a,0xa2,0x16,
      0x4b,0xf0,0x45,0xcb,0xc0,0x71,0xf1,0x1f,
      0x24,0xb2,0xd1,0x95,0x1e,0x0c,0x78,0x1f,
      0x6b,0xc7,0x40,0x01,0x0c,0x65,0xa7,0xa5},
     {0xe0,0x43,0x2f,0xf2,0x9a,0x2d,0x93,0x19,
      0xc4,0xe9,0x79,0xac,0xb9,0x2a,0x54,0xb3,
      0x75,0x81,0x2d,0x4f,0x5d,0x52,0x0b,0xfb,
      0xad,0x6c,0x1e,0xbf,0xaa,0xd2,0xba,0xc4}},
    {{0x94,0xd0,0x6e,0x4c,0x39,0xbb,0x4d,0x6c,
      0x0a,0x85,0x42,0xfb,0x03,0x12,0x1f,0x49,
      0x64,0x43,0xc2,0x72,0xca,0xe6,0x44,0x5f,
      0x09,0xa7,0x37,0x8e,0xeb,0x5f,0x66,0xd6},
     {0x27,0x5c,0x54,0xc1,0xce,0x5a,0x5f,0x04,
      0xd8,0x62,0xe3,0xbf,0xb5,0x53,0x4b,0xa2,
      0xfa,0x03,0x07,0x67,0x0f,0x80,0x79,0xbd,
      0x8b,0x96,0xd0,0x20,0x66,0x0c,0xb0,0x6f}}
};
#else
static const uint8_t CORE_IDS[2][32] = {
    {0x0a,0x9f,0x3e,0x76,0x1c,0x09,0x25,0x0f,
     0x20,0x76,0x9f,0x6d,0x73,0x24,0x1f,0xe7,
     0x16,0x5a,0x9c,0xe0,0x20,0xdf,0xc3,0x3f,
     0x65,0x7e,0x5d,0xa1,0x7a,0xd8,0x1f,0xd2},
    {0x01,0x8f,0xfe,0x00,0x20,0x25,0xd6,0x25,
     0x6e,0x4e,0x9f,0x2f,0x5e,0xde,0x7f,0x7b,
     0x36,0xe2,0x8c,0x25,0x61,0xb7,0x37,0xfa,
     0xd6,0xaf,0x31,0x98,0x3d,0xfb,0xb2,0x8e}
};
#endif
static const uint8_t ADMISSION_IDS[2][32] = {
    {0xc3,0x3c,0xd5,0xee,0xde,0x28,0xba,0xaf,
     0x5a,0x8c,0xab,0xdf,0x8a,0xbe,0xca,0x59,
     0x02,0x38,0x5d,0x25,0x21,0xfd,0x27,0xca,
     0x29,0x55,0x11,0x42,0xcd,0x83,0x84,0x2e},
    {0x96,0x21,0x72,0x41,0x01,0xee,0x74,0x33,
     0x2d,0xe6,0xe9,0x75,0xb9,0x6f,0xd0,0x89,
     0x23,0xd2,0x78,0x17,0x5a,0x27,0xb0,0x9e,
     0x65,0x6c,0x30,0xd5,0xc0,0xe5,0x85,0x85}
};

typedef struct {
    uint32_t id;
    uint32_t direction;
    uint32_t type;
    noun initial;
} d5_value_t;

typedef struct {
    uint32_t id;
    uint32_t direction;
    uint32_t with_count;
    uint32_t with_ids[D5_MAX_WITH];
} d5_event_t;

typedef struct {
    uint32_t id;
    uint32_t initial;
} d5_state_def_t;

typedef struct {
    uint32_t id;
    uint32_t value_count;
    uint32_t event_count;
    uint32_t state_count;
    d5_value_t values[D5_MAX_VALUES];
    d5_event_t events[D5_MAX_EVENTS];
    d5_state_def_t states[D5_MAX_STATES];
} d5_type_t;

typedef struct {
    uint32_t type_count;
    uint32_t instance_count;
    uint32_t route_count;
    d5_type_t types[D5_MAX_TYPES];
    uint32_t instance_types[D5_MAX_INSTANCES];
    noun types_noun;
    noun instances_noun;
    noun routes_noun;
    noun formula;
} d5_plan_t;

typedef struct {
    uint32_t state_ids[D5_MAX_INSTANCES];
    uint32_t values[D5_MAX_INSTANCES][D5_MAX_VALUES];
} d5_state_t;

typedef struct {
    uint8_t admitted;
    uint8_t core_id[32];
    uint8_t admission_id[32];
    noun core;
    noun admission;
} d5_catalog_t;

typedef struct {
    uint8_t used;
    uint8_t latest;
    uint32_t catalog;
    uint64_t generation;
    uint32_t state_kind;
    d5_state_t state;
    d5_state_t snapshot_state;
    uint8_t snapshot_digest[32];
} d5_slot_t;

typedef struct {
    uint32_t operation;
    noun first;
    noun second;
} d5_request_t;

typedef struct {
    uint8_t core_id[32];
    d5_plan_t plan;
    int catalog_index;
} d5_load_validation_t;

/* Ingress preflight is a bounded, read-only semantic pass.  It shadows only
 * the slot facts needed to resolve deterministic handles and the two
 * catalog entries admitted by D5.  It never runs the evaluator or publishes
 * a catalog/slot; the real dispatch remains the sole state mutator. */
typedef struct {
    d5_slot_t slots[D5_SLOT_COUNT];
    d5_plan_t plans[D5_CATALOG_KNOWN_COUNT];
    uint8_t core_ids[D5_CATALOG_KNOWN_COUNT][32];
    uint8_t plan_ready[D5_CATALOG_KNOWN_COUNT];
    uint8_t pending_snapshot[D5_SLOT_COUNT];
} d5_ingress_shadow_t;

typedef struct {
    cell_t *cells;
    uint32_t *source;
    noun *value;
    uint32_t capacity;
    uint32_t cell_count;
    noun root;
} d5_result_arena_t;

static d5_catalog_t g_catalog[D5_CATALOG_CAPACITY];
static d5_slot_t g_slots[D5_SLOT_COUNT];
static uint64_t g_publications;
#if defined(M38_D7_NATIVE)
/* D7 stages all observable publications until the complete request batch has
 * succeeded.  The counter is a witness of staged events, never a commit
 * authority. */
static uint8_t g_d7_batch_active;
static uint64_t g_d7_batch_publications;
#endif
static uint8_t g_in_flight;
static uint8_t g_preimage[JAM_MAX_BYTES + D5_MAX_IDENTITY_BYTES];
static volatile uint32_t g_eval_slot;
static volatile uint32_t g_eval_reason;
static cell_t g_result_cells[D5_RESULT_CELL_CAPACITY];
static uint32_t g_result_source[D5_RESULT_CELL_CAPACITY];
static noun g_result_value[D5_RESULT_CELL_CAPACITY];
static cell_t g_nested_result_cells[D5_NESTED_RESULT_CELL_CAPACITY];
static uint32_t g_nested_result_source[D5_NESTED_RESULT_CELL_CAPACITY];
static noun g_nested_result_value[D5_NESTED_RESULT_CELL_CAPACITY];
static d5_result_arena_t g_result_arena = {
    g_result_cells, g_result_source, g_result_value,
    D5_RESULT_CELL_CAPACITY, 0, 0
};
static d5_result_arena_t g_nested_result_arena = {
    g_nested_result_cells, g_nested_result_source, g_nested_result_value,
    D5_NESTED_RESULT_CELL_CAPACITY, 0, 0
};
static d5_ingress_shadow_t g_ingress_shadow;
/* A witness may lower the next top-level result copy only.  The failed copy
 * consumes the control, so its refusal can still be returned and retried. */
static uint32_t g_result_stage_limit = D5_RESULT_CELL_CAPACITY;
#if defined(M38_D8_NATIVE)
/* Experiment-local raw Jam/catalog reservation.  It is deliberately separate
 * from the noun heap and atom store so the placement ledger cannot charge
 * canonical ResourceCore bytes to another domain. */
static uint8_t g_d8_raw_catalog[D8_RAW_CATALOG_RESERVATION];
static uint32_t g_d8_raw_catalog_used;
static uint32_t g_d8_raw_catalog_lengths[D8_RECORD_COUNT];
#endif
#if defined(M38_D7_NATIVE)
static uint8_t g_d7_retry_source;
static uint8_t g_d7_retry_used;
static uint64_t g_d7_evaluator_ops_limit;
static uint32_t g_d7_result_stage_limit;
#endif

static int d5_result_status_reason(noun result, uint32_t *status,
                                   uint32_t *reason);

#if defined(M38_D5_NATIVE_WITNESS)
static volatile uint64_t g_witness_ops_limit;
static volatile uint64_t g_witness_cells_limit;
static volatile uint64_t g_witness_stack_limit;
static volatile uint32_t g_witness_result_cells_limit;
static volatile uint8_t g_witness_reenter_next;
static volatile uint32_t g_witness_nested_status;
static volatile uint32_t g_witness_nested_reason;
static volatile uint8_t g_witness_late_reentry_ok;
static uint8_t g_witness_retry_source;
static uint8_t g_witness_retry_used;
#endif

extern uint8_t _pill_embed_start[];
extern uint8_t _pill_embed_end[];

static void d5_hex64(uint64_t value);

static void d5_publish(void)
{
#if defined(M38_D7_NATIVE)
    if (g_d7_batch_active) {
        g_d7_batch_publications++;
        return;
    }
#endif
    g_publications++;
}

static size_t d5_strlen(const char *s)
{
    size_t n = 0;
    while (s && s[n])
        n++;
    return n;
}

static noun d5_atom(const char *s)
{
    return cord_from_bytes(s, d5_strlen(s));
}

static noun d5_runtime_stimulus_tag(void)
{
    /* Exact bytes of the frozen numeric literal in m38_nock.py. */
    return d5_atom(RUNTIME_STIMULUS_TAG_PREFIX);
}

static int d5_same_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int d5_atom_bytes(noun value, uint8_t *out, size_t len)
{
    return noun_is_atom(value) && noun_atom_read_fixed(value, out, len) != 0;
}

static int d5_atom_is(noun value, const char *text)
{
    size_t len = d5_strlen(text);
    uint8_t got[D5_MAX_IDENTITY_BYTES] = {0};
    if (len > sizeof got || !d5_atom_bytes(value, got, len))
        return 0;
    for (size_t i = 0; i < len; i++)
        if (got[i] != (uint8_t)text[i])
            return 0;
    for (size_t i = len; i < sizeof got; i++)
        if (got[i] != 0)
            return 0;
    return 1;
}

static int d5_record(noun value, noun *fields, uint32_t count)
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

static int d5_pair(noun value, noun *head, noun *tail)
{
    if (!noun_is_cell(value))
        return 0;
    cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(value);
    *head = cell->head;
    *tail = cell->tail;
    return 1;
}

static int d5_prefix(noun value, noun *fields, uint32_t count)
{
    noun current = value;
    for (uint32_t i = 0; i < count; i++) {
        if (!noun_is_cell(current))
            return 0;
        cell_t *cell = (cell_t *)(uintptr_t)cell_ptr(current);
        fields[i] = cell->head;
        current = cell->tail;
    }
    return 1;
}

static int d5_list(noun value, noun *items, uint32_t limit, uint32_t *count)
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

static int d5_u(noun value, uint64_t max, uint32_t *out)
{
    if (!noun_is_direct(value) || direct_val(value) > max)
        return 0;
    *out = (uint32_t)direct_val(value);
    return 1;
}

static noun d5_list_build(const noun *items, uint32_t count)
{
    noun result = NOUN_ZERO;
    for (uint32_t i = count; i != 0; i--) {
        noun next;
        if (!alloc_cell_checked(items[i - 1], result, &next))
            return NOUN_ZERO;
        result = next;
    }
    return result;
}

static noun d5_record_build(const noun *items, uint32_t count)
{
    return d5_list_build(items, count);
}

static noun d5_pair_build(noun head, noun tail)
{
    noun result;
    return alloc_cell_checked(head, tail, &result) ? result : NOUN_ZERO;
}

static noun d5_digest_atom(const uint8_t bytes[32])
{
    uint64_t limbs[4];
    for (uint32_t i = 0; i < 4; i++) {
        limbs[i] = 0;
        for (uint32_t j = 0; j < 8; j++)
            limbs[i] |= (uint64_t)bytes[i * 8 + j] << (j * 8);
    }
    noun result = NOUN_ZERO;
    if (!make_atom_checked(limbs, 4, &result))
        return NOUN_ZERO;
    return result;
}

static int d5_jam_digest(noun value, uint8_t digest[32],
                         jam_admission_budget_t *budget)
{
    const uint8_t *jammed;
    uint64_t bytes;
    if (jam_encode_bytes_identity_bounded(value, &jammed, &bytes, budget) != 0
        || bytes > JAM_MAX_BYTES)
        return 0;
    uint8_t raw[32];
    blake3_hash(jammed, (size_t)bytes, raw);
    for (uint32_t i = 0; i < 32; i++)
        digest[i] = raw[31u - i];
    return 1;
}

static int d5_domain_digest(noun value, const char *domain, uint8_t digest[32],
                            jam_admission_budget_t *budget)
{
    const uint8_t *jammed;
    uint64_t bytes;
    size_t domain_len = d5_strlen(domain);
    if (domain_len + 1u + JAM_MAX_BYTES > sizeof g_preimage
        || jam_encode_bytes_identity_bounded(value, &jammed, &bytes, budget) != 0
        || domain_len + 1u + bytes > sizeof g_preimage)
        return 0;
    for (size_t i = 0; i < domain_len; i++)
        g_preimage[i] = (uint8_t)domain[i];
    g_preimage[domain_len] = 0;
    for (uint64_t i = 0; i < bytes; i++)
        g_preimage[domain_len + 1u + i] = jammed[i];
    uint8_t raw[32];
    blake3_hash(g_preimage, domain_len + 1u + (size_t)bytes, raw);
    for (uint32_t i = 0; i < 32; i++)
        digest[i] = raw[31u - i];
    return 1;
}

static int d5_sha256_digest(noun value, uint8_t digest[32])
{
    const uint8_t *jammed;
    uint64_t bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    if (jam_encode_bytes_identity_bounded(value, &jammed, &bytes, &budget) != 0)
        return 0;
    sha256_hash(jammed, bytes, digest);
    return 1;
}

static int d5_identity_descriptor(noun value, const char *domain,
                                  const char *algorithm,
                                  const uint8_t expected[32],
                                  int require_expected)
{
    noun tag, body, fields[5];
    if (!d5_pair(value, &tag, &body) || !d5_atom_is(tag, TAG_IDENTITY)
        || !d5_record(body, fields, 5))
        return 0;
    if (!d5_atom_is(fields[0], TAG_IDENTITY_SCHEMA)
        || !d5_atom_is(fields[1], algorithm)
        || !d5_atom_is(fields[2], domain)
        || !d5_atom_is(fields[3], D5_BYTE_ORDER)
        || !d5_atom_bytes(fields[4], g_preimage, 32))
        return 0;
    return !require_expected || d5_same_bytes(g_preimage, expected, 32);
}

static int d5_core_descriptor_matches(noun value, const uint8_t core_id[32])
{
    return d5_identity_descriptor(value, D5_CORE_DOMAIN,
                                  "blake3-256-jam", core_id, 1);
}

static int d5_typed(noun type, noun raw)
{
    uint32_t code;
    if (!d5_u(type, D5_TYPE_UINT16, &code) || !noun_is_direct(raw))
        return 0;
    return (code == D5_TYPE_BOOL && direct_val(raw) <= 1)
        || (code == D5_TYPE_UINT16 && direct_val(raw) <= 65535);
}

static const d5_type_t *d5_find_type(const d5_plan_t *plan, uint32_t id)
{
    return id && id <= plan->type_count ? &plan->types[id - 1] : 0;
}

static const d5_value_t *d5_find_value(const d5_type_t *type, uint32_t id)
{
    return type && id && id <= type->value_count ? &type->values[id - 1] : 0;
}

static const d5_event_t *d5_find_event(const d5_type_t *type, uint32_t id,
                                       uint32_t direction)
{
    if (!type)
        return 0;
    for (uint32_t i = 0; i < type->event_count; i++)
        if (type->events[i].id == id && type->events[i].direction == direction)
            return &type->events[i];
    return 0;
}

static int d5_expr(noun value, const d5_type_t *type, uint32_t expected,
                   uint32_t depth)
{
    noun fields[5];
    uint32_t kind, expr_type;
    if (depth > 32 || !noun_is_cell(value))
        return 0;
    if (d5_record(value, fields, 3)) {
        if (!d5_u(fields[0], 3, &kind)
            || !d5_u(fields[1], D5_TYPE_UINT16, &expr_type)
            || expr_type != expected)
            return 0;
        if (kind == 1) {
            uint32_t id;
            return d5_u(fields[2], D5_MAX_VALUES, &id)
                && d5_find_value(type, id) != 0
                && d5_find_value(type, id)->type == expected;
        }
        return kind == 2 && d5_typed(fields[1], fields[2]);
    }
    if (!d5_record(value, fields, 5)
        || !d5_u(fields[0], 3, &kind) || kind != 3
        || !d5_u(fields[1], D5_TYPE_UINT16, &expr_type)
        || expr_type != expected)
        return 0;
    uint32_t op;
    if (!d5_u(fields[2], 4, &op))
        return 0;
    if (op == 1 && expected != D5_TYPE_UINT16)
        return 0;
    if ((op == 2 || op == 3 || op == 4) && expected != D5_TYPE_BOOL)
        return 0;
    if (op < 1 || op > 4)
        return 0;
    uint32_t child = op == 1 ? D5_TYPE_UINT16 : (op == 4 ? D5_TYPE_BOOL : D5_TYPE_UINT16);
    return d5_expr(fields[3], type, child, depth + 1)
        && d5_expr(fields[4], type, child, depth + 1);
}

static int d5_parse_type(noun value, uint32_t expected_id, d5_type_t *out)
{
    noun fields[6], items[16];
    uint32_t count;
    d5_type_t type = {0};
    if (!d5_record(value, fields, 6) || !d5_u(fields[0], D5_MAX_TYPES, &type.id)
        || type.id != expected_id)
        return 0;
    if (!d5_list(fields[1], items, D5_MAX_EVENTS, &count))
        return 0;
    type.event_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun ef[3], with[D5_MAX_WITH];
        uint32_t id, direction, with_count;
        if (!d5_record(items[i], ef, 3) || !d5_u(ef[0], D5_MAX_EVENTS, &id)
            || id == 0 || !d5_u(ef[1], 2, &direction)
            || !d5_list(ef[2], with, D5_MAX_WITH, &with_count))
            return 0;
        for (uint32_t j = 0; j < i; j++)
            if (type.events[j].id == id && type.events[j].direction == direction)
                return 0;
        type.events[i].id = id;
        type.events[i].direction = direction;
        type.events[i].with_count = with_count;
        for (uint32_t j = 0; j < with_count; j++) {
            if (!d5_u(with[j], D5_MAX_VALUES, &type.events[i].with_ids[j])
                || type.events[i].with_ids[j] == 0)
                return 0;
        }
    }
    if (!d5_list(fields[2], items, D5_MAX_VALUES, &count))
        return 0;
    type.value_count = count;
    for (uint32_t i = 0; i < count; i++) {
        noun vf[4];
        uint32_t id, direction, code;
        if (!d5_record(items[i], vf, 4) || !d5_u(vf[0], D5_MAX_VALUES, &id)
            || id != i + 1 || !d5_u(vf[1], 2, &direction)
            || !d5_u(vf[2], D5_TYPE_UINT16, &code)
            || (code != D5_TYPE_BOOL && code != D5_TYPE_UINT16)
            || !d5_typed(vf[2], vf[3]))
            return 0;
        type.values[i].id = id;
        type.values[i].direction = direction;
        type.values[i].type = code;
        type.values[i].initial = vf[3];
    }
    for (uint32_t i = 0; i < type.event_count; i++)
        for (uint32_t j = 0; j < type.events[i].with_count; j++) {
            const d5_value_t *v = d5_find_value(&type, type.events[i].with_ids[j]);
            if (!v || v->direction != type.events[i].direction)
                return 0;
            for (uint32_t k = 0; k < j; k++)
                if (type.events[i].with_ids[k] == type.events[i].with_ids[j])
                    return 0;
        }
    if (!d5_list(fields[3], items, D5_MAX_STATES, &count) || count == 0)
        return 0;
    type.state_count = count;
    uint32_t initial_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        noun sf[3];
        uint32_t id, initial;
        if (!d5_record(items[i], sf, 3) || !d5_u(sf[0], D5_MAX_STATES, &id)
            || id != i + 1 || !d5_u(sf[1], 1, &initial))
            return 0;
        type.states[i].id = id;
        type.states[i].initial = initial;
        initial_count += initial;
        noun actions[D5_MAX_ACTIONS];
        uint32_t action_count;
        if (!d5_list(sf[2], actions, D5_MAX_ACTIONS, &action_count))
            return 0;
        for (uint32_t j = 0; j < action_count; j++) {
            noun af[3];
            uint32_t ordinal, algorithm, output;
            if (!d5_record(actions[j], af, 3)
                || !d5_u(af[0], D5_MAX_ACTIONS, &ordinal) || ordinal != j + 1
                || !d5_u(af[1], D5_MAX_ALGORITHMS, &algorithm)
                || !d5_u(af[2], D5_MAX_EVENTS, &output)
                || (output != 0 && !d5_find_event(&type, output, 1)))
                return 0;
        }
    }
    if (initial_count != 1)
        return 0;
    if (!d5_list(fields[4], items, D5_MAX_TRANSITIONS, &count) || count == 0)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun tf[5];
        uint32_t ordinal, source, destination, event;
        if (!d5_record(items[i], tf, 5)
            || !d5_u(tf[0], D5_MAX_TRANSITIONS, &ordinal) || ordinal != i + 1
            || !d5_u(tf[1], D5_MAX_STATES, &source) || source == 0
            || !d5_u(tf[2], D5_MAX_STATES, &destination) || destination == 0
            || source > type.state_count || destination > type.state_count
            || !d5_u(tf[3], D5_MAX_EVENTS, &event)
            || (event != 0 && !d5_find_event(&type, event, 0)))
            return 0;
        uint32_t expected = D5_TYPE_BOOL;
        if (!d5_expr(tf[4], &type, expected, 0))
            return 0;
    }
    if (!d5_list(fields[5], items, D5_MAX_ALGORITHMS, &count))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        noun af[2], assignments[D5_MAX_VALUES];
        uint32_t id, assignment_count;
        if (!d5_record(items[i], af, 2) || !d5_u(af[0], D5_MAX_ALGORITHMS, &id)
            || id == 0 || !d5_list(af[1], assignments, D5_MAX_VALUES, &assignment_count))
            return 0;
        for (uint32_t j = 0; j < assignment_count; j++) {
            noun xf[2];
            uint32_t value_id;
            if (!d5_record(assignments[j], xf, 2)
                || !d5_u(xf[0], D5_MAX_VALUES, &value_id)
                || value_id == 0 || value_id > type.value_count
                || !d5_expr(xf[1], &type, type.values[value_id - 1].type, 0))
                return 0;
        }
    }
    *out = type;
    return 1;
}

static int d5_parse_plan(noun core, d5_plan_t *out)
{
    noun formula, payload, payload_tag, payload_body, core_fields[2], semantic[5];
    noun types[D5_MAX_TYPES], instances[D5_MAX_INSTANCES], routes[D5_MAX_ROUTES];
    uint32_t type_count, instance_count, route_count;
    if (!d5_pair(core, &formula, &payload)
        || !d5_pair(payload, &payload_tag, &payload_body)
        || !d5_atom_is(payload_tag, TAG_PAYLOAD)
        || !d5_record(payload_body, core_fields, 2)
        || !d5_atom_is(core_fields[0], TAG_PAYLOAD_SCHEMA)
        || !d5_record(core_fields[1], semantic, 5))
        return 0;
    if (!d5_list(semantic[0], types, D5_MAX_TYPES, &type_count)
        || !d5_list(semantic[1], instances, D5_MAX_INSTANCES, &instance_count)
        || !d5_list(semantic[2], routes, D5_MAX_ROUTES, &route_count)
        || type_count == 0 || instance_count == 0)
        return 0;
    d5_plan_t plan = {0};
    plan.type_count = type_count;
    plan.instance_count = instance_count;
    plan.route_count = route_count;
    plan.types_noun = semantic[0];
    plan.instances_noun = semantic[1];
    plan.routes_noun = semantic[2];
    plan.formula = formula;
    for (uint32_t i = 0; i < type_count; i++)
        if (!d5_parse_type(types[i], i + 1, &plan.types[i]))
            return 0;
    for (uint32_t i = 0; i < instance_count; i++) {
        noun f[2];
        uint32_t id, type_id;
        if (!d5_record(instances[i], f, 2)
            || !d5_u(f[0], D5_MAX_INSTANCES, &id) || id != i + 1
            || !d5_u(f[1], D5_MAX_TYPES, &type_id)
            || !d5_find_type(&plan, type_id))
            return 0;
        plan.instance_types[i] = type_id;
    }
    /* Routes and boundary lists are bounded before the formula sees them. */
    for (uint32_t i = 0; i < route_count; i++) {
        noun f[6];
        uint32_t ordinal, source, source_event, target, target_event;
        if (!d5_record(routes[i], f, 6)
            || !d5_u(f[0], D5_MAX_ROUTES, &ordinal) || ordinal != i + 1
            || !d5_u(f[1], D5_MAX_INSTANCES, &source) || source == 0
            || !d5_u(f[2], 0xFFFF, &source_event) || source_event == 0
            || !d5_u(f[3], D5_MAX_INSTANCES, &target) || target == 0
            || !d5_u(f[4], 0xFFFF, &target_event) || target_event == 0)
            return 0;
        noun bindings[D5_MAX_VALUES];
        uint32_t binding_count;
        if (!d5_list(f[5], bindings, D5_MAX_VALUES, &binding_count))
            return 0;
        for (uint32_t j = 0; j < binding_count; j++) {
            noun bf[3];
            if (!d5_record(bindings[j], bf, 3) || !d5_u(bf[0], 0xFFFF, &source_event)
                || !d5_u(bf[1], 0xFFFF, &target_event)
                || !d5_u(bf[2], D5_TYPE_UINT16, &ordinal)
                || (ordinal != D5_TYPE_BOOL && ordinal != D5_TYPE_UINT16))
                return 0;
        }
    }
    noun boundaries[D5_MAX_INSTANCES];
    for (uint32_t which = 3; which < 5; which++) {
        uint32_t count;
        if (!d5_list(semantic[which], boundaries, D5_MAX_INSTANCES, &count))
            return 0;
        for (uint32_t i = 0; i < count; i++) {
            noun f[3];
            if (!d5_record(boundaries[i], f, 3))
                return 0;
            noun values[D5_MAX_VALUES];
            uint32_t value_count;
            if (!d5_list(f[2], values, D5_MAX_VALUES, &value_count))
                return 0;
            for (uint32_t j = 0; j < value_count; j++) {
                noun vf[2];
                uint32_t id, code;
                if (!d5_record(values[j], vf, 2)
                    || !d5_u(vf[0], 0xFFFF, &id) || id == 0
                    || !d5_u(vf[1], D5_TYPE_UINT16, &code)
                    || (code != D5_TYPE_BOOL && code != D5_TYPE_UINT16))
                    return 0;
            }
        }
    }
    *out = plan;
    return 1;
}

static int d5_validate_admission(noun admission, const uint8_t core_id[32],
                                 int catalog_index)
{
    noun tag, body, binding_tag, binding, fields[6], binding_body[5];
    uint8_t expected_id[32] = {0};
    if (!d5_pair(admission, &tag, &body) || !d5_atom_is(tag, TAG_ADMISSION)
        || !d5_record(body, fields, 6)
        || !d5_atom_is(fields[0], TAG_ADMISSION_SCHEMA)
        || !d5_pair(fields[1], &binding_tag, &binding))
        return 0;
    if (!d5_atom_is(binding_tag, TAG_BINDING)
        || !d5_record(binding, binding_body, 5))
        return 0;
    if (!d5_atom_is(binding_body[0], TAG_BINDING_SCHEMA))
        return 0;
    for (uint32_t i = 1; i < 5; i++)
        if (!d5_identity_descriptor(binding_body[i],
              i == 1 ? "1499kernel:m38-a:source:v2" :
              i == 2 ? "1499kernel-i2-m38-a-application-model-v2" :
              i == 3 ? "1499kernel-i2-m38-a-executable-application-plan-v2" :
                        "1499kernel-i2-m38-a-executable-application-package-v2",
              "sha256", expected_id, 0))
            return 0;
    if (!d5_identity_descriptor(fields[2],
            "1499kernel:i2:m38-d0-r2:deployment-binding:v1", "sha256", expected_id, 0)
        || !d5_core_descriptor_matches(fields[3], core_id)
        || !d5_identity_descriptor(fields[4],
            "1499kernel:i2:m38-d0-r2:resource-path:v2", "sha256", expected_id, 0))
        return 0;
    noun bounds[3];
    if (!d5_record(fields[5], bounds, 3)
        || !noun_is_direct(bounds[0]) || direct_val(bounds[0]) != D5_POLICY_MAX_OPS
        || !noun_is_direct(bounds[1]) || direct_val(bounds[1]) != D5_POLICY_MAX_CELLS
        || !noun_is_direct(bounds[2]) || direct_val(bounds[2]) != D5_POLICY_MAX_STACK)
        return 0;
    uint8_t admission_id[32];
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    if (!d5_jam_digest(admission, admission_id, &budget)
        || catalog_index < 0 || catalog_index >= 2
        || !d5_same_bytes(admission_id, ADMISSION_IDS[catalog_index], 32))
        return 0;
    (void)catalog_index;
    return 1;
}

static int d5_validate_core(noun core, uint8_t core_id[32], d5_plan_t *plan,
                            int *catalog_index)
{
    noun formula, payload;
    uint8_t formula_digest[32];
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    if (!d5_pair(core, &formula, &payload)
        || !d5_jam_digest(formula, formula_digest, &budget)
        || !d5_parse_plan(core, plan)
        || !d5_domain_digest(core, D5_CORE_DOMAIN, core_id, &budget))
        return 0;
    int index = -1;
    for (int i = 0; i < 2; i++)
#if defined(M38_D7_NATIVE)
        if (d5_same_bytes(core_id, D7_AUTHORITIES[i].core_id, 32))
#else
        if (d5_same_bytes(core_id, CORE_IDS[i], 32))
#endif
            index = i;
#if defined(M38_D7_NATIVE)
    if (index < 0 || !d5_same_bytes(formula_digest,
                                    D7_AUTHORITIES[index].formula_id, 32))
        return 0;
    *catalog_index = index;
    return 1;
#else
    if (!d5_same_bytes(formula_digest, FORMULA_ID, 32))
        return 0;
    *catalog_index = index;
    return index >= 0;
#endif
}

/* LOAD authority is a read-only admission decision.  Keep this shared by
 * ingress preflight and dispatch so the transaction boundary cannot drift
 * from the operation's actual catalog/core checks. */
static int d5_validate_load_request(noun core, noun admission,
                                    d5_load_validation_t *out)
{
    if (!d5_validate_core(core, out->core_id, &out->plan,
                          &out->catalog_index))
        return 2; /* unknown-core */
    if (!d5_validate_admission(admission, out->core_id, out->catalog_index))
        return 3; /* unauthorized-admission */
    return 0;
}

static noun d5_handle(uint32_t slot, uint64_t generation)
{
    noun fields[3] = {d5_atom(TAG_HANDLE_SCHEMA), direct(slot), direct(generation)};
    noun body = d5_record_build(fields, 3);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(d5_atom(TAG_HANDLE), body);
}

static int d5_decode_handle(noun value, uint32_t *slot, uint64_t *generation)
{
    noun tag, body, fields[3];
    if (!d5_pair(value, &tag, &body) || !d5_atom_is(tag, TAG_HANDLE)
        || !d5_record(body, fields, 3)
        || !d5_atom_is(fields[0], TAG_HANDLE_SCHEMA)
        || !noun_is_direct(fields[1]) || !noun_is_direct(fields[2])
        || direct_val(fields[1]) < 1 || direct_val(fields[1]) > D5_SLOT_COUNT
        || direct_val(fields[2]) < 1 || direct_val(fields[2]) > D5_MAX_GENERATION)
        return 0;
    *slot = (uint32_t)direct_val(fields[1]);
    *generation = direct_val(fields[2]);
    return 1;
}

static noun d5_identity(const char *domain, const char *algorithm,
                        const uint8_t digest[32])
{
    noun fields[5] = {d5_atom(TAG_IDENTITY_SCHEMA), d5_atom(algorithm),
                      d5_atom(domain), d5_atom(D5_BYTE_ORDER), d5_digest_atom(digest)};
    noun body = d5_record_build(fields, 5);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(d5_atom(TAG_IDENTITY), body);
}

static noun d5_core_descriptor(noun value)
{
    uint8_t id[32];
    if (!d5_atom_bytes(value, id, 32))
        return NOUN_ZERO;
    return d5_identity(D5_CORE_DOMAIN, "blake3-256-jam", id);
}

static noun d5_state_noun(const d5_plan_t *plan, const d5_state_t *state,
                          uint32_t slot, uint64_t generation,
                          const uint8_t core_id[32], uint32_t kind)
{
    noun rows[D5_MAX_INSTANCES];
    noun handle = d5_handle(slot, generation);
    noun core_descriptor = d5_core_descriptor(d5_digest_atom(core_id));
    if (handle == NOUN_ZERO || core_descriptor == NOUN_ZERO)
        return NOUN_ZERO;
    for (uint32_t i = plan->instance_count; i != 0; i--) {
        uint32_t instance = i - 1;
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance]);
        noun values[D5_MAX_VALUES];
        for (uint32_t j = type->value_count; j != 0; j--) {
            uint32_t value = j - 1;
            noun fields[3] = {direct(value + 1),
                              direct(type->values[value].type),
                              direct(state->values[instance][value])};
            values[value] = d5_record_build(fields, 3);
            if (values[value] == NOUN_ZERO)
                return NOUN_ZERO;
        }
        noun value_list = d5_list_build(values, type->value_count);
        noun record[3] = {direct(instance + 1), direct(state->state_ids[instance]), value_list};
        rows[instance] = d5_record_build(record, 3);
        if (rows[instance] == NOUN_ZERO)
            return NOUN_ZERO;
    }
    noun row_list = d5_list_build(rows, plan->instance_count);
    noun fields[5] = {d5_atom(TAG_STATE_SCHEMA), handle, core_descriptor,
                      direct(kind), row_list};
    noun body = d5_record_build(fields, 5);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(d5_atom(TAG_STATE), body);
}

static uint32_t d5_runtime_event_id(const d5_type_t *type, uint32_t id,
                                    uint32_t direction)
{
    uint32_t ordinal = 0;
    for (uint32_t i = 0; i < type->event_count; i++) {
        if (type->events[i].direction != direction)
            continue;
        ordinal++;
        if (type->events[i].id == id)
            return ordinal;
    }
    return 0;
}

/* D0 type records use type-local event ids.  M38-B's runtime type records
 * use the resource-local event namespace (one ordinal per direction), so
 * rebuild only the event-bearing fields while retaining the validated D0
 * values, expressions, and algorithms. */
static noun d5_runtime_types(const d5_plan_t *plan)
{
    noun source_types[D5_MAX_TYPES], runtime_types[D5_MAX_TYPES];
    uint32_t type_count;
    if (!d5_list(plan->types_noun, source_types, D5_MAX_TYPES, &type_count))
        return NOUN_ZERO;
    for (uint32_t i = 0; i < type_count; i++) {
        noun fields[6], source_events[D5_MAX_EVENTS], runtime_events[D5_MAX_EVENTS];
        uint32_t event_count;
        if (!d5_record(source_types[i], fields, 6)
            || !d5_list(fields[1], source_events, D5_MAX_EVENTS, &event_count))
            return NOUN_ZERO;
        const d5_type_t *type = d5_find_type(plan, i + 1);
        if (!type || event_count != type->event_count)
            return NOUN_ZERO;
        for (uint32_t j = 0; j < event_count; j++) {
            noun event_fields[3];
            uint32_t old_id, direction, runtime_id;
            if (!d5_record(source_events[j], event_fields, 3)
                || !d5_u(event_fields[0], D5_MAX_EVENTS, &old_id)
                || !d5_u(event_fields[1], 2, &direction)
                || (runtime_id = d5_runtime_event_id(type, old_id, direction)) == 0)
                return NOUN_ZERO;
            noun runtime_event[3] = {direct(runtime_id), event_fields[1], event_fields[2]};
            runtime_events[j] = d5_record_build(runtime_event, 3);
        }

        noun source_states[D5_MAX_STATES], runtime_states[D5_MAX_STATES];
        uint32_t state_count;
        if (!d5_list(fields[3], source_states, D5_MAX_STATES, &state_count))
            return NOUN_ZERO;
        for (uint32_t j = 0; j < state_count; j++) {
            noun state_fields[3], source_actions[D5_MAX_ACTIONS], runtime_actions[D5_MAX_ACTIONS];
            uint32_t action_count;
            if (!d5_record(source_states[j], state_fields, 3)
                || !d5_list(state_fields[2], source_actions, D5_MAX_ACTIONS, &action_count))
                return NOUN_ZERO;
            for (uint32_t k = 0; k < action_count; k++) {
                noun action_fields[3];
                uint32_t output;
                if (!d5_record(source_actions[k], action_fields, 3)
                    || !d5_u(action_fields[2], D5_MAX_EVENTS, &output))
                    return NOUN_ZERO;
                if (output != 0) {
                    output = d5_runtime_event_id(type, output, 1);
                    if (output == 0)
                        return NOUN_ZERO;
                }
                noun runtime_action[3] = {action_fields[0], action_fields[1], direct(output)};
                runtime_actions[k] = d5_record_build(runtime_action, 3);
            }
            noun runtime_state[3] = {state_fields[0], state_fields[1],
                                     d5_list_build(runtime_actions, action_count)};
            runtime_states[j] = d5_record_build(runtime_state, 3);
        }

        noun source_transitions[D5_MAX_TRANSITIONS], runtime_transitions[D5_MAX_TRANSITIONS];
        uint32_t transition_count;
        if (!d5_list(fields[4], source_transitions, D5_MAX_TRANSITIONS, &transition_count))
            return NOUN_ZERO;
        for (uint32_t j = 0; j < transition_count; j++) {
            noun transition_fields[5];
            uint32_t input;
            if (!d5_record(source_transitions[j], transition_fields, 5)
                || !d5_u(transition_fields[3], D5_MAX_EVENTS, &input))
                return NOUN_ZERO;
            if (input != 0) {
                input = d5_runtime_event_id(type, input, 0);
                if (input == 0)
                    return NOUN_ZERO;
            }
            noun runtime_transition[5] = {transition_fields[0], transition_fields[1],
                                           transition_fields[2], direct(input), transition_fields[4]};
            runtime_transitions[j] = d5_record_build(runtime_transition, 5);
        }
        noun runtime_type[6] = {fields[0], d5_list_build(runtime_events, event_count),
                                fields[2], d5_list_build(runtime_states, state_count),
                                d5_list_build(runtime_transitions, transition_count), fields[5]};
        runtime_types[i] = d5_record_build(runtime_type, 6);
    }
    return d5_list_build(runtime_types, type_count);
}

static int d5_initial_state(const d5_plan_t *plan, d5_state_t *state)
{
    for (uint32_t i = 0; i < plan->instance_count; i++) {
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[i]);
        uint32_t initial = 0;
        for (uint32_t s = 0; s < type->state_count; s++)
            if (type->states[s].initial)
                initial = type->states[s].id;
        if (initial == 0)
            return 0;
        state->state_ids[i] = initial;
        for (uint32_t v = 0; v < type->value_count; v++)
            state->values[i][v] = noun_is_direct(type->values[v].initial)
                ? (uint32_t)direct_val(type->values[v].initial) : 0;
    }
    return 1;
}

static noun d5_runtime_plan(const d5_plan_t *plan, const uint8_t core_id[32])
{
    noun identity = d5_digest_atom(core_id);
    noun runtime_types = d5_runtime_types(plan);
    noun source_routes[D5_MAX_ROUTES], runtime_routes[D5_MAX_ROUTES];
    uint32_t route_count;
    if (!d5_list(plan->routes_noun, source_routes, D5_MAX_ROUTES, &route_count))
        return NOUN_ZERO;
    for (uint32_t i = 0; i < route_count; i++) {
        noun fields[6];
        uint32_t ordinal, source, source_event, target, target_event;
        if (!d5_record(source_routes[i], fields, 6)
            || !d5_u(fields[0], D5_MAX_ROUTES, &ordinal)
            || !d5_u(fields[1], D5_MAX_INSTANCES, &source)
            || !d5_u(fields[2], 0xFFFF, &source_event)
            || !d5_u(fields[3], D5_MAX_INSTANCES, &target)
            || !d5_u(fields[4], 0xFFFF, &target_event)
            || source == 0 || target == 0
            || source_event <= source * 1024u
            || target_event <= target * 1024u)
            return NOUN_ZERO;
        noun bindings[D5_MAX_VALUES], runtime_bindings[D5_MAX_VALUES];
        uint32_t binding_count;
        if (!d5_list(fields[5], bindings, D5_MAX_VALUES, &binding_count))
            return NOUN_ZERO;
        for (uint32_t j = 0; j < binding_count; j++) {
            noun binding[3];
            uint32_t source_value, target_value, type;
            if (!d5_record(bindings[j], binding, 3)
                || !d5_u(binding[0], 0xFFFF, &source_value)
                || !d5_u(binding[1], 0xFFFF, &target_value)
                || !d5_u(binding[2], D5_TYPE_UINT16, &type)
                || source_value <= source * 1024u
                || target_value <= target * 1024u)
                return NOUN_ZERO;
            noun runtime_binding[3] = {direct(source_value - source * 1024u),
                                       direct(target_value - target * 1024u), direct(type)};
            runtime_bindings[j] = d5_record_build(runtime_binding, 3);
        }
        noun runtime_route[6] = {direct(ordinal), direct(source),
                                 direct(source_event - source * 1024u), direct(target),
                                 direct(target_event - target * 1024u),
                                 d5_list_build(runtime_bindings, binding_count)};
        runtime_routes[i] = d5_record_build(runtime_route, 6);
    }
    noun fields[4] = {identity, runtime_types, plan->instances_noun,
                      d5_list_build(runtime_routes, route_count)};
    noun body = d5_record_build(fields, 4);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(direct(RUNTIME_PLAN_TAG), body);
}

static noun d5_runtime_state(const d5_plan_t *plan, const d5_state_t *state,
                             const uint8_t core_id[32])
{
    noun records[D5_MAX_INSTANCES];
    for (uint32_t i = plan->instance_count; i != 0; i--) {
        uint32_t instance = i - 1;
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance]);
        noun values[D5_MAX_VALUES];
        for (uint32_t j = type->value_count; j != 0; j--) {
            uint32_t value = j - 1;
            noun vf[3] = {direct(value + 1),
                          direct(type->values[value].type),
                          direct(state->values[instance][value])};
            values[value] = d5_record_build(vf, 3);
        }
        noun record[3] = {direct(instance + 1), direct(state->state_ids[instance]),
                          d5_list_build(values, type->value_count)};
        records[instance] = d5_record_build(record, 3);
    }
    noun fields[2] = {d5_digest_atom(core_id), d5_list_build(records, plan->instance_count)};
    noun body = d5_record_build(fields, 2);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(direct(RUNTIME_STATE_TAG), body);
}

static noun d5_bounds(void)
{
    noun fields[3] = {direct(D5_QUEUE_LIMIT), direct(D5_WORKLIST_LIMIT), direct(D5_TRACE_LIMIT)};
    noun limits = d5_record_build(fields, 3);
    return d5_pair_build(limits, NOUN_ZERO);
}

static int d5_decode_request(noun request, d5_request_t *out)
{
    noun tag, request_body, body[3];
    if (!d5_pair(request, &tag, &request_body)
        || !d5_atom_is(tag, TAG_REQUEST)
        || !d5_record(request_body, body, 3)
        || !d5_atom_is(body[0], TAG_REQUEST_SCHEMA) || !noun_is_direct(body[1])
        || direct_val(body[1]) < D5_OP_LOAD || direct_val(body[1]) > D5_OP_RESTORE)
        return 0;
    out->operation = (uint32_t)direct_val(body[1]);
    out->first = body[2];
    out->second = NOUN_ZERO;
    if (out->operation == D5_OP_LOAD || out->operation == D5_OP_POKE
        || out->operation == D5_OP_PEEK || out->operation == D5_OP_RESTORE) {
        noun args[2];
        if (!d5_record(body[2], args, 2)) {
            return 0;
        }
        out->first = args[0];
        out->second = args[1];
    }
    return 1;
}

static int d5_slot_resolve_in(const d5_slot_t *slots, noun handle, uint32_t *slot)
{
    uint64_t generation;
    if (!d5_decode_handle(handle, slot, &generation) || !slots[*slot - 1].used
        || slots[*slot - 1].generation != generation)
        return 0;
    return 1;
}

static int d5_slot_resolve(noun handle, uint32_t *slot)
{
    return d5_slot_resolve_in(g_slots, handle, slot);
}

static noun d5_reason(uint32_t code, uint32_t detail)
{
    noun fields[3] = {d5_atom(TAG_REASON_SCHEMA), direct(code), direct(detail)};
    noun body = d5_record_build(fields, 3);
    return body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(d5_atom(TAG_REASON), body);
}

/* Dispatcher results are owned by a bounded module-local arena.  The arena
 * is reset only when the next dispatch starts, after the caller has had the
 * current call's result available for serialization/copy.  Transient nouns
 * stay in the scratch epoch and are rewound at the dispatch boundary; no
 * returned noun points into that reclaimable epoch.  The source-to-result
 * map is open-addressed so staging remains linear in the copied graph. */
static uint32_t d5_result_hash(uint32_t source_ptr, uint32_t capacity)
{
    uint32_t value = source_ptr >> 3;
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    return value & (capacity - 1u);
}

static noun d5_result_copy_rec(d5_result_arena_t *arena, noun source,
                               uint32_t depth, uint32_t limit, int *ok)
{
    if (!noun_is_cell(source))
        return source;
    if (depth > D5_RESULT_DEPTH_MAX) {
        *ok = 0;
        return NOUN_ZERO;
    }
    uint32_t source_ptr = cell_ptr(source);
    uint32_t map_slot = d5_result_hash(source_ptr, arena->capacity);
    for (uint32_t probe = 0; probe < arena->capacity; probe++) {
        uint32_t mapped_source = arena->source[map_slot];
        if (mapped_source == 0)
            break;
        if (mapped_source == source_ptr)
            return arena->value[map_slot];
        map_slot = (map_slot + 1u) & (arena->capacity - 1u);
    }
    if (arena->cell_count >= limit) {
        *ok = 0;
        return NOUN_ZERO;
    }
    uint32_t index = arena->cell_count++;
    noun result = cell_noun((uint32_t)(uintptr_t)&arena->cells[index]);
    arena->source[map_slot] = source_ptr;
    arena->value[map_slot] = result;
    arena->cells[index].refcount = 1;
    arena->cells[index]._pad = 0;
    arena->cells[index].head = NOUN_ZERO;
    arena->cells[index].tail = NOUN_ZERO;
    cell_t *cell = (cell_t *)(uintptr_t)source_ptr;
    arena->cells[index].head = d5_result_copy_rec(arena, cell->head, depth + 1,
                                                  limit, ok);
    arena->cells[index].tail = d5_result_copy_rec(arena, cell->tail, depth + 1,
                                                  limit, ok);
    return result;
}

static noun d5_result_stage_into(d5_result_arena_t *arena, noun source,
                                 uint32_t limit)
{
    for (uint32_t i = 0; i < arena->capacity; i++)
        arena->source[i] = 0;
    arena->cell_count = 0;
    arena->root = NOUN_ZERO;
    if (limit == 0 || limit > arena->capacity)
        limit = arena->capacity;
    int ok = 1;
    noun result = d5_result_copy_rec(arena, source, 1, limit, &ok);
    if (!ok || !noun_is_cell(result))
        return NOUN_ZERO;
    arena->root = result;
    return result;
}

static noun d5_result_stage(noun source)
{
    uint32_t limit = g_result_stage_limit;
    g_result_stage_limit = D5_RESULT_CELL_CAPACITY;
    return d5_result_stage_into(&g_result_arena, source, limit);
}

static noun d5_nested_result_stage(noun source)
{
    return d5_result_stage_into(&g_nested_result_arena, source,
                                D5_NESTED_RESULT_CELL_CAPACITY);
}

static noun d5_result(uint32_t status, noun body)
{
    noun fields[3] = {d5_atom(TAG_RESULT_SCHEMA), direct(status), body};
    noun result_body = d5_record_build(fields, 3);
    return result_body == NOUN_ZERO ? NOUN_ZERO : d5_pair_build(d5_atom(TAG_RESULT), result_body);
}

static noun d5_refuse(uint32_t code, uint32_t detail, noun unchanged)
{
    noun fields[2] = {d5_reason(code, detail), unchanged};
    return d5_result(D5_STATUS_REFUSE, d5_record_build(fields, 2));
}

static int d5_product_state(const d5_plan_t *plan, noun runtime_state,
                            const uint8_t core_id[32], d5_state_t *out)
{
    noun tag, body, fields[2];
    if (!d5_pair(runtime_state, &tag, &body)
        || tag != direct(RUNTIME_STATE_TAG)
        || !d5_record(body, fields, 2)
        || !noun_eq(fields[0], d5_digest_atom(core_id)))
        return 0;
    noun rows[D5_MAX_INSTANCES];
    uint32_t count;
    if (!d5_list(fields[1], rows, D5_MAX_INSTANCES, &count)
        || count != plan->instance_count)
        return 0;
    uint8_t seen[D5_MAX_INSTANCES] = {0};
    for (uint32_t i = 0; i < count; i++) {
        noun rf[3];
        uint32_t instance, state_id;
        if (!d5_record(rows[i], rf, 3) || !d5_u(rf[0], D5_MAX_INSTANCES, &instance)
            || instance == 0 || seen[instance - 1]
            || !d5_u(rf[1], D5_MAX_STATES, &state_id) || state_id == 0
            || instance > plan->instance_count)
            return 0;
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance - 1]);
        if (state_id > type->state_count)
            return 0;
        noun values[D5_MAX_VALUES];
        uint32_t value_count;
        if (!d5_list(rf[2], values, D5_MAX_VALUES, &value_count)
            || value_count != type->value_count)
            return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[3];
            uint32_t id, code;
            if (!d5_record(values[j], vf, 3) || !d5_u(vf[0], 0xFFFF, &id)
                || !d5_u(vf[1], D5_TYPE_UINT16, &code)
                || id != j + 1 || code != type->values[j].type
                || !d5_typed(vf[1], vf[2]))
                return 0;
            out->values[instance - 1][j] = (uint32_t)direct_val(vf[2]);
        }
        out->state_ids[instance - 1] = state_id;
        seen[instance - 1] = 1;
    }
    for (uint32_t i = 0; i < count; i++)
        if (!seen[i])
            return 0;
    return 1;
}

static int d5_decode_state(const d5_plan_t *plan, noun state_noun,
                           noun expected_handle, const uint8_t core_id[32],
                           d5_state_t *out, uint32_t *kind_out)
{
    noun tag, body, fields[5];
    if (!d5_pair(state_noun, &tag, &body) || !d5_atom_is(tag, TAG_STATE)
        || !d5_record(body, fields, 5)
        || !d5_atom_is(fields[0], TAG_STATE_SCHEMA)
        || !noun_eq(fields[1], expected_handle)
        || !d5_core_descriptor_matches(fields[2], core_id)
        || !noun_is_direct(fields[3])
        || (direct_val(fields[3]) != D5_STATE_INITIALIZED
            && direct_val(fields[3]) != D5_STATE_NEXT))
        return 0;
    noun rows[D5_MAX_INSTANCES];
    uint32_t count;
    if (!d5_list(fields[4], rows, D5_MAX_INSTANCES, &count)
        || count != plan->instance_count)
        return 0;
    d5_state_t candidate = {0};
    uint8_t seen[D5_MAX_INSTANCES] = {0};
    for (uint32_t i = 0; i < count; i++) {
        noun row[3];
        uint32_t instance, state_id, value_count;
        if (!d5_record(rows[i], row, 3)
            || !d5_u(row[0], D5_MAX_INSTANCES, &instance)
            || instance == 0 || instance > plan->instance_count || seen[instance - 1]
            || !d5_u(row[1], D5_MAX_STATES, &state_id) || state_id == 0)
            return 0;
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance - 1]);
        noun values[D5_MAX_VALUES];
        if (!type || state_id > type->state_count
            || !d5_list(row[2], values, D5_MAX_VALUES, &value_count)
            || value_count != type->value_count)
            return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value[3];
            uint32_t id, code;
            if (!d5_record(values[j], value, 3)
                || !d5_u(value[0], 0xFFFF, &id)
                || id != j + 1
                || !d5_u(value[1], D5_TYPE_UINT16, &code)
                || code != type->values[j].type
                || !d5_typed(value[1], value[2]))
                return 0;
            candidate.values[instance - 1][j] = (uint32_t)direct_val(value[2]);
        }
        candidate.state_ids[instance - 1] = state_id;
        seen[instance - 1] = 1;
    }
    for (uint32_t i = 0; i < count; i++)
        if (!seen[i])
            return 0;
    *out = candidate;
    *kind_out = (uint32_t)direct_val(fields[3]);
    return 1;
}

static uint32_t d5_runtime_output_event_id(const d5_plan_t *plan,
                                           uint32_t instance, uint32_t ordinal)
{
    if (instance == 0 || instance > plan->instance_count)
        return 0;
    const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance - 1]);
    uint32_t output_ordinal = 0;
    for (uint32_t i = 0; i < type->event_count; i++) {
        if (type->events[i].direction != 1)
            continue;
        output_ordinal++;
        if (output_ordinal == ordinal)
            return type->events[i].id;
    }
    return 0;
}

static int d5_route_event(const d5_plan_t *plan, uint32_t instance, uint32_t event)
{
    uint32_t source_event_id = d5_runtime_output_event_id(plan, instance, event);
    if (source_event_id == 0)
        return 1;
    noun rows[D5_MAX_ROUTES];
    uint32_t count;
    if (!d5_list(plan->routes_noun, rows, D5_MAX_ROUTES, &count))
        return 1;
    for (uint32_t i = 0; i < count; i++) {
        noun f[6];
        uint32_t source, source_event;
        if (!d5_record(rows[i], f, 6) || !d5_u(f[1], D5_MAX_INSTANCES, &source)
            || !d5_u(f[2], 0xFFFF, &source_event))
            return 1;
        if (source == instance && source_event == instance * 1024u + source_event_id)
            return 1;
    }
    return 0;
}

static noun d5_effects(const d5_plan_t *plan, noun trace)
{
    noun rows[D5_MAX_EFFECTS];
    uint32_t trace_count, effect_count = 0;
    if (!d5_list(trace, rows, D5_TRACE_LIMIT, &trace_count))
        return NOUN_ZERO;
    noun emissions[D5_MAX_EFFECTS];
    for (uint32_t i = 0; i < trace_count; i++) {
        noun f[4];
        uint32_t kind, instance, event;
        if (!d5_prefix(rows[i], f, 1) || !d5_u(f[0], 7, &kind))
            return NOUN_ZERO;
        if (kind != 6)
            continue;
        if (!d5_prefix(rows[i], f, 4)
            || !d5_u(f[1], D5_MAX_INSTANCES, &instance)
            || !d5_u(f[2], 0xFFFF, &event) || instance == 0
            || d5_route_event(plan, instance, event))
            continue;
        /* The R5 trace ordinal is the D0 output-event id.  The plan-derived
         * id above is only for matching the compiled route source namespace. */
        uint32_t event_id = event;
        if (effect_count >= D5_MAX_EFFECTS)
            return NOUN_ZERO;
        noun runtime_values[D5_MAX_VALUES], d0_values[D5_MAX_VALUES];
        uint32_t value_count;
        if (!d5_list(f[3], runtime_values, D5_MAX_VALUES, &value_count))
            return NOUN_ZERO;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value[3];
            uint32_t local_id;
            if (!d5_record(runtime_values[j], value, 3)
                || !d5_u(value[0], D5_MAX_VALUES, &local_id) || local_id == 0)
                return NOUN_ZERO;
            noun d0_value[3] = {direct(local_id), value[1], value[2]};
            d0_values[j] = d5_record_build(d0_value, 3);
        }
        noun ef_values = d5_list_build(d0_values, value_count);
        noun ef[5] = {d5_atom(TAG_EFFECT_EMISSION_SCHEMA), instance,
                      direct(event_id), direct(effect_count + 1), ef_values};
        noun body = d5_record_build(ef, 5);
        emissions[effect_count++] = d5_pair_build(d5_atom(TAG_EFFECT_EMISSION), body);
    }
    noun fields[2] = {d5_atom(TAG_EFFECTS_SCHEMA), d5_list_build(emissions, effect_count)};
    noun body = d5_record_build(fields, 2);
    return d5_pair_build(d5_atom(TAG_EFFECTS), body);
}

static noun d5_observations(noun observation_trace)
{
    noun rows[D5_MAX_OBSERVATIONS];
    noun value_rows[D5_MAX_VALUES];
    uint32_t count;
    if (!d5_list(observation_trace, rows, D5_TRACE_LIMIT, &count))
        return NOUN_ZERO;
    noun observations[D5_MAX_OBSERVATIONS];
    uint32_t used = 0;
    for (uint32_t i = 0; i < count; i++) {
        noun row_tail, values, instance_noun, event_noun;
        uint32_t instance, event, value_count;
        if (used >= D5_MAX_OBSERVATIONS
            || !d5_pair(rows[i], &instance_noun, &row_tail)
            || !d5_pair(row_tail, &event_noun, &values)
            || !d5_u(instance_noun, D5_MAX_INSTANCES, &instance)
            || instance == 0 || !d5_u(event_noun, 0xFFFF, &event)
            || !d5_list(values, value_rows, D5_MAX_VALUES, &value_count))
            return NOUN_ZERO;
        noun runtime_values[D5_MAX_VALUES], d0_values[D5_MAX_VALUES];
        for (uint32_t j = 0; j < value_count; j++)
            runtime_values[j] = value_rows[j];
        uint32_t target = event;
        for (uint32_t j = 0; j < value_count; j++) {
            noun value_fields[3];
            uint32_t local_id;
            if (!d5_record(runtime_values[j], value_fields, 3)
                || !d5_u(value_fields[0], D5_MAX_VALUES, &local_id)
                || local_id == 0)
                return NOUN_ZERO;
            if (j == 0)
                target = local_id;
            noun d0_value[3] = {direct(local_id),
                                value_fields[1], value_fields[2]};
            d0_values[j] = d5_record_build(d0_value, 3);
        }
        noun selector_fields[3] = {d5_atom(TAG_SELECTOR_SCHEMA), direct(1),
                                   direct(target)};
        noun selector_body = d5_record_build(selector_fields, 3);
        noun selector = d5_pair_build(d5_atom(TAG_SELECTOR), selector_body);
        noun obs_fields[4] = {d5_atom(TAG_OBSERVATION_SCHEMA), direct(used + 1),
                              selector, d5_list_build(d0_values, value_count)};
        noun obs_body = d5_record_build(obs_fields, 4);
        observations[used++] = d5_pair_build(d5_atom(TAG_OBSERVATION), obs_body);
    }
    noun fields[2] = {d5_atom(TAG_OBSERVATIONS_SCHEMA), d5_list_build(observations, used)};
    noun body = d5_record_build(fields, 2);
    return d5_pair_build(d5_atom(TAG_OBSERVATIONS), body);
}

static noun d5_metrics(uint64_t ops, uint64_t cells, uint64_t stack,
                       uint32_t queue, uint32_t work)
{
    if (ops > D5_POLICY_MAX_OPS || cells > D5_POLICY_MAX_CELLS
        || stack > D5_POLICY_MAX_STACK || queue > D5_QUEUE_LIMIT
        || work > D5_WORKLIST_LIMIT)
        return NOUN_ZERO;
    noun fields[6] = {d5_atom(TAG_METRICS_SCHEMA), direct(ops), direct(cells),
                      direct(stack), direct(queue), direct(work)};
    noun body = d5_record_build(fields, 6);
    return d5_pair_build(d5_atom(TAG_METRICS), body);
}

static int d5_snapshot_digest(noun snapshot, uint8_t digest[32])
{
    const uint8_t *jammed;
    uint64_t bytes;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    if (jam_encode_bytes_identity_bounded(snapshot, &jammed, &bytes, &budget) != 0)
        return 0;
    sha256_ctx_t context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)D5_SNAPSHOT_DOMAIN,
                  d5_strlen(D5_SNAPSHOT_DOMAIN));
    uint8_t zero = 0;
    sha256_update(&context, &zero, 1);
    sha256_update(&context, jammed, bytes);
    sha256_final(&context, digest);
    return 1;
}

static noun d5_snapshot(const d5_plan_t *plan, const d5_slot_t *slot,
                        uint32_t slot_number, const uint8_t core_id[32])
{
    noun state = d5_state_noun(plan, &slot->state, slot_number, slot->generation,
                                core_id, slot->state_kind);
    noun fields[3] = {d5_atom(TAG_SNAPSHOT_SCHEMA), d5_core_descriptor(d5_digest_atom(core_id)), state};
    noun body = d5_record_build(fields, 3);
    return d5_pair_build(d5_atom(TAG_SNAPSHOT), body);
}

static int d5_validate_restore_snapshot_shape(const d5_plan_t *plan,
                                              noun handle, noun snapshot,
                                              const uint8_t core_id[32],
                                              d5_state_t *restored,
                                              uint32_t *restored_kind)
{
    noun snapshot_tag, snapshot_body, fields[3];
    if (!d5_pair(snapshot, &snapshot_tag, &snapshot_body)
        || !d5_atom_is(snapshot_tag, TAG_SNAPSHOT)
        || !d5_record(snapshot_body, fields, 3)
        || !d5_atom_is(fields[0], TAG_SNAPSHOT_SCHEMA)
        || !d5_core_descriptor_matches(fields[1], core_id))
        return 0;
    return d5_decode_state(plan, fields[2], handle, core_id,
                           restored, restored_kind);
}

static int d5_validate_restore_snapshot(const d5_plan_t *plan,
                                        const d5_slot_t *slot, noun handle,
                                        noun snapshot, const uint8_t core_id[32],
                                        d5_state_t *restored,
                                        uint32_t *restored_kind)
{
    uint8_t digest[32];
    if (!slot->latest || !d5_snapshot_digest(snapshot, digest)
        || !d5_same_bytes(digest, slot->snapshot_digest, 32))
        return 0;
    return d5_validate_restore_snapshot_shape(plan, handle, snapshot, core_id,
                                              restored, restored_kind);
}

/* Private semispace catalog admission.  Existing catalog roots are copied to
 * the candidate semispace before the new root is published, so a failed copy
 * cannot retire or orphan an already admitted core. */
static int d5_admit_catalog(uint32_t index, noun core, noun admission)
{
    if (g_catalog[index].admitted) {
        return noun_eq(g_catalog[index].core, core)
            && noun_eq(g_catalog[index].admission, admission);
    }
    d5_catalog_t candidate[D5_CATALOG_CAPACITY];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        candidate[i] = g_catalog[i];
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++) {
        if (i == index)
            continue;
        if (!candidate[i].admitted)
            continue;
        if (!noun_copy_checked(g_catalog[i].core, &candidate[i].core)
            || !noun_copy_checked(g_catalog[i].admission, &candidate[i].admission)) {
            heap_persist_abort_tx();
            heap_set_mode(HEAP_MODE_SCRATCH);
            return -2;
        }
    }
    if (!noun_copy_checked(core, &candidate[index].core)
        || !noun_copy_checked(admission, &candidate[index].admission)) {
        heap_persist_abort_tx();
        heap_set_mode(HEAP_MODE_SCRATCH);
        return -2;
    }
    candidate[index].admitted = 1;
    for (uint32_t i = 0; i < 32; i++) {
#if defined(M38_D7_NATIVE)
        candidate[index].core_id[i] = D7_AUTHORITIES[index].core_id[i];
#else
        candidate[index].core_id[i] = CORE_IDS[index][i];
#endif
        candidate[index].admission_id[i] = ADMISSION_IDS[index][i];
    }
    heap_persist_commit_tx();
    g_catalog[index] = candidate[index];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        if (i != index && candidate[i].admitted)
            g_catalog[i] = candidate[i];
    heap_set_mode(HEAP_MODE_SCRATCH);
    d5_publish();
    return 1;
}

static int d5_decode_poke_stimulus(const d5_plan_t *plan, noun stimulus,
                                   const uint8_t core_id[32], noun *runtime,
                                   uint32_t *instance, uint32_t *event)
{
    noun tag, body, fields[5];
    if (!d5_pair(stimulus, &tag, &body) || !d5_atom_is(tag, TAG_STIMULUS)
        || !d5_record(body, fields, 5) || !d5_atom_is(fields[0], TAG_STIMULUS_SCHEMA))
        return 0;
    if (!d5_core_descriptor_matches(fields[1], core_id))
        return 0;
    uint32_t iid, eid;
    if (!d5_u(fields[2], D5_MAX_INSTANCES, &iid) || iid == 0
        || iid > plan->instance_count || !d5_u(fields[3], 0xFFFF, &eid) || eid == 0)
        return 0;
    const d5_type_t *type = d5_find_type(plan, plan->instance_types[iid - 1]);
    const d5_event_t *event_def = d5_find_event(type, eid, 0);
    if (!event_def)
        return 0;
    noun values[D5_MAX_WITH];
    uint32_t value_count;
    if (!d5_list(fields[4], values, D5_MAX_WITH, &value_count)
        || value_count != event_def->with_count)
        return 0;
    for (uint32_t i = 0; i < value_count; i++) {
        noun vf[3];
        uint32_t id, code;
        if (!d5_record(values[i], vf, 3) || !d5_u(vf[0], 0xFFFF, &id)
            || !d5_u(vf[1], D5_TYPE_UINT16, &code)
            || id != event_def->with_ids[i]
            || code != type->values[event_def->with_ids[i] - 1].type
            || !d5_typed(vf[1], vf[2]))
            return 0;
    }
    *instance = iid - 1;
    *event = eid;
    if (!runtime)
        return 1;
    noun runtime_values[D5_MAX_WITH];
    for (uint32_t i = 0; i < value_count; i++) {
        noun vf[3];
        if (!d5_record(values[i], vf, 3))
            return 0;
        noun runtime_value[3] = {direct(event_def->with_ids[i]), vf[1], vf[2]};
        runtime_values[i] = d5_record_build(runtime_value, 3);
    }
    noun runtime_fields[4] = {d5_digest_atom(core_id), direct(iid),
                               direct(eid),
                               d5_list_build(runtime_values, value_count)};
    noun runtime_body = d5_record_build(runtime_fields, 4);
    *runtime = d5_pair_build(d5_runtime_stimulus_tag(), runtime_body);
    return *runtime != NOUN_ZERO;
}

static int d5_validate_peek_selector(const d5_plan_t *plan, noun selector,
                                     uint32_t *target_out)
{
    noun selector_tag, selector_body, sf[3];
    if (!d5_pair(selector, &selector_tag, &selector_body)
        || !d5_atom_is(selector_tag, TAG_SELECTOR)
        || !d5_record(selector_body, sf, 3)
        || !d5_atom_is(sf[0], TAG_SELECTOR_SCHEMA)
        || !noun_is_direct(sf[1]) || direct_val(sf[1]) != 1
        || !noun_is_direct(sf[2]) || direct_val(sf[2]) > 0xFFFF
        || direct_val(sf[2]) == 0)
        return 0;
    uint32_t target = (uint32_t)direct_val(sf[2]);
    for (uint32_t i = 0; i < plan->instance_count; i++) {
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[i]);
        for (uint32_t v = 0; v < type->value_count; v++)
            if (v + 1 == target) {
                *target_out = target;
                return 1;
            }
    }
    return 0;
}

static noun d5_dispatch_load(noun core, noun admission)
{
    d5_load_validation_t validation;
    int validation_reason = d5_validate_load_request(core, admission, &validation);
    if (validation_reason != 0)
        return d5_refuse((uint32_t)validation_reason, 0, NOUN_ZERO);
    uint8_t *core_id = validation.core_id;
    d5_plan_t *plan = &validation.plan;
    int index = validation.catalog_index;
    uint32_t slot_number = 0;
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        if (!g_slots[i].used) {
            slot_number = i + 1;
            break;
        }
    if (slot_number == 0)
        return d5_refuse(9, 0, NOUN_ZERO);
    d5_state_t initial;
    if (!d5_initial_state(plan, &initial))
        return d5_refuse(2, 0, NOUN_ZERO);
    noun state = d5_state_noun(plan, &initial, slot_number,
                               g_slots[slot_number - 1].generation, core_id,
                               D5_STATE_INITIALIZED);
    noun handle = d5_handle(slot_number, g_slots[slot_number - 1].generation);
    if (state == NOUN_ZERO || handle == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    noun body_fields[2] = {handle, state};
    noun result = d5_result(D5_STATUS_LOAD, d5_record_build(body_fields, 2));
    if (result == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    noun owned = d5_result_stage(result);
    if (owned == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    int admission_result = d5_admit_catalog((uint32_t)index, core, admission);
    if (admission_result <= 0)
        return d5_refuse(admission_result < 0 ? 11 : 10, 0, NOUN_ZERO);
    g_slots[slot_number - 1].catalog = (uint32_t)index;
    g_slots[slot_number - 1].state = initial;
    g_slots[slot_number - 1].state_kind = D5_STATE_INITIALIZED;
    g_slots[slot_number - 1].latest = 0;
    g_slots[slot_number - 1].used = 1;
    d5_publish();
    return owned;
}

static noun d5_dispatch_peek(noun handle, noun selector)
{
    uint32_t slot_number;
    if (!d5_slot_resolve(handle, &slot_number))
        return d5_refuse(1, 0, NOUN_ZERO);
    d5_slot_t *slot = &g_slots[slot_number - 1];
    d5_catalog_t *catalog = &g_catalog[slot->catalog];
    d5_plan_t plan;
    if (!d5_parse_plan(catalog->core, &plan))
        return d5_refuse(8, 0, NOUN_ZERO);
    uint32_t target;
    if (!d5_validate_peek_selector(&plan, selector, &target))
        return d5_refuse(5, 0, NOUN_ZERO);
    for (uint32_t i = 0; i < plan.instance_count; i++) {
        const d5_type_t *type = d5_find_type(&plan, plan.instance_types[i]);
        for (uint32_t v = 0; v < type->value_count; v++)
            if (v + 1 == target) {
                noun values[1] = {direct(g_slots[slot_number - 1].state.values[i][v])};
                noun row[3] = {direct(target), direct(type->values[v].type), values[0]};
                noun typed = d5_record_build(row, 3);
                noun obs_fields[4] = {d5_atom(TAG_OBSERVATION_SCHEMA), direct(1), selector,
                                      d5_list_build(&typed, 1)};
                noun obs_body = d5_record_build(obs_fields, 4);
                noun observation = d5_pair_build(d5_atom(TAG_OBSERVATION), obs_body);
                noun fields[2] = {selector, observation};
                return d5_result(D5_STATUS_PEEK, d5_record_build(fields, 2));
            }
    }
    return d5_refuse(5, 0, NOUN_ZERO);
}

/* Do not inspect automatic locals that were live across setjmp() after a
 * Nock abort.  The evaluator can longjmp from deep inside the formula, so
 * reconstruct the unchanged state from the volatile slot number instead. */
static noun d5_eval_abort_refusal(uint32_t reason)
{
    uint32_t slot_number = g_eval_slot;
    if (slot_number >= 1 && slot_number <= D5_SLOT_COUNT
        && g_slots[slot_number - 1].used) {
        d5_slot_t *slot = &g_slots[slot_number - 1];
        d5_catalog_t *catalog = &g_catalog[slot->catalog];
        d5_plan_t plan;
        if (catalog->admitted && d5_parse_plan(catalog->core, &plan))
            return d5_refuse(reason, 0,
                              d5_state_noun(&plan, &slot->state, slot_number,
                                            slot->generation, catalog->core_id,
                                            slot->state_kind));
    }
    return d5_refuse(reason, 0, NOUN_ZERO);
}

static noun d5_dispatch_poke(noun handle, noun stimulus)
{
    uint32_t slot_number;
    if (!d5_slot_resolve(handle, &slot_number))
        return d5_refuse(1, 0, NOUN_ZERO);
    d5_slot_t *slot = &g_slots[slot_number - 1];
    d5_catalog_t *catalog = &g_catalog[slot->catalog];
    d5_plan_t plan;
    noun runtime_stimulus;
    uint32_t instance, event;
#if defined(M38_D7_NATIVE)
    uint8_t evaluator_identity[32];
    if (!d7_layout_digest(catalog->core, evaluator_identity))
        return d5_refuse(8, 0, NOUN_ZERO);
#else
    const uint8_t *evaluator_identity = catalog->core_id;
#endif
    if (!d5_parse_plan(catalog->core, &plan)
        || !d5_decode_poke_stimulus(&plan, stimulus, evaluator_identity,
                                    &runtime_stimulus, &instance, &event))
        return d5_refuse(4, 0, NOUN_ZERO);
#if defined(M38_D7_NATIVE)
    noun runtime_plan, formula, payload;
    if (!d5_pair(catalog->core, &formula, &payload))
        return d5_refuse(8, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    /* The D7 ResourceCore formula consumes the neutral payload directly.
     * State and stimulus remain the same bounded numeric runtime nouns; the
     * legacy D5 runtime-plan adapter is not an authority on this path. */
    runtime_plan = payload;
#else
    noun runtime_plan = d5_runtime_plan(&plan, catalog->core_id);
#endif
    noun runtime_state = d5_runtime_state(&plan, &slot->state, evaluator_identity);
    noun bounds = d5_bounds();
    noun tail = d5_pair_build(runtime_stimulus, bounds);
    tail = d5_pair_build(runtime_state, tail);
    noun subject = d5_pair_build(runtime_plan, tail);
    if (runtime_plan == NOUN_ZERO || runtime_state == NOUN_ZERO || bounds == NOUN_ZERO
        || subject == NOUN_ZERO)
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    g_eval_slot = slot_number;
    g_eval_reason = 8;
    uint64_t max_ops = D5_POLICY_MAX_OPS;
    uint64_t max_cells = D5_POLICY_MAX_CELLS;
    uint64_t max_stack = D5_POLICY_MAX_STACK;
#if defined(M38_D5_NATIVE_WITNESS)
    if (g_witness_ops_limit != 0)
        max_ops = g_witness_ops_limit;
    if (g_witness_cells_limit != 0)
        max_cells = g_witness_cells_limit;
    if (g_witness_stack_limit != 0)
        max_stack = g_witness_stack_limit;
    g_witness_ops_limit = 0;
    g_witness_cells_limit = 0;
    g_witness_stack_limit = 0;
#endif
#if defined(M38_D7_NATIVE)
    if (g_d7_evaluator_ops_limit != 0)
        max_ops = g_d7_evaluator_ops_limit;
    g_d7_evaluator_ops_limit = 0;
#endif
    nock_budget_set_limits(max_ops, max_cells);
    nock_eval_stack_set_limit(max_stack);
    jmp_buf saved_abort;
    __builtin_memcpy(saved_abort, nock_abort, sizeof saved_abort);
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        uint64_t reason = nock_budget_abort_reason();
        nock_budget_finish();
        __builtin_memcpy(nock_abort, saved_abort, sizeof saved_abort);
        g_eval_reason = reason == 1 || reason == 3 ? 7 : 8;
        return d5_eval_abort_refusal((uint32_t)g_eval_reason);
    }
    noun product = nock(subject, plan.formula);
    /* D5 temporarily owns the evaluator recovery point.  Restore the caller's
     * context before later boundary work, so a future unrelated crash cannot
     * jump into this returned frame. */
    __builtin_memcpy(nock_abort, saved_abort, sizeof saved_abort);
    uint64_t ops = nock_ops_used();
    uint64_t cells = nock_cells_used();
    nock_budget_finish();
    uint64_t evaluator_peak_frames = nock_eval_stack_peak();
    noun product_tag, product_body, pf[7];
    if (!d5_pair(product, &product_tag, &product_body)
        || !d5_atom_is(product_tag, "m38-product-v2")
        || !d5_record(product_body, pf, 7)
        || !noun_eq(pf[0], d5_digest_atom(evaluator_identity))
        || !d5_atom_is(pf[1], "commit"))
        return d5_refuse(8, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    d5_state_t candidate = {0};
    if (!d5_product_state(&plan, pf[2], evaluator_identity, &candidate))
        return d5_refuse(8, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    uint32_t queue, work;
    if (!d5_u(pf[5], D5_QUEUE_LIMIT, &queue) || !d5_u(pf[6], D5_WORKLIST_LIMIT, &work)) {
        uart_puts("M38D5 PRODUCT_REFUSE queue=");
        if (noun_is_direct(pf[5])) d5_hex64(direct_val(pf[5])); else uart_puts("atom");
        uart_puts(" work=");
        if (noun_is_direct(pf[6])) d5_hex64(direct_val(pf[6])); else uart_puts("atom");
        uart_puts("\r\n");
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    }
    noun effects = d5_effects(&plan, pf[4]);
    noun observations = d5_observations(pf[3]);
    noun metrics = d5_metrics(ops, cells, evaluator_peak_frames, queue, work);
    noun next = d5_state_noun(&plan, &candidate, slot_number, slot->generation,
                              catalog->core_id, D5_STATE_NEXT);
    if (effects == NOUN_ZERO || observations == NOUN_ZERO || metrics == NOUN_ZERO
        || next == NOUN_ZERO)
        return d5_refuse(8, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    noun body[4] = {next, effects, observations, metrics};
    noun result = d5_result(D5_STATUS_POKE, d5_record_build(body, 4));
    if (result == NOUN_ZERO)
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    noun owned = d5_result_stage(result);
    if (owned == NOUN_ZERO)
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    slot->state = candidate;
    slot->state_kind = D5_STATE_NEXT;
    d5_publish();
    return owned;
}

static noun d5_dispatch_snapshot(noun handle)
{
    uint32_t slot_number;
    if (!d5_slot_resolve(handle, &slot_number))
        return d5_refuse(1, 0, NOUN_ZERO);
    d5_slot_t *slot = &g_slots[slot_number - 1];
    d5_catalog_t *catalog = &g_catalog[slot->catalog];
    d5_plan_t plan;
    if (!d5_parse_plan(catalog->core, &plan))
        return d5_refuse(8, 0, NOUN_ZERO);
    noun snapshot = d5_snapshot(&plan, slot, slot_number, catalog->core_id);
    uint8_t digest[32];
    if (snapshot == NOUN_ZERO || !d5_snapshot_digest(snapshot, digest))
        return d5_refuse(7, 0, NOUN_ZERO);
    noun result = d5_result(D5_STATUS_SNAPSHOT, snapshot);
    if (result == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    noun owned = d5_result_stage(result);
    if (owned == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    for (uint32_t i = 0; i < D5_MAX_INSTANCES; i++) {
        slot->snapshot_state.state_ids[i] = slot->state.state_ids[i];
        for (uint32_t j = 0; j < D5_MAX_VALUES; j++)
            slot->snapshot_state.values[i][j] = slot->state.values[i][j];
    }
    for (uint32_t i = 0; i < 32; i++)
        slot->snapshot_digest[i] = digest[i];
    slot->latest = 1;
    d5_publish();
    return owned;
}

static noun d5_dispatch_restore(noun handle, noun snapshot)
{
    uint32_t slot_number;
    if (!d5_slot_resolve(handle, &slot_number))
        return d5_refuse(1, 0, NOUN_ZERO);
    d5_slot_t *slot = &g_slots[slot_number - 1];
    d5_catalog_t *catalog = &g_catalog[slot->catalog];
    d5_plan_t plan;
    if (!d5_parse_plan(catalog->core, &plan))
        return d5_refuse(8, 0, NOUN_ZERO);
    d5_state_t restored;
    uint32_t restored_kind;
    if (!d5_validate_restore_snapshot(&plan, slot, handle, snapshot,
                                      catalog->core_id, &restored,
                                      &restored_kind))
        return d5_refuse(6, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    noun restored_noun = d5_state_noun(&plan, &restored, slot_number, slot->generation,
                                       catalog->core_id, restored_kind);
    /* Match the host boundary's fresh noun construction: the result handle,
     * the state-embedded handle, and the receipt handle are distinct cells
     * even though they carry the same exact value.  Jam identity preserves
     * that sharing graph, so this is part of the byte-level ABI evidence. */
    noun result_handle = d5_handle(slot_number, slot->generation);
    noun receipt_handle = d5_handle(slot_number, slot->generation);
    noun receipt_fields[3] = {d5_atom(TAG_RECEIPT_SCHEMA), receipt_handle, direct(restored_kind)};
    noun receipt_body = d5_record_build(receipt_fields, 3);
    noun receipt = d5_pair_build(d5_atom(TAG_RECEIPT), receipt_body);
    noun body[3] = {result_handle, restored_noun, receipt};
    noun result = d5_result(D5_STATUS_RESTORE, d5_record_build(body, 3));
    if (result == NOUN_ZERO)
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    noun owned = d5_result_stage(result);
    if (owned == NOUN_ZERO)
        return d5_refuse(7, 0, d5_state_noun(&plan, &slot->state, slot_number,
                                              slot->generation, catalog->core_id,
                                              slot->state_kind));
    slot->state = restored;
    slot->state_kind = restored_kind;
    d5_publish();
    return owned;
}

/* The one public native ResourceABI entry point.  All refusals are staged
 * before changing a resident slot.  Reentrancy is fenced even though this
 * target has one scheduler core and no callback path. */
noun m38_resource_abi_dispatch(noun request)
{
    if (g_in_flight) {
        uint64_t nested_mark = heap_scratch_mark();
        noun refused = d5_refuse(16, 0, NOUN_ZERO);
        noun owned = d5_nested_result_stage(refused);
        (void)heap_scratch_rewind(nested_mark);
        return owned;
    }
    g_in_flight = 1;
    uint64_t scratch_mark = heap_scratch_mark();
    heap_set_mode(HEAP_MODE_SCRATCH);
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
#if defined(M38_D5_NATIVE_WITNESS)
    g_result_stage_limit = g_witness_result_cells_limit != 0
        ? g_witness_result_cells_limit : D5_RESULT_CELL_CAPACITY;
    g_witness_result_cells_limit = 0;
#elif defined(M38_D7_NATIVE)
    g_result_stage_limit = g_d7_result_stage_limit != 0
        ? g_d7_result_stage_limit : D5_RESULT_CELL_CAPACITY;
    g_d7_result_stage_limit = 0;
#else
    g_result_stage_limit = D5_RESULT_CELL_CAPACITY;
#endif
    d5_request_t decoded;
    noun result;
    if (!d5_decode_request(request, &decoded)) {
        result = d5_refuse(16, 0, NOUN_ZERO);
    }
    else if (decoded.operation == D5_OP_LOAD)
        result = d5_dispatch_load(decoded.first, decoded.second);
    else if (decoded.operation == D5_OP_POKE)
        result = d5_dispatch_poke(decoded.first, decoded.second);
    else if (decoded.operation == D5_OP_PEEK)
        result = d5_dispatch_peek(decoded.first, decoded.second);
    else if (decoded.operation == D5_OP_SNAPSHOT)
        result = d5_dispatch_snapshot(decoded.first);
    else
        result = d5_dispatch_restore(decoded.first, decoded.second);
    noun owned = result == g_result_arena.root ? result : d5_result_stage(result);
#if defined(M38_D5_NATIVE_WITNESS)
    if (g_witness_reenter_next) {
        uint8_t outer_before[32], outer_after[32];
        uint32_t nested_status = 0, nested_reason = 0;
        g_witness_reenter_next = 0;
        int outer_before_ok = d5_sha256_digest(owned, outer_before);
        noun nested = m38_resource_abi_dispatch(NOUN_ZERO);
        int nested_ok = d5_result_status_reason(nested, &nested_status,
                                                 &nested_reason);
        int outer_after_ok = d5_sha256_digest(owned, outer_after);
        g_witness_nested_status = nested_status;
        g_witness_nested_reason = nested_reason;
        g_witness_late_reentry_ok = outer_before_ok && nested_ok
            && nested_status == D5_STATUS_REFUSE && nested_reason == 16
            && outer_after_ok
            && d5_same_bytes(outer_before, outer_after, sizeof outer_before);
    }
#endif
    g_in_flight = 0;
    int rewound = heap_scratch_rewind(scratch_mark);
    if (owned == NOUN_ZERO) {
        /* A bounded result-arena refusal is itself an ABI refusal.  Return it
         * through the normal staged path so a D7 batch can roll back after
         * result construction without treating NOUN_ZERO as success or
         * executing the evaluator a second time. */
        g_result_stage_limit = D5_RESULT_CELL_CAPACITY;
        noun refused = d5_refuse(7, 0, NOUN_ZERO);
        owned = d5_result_stage(refused);
    }
    if (owned == NOUN_ZERO || !rewound)
        return NOUN_ZERO;
    return owned;
}

static int d5_pill_source(const volatile uint8_t **base, uint64_t *available)
{
#if defined(M38_D7_NATIVE)
    uint64_t pill_base = g_d7_retry_source
        ? PILL_BASE + D7_RETRY_PILL_OFFSET : PILL_BASE;
#elif defined(M38_D5_NATIVE_WITNESS)
    uint64_t pill_base = g_witness_retry_source
        ? PILL_BASE + D5_WITNESS_RETRY_PILL_OFFSET : PILL_BASE;
#else
    uint64_t pill_base = PILL_BASE;
#endif
    const volatile uint8_t *q = (const volatile uint8_t *)(uintptr_t)pill_base;
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

#if defined(M38_D5_NATIVE_WITNESS)
void m38_resource_abi_boot(void);

static int d5_witness_retry_pill_present(void)
{
    const volatile uint8_t *q = (const volatile uint8_t *)(uintptr_t)
        (PILL_BASE + D5_WITNESS_RETRY_PILL_OFFSET);
    int any = 0;
    for (unsigned i = 0; i < 8; i++)
        any |= q[i] != 0;
    return !g_witness_retry_used && any;
}

/* The witness may supply a second, independently loaded valid PILL.  Invoke
 * it only after an authority preflight abort, proving retryability in the
 * same QEMU guest without committing the rejected candidate. */
static void d5_witness_retry_after_authority_refusal(void)
{
    if (!d5_witness_retry_pill_present())
        return;
    g_witness_retry_used = 1;
    g_witness_retry_source = 1;
    m38_resource_abi_boot();
    g_witness_retry_source = 0;
}
#endif

static int d5_decode_pill(noun *out, cue_bounded_status_t *status)
{
    const volatile uint8_t *base;
    uint64_t available, length = 0;
    *status = CUE_BOUNDED_INPUT;
    if (!d5_pill_source(&base, &available) || available < 16)
        return 0;
    for (unsigned i = 0; i < 8; i++)
        length |= (uint64_t)base[i] << (i * 8);
    if (length == 0 || length > PILL_SCRATCH_SIZE
        || length > cue_i2_limits.max_input_bytes || length > available - 16)
        return 0;
    if (base[8] > 1 || base[9] != 1 || base[10] != 0 || base[11] != 0
        || base[12] != 0 || base[13] != 0 || base[14] != 0 || base[15] != 0)
        return 0;
    *status = cue_bounded_bytes((const uint8_t *)(uintptr_t)(base + 16), length,
                                &cue_i2_limits, HEAP_MODE_SCRATCH, out);
    return *status == CUE_BOUNDED_OK;
}

static void d5_hex64(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4)
        uart_putc(digits[(value >> shift) & 0xf]);
}

static void d5_sha256_text(noun value)
{
    const uint8_t *jammed;
    uint64_t bytes;
    jam_admission_budget_t budget;
    uint8_t digest[32];
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    if (jam_encode_bytes_identity_bounded(value, &jammed, &bytes, &budget) != 0) {
        uart_puts("jam-error");
        return;
    }
    sha256_hash(jammed, bytes, digest);
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < 32; i++) {
        uart_putc(digits[digest[i] >> 4]);
        uart_putc(digits[digest[i] & 0xf]);
    }
}

static void d5_terminal(const char *status)
{
    uart_puts("M38D5 TERMINAL status=");
    uart_puts(status);
    uart_puts("\r\n");
}

static void d5_digest_text(const uint8_t digest[32])
{
    static const char digits[] = "0123456789abcdef";
    for (uint32_t i = 0; i < 32; i++) {
        uart_putc(digits[digest[i] >> 4]);
        uart_putc(digits[digest[i] & 0xf]);
    }
}

/* In-process mutation fingerprint used only by the compiled hostile witness.
 * This is a raw-struct diagnostic fingerprint, not a canonical cross-run
 * authority identity. */
#if defined(M38_D5_NATIVE_WITNESS) || defined(M38_D7_NATIVE)
static void d5_mutation_fingerprint(uint8_t digest[32])
{
    sha256_ctx_t context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)g_catalog, sizeof g_catalog);
    sha256_update(&context, (const uint8_t *)g_slots, sizeof g_slots);
    sha256_update(&context, (const uint8_t *)&g_publications, sizeof g_publications);
    uint64_t persist_selector = heap_persist_selector();
    uint64_t persist_cells = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t scratch_mark = heap_scratch_mark();
    sha256_update(&context, (const uint8_t *)&persist_selector, sizeof persist_selector);
    sha256_update(&context, (const uint8_t *)&persist_cells, sizeof persist_cells);
    sha256_update(&context, (const uint8_t *)&scratch_mark, sizeof scratch_mark);
    uint64_t atom_bytes = atom_store_bytes_used();
    uint64_t atom_occupancy = atom_store_index_occupancy();
    sha256_update(&context, (const uint8_t *)&atom_bytes, sizeof atom_bytes);
    sha256_update(&context, (const uint8_t *)&atom_occupancy, sizeof atom_occupancy);
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++) {
        uint8_t item[32] = {0};
        if (g_catalog[i].admitted) {
            jam_admission_budget_t budget;
            jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
            (void)d5_jam_digest(g_catalog[i].core, item, &budget);
            sha256_update(&context, item, sizeof item);
            jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
            (void)d5_jam_digest(g_catalog[i].admission, item, &budget);
        }
        sha256_update(&context, item, sizeof item);
    }
    sha256_final(&context, digest);
}

/* Canonical semantic authority excludes pointers, padding, allocator
 * addresses, and other in-process representation details.  It is a stable
 * encoding of the catalog/slot semantics only; publications, allocator
 * counters, and diagnostic telemetry are witnessed separately. */
static void d5_semantic_u32(sha256_ctx_t *context, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)value, (uint8_t)(value >> 8),
        (uint8_t)(value >> 16), (uint8_t)(value >> 24),
    };
    sha256_update(context, bytes, sizeof bytes);
}

static void d5_semantic_u64(sha256_ctx_t *context, uint64_t value)
{
    uint8_t bytes[8];
    for (uint32_t i = 0; i < sizeof bytes; i++)
        bytes[i] = (uint8_t)(value >> (i * 8));
    sha256_update(context, bytes, sizeof bytes);
}

static void d5_semantic_authority_digest(uint8_t digest[32])
{
    static const char domain[] =
        "1499kernel:i2:m38-d5:semantic-authority:v1";
    sha256_ctx_t context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)domain, sizeof domain - 1);
    uint8_t zero = 0;
    sha256_update(&context, &zero, 1);
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++) {
        d5_semantic_u32(&context, g_catalog[i].admitted);
        sha256_update(&context, g_catalog[i].core_id,
                      sizeof g_catalog[i].core_id);
        sha256_update(&context, g_catalog[i].admission_id,
                      sizeof g_catalog[i].admission_id);
    }
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++) {
        const d5_slot_t *slot = &g_slots[i];
        d5_semantic_u32(&context, slot->used);
        d5_semantic_u32(&context, slot->latest);
        d5_semantic_u32(&context, slot->catalog);
        d5_semantic_u64(&context, slot->generation);
        d5_semantic_u32(&context, slot->state_kind);
        for (uint32_t j = 0; j < D5_MAX_INSTANCES; j++) {
            d5_semantic_u32(&context, slot->state.state_ids[j]);
            for (uint32_t k = 0; k < D5_MAX_VALUES; k++)
                d5_semantic_u32(&context, slot->state.values[j][k]);
            d5_semantic_u32(&context, slot->snapshot_state.state_ids[j]);
            for (uint32_t k = 0; k < D5_MAX_VALUES; k++)
                d5_semantic_u32(&context, slot->snapshot_state.values[j][k]);
        }
        sha256_update(&context, slot->snapshot_digest,
                      sizeof slot->snapshot_digest);
    }
    sha256_final(&context, digest);
}
#endif

/* Refusal paths use these fixed atoms to build ABI-RESULT/REASON nouns.  Warm
 * all boundary literals before the first measured dispatch so a refusal does
 * not silently change the atom store while its resource fingerprint is held. */
static void d5_warm_fixed_atoms(void)
{
    static const char *const atoms[] = {
        TAG_IDENTITY, TAG_IDENTITY_SCHEMA, TAG_PAYLOAD, TAG_PAYLOAD_SCHEMA,
        TAG_ADMISSION, TAG_ADMISSION_SCHEMA, TAG_BINDING, TAG_BINDING_SCHEMA,
        TAG_REQUEST, TAG_REQUEST_SCHEMA, TAG_RESULT, TAG_RESULT_SCHEMA,
        TAG_HANDLE, TAG_HANDLE_SCHEMA, TAG_STATE, TAG_STATE_SCHEMA,
        TAG_STIMULUS, TAG_STIMULUS_SCHEMA, TAG_EFFECTS, TAG_EFFECTS_SCHEMA,
        TAG_EFFECT_EMISSION, TAG_EFFECT_EMISSION_SCHEMA, TAG_OBSERVATIONS,
        TAG_OBSERVATIONS_SCHEMA, TAG_OBSERVATION, TAG_OBSERVATION_SCHEMA,
        TAG_METRICS, TAG_METRICS_SCHEMA, TAG_REASON, TAG_REASON_SCHEMA,
        TAG_SELECTOR, TAG_SELECTOR_SCHEMA, TAG_SNAPSHOT, TAG_SNAPSHOT_SCHEMA,
        TAG_RECEIPT, TAG_RECEIPT_SCHEMA, D5_CORE_DOMAIN, D5_SNAPSHOT_DOMAIN,
        D5_BYTE_ORDER, "blake3-256-jam", "sha256", "m38-product-v2",
        "m38-d5-r-native-test-control-v1", "m38-d5-r-native-cap-ops",
        "m38-d5-r-native-cap-cells", "m38-d5-r-native-cap-stack",
        "m38-d5-r-native-cap-result", "m38-d5-r-native-reenter",
        "1499kernel:m38-a:source:v2",
        "1499kernel-i2-m38-a-application-model-v2",
        "1499kernel-i2-m38-a-executable-application-plan-v2",
        "1499kernel-i2-m38-a-executable-application-package-v2",
        "1499kernel:i2:m38-d0-r2:deployment-binding:v1",
        "1499kernel:i2:m38-d0-r2:resource-path:v2",
        RUNTIME_STIMULUS_TAG_PREFIX,
    };
    heap_set_mode(HEAP_MODE_SCRATCH);
    for (uint32_t i = 0; i < sizeof atoms / sizeof atoms[0]; i++)
        (void)d5_atom(atoms[i]);
}

static int d5_result_status_reason(noun result, uint32_t *status,
                                   uint32_t *reason)
{
    noun tag, body, fields[3];
    if (!d5_pair(result, &tag, &body))
        return 0;
    if (!d5_atom_is(tag, TAG_RESULT))
        return 0;
    if (!d5_record(body, fields, 3))
        return 0;
    if (!d5_u(fields[1], 0xFF, status))
        return 0;
    *reason = 0;
    if (*status == D5_STATUS_REFUSE) {
        noun reason_tag, reason_body, reason_fields[3];
        if (!d5_record(fields[2], reason_fields, 2))
            return 0;
        if (!d5_pair(reason_fields[0], &reason_tag, &reason_body)) {
            return 0;
        }
        if (!d5_atom_is(reason_tag, TAG_REASON))
            return 0;
        if (!d5_record(reason_body, reason_fields, 3))
            return 0;
        if (!d5_u(reason_fields[1], 0xFF, reason))
            return 0;
    }
    return 1;
}

static const char *d5_operation_name(uint32_t operation)
{
    switch (operation) {
    case D5_OP_LOAD: return "LOAD";
    case D5_OP_POKE: return "POKE";
    case D5_OP_PEEK: return "PEEK";
    case D5_OP_SNAPSHOT: return "SNAPSHOT";
    case D5_OP_RESTORE: return "RESTORE";
    default: return "MALFORMED";
    }
}

static const char *d5_status_name(uint32_t status)
{
    switch (status) {
    case D5_STATUS_LOAD: return "loaded";
    case D5_STATUS_POKE: return "poke-commit";
    case D5_STATUS_PEEK: return "peek";
    case D5_STATUS_SNAPSHOT: return "snapshot";
    case D5_STATUS_RESTORE: return "restore";
    case D5_STATUS_REFUSE: return "refuse";
    default: return "unknown";
    }
}

#if defined(M38_D5_NATIVE_WITNESS)
static int d5_decode_witness_control(noun item, uint32_t *kind, uint64_t *value)
{
    noun tag, body, fields[2];
    if (!d5_pair(item, &tag, &body) || !d5_record(body, fields, 2)
        || !d5_atom_is(fields[0], "m38-d5-r-native-test-control-v1")
        || !noun_is_direct(fields[1]))
        return 0;
    if (d5_atom_is(tag, "m38-d5-r-native-cap-ops"))
        *kind = 1;
    else if (d5_atom_is(tag, "m38-d5-r-native-cap-cells"))
        *kind = 2;
    else if (d5_atom_is(tag, "m38-d5-r-native-cap-stack"))
        *kind = 3;
    else if (d5_atom_is(tag, "m38-d5-r-native-cap-result"))
        *kind = 4;
    else if (d5_atom_is(tag, "m38-d5-r-native-reenter"))
        *kind = 5;
    else
        return 0;
    *value = direct_val(fields[1]);
    return 1;
}
#endif

static int d5_decode_ingress(noun value, noun *items, uint32_t *count)
{
    return d5_list(value, items, 64u, count) && *count != 0;
}

static void d5_ingress_shadow_init(d5_ingress_shadow_t *shadow)
{
    *shadow = (d5_ingress_shadow_t){0};
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        shadow->slots[i] = g_slots[i];
    for (uint32_t i = 0; i < D5_CATALOG_KNOWN_COUNT; i++) {
        if (!g_catalog[i].admitted)
            continue;
        for (uint32_t j = 0; j < 32; j++)
            shadow->core_ids[i][j] = g_catalog[i].core_id[j];
        shadow->plan_ready[i] = d5_parse_plan(g_catalog[i].core,
                                               &shadow->plans[i]);
    }
}

static int d5_ingress_shadow_resource(const d5_ingress_shadow_t *shadow,
                                      noun handle, uint32_t *slot_number,
                                      const d5_plan_t **plan,
                                      const uint8_t **core_id)
{
    if (!d5_slot_resolve_in(shadow->slots, handle, slot_number))
        return 0;
    uint32_t catalog = shadow->slots[*slot_number - 1].catalog;
    if (catalog >= D5_CATALOG_KNOWN_COUNT || !shadow->plan_ready[catalog])
        return 0;
    *plan = &shadow->plans[catalog];
    *core_id = shadow->core_ids[catalog];
    return 1;
}

static void d5_ingress_shadow_load(d5_ingress_shadow_t *shadow,
                                   const d5_load_validation_t *validation)
{
    uint32_t slot_number = 0;
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++) {
        if (!shadow->slots[i].used) {
            slot_number = i + 1;
            break;
        }
    }
    /* Slot exhaustion remains a bounded runtime-capacity refusal.  It does
     * not make the input noun unsafe to commit, and dispatch retains the
     * existing refusal code and sequential witness coverage. */
    if (slot_number == 0)
        return;
    uint32_t catalog = (uint32_t)validation->catalog_index;
    shadow->plans[catalog] = validation->plan;
    for (uint32_t i = 0; i < 32; i++)
        shadow->core_ids[catalog][i] = validation->core_id[i];
    shadow->plan_ready[catalog] = 1;
    d5_slot_t *slot = &shadow->slots[slot_number - 1];
    d5_state_t initial;
    if (!d5_initial_state(&validation->plan, &initial))
        return;
    slot->used = 1;
    slot->latest = 0;
    slot->catalog = catalog;
    slot->state_kind = D5_STATE_INITIALIZED;
    slot->state = initial;
}

/* This is the single ingress atomicity rule for all five public operations:
 * every request is checked against bounded, read-only semantic state before
 * Cue commits.  The evaluator and publication paths remain dispatch-only. */
static uint32_t d5_request_preflight_reason(const d5_request_t *request,
                                             d5_ingress_shadow_t *shadow)
{
    uint32_t slot_number;
    const d5_plan_t *plan;
    const uint8_t *core_id;
    switch (request->operation) {
    case D5_OP_LOAD: {
        d5_load_validation_t validation;
        uint32_t reason = (uint32_t)d5_validate_load_request(
            request->first, request->second, &validation);
        if (reason == 0)
            d5_ingress_shadow_load(shadow, &validation);
        return reason;
    }
    case D5_OP_POKE: {
        uint32_t instance, event;
        if (!d5_ingress_shadow_resource(shadow, request->first,
                                        &slot_number, &plan, &core_id)
            || !d5_decode_poke_stimulus(plan, request->second, core_id, 0,
                                        &instance, &event))
            return 4;
        return 0;
    }
    case D5_OP_PEEK: {
        uint32_t target;
        if (!d5_ingress_shadow_resource(shadow, request->first,
                                        &slot_number, &plan, &core_id)
            || !d5_validate_peek_selector(plan, request->second, &target))
            return 5;
        return 0;
    }
    case D5_OP_SNAPSHOT:
        if (!d5_ingress_shadow_resource(shadow, request->first,
                                        &slot_number, &plan, &core_id))
            return 1;
        /* The snapshot noun is produced by dispatch, so its exact digest is
         * not available to this read-only pass.  A later RESTORE still gets
         * full structural validation here and the live latest-digest check
         * remains mandatory in dispatch. */
        shadow->pending_snapshot[slot_number - 1] = 1;
        return 0;
    case D5_OP_RESTORE: {
        d5_state_t restored;
        uint32_t restored_kind;
        if (!d5_ingress_shadow_resource(shadow, request->first,
                                        &slot_number, &plan, &core_id)
            || (shadow->pending_snapshot[slot_number - 1]
                ? !d5_validate_restore_snapshot_shape(
                    plan, request->first, request->second, core_id,
                    &restored, &restored_kind)
                : !d5_validate_restore_snapshot(
                    plan, &shadow->slots[slot_number - 1], request->first,
                    request->second, core_id, &restored, &restored_kind)))
            return 6;
        shadow->slots[slot_number - 1].state = restored;
        shadow->slots[slot_number - 1].state_kind = restored_kind;
        return 0;
    }
    default:
        return 16;
    }
}

#if defined(M38_D5_NATIVE_WITNESS)
static void d5_ingest_abort(const char *kind, uint32_t code,
                            const uint8_t mutation_before[32],
                            const uint8_t semantic_before[32],
                            uint64_t scratch_mark_before,
                            uint64_t scratch_cells_before,
                            uint64_t persist_cells_before,
                            uint64_t atom_bytes_before,
                            uint64_t atom_occupancy_before,
                            uint64_t publications_before)
{
    uint8_t mutation_after[32], semantic_after[32];
    uint64_t scratch_mark_after = heap_scratch_mark();
    uint64_t scratch_cells_after = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t persist_cells_after = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atom_bytes_after = atom_store_bytes_used();
    uint64_t atom_occupancy_after = atom_store_index_occupancy();
    uint64_t publications_after = g_publications;
    d5_mutation_fingerprint(mutation_after);
    d5_semantic_authority_digest(semantic_after);
    int invariant = scratch_cells_before == scratch_cells_after
        && persist_cells_before == persist_cells_after
        && atom_bytes_before == atom_bytes_after
        && atom_occupancy_before == atom_occupancy_after
        && publications_before == publications_after
        && d5_same_bytes(mutation_before, mutation_after, 32)
        && d5_same_bytes(semantic_before, semantic_after, 32);
    uart_puts("M38D5 INGEST_ABORT kind=");
    uart_puts(kind);
    uart_puts(" code=");
    d5_hex64(code);
    uart_puts(" mutation_fingerprint_before_sha256=");
    d5_digest_text(mutation_before);
    uart_puts(" mutation_fingerprint_after_sha256=");
    d5_digest_text(mutation_after);
    uart_puts(" semantic_authority_before_sha256=");
    d5_digest_text(semantic_before);
    uart_puts(" semantic_authority_after_sha256=");
    d5_digest_text(semantic_after);
    uart_puts(" scratch_mark_before=");
    d5_hex64(scratch_mark_before);
    uart_puts(" scratch_mark_after=");
    d5_hex64(scratch_mark_after);
    uart_puts(" scratch_cells_before=");
    d5_hex64(scratch_cells_before);
    uart_puts(" scratch_cells_after=");
    d5_hex64(scratch_cells_after);
    uart_puts(" persist_cells_before=");
    d5_hex64(persist_cells_before);
    uart_puts(" persist_cells_after=");
    d5_hex64(persist_cells_after);
    uart_puts(" atom_bytes_before=");
    d5_hex64(atom_bytes_before);
    uart_puts(" atom_bytes_after=");
    d5_hex64(atom_bytes_after);
    uart_puts(" atom_occupancy_before=");
    d5_hex64(atom_occupancy_before);
    uart_puts(" atom_occupancy_after=");
    d5_hex64(atom_occupancy_after);
    uart_puts(" publications_before=");
    d5_hex64(publications_before);
    uart_puts(" publications_after=");
    d5_hex64(publications_after);
    uart_puts(" invariant=");
    uart_puts(invariant ? "pass" : "fail");
    uart_puts("\r\n");
}
#endif

void m38_resource_abi_boot(void)
{
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        nock_budget_finish();
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        uart_puts("M38D5 REFUSE evaluator-abort\r\n");
        d5_terminal("refuse");
        return;
    }

    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        g_catalog[i] = (d5_catalog_t){0};
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        g_slots[i] = (d5_slot_t){.generation = 1};
    g_publications = 0;
    g_in_flight = 0;
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
    g_nested_result_arena.cell_count = 0;
    g_nested_result_arena.root = NOUN_ZERO;
    g_result_stage_limit = D5_RESULT_CELL_CAPACITY;
#if defined(M38_D5_NATIVE_WITNESS)
    g_witness_ops_limit = 0;
    g_witness_cells_limit = 0;
    g_witness_stack_limit = 0;
    g_witness_result_cells_limit = 0;
    g_witness_reenter_next = 0;
    g_witness_nested_status = 0;
    g_witness_nested_reason = 0;
    g_witness_late_reentry_ok = 0;
#endif

    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);
    uint64_t ingest_scratch_mark_before = heap_scratch_mark();
    uint64_t ingest_scratch_cells_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t ingest_persist_cells_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t ingest_atom_bytes_before = atom_store_bytes_used();
    uint64_t ingest_atom_occupancy_before = atom_store_index_occupancy();
    uint64_t ingest_publications_before = g_publications;
    uint8_t ingest_mutation_before[32] = {0};
    uint8_t ingest_semantic_before[32] = {0};
#if defined(M38_D5_NATIVE_WITNESS)
    d5_mutation_fingerprint(ingest_mutation_before);
    d5_semantic_authority_digest(ingest_semantic_before);
#endif
    noun ingress_noun;
    cue_bounded_status_t cue_status;
    if (!d5_decode_pill(&ingress_noun, &cue_status)) {
        if (noun_tx_active())
            noun_tx_abort();
#if defined(M38_D5_NATIVE_WITNESS)
        (void)heap_scratch_rewind(ingest_scratch_mark_before);
        d5_ingest_abort("cue", (uint32_t)cue_status, ingest_mutation_before,
                        ingest_semantic_before, ingest_scratch_mark_before,
                        ingest_scratch_cells_before, ingest_persist_cells_before,
                        ingest_atom_bytes_before,
                        ingest_atom_occupancy_before, ingest_publications_before);
#endif
        uart_puts("M38D5 REFUSE malformed-input\r\n");
        d5_terminal("refuse");
        return;
    }

    noun ingress[64];
    uint32_t ingress_count;
    if (!d5_decode_ingress(ingress_noun, ingress, &ingress_count)) {
#if defined(M38_D5_NATIVE_WITNESS)
        if (noun_tx_active())
            noun_tx_abort();
        (void)heap_scratch_rewind(ingest_scratch_mark_before);
        d5_ingest_abort("ingress", 0, ingest_mutation_before,
                        ingest_semantic_before, ingest_scratch_mark_before,
                        ingest_scratch_cells_before, ingest_persist_cells_before,
                        ingest_atom_bytes_before,
                        ingest_atom_occupancy_before, ingest_publications_before);
#else
        if (noun_tx_active())
            noun_tx_abort();
#endif
        uart_puts("M38D5 REFUSE malformed-ingress\r\n");
        d5_terminal("refuse");
        return;
    }

    d5_ingress_shadow_init(&g_ingress_shadow);
#if defined(M38_D5_NATIVE_WITNESS)
    uint8_t preflight_controls[64] = {0};
#endif
    for (uint32_t i = 0; i < ingress_count; i++) {
        d5_request_t preflight_request;
        if (d5_decode_request(ingress[i], &preflight_request)) {
            uint32_t preflight_reason =
                d5_request_preflight_reason(&preflight_request,
                                            &g_ingress_shadow);
            if (preflight_reason == 0)
                continue;
            if (noun_tx_active())
                noun_tx_abort();
#if defined(M38_D5_NATIVE_WITNESS)
            (void)heap_scratch_rewind(ingest_scratch_mark_before);
            d5_ingest_abort("ingress-authority", preflight_reason,
                            ingest_mutation_before, ingest_semantic_before,
                            ingest_scratch_mark_before,
                            ingest_scratch_cells_before,
                            ingest_persist_cells_before,
                            ingest_atom_bytes_before,
                            ingest_atom_occupancy_before,
                            ingest_publications_before);
#endif
            uart_puts("M38D5 REFUSE unauthorized-ingress-request\r\n");
            d5_terminal("refuse");
#if defined(M38_D5_NATIVE_WITNESS)
            d5_witness_retry_after_authority_refusal();
#endif
            return;
        }
#if defined(M38_D5_NATIVE_WITNESS)
        uint32_t control_kind = 0;
        uint64_t control_value = 0;
        if (d5_decode_witness_control(ingress[i], &control_kind,
                                      &control_value)) {
            preflight_controls[i] = 1;
            continue;
        }
#endif
        if (noun_tx_active())
            noun_tx_abort();
#if defined(M38_D5_NATIVE_WITNESS)
        (void)heap_scratch_rewind(ingest_scratch_mark_before);
        d5_ingest_abort("ingress-request", 16, ingest_mutation_before,
                        ingest_semantic_before, ingest_scratch_mark_before,
                        ingest_scratch_cells_before, ingest_persist_cells_before,
                        ingest_atom_bytes_before, ingest_atom_occupancy_before,
                        ingest_publications_before);
#endif
        uart_puts("M38D5 REFUSE malformed-ingress-request\r\n");
        d5_terminal("refuse");
        return;
    }
    if (noun_tx_active())
        noun_tx_commit();
    d5_warm_fixed_atoms();

    int witness_ok = 1;
    for (uint32_t i = 0; i < ingress_count; i++) {
        uint32_t operation = 0;
        d5_request_t decoded;
        int request_valid = d5_decode_request(ingress[i], &decoded);
        if (request_valid)
            operation = decoded.operation;
#if defined(M38_D5_NATIVE_WITNESS)
        uint32_t control_kind = 0;
        uint64_t control_value = 0;
        if (!request_valid && preflight_controls[i]
            && d5_decode_witness_control(ingress[i], &control_kind,
                                         &control_value)) {
            if (control_kind == 1)
                g_witness_ops_limit = control_value;
            else if (control_kind == 2)
                g_witness_cells_limit = control_value;
            else if (control_kind == 3)
                g_witness_stack_limit = control_value;
            else if (control_kind == 4)
                g_witness_result_cells_limit = (uint32_t)control_value;
            else
                g_witness_reenter_next = 1;
            uart_puts("M38D5 CONTROL index=");
            d5_hex64(i + 1);
            uart_puts(" kind=");
            uart_puts(control_kind == 1 ? "cap-ops" :
                      control_kind == 2 ? "cap-cells" :
                      control_kind == 3 ? "cap-stack" :
                      control_kind == 4 ? "cap-result" : "reenter");
            uart_puts(" value=");
            d5_hex64(control_value);
            uart_puts("\r\n");
            continue;
        }
#endif

        uint8_t before[32] = {0}, after[32] = {0};
#if defined(M38_D5_NATIVE_WITNESS)
        d5_mutation_fingerprint(before);
#endif
        uint64_t scratch_before = heap_scratch_mark();
#if defined(M38_D5_NATIVE_WITNESS)
        g_witness_nested_status = 0;
        g_witness_nested_reason = 0;
#endif
        noun result = m38_resource_abi_dispatch(ingress[i]);
        uint64_t scratch_after = heap_scratch_mark();
#if defined(M38_D5_NATIVE_WITNESS)
        d5_mutation_fingerprint(after);
#endif

        uint32_t status = 0, reason = 0;
        int result_valid = d5_result_status_reason(result, &status, &reason);
        int invariant = result_valid && scratch_before == scratch_after;
#if defined(M38_D5_NATIVE_WITNESS)
        if (result_valid && status == D5_STATUS_REFUSE)
            invariant = invariant && d5_same_bytes(before, after, sizeof before);
#endif
        if (operation == D5_OP_PEEK && result_valid)
            invariant = invariant && d5_same_bytes(before, after, sizeof before);
        if (!result_valid)
            witness_ok = 0;
        if (!invariant)
            witness_ok = 0;

        uart_puts("M38D5 INGRESS index=");
        d5_hex64(i + 1);
        uart_puts(" operation=");
        uart_puts(d5_operation_name(operation));
        uart_puts(" status=");
        uart_puts(result_valid ? d5_status_name(status) : "invalid");
        uart_puts(" reason=");
        d5_hex64(reason);
        uart_puts(" result_sha256=");
        if (result_valid)
            d5_sha256_text(result);
        else
            uart_puts("invalid");
        uart_puts(" mutation_fingerprint_before_sha256=");
        d5_digest_text(before);
        uart_puts(" mutation_fingerprint_after_sha256=");
        d5_digest_text(after);
        uart_puts(" scratch_before=");
        d5_hex64(scratch_before);
        uart_puts(" scratch_after=");
        d5_hex64(scratch_after);
        uart_puts(" result_cells=");
        d5_hex64(g_result_arena.cell_count);
        uart_puts(" invariant=");
        uart_puts(invariant ? "pass" : "fail");
#if defined(M38_D5_NATIVE_WITNESS)
        if (g_witness_nested_status != 0) {
            uart_puts(" nested_status=");
            d5_hex64(g_witness_nested_status);
            uart_puts(" nested_reason=");
            d5_hex64(g_witness_nested_reason);
            uart_puts(" outer_stable=");
            uart_puts(g_witness_late_reentry_ok ? "pass" : "fail");
        }
#endif
        if (result_valid && status == D5_STATUS_POKE) {
            noun result_tag, result_body, result_fields[3], poke_fields[4];
            noun metrics_tag, metrics_body;
            noun metrics_fields[6];
            if (d5_pair(result, &result_tag, &result_body)
                && d5_record(result_body, result_fields, 3)
                && d5_record(result_fields[2], poke_fields, 4)
                && d5_pair(poke_fields[3], &metrics_tag, &metrics_body)
                && d5_record(metrics_body, metrics_fields, 6)
                && noun_is_direct(metrics_fields[1])
                && noun_is_direct(metrics_fields[2])
                && noun_is_direct(metrics_fields[3])) {
                uart_puts(" ops=");
                d5_hex64(direct_val(metrics_fields[1]));
                uart_puts(" cells=");
                d5_hex64(direct_val(metrics_fields[2]));
                uart_puts(" stack=");
                d5_hex64(direct_val(metrics_fields[3]));
                uart_puts(" next_sha256=");
                d5_sha256_text(poke_fields[0]);
                uart_puts(" effects_sha256=");
                d5_sha256_text(poke_fields[1]);
                uart_puts(" observations_sha256=");
                d5_sha256_text(poke_fields[2]);
                uart_puts(" metrics_sha256=");
                d5_sha256_text(poke_fields[3]);
            } else {
                witness_ok = 0;
            }
        }
        uart_puts("\r\n");
    }
    d5_terminal(witness_ok ? "pass" : "refuse");
}

#if defined(M38_D7_NATIVE)
/*
 * M38-D7 bounded native compatibility witness.
 *
 * D5 supplied the bounded, data-driven payload decoder and the existing Nock
 * evaluator.  D7 gives that engine a separate boundary: the candidate input
 * is [ResourceCore, CoreExecutionDescriptor, PolicyWitness, operations,
 * witness controls].  The peer policy noun is retained as compare-only
 * evidence.  The legacy D0 admission noun is not constructed or accepted on
 * this path.  The small conversion helpers below
 * translate the neutral R5 state/ingress nouns into the evaluator's internal
 * numeric subject; they do not select a graph or carry application metadata.
 */

typedef struct {
    uint32_t operation;
    noun args;
} d7_request_t;

typedef struct {
    uint32_t request_index;
    uint32_t kind;
    uint64_t value;
} d7_control_t;

typedef struct {
    uint32_t operation;
    uint32_t status;
    uint64_t reason;
    uint64_t ops;
    uint64_t cells;
    uint64_t stack;
    uint8_t result[32];
    uint8_t handle[32];
    uint8_t state[32];
    uint8_t next[32];
    uint8_t effects[32];
    uint8_t observations[32];
    uint8_t metrics[32];
    uint8_t has_load_shape;
    uint8_t has_poke_shape;
} d7_result_record_t;

enum {
    D7_CONTROL_EVALUATOR_REFUSAL = 1,
    D7_CONTROL_RESULT_STAGE_REFUSAL = 2,
};

static const char *d7_status_name(uint32_t status)
{
    return d5_status_name(status);
}

static int d7_digest_atom_matches(noun value, const uint8_t expected[32])
{
    uint8_t got[32];
    return d5_atom_bytes(value, got, sizeof got)
        && d5_same_bytes(got, expected, sizeof got);
}

static int d7_layout_digest(noun core, uint8_t digest[32])
{
    noun formula, payload;
    jam_admission_budget_t budget;
    if (!d5_pair(core, &formula, &payload))
        return 0;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    return d5_domain_digest(payload, D7_PAYLOAD_DOMAIN, digest, &budget);
}

static int d7_validate_descriptor(noun descriptor,
                                 const uint8_t core_id[32])
{
    noun tag, body, fields[3];
    return d5_pair(descriptor, &tag, &body)
        && d5_atom_is(tag, D7_DESCRIPTOR_TAG)
        && d5_record(body, fields, 3)
        && d5_atom_is(fields[0], D7_DESCRIPTOR_SCHEMA)
        && d5_atom_is(fields[1], D7_EXECUTION_ABI)
        && d7_digest_atom_matches(fields[2], core_id);
}

static int d7_validate_policy(noun policy, const uint8_t core_id[32])
{
    noun tag, body, fields[7];
    if (policy == NOUN_ZERO)
        return 1; /* peer policy is optional compare-only evidence */
    return d5_pair(policy, &tag, &body)
        && d5_atom_is(tag, D7_POLICY_TAG)
        && d5_record(body, fields, 7)
        && d5_atom_is(fields[0], D7_POLICY_SCHEMA)
        && d5_atom_is(fields[1], D7_EXECUTION_ABI)
        && d7_digest_atom_matches(fields[2], core_id)
        && noun_is_direct(fields[3]) && direct_val(fields[3]) == 1
        && noun_is_direct(fields[4]) && direct_val(fields[4]) == D5_POLICY_MAX_OPS
        && noun_is_direct(fields[5]) && direct_val(fields[5]) == D5_POLICY_MAX_CELLS
        && noun_is_direct(fields[6]) && direct_val(fields[6]) == D5_POLICY_MAX_STACK;
}

/* The exact four-field D7 handle is [schema, slot, generation, core]. */
static int d7_decode_handle(noun value, const uint8_t core_id[32],
                            noun *legacy, uint32_t *slot_out,
                            uint64_t *generation_out)
{
    noun tag, body, fields[4];
    uint32_t slot;
    uint64_t generation;
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_HANDLE_TAG)
        || !d5_record(body, fields, 4)
        || !d5_atom_is(fields[0], D7_HANDLE_SCHEMA)
        || !noun_is_direct(fields[1]) || !noun_is_direct(fields[2])
        || direct_val(fields[1]) < 1 || direct_val(fields[1]) > D5_SLOT_COUNT
        || direct_val(fields[2]) < 1 || direct_val(fields[2]) > D5_MAX_GENERATION
        || !d7_digest_atom_matches(fields[3], core_id))
        return 0;
    slot = (uint32_t)direct_val(fields[1]);
    generation = direct_val(fields[2]);
    *legacy = d5_handle(slot, generation);
    if (*legacy == NOUN_ZERO)
        return 0;
    if (slot_out)
        *slot_out = slot;
    if (generation_out)
        *generation_out = generation;
    return 1;
}

static int d7_decode_request(noun value, d7_request_t *out)
{
    noun tag, body, fields[3];
    uint32_t operation;
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_REQUEST_TAG)
        || !d5_record(body, fields, 3)
        || !d5_atom_is(fields[0], D7_REQUEST_SCHEMA)
        || !d5_u(fields[1], D5_OP_RESTORE, &operation))
        return 0;
    if (operation < D5_OP_LOAD || operation > D5_OP_RESTORE)
        return 0;
    out->operation = operation;
    out->args = fields[2];
    return 1;
}

static int d7_decode_control(noun value, d7_control_t *out)
{
    noun tag, body, fields[4];
    uint32_t request_index, kind;
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_CONTROL_TAG)
        || !d5_record(body, fields, 4)
        || !d5_atom_is(fields[0], D7_CONTROL_SCHEMA)
        || !d5_u(fields[1], 63, &request_index)
        || !d5_u(fields[2], D7_CONTROL_RESULT_STAGE_REFUSAL, &kind)
        || !noun_is_direct(fields[3]))
        return 0;
    if (request_index >= 64 || kind == 0)
        return 0;
    out->request_index = request_index;
    out->kind = kind;
    out->value = direct_val(fields[3]);
    return out->value != 0;
}

static int d7_decode_input(noun value, noun *core, noun *descriptor,
                           noun *policy, noun *operations, noun *controls,
                           d7_request_t *requests, uint32_t *count,
                           d7_control_t *decoded_controls,
                           uint32_t *control_count)
{
    noun tag, body, fields[6], items[64], control_items[16];
    uint32_t used, controls_used;
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_INPUT_TAG)
        || !d5_record(body, fields, 6)
        || !d5_atom_is(fields[0], D7_INPUT_SCHEMA)
        || !d5_list(fields[4], items, 64, &used) || used == 0
        || !d5_list(fields[5], control_items, 16, &controls_used))
        return 0;
    for (uint32_t i = 0; i < used; i++)
        if (!d7_decode_request(items[i], &requests[i]))
            return 0;
    for (uint32_t i = 0; i < controls_used; i++)
        if (!d7_decode_control(control_items[i], &decoded_controls[i]))
            return 0;
    *core = fields[1];
    *descriptor = fields[2];
    *policy = fields[3];
    *operations = fields[4];
    *controls = fields[5];
    *count = used;
    *control_count = controls_used;
    return 1;
}

static int d7_decode_r5_ingress(const d5_plan_t *plan, noun value,
                                const uint8_t core_id[32],
                                const uint8_t layout[32], noun *legacy)
{
    noun tag, body, fields[7];
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_INGRESS_TAG)
        || !d5_record(body, fields, 7)
        || !d5_atom_is(fields[0], D7_INGRESS_SCHEMA)
        || !d5_atom_is(fields[1], D7_EXECUTION_ABI)
        || !d7_digest_atom_matches(fields[2], core_id))
        return 0;
    if (!d7_digest_atom_matches(fields[3], layout))
        return 0;

    /* Values retain the neutral R5 [id,type,raw] list.  The old D0 stimulus
     * wrapper is an evaluator-internal noun, never an admission input. */
    noun stimulus_fields[5] = {
        d5_atom(TAG_STIMULUS_SCHEMA), d5_core_descriptor(d5_digest_atom(layout)),
        fields[4], fields[5], fields[6]
    };
    noun stimulus_body = d5_record_build(stimulus_fields, 5);
    *legacy = d5_pair_build(d5_atom(TAG_STIMULUS), stimulus_body);
    if (*legacy == NOUN_ZERO)
        return 0;
    return d5_decode_poke_stimulus(plan, *legacy, layout, 0, 0, 0);
}

static int d7_decode_selector(const d5_plan_t *plan, noun value,
                              const uint8_t core_id[32],
                              const uint8_t layout[32], noun *legacy)
{
    noun tag, body, fields[5];
    uint32_t target;
    noun selector_fields[3];
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_SELECTOR_TAG)
        || !d5_record(body, fields, 5)
        || !d5_atom_is(fields[0], D7_SELECTOR_SCHEMA)
        || !d5_atom_is(fields[1], D7_EXECUTION_ABI)
        || !d7_digest_atom_matches(fields[2], core_id)
        || !noun_is_direct(fields[4])
        || !d5_u(fields[4], 0xFFFF, &target) || target == 0
        || !d7_digest_atom_matches(fields[3], layout))
        return 0;
    selector_fields[0] = d5_atom(TAG_SELECTOR_SCHEMA);
    selector_fields[1] = direct(1);
    selector_fields[2] = direct(target);
    *legacy = d5_pair_build(d5_atom(TAG_SELECTOR),
                            d5_record_build(selector_fields, 3));
    return *legacy != NOUN_ZERO && d5_validate_peek_selector(plan, *legacy, &target);
}

static int d7_snapshot_to_legacy(const d5_plan_t *plan, noun value,
                                 noun handle, const uint8_t core_id[32],
                                 const uint8_t layout[32],
                                 noun *legacy)
{
    noun tag, body, fields[3], snap_tag, snap_body, snap_fields[3];
    noun state_tag, state_body, state_fields[5], rows[D5_MAX_INSTANCES];
    uint32_t kind, row_count;
    d5_state_t candidate = {0};
    uint8_t seen[D5_MAX_INSTANCES] = {0};
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D7_SNAPSHOT_TAG)
        || !d5_record(body, fields, 3)
        || !d5_atom_is(fields[0], D7_SNAPSHOT_SCHEMA)
        || !d5_u(fields[2], D5_STATE_NEXT, &kind)
        || (kind != D5_STATE_INITIALIZED && kind != D5_STATE_NEXT)
        || !d5_pair(fields[1], &snap_tag, &snap_body)
        || !d5_atom_is(snap_tag, D7_R5_SNAPSHOT_TAG)
        || !d5_record(snap_body, snap_fields, 3)
        || !d5_atom_is(snap_fields[0], D7_R5_SNAPSHOT_SCHEMA)
        || !d5_atom_is(snap_fields[1], D7_EXECUTION_ABI)
        || !d5_pair(snap_fields[2], &state_tag, &state_body)
        || !d5_atom_is(state_tag, D7_STATE_TAG)
        || !d5_record(state_body, state_fields, 5)
        || !d5_atom_is(state_fields[0], D7_STATE_SCHEMA)
        || !d5_atom_is(state_fields[1], D7_EXECUTION_ABI)
        || !d7_digest_atom_matches(state_fields[2], core_id)
        || !d7_digest_atom_matches(state_fields[3], layout)
        || !d5_list(state_fields[4], rows, D5_MAX_INSTANCES, &row_count)
        || row_count != plan->instance_count)
        return 0;
    for (uint32_t i = 0; i < row_count; i++) {
        noun row[3], values[D5_MAX_VALUES];
        uint32_t instance, state_id, value_count;
        if (!d5_record(rows[i], row, 3)
            || !d5_u(row[0], D5_MAX_INSTANCES, &instance)
            || instance == 0 || instance > plan->instance_count
            || seen[instance - 1]
            || !d5_u(row[1], D5_MAX_STATES, &state_id) || state_id == 0
            || !d5_list(row[2], values, D5_MAX_VALUES, &value_count))
            return 0;
        const d5_type_t *type = d5_find_type(plan, plan->instance_types[instance - 1]);
        if (!type || state_id > type->state_count || value_count != type->value_count)
            return 0;
        for (uint32_t j = 0; j < value_count; j++) {
            noun vf[3];
            uint32_t value_id, type_code;
            if (!d5_record(values[j], vf, 3)
                || !d5_u(vf[0], 0xFFFF, &value_id) || value_id != j + 1
                || !d5_u(vf[1], D5_TYPE_UINT16, &type_code)
                || type_code != type->values[j].type || !d5_typed(vf[1], vf[2]))
                return 0;
            candidate.values[instance - 1][j] = (uint32_t)direct_val(vf[2]);
        }
        candidate.state_ids[instance - 1] = state_id;
        seen[instance - 1] = 1;
    }
    for (uint32_t i = 0; i < row_count; i++)
        if (!seen[i])
            return 0;
    uint32_t slot_number;
    uint64_t generation;
    if (!d5_decode_handle(handle, &slot_number, &generation))
        return 0;
    noun state = d5_state_noun(plan, &candidate, slot_number, generation,
                               core_id, kind);
    if (state == NOUN_ZERO)
        return 0;
    noun legacy_fields[3] = {
        d5_atom(TAG_SNAPSHOT_SCHEMA), d5_core_descriptor(d5_digest_atom(core_id)), state
    };
    *legacy = d5_pair_build(d5_atom(TAG_SNAPSHOT),
                            d5_record_build(legacy_fields, 3));
    return *legacy != NOUN_ZERO
        && d5_validate_restore_snapshot_shape(plan, handle, *legacy, core_id,
                                              &candidate, &kind);
}

static int d7_admit_core(uint32_t index, noun core, const uint8_t core_id[32])
{
    if (index >= D5_CATALOG_KNOWN_COUNT)
        return 0;
    if (g_catalog[index].admitted)
        return noun_eq(g_catalog[index].core, core)
            && d5_same_bytes(g_catalog[index].core_id, core_id, 32);
#if defined(M38_D7_NATIVE)
    if (g_d7_batch_active) {
        /* The batch transaction owns this scratch root.  It is deliberately
         * not promoted here; d7_commit_catalog() is the only persistence
         * boundary after every request and result has succeeded. */
        g_catalog[index].admitted = 1;
        g_catalog[index].core = core;
        g_catalog[index].admission = NOUN_ZERO;
        for (uint32_t i = 0; i < 32; i++) {
            g_catalog[index].core_id[i] = core_id[i];
            g_catalog[index].admission_id[i] = 0;
        }
        d5_publish();
        return 1;
    }
#endif
    d5_catalog_t candidate[D5_CATALOG_CAPACITY];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        candidate[i] = g_catalog[i];
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++) {
        if (i == index || !candidate[i].admitted)
            continue;
        if (!noun_copy_checked(g_catalog[i].core, &candidate[i].core)) {
            heap_persist_abort_tx();
            heap_set_mode(HEAP_MODE_SCRATCH);
            return 0;
        }
    }
    if (!noun_copy_checked(core, &candidate[index].core)) {
        heap_persist_abort_tx();
        heap_set_mode(HEAP_MODE_SCRATCH);
        return 0;
    }
    candidate[index].admitted = 1;
    candidate[index].admission = NOUN_ZERO;
    for (uint32_t i = 0; i < 32; i++) {
        candidate[index].core_id[i] = core_id[i];
        candidate[index].admission_id[i] = 0;
    }
    heap_persist_commit_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        if (candidate[i].admitted)
            g_catalog[i] = candidate[i];
    heap_set_mode(HEAP_MODE_SCRATCH);
    d5_publish();
    return 1;
}

static int d7_commit_catalog(void)
{
    d5_catalog_t candidate[D5_CATALOG_CAPACITY];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        candidate[i] = g_catalog[i];
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_persist_begin_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++) {
        if (!candidate[i].admitted)
            continue;
        if (!noun_copy_checked(g_catalog[i].core, &candidate[i].core)) {
            heap_persist_abort_tx();
            heap_set_mode(HEAP_MODE_SCRATCH);
            return 0;
        }
    }
    heap_persist_commit_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        if (candidate[i].admitted)
            g_catalog[i] = candidate[i];
    heap_set_mode(HEAP_MODE_SCRATCH);
    return 1;
}

static noun d7_dispatch_load(noun core, const uint8_t core_id[32],
                             const d5_plan_t *plan, int catalog_index)
{
    uint32_t slot_number = 0;
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        if (!g_slots[i].used) {
            slot_number = i + 1;
            break;
        }
    if (slot_number == 0)
        return d5_refuse(9, 0, NOUN_ZERO);
    d5_state_t initial;
    if (!d5_initial_state(plan, &initial))
        return d5_refuse(2, 0, NOUN_ZERO);
    noun state = d5_state_noun(plan, &initial, slot_number,
                               g_slots[slot_number - 1].generation,
                               core_id, D5_STATE_INITIALIZED);
    noun handle = d5_handle(slot_number, g_slots[slot_number - 1].generation);
    if (state == NOUN_ZERO || handle == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    noun body[2] = {handle, state};
    noun result = d5_result(D5_STATUS_LOAD, d5_record_build(body, 2));
    noun owned = d5_result_stage(result);
    if (owned == NOUN_ZERO)
        return d5_refuse(7, 0, NOUN_ZERO);
    /* Keep catalog admission behind all allocation and result-shape work.
     * If this final persistence copy fails, no slot or catalog publication
     * has happened and the outer refusal can replace the staged scratch. */
    if (!d7_admit_core((uint32_t)catalog_index, core, core_id))
        return d5_refuse(9, 0, NOUN_ZERO);
    d5_slot_t *slot = &g_slots[slot_number - 1];
    slot->catalog = (uint32_t)catalog_index;
    slot->state = initial;
    slot->state_kind = D5_STATE_INITIALIZED;
    slot->latest = 0;
    slot->used = 1;
    d5_publish();
    return owned;
}

static int d7_preflight(const d7_request_t *requests, uint32_t count,
                        noun core, noun descriptor, noun policy,
                        uint8_t core_id[32], d5_plan_t *plan,
                        int *catalog_index)
{
    uint8_t layout[32];
    if (!d5_validate_core(core, core_id, plan, catalog_index)) {
        return 0;
    }
    if (!d7_validate_descriptor(descriptor, core_id)) {
        return 0;
    }
    if (!d7_validate_policy(policy, core_id)) {
        return 0;
    }
    if (!d7_layout_digest(core, layout)) {
        return 0;
    }
    if (count == 0 || requests[0].operation != D5_OP_LOAD
        || requests[0].args != NOUN_ZERO) {
        return 0;
    }
    for (uint32_t i = 1; i < count; i++) {
        noun handle, translated, op_args[2];
        uint32_t slot_number;
        uint64_t generation;
        noun handle_input = requests[i].args;
        noun operation_value = requests[i].args;
        if (requests[i].operation == D5_OP_POKE
            || requests[i].operation == D5_OP_PEEK
            || requests[i].operation == D5_OP_RESTORE) {
            if (!d5_record(requests[i].args, op_args, 2))
                return 0;
            handle_input = op_args[0];
            operation_value = op_args[1];
        }
        if (requests[i].operation == D5_OP_LOAD
            || !d7_decode_handle(handle_input, core_id, &handle, &slot_number,
                                 &generation)
            || slot_number != 1 || generation != 1)
            return 0;
        if (requests[i].operation == D5_OP_POKE) {
            if (!d7_decode_r5_ingress(plan, operation_value, core_id,
                                      layout, &translated))
                return 0;
        } else if (requests[i].operation == D5_OP_PEEK) {
            if (!d7_decode_selector(plan, operation_value, core_id,
                                    layout, &translated))
                return 0;
        } else if (requests[i].operation == D5_OP_RESTORE) {
            if (!d7_snapshot_to_legacy(plan, operation_value, handle,
                                       core_id, layout, &translated))
                return 0;
        }
    }
    return 1;
}

static noun d7_run_one(const d7_request_t *request, noun core,
                       const uint8_t core_id[32], const d5_plan_t *input_plan,
                       int input_catalog_index)
{
    if (request->operation == D5_OP_LOAD) {
        return d7_dispatch_load(core, core_id, input_plan, input_catalog_index);
    }
    noun raw_handle = request->args;
    noun raw_second = NOUN_ZERO;
    if (request->operation == D5_OP_POKE
        || request->operation == D5_OP_PEEK
        || request->operation == D5_OP_RESTORE) {
        noun args[2];
        if (!d5_record(request->args, args, 2))
            return d5_refuse(16, 0, NOUN_ZERO);
        raw_handle = args[0];
        raw_second = args[1];
    }
    noun handle;
    uint32_t slot_number;
    if (!d7_decode_handle(raw_handle, core_id, &handle, &slot_number, 0)
        || !d5_slot_resolve(handle, &slot_number))
        return d5_refuse(1, 0, NOUN_ZERO);
    d5_catalog_t *catalog = &g_catalog[g_slots[slot_number - 1].catalog];
    d5_plan_t plan;
    if (!catalog->admitted || !d5_parse_plan(catalog->core, &plan))
        return d5_refuse(8, 0, NOUN_ZERO);
    uint8_t layout[32];
    if (!d7_layout_digest(catalog->core, layout))
        return d5_refuse(8, 0, NOUN_ZERO);
    noun translated;
    if (request->operation == D5_OP_POKE) {
        if (!d7_decode_r5_ingress(&plan, raw_second, core_id,
                                  layout, &translated))
            return d5_refuse(4, 0, NOUN_ZERO);
        g_result_stage_limit = g_d7_result_stage_limit != 0
            ? g_d7_result_stage_limit : D5_RESULT_CELL_CAPACITY;
        g_d7_result_stage_limit = 0;
        return d5_dispatch_poke(handle, translated);
    }
    if (request->operation == D5_OP_PEEK) {
        if (!d7_decode_selector(&plan, raw_second, core_id,
                                layout, &translated))
            return d5_refuse(5, 0, NOUN_ZERO);
        return d5_dispatch_peek(handle, translated);
    }
    if (request->operation == D5_OP_SNAPSHOT)
        return d5_dispatch_snapshot(handle);
    if (!d7_snapshot_to_legacy(&plan, raw_second, handle,
                               core_id, layout, &translated)
        || !d5_validate_restore_snapshot(&plan, &g_slots[slot_number - 1],
                                          handle, translated, core_id,
                                          &(d5_state_t){0}, &(uint32_t){0}))
        return d5_refuse(6, 0, d5_state_noun(&plan, &g_slots[slot_number - 1].state,
                                             slot_number, g_slots[slot_number - 1].generation,
                                             core_id, g_slots[slot_number - 1].state_kind));
    return d5_dispatch_restore(handle, translated);
}

static void d7_apply_control(const d7_control_t *controls, uint32_t count,
                             uint32_t request_index)
{
    for (uint32_t i = 0; i < count; i++) {
        if (controls[i].request_index != request_index)
            continue;
        if (controls[i].kind == D7_CONTROL_EVALUATOR_REFUSAL)
            g_d7_evaluator_ops_limit = controls[i].value;
        else if (controls[i].kind == D7_CONTROL_RESULT_STAGE_REFUSAL)
            g_d7_result_stage_limit = (uint32_t)controls[i].value;
    }
}

static int d7_capture_result(uint32_t operation, noun result,
                             d7_result_record_t *out)
{
    uint32_t status = 0;
    uint32_t reason = 0;
    *out = (d7_result_record_t){.operation = operation};
    if (!d5_result_status_reason(result, &status, &reason)
        || !d5_sha256_digest(result, out->result))
        return 0;
    out->status = status;
    out->reason = reason;
    if (operation == D5_OP_LOAD && status == D5_STATUS_LOAD) {
        noun tag, body, fields[3], load_fields[2];
        if (!d5_pair(result, &tag, &body) || !d5_record(body, fields, 3)
            || !d5_record(fields[2], load_fields, 2)
            || !d5_sha256_digest(load_fields[0], out->handle)
            || !d5_sha256_digest(load_fields[1], out->state))
            return 0;
        out->has_load_shape = 1;
    } else if (operation == D5_OP_POKE && status == D5_STATUS_POKE) {
        noun tag, body, fields[3], poke_fields[4], mt, mb, mf[6];
        if (!d5_pair(result, &tag, &body) || !d5_record(body, fields, 3)
            || !d5_record(fields[2], poke_fields, 4)
            || !d5_pair(poke_fields[3], &mt, &mb)
            || !d5_record(mb, mf, 6)
            || !noun_is_direct(mf[1]) || !noun_is_direct(mf[2])
            || !noun_is_direct(mf[3])
            || !d5_sha256_digest(poke_fields[0], out->next)
            || !d5_sha256_digest(poke_fields[1], out->effects)
            || !d5_sha256_digest(poke_fields[2], out->observations)
            || !d5_sha256_digest(poke_fields[3], out->metrics))
            return 0;
        out->ops = direct_val(mf[1]);
        out->cells = direct_val(mf[2]);
        out->stack = direct_val(mf[3]);
        out->has_poke_shape = 1;
    }
    return 1;
}

static void d7_print_record(const d7_result_record_t *record)
{
    uart_puts("M38D7 op=");
    uart_puts(d5_operation_name(record->operation));
    uart_puts(" status=");
    uart_puts(d7_status_name(record->status));
    uart_puts(" reason=");
    d5_hex64(record->reason);
    uart_puts(" result_sha256=");
    d5_digest_text(record->result);
    if (record->has_load_shape) {
        uart_puts(" handle_sha256="); d5_digest_text(record->handle);
        uart_puts(" state_sha256="); d5_digest_text(record->state);
    } else if (record->has_poke_shape) {
        uart_puts(" ops="); d5_hex64(record->ops);
        uart_puts(" cells="); d5_hex64(record->cells);
        uart_puts(" stack="); d5_hex64(record->stack);
        uart_puts(" next_sha256="); d5_digest_text(record->next);
        uart_puts(" effects_sha256="); d5_digest_text(record->effects);
        uart_puts(" observations_sha256="); d5_digest_text(record->observations);
        uart_puts(" metrics_sha256="); d5_digest_text(record->metrics);
    }
    uart_puts("\r\n");
}

static void d7_print_rollback_witness(uint64_t scratch_before,
                                      uint64_t persist_before,
                                      uint64_t atom_bytes_before,
                                      uint64_t atom_occupancy_before,
                                      uint64_t publications_before,
                                      const uint8_t semantic_before[32])
{
    uint8_t semantic_after[32];
    uint64_t scratch_after = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t persist_after = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atom_bytes_after = atom_store_bytes_used();
    uint64_t atom_occupancy_after = atom_store_index_occupancy();
    uint64_t publications_after = g_publications;
    d5_semantic_authority_digest(semantic_after);
    int invariant = scratch_before == scratch_after
        && persist_before == persist_after
        && atom_bytes_before == atom_bytes_after
        && atom_occupancy_before == atom_occupancy_after
        && publications_before == publications_after
        && d5_same_bytes(semantic_before, semantic_after, 32);
    uart_puts("M38D7 ROLLBACK status="); uart_puts(invariant ? "pass" : "fail");
    uart_puts(" scratch_cells_before="); d5_hex64(scratch_before);
    uart_puts(" scratch_cells_after="); d5_hex64(scratch_after);
    uart_puts(" persist_cells_before="); d5_hex64(persist_before);
    uart_puts(" persist_cells_after="); d5_hex64(persist_after);
    uart_puts(" atom_bytes_before="); d5_hex64(atom_bytes_before);
    uart_puts(" atom_bytes_after="); d5_hex64(atom_bytes_after);
    uart_puts(" atom_occupancy_before="); d5_hex64(atom_occupancy_before);
    uart_puts(" atom_occupancy_after="); d5_hex64(atom_occupancy_after);
    uart_puts(" publications_before="); d5_hex64(publications_before);
    uart_puts(" publications_after="); d5_hex64(publications_after);
    uart_puts(" semantic_authority_before_sha256="); d5_digest_text(semantic_before);
    uart_puts(" semantic_authority_after_sha256="); d5_digest_text(semantic_after);
    uart_puts("\r\n");
}

static int d7_retry_present(void)
{
    const volatile uint8_t *q = (const volatile uint8_t *)(uintptr_t)
        (PILL_BASE + D7_RETRY_PILL_OFFSET);
    int any = 0;
    for (unsigned i = 0; i < 8; i++)
        any |= q[i] != 0;
    return !g_d7_retry_used && any;
}

void m38_resource_compatibility_witness_boot(void);

static void d7_retry_after_refusal(void)
{
    if (!d7_retry_present())
        return;
    g_d7_retry_used = 1;
    g_d7_retry_source = 1;
    m38_resource_compatibility_witness_boot();
    g_d7_retry_source = 0;
}

void m38_resource_compatibility_witness_boot(void)
{
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        nock_budget_finish();
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        uart_puts("M38D7 REFUSE evaluator-abort\r\nM38D7 TERMINAL status=refuse\r\n");
        return;
    }
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        g_catalog[i] = (d5_catalog_t){0};
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        g_slots[i] = (d5_slot_t){.generation = 1};
    g_publications = 0;
    g_d7_batch_active = 0;
    g_d7_batch_publications = 0;
    g_d7_evaluator_ops_limit = 0;
    g_d7_result_stage_limit = 0;
    g_in_flight = 0;
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
    g_nested_result_arena.cell_count = 0;
    g_nested_result_arena.root = NOUN_ZERO;
    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);

    d5_catalog_t catalog_before[D5_CATALOG_CAPACITY];
    d5_slot_t slots_before[D5_SLOT_COUNT];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        catalog_before[i] = g_catalog[i];
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        slots_before[i] = g_slots[i];
    uint64_t scratch_cells_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t persist_cells_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atom_bytes_before = atom_store_bytes_used();
    uint64_t atom_occupancy_before = atom_store_index_occupancy();
    uint64_t publications_before = g_publications;
    uint8_t semantic_before[32];
    d5_semantic_authority_digest(semantic_before);

    noun input, core, descriptor, policy, operations, controls;
    d7_request_t requests[64];
    d7_control_t decoded_controls[16];
    uint32_t request_count = 0;
    uint32_t control_count = 0;
    cue_bounded_status_t cue_status;
    if (!d5_decode_pill(&input, &cue_status)
        || !d7_decode_input(input, &core, &descriptor, &policy, &operations,
                            &controls, requests, &request_count,
                            decoded_controls, &control_count)) {
        if (noun_tx_active()) noun_tx_abort();
        heap_scratch_reset();
        uart_puts("M38D7 REFUSE malformed-or-noncanonical-input\r\n");
        uart_puts("M38D7 REFUSE publications="); d5_hex64(g_publications);
        uart_puts("\r\n");
        uart_puts("M38D7 TERMINAL status=refuse\r\n");
        d7_retry_after_refusal();
        return;
    }
    uint8_t core_id[32];
    d5_plan_t plan;
    int catalog_index = -1;
    if (!d7_preflight(requests, request_count, core, descriptor, policy,
                      core_id, &plan, &catalog_index)) {
        if (noun_tx_active()) noun_tx_abort();
        heap_scratch_reset();
        uart_puts("M38D7 REFUSE semantic-or-authority-preflight\r\n");
        uart_puts("M38D7 REFUSE publications="); d5_hex64(g_publications);
        uart_puts("\r\n");
        uart_puts("M38D7 TERMINAL status=refuse\r\n");
        d7_retry_after_refusal();
        return;
    }
    d5_warm_fixed_atoms();
    d7_result_record_t records[64];
    uint32_t record_count = 0;
    uint32_t failed_index = 0;
    int batch_ok = 1;
    g_d7_batch_active = 1;
    g_d7_batch_publications = 0;
    for (uint32_t i = 0; i < request_count; i++) {
        d7_apply_control(decoded_controls, control_count, i);
        noun result = d7_run_one(&requests[i], core, core_id, &plan, catalog_index);
        if (result != g_result_arena.root && result != NOUN_ZERO)
            result = d5_result_stage(result);
        if (record_count >= 64
            || !d7_capture_result(requests[i].operation, result,
                                  &records[record_count])) {
            batch_ok = 0;
            failed_index = i;
            break;
        }
        uint32_t status = records[record_count].status;
        record_count++;
        if (status == D5_STATUS_REFUSE) {
            batch_ok = 0;
            failed_index = i;
            break;
        }
    }
    if (batch_ok && !d7_commit_catalog()) {
        batch_ok = 0;
        failed_index = request_count;
    }
    if (batch_ok) {
        g_d7_batch_active = 0;
        g_publications = publications_before + g_d7_batch_publications;
        if (noun_tx_active())
            noun_tx_commit();
        heap_set_mode(HEAP_MODE_SCRATCH);
        (void)heap_scratch_rewind(0);
        uart_puts("M38D7 CORE identity=");
        d5_digest_text(core_id);
        uart_puts("\r\n");
        for (uint32_t i = 0; i < record_count; i++)
            d7_print_record(&records[i]);
        uart_puts("M38D7 TERMINAL status=pass\r\n");
        return;
    }
    g_d7_batch_active = 0;
    heap_persist_abort_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        g_catalog[i] = catalog_before[i];
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        g_slots[i] = slots_before[i];
    g_publications = publications_before;
    if (noun_tx_active())
        noun_tx_abort();
    heap_set_mode(HEAP_MODE_SCRATCH);
    (void)heap_scratch_rewind(0);
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
    if (record_count > 0)
        d7_print_record(&records[record_count - 1]);
    uart_puts("M38D7 REFUSE batch-rollback failed_index=");
    d5_hex64(failed_index);
    uart_puts("\r\n");
    d7_print_rollback_witness(scratch_cells_before, persist_cells_before,
                              atom_bytes_before, atom_occupancy_before,
                              publications_before, semantic_before);
    uart_puts("M38D7 REFUSE publications="); d5_hex64(g_publications);
    uart_puts("\r\n");
    uart_puts("M38D7 TERMINAL status=refuse\r\n");
    d7_retry_after_refusal();
}
#endif

#if defined(M38_D8_NATIVE)

typedef struct {
    noun core;
    noun core_ref;
    noun battery;
    noun jam;
    uint32_t jam_bytes;
    uint32_t raw_offset;
    noun descriptor;
    noun policy;
    d7_request_t requests[64];
    d7_control_t controls[16];
    uint32_t request_count;
    uint32_t control_count;
    uint8_t core_id[32];
    d5_plan_t plan;
    int catalog_index;
} d8_record_t;

extern uint8_t __text_start[];
extern uint8_t __text_end[];
extern uint8_t __rodata_start[];
extern uint8_t __rodata_end[];
extern uint8_t __bss_start[];
extern uint8_t __bss_end[];

static const uint8_t D8_BATTERY_IDENTITIES[D8_RECORD_COUNT][32] = {
    {0x08,0x46,0xf5,0xa4,0x97,0x30,0x90,0x05,
     0x98,0xd1,0x6e,0x07,0x85,0x0f,0xce,0xa4,
     0xa8,0x19,0x56,0xa4,0x76,0x10,0x8d,0x72,
     0x47,0x19,0x91,0xb7,0xf4,0x21,0xae,0x91},
    {0xc5,0x0b,0xde,0x89,0x10,0x13,0x2d,0x6f,
     0x0e,0xd8,0x0f,0x0a,0x76,0xf8,0x83,0x66,
     0x7c,0xd7,0x7d,0xe0,0x07,0xa4,0xb7,0xa6,
     0x51,0x5d,0x57,0x39,0x76,0xe5,0x40,0x1d}
};

static void d8_zero_bytes(uint8_t *out, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++)
        out[i] = 0;
}

static void d8_clear_raw_catalog(void)
{
    d8_zero_bytes(g_d8_raw_catalog, D8_RAW_CATALOG_RESERVATION);
    for (uint32_t i = 0; i < D8_RECORD_COUNT; i++)
        g_d8_raw_catalog_lengths[i] = 0;
    g_d8_raw_catalog_used = 0;
}

static uint32_t d8_catalog_entries(void)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        count += g_catalog[i].admitted != 0;
    return count;
}

static uint32_t d8_used_slots(void)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        count += g_slots[i].used != 0;
    return count;
}

static int d8_decode_input(noun value, d8_record_t records[D8_RECORD_COUNT],
                           uint32_t *active, uint32_t *fault)
{
    noun tag, body, fields[4], rows[D8_RECORD_COUNT];
    uint32_t row_count;
    if (!d5_pair(value, &tag, &body)
        || !d5_atom_is(tag, D8_INPUT_TAG)
        || !d5_record(body, fields, 4)
        || !d5_atom_is(fields[0], D8_INPUT_SCHEMA)
        || !d5_list(fields[1], rows, D8_RECORD_COUNT, &row_count)
        || row_count != D8_RECORD_COUNT
        || !d5_u(fields[2], D8_RECORD_COUNT - 1u, active)
        || !d5_u(fields[3], D8_MAX_PLACEMENT_FAULT, fault))
        return 0;
    for (uint32_t i = 0; i < D8_RECORD_COUNT; i++) {
        noun rf[9], operations[64], controls[16];
        uint32_t operation_count, control_count;
        if (!d5_record(rows[i], rf, 9)
            || !d5_u(rf[4], D8_RAW_CATALOG_RESERVATION, &records[i].jam_bytes)
            || !d5_list(rf[7], operations, 64, &operation_count)
            || operation_count == 0
            || !d5_list(rf[8], controls, 16, &control_count))
            return 0;
        records[i].core = rf[0];
        records[i].core_ref = rf[1];
        records[i].battery = rf[2];
        records[i].jam = rf[3];
        records[i].descriptor = rf[5];
        records[i].policy = rf[6];
        records[i].request_count = operation_count;
        records[i].control_count = control_count;
        for (uint32_t j = 0; j < operation_count; j++)
            if (!d7_decode_request(operations[j], &records[i].requests[j]))
                return 0;
        for (uint32_t j = 0; j < control_count; j++)
            if (!d7_decode_control(controls[j], &records[i].controls[j]))
                return 0;
    }
    return 1;
}

static int d8_validate_and_copy(d8_record_t *record)
{
    uint8_t supplied_core_id[32], supplied_battery_id[32];
    uint8_t computed_battery_id[32];
    noun formula, payload;
    jam_admission_budget_t battery_budget;
    if (!d5_atom_bytes(record->core_ref, supplied_core_id, sizeof supplied_core_id))
        return 0;
    if (!d5_atom_bytes(record->battery, supplied_battery_id,
                       sizeof supplied_battery_id))
        return 0;
    if (!d5_pair(record->core, &formula, &payload))
        return 0;
    jam_admission_budget_init(&battery_budget, D5_JAM_WORK_LIMIT);
    if (!d5_validate_core(record->core, record->core_id, &record->plan,
                          &record->catalog_index))
        return 0;
    if (!d5_same_bytes(record->core_id, supplied_core_id, 32))
        return 0;
    if (!d5_domain_digest(formula, D8_FORMULA_DOMAIN, computed_battery_id,
                          &battery_budget))
        return 0;
    if (!d5_same_bytes(computed_battery_id, supplied_battery_id, 32))
        return 0;
    if (!d5_same_bytes(computed_battery_id,
                       D8_BATTERY_IDENTITIES[record->catalog_index], 32))
        return 0;
    jam_admission_budget_t budget;
    jam_admission_budget_init(&budget, D5_JAM_WORK_LIMIT);
    const uint8_t *canonical;
    uint64_t canonical_bytes;
    if (jam_encode_bytes_identity_bounded(record->core, &canonical,
                                           &canonical_bytes, &budget) != 0
        || canonical_bytes != record->jam_bytes
        || record->jam_bytes == 0
        || g_d8_raw_catalog_used > D8_RAW_CATALOG_RESERVATION - record->jam_bytes)
        return 0;
    record->raw_offset = g_d8_raw_catalog_used;
    if (!noun_atom_read_fixed(record->jam,
                              g_d8_raw_catalog + record->raw_offset,
                              record->jam_bytes)
        || !d5_same_bytes(canonical,
                          g_d8_raw_catalog + record->raw_offset,
                          record->jam_bytes))
        return 0;
    g_d8_raw_catalog_used += record->jam_bytes;
    g_d8_raw_catalog_lengths[record->catalog_index] = record->jam_bytes;
    return 1;
}

static int d8_raw_catalog_is_zero(void)
{
    for (uint32_t i = 0; i < D8_RAW_CATALOG_RESERVATION; i++)
        if (g_d8_raw_catalog[i] != 0)
            return 0;
    return g_d8_raw_catalog_used == 0;
}

static void d8_print_placement(const char *phase, uint64_t copy_mutations)
{
    uint8_t core_hash[32] = {0};
    sha256_hash(g_d8_raw_catalog, g_d8_raw_catalog_used, core_hash);
    uart_puts("M38D8 PLACEMENT phase="); uart_puts(phase);
    uart_puts(" raw_catalog_reservation_bytes="); d5_hex64(D8_RAW_CATALOG_RESERVATION);
    uart_puts(" raw_catalog_used_bytes="); d5_hex64(g_d8_raw_catalog_used);
    uart_puts(" raw_catalog_core0_bytes="); d5_hex64(g_d8_raw_catalog_lengths[0]);
    uart_puts(" raw_catalog_core1_bytes="); d5_hex64(g_d8_raw_catalog_lengths[1]);
    uart_puts(" raw_catalog_sha256="); d5_digest_text(core_hash);
    uart_puts(" persistent_semispace_capacity_bytes="); d5_hex64(HEAP_PERSIST_HALF);
    uart_puts(" persistent_used_bytes="); d5_hex64(heap_cells_used(HEAP_MODE_PERSIST) * sizeof(cell_t));
    uart_puts(" persistent_copy_pair_bytes="); d5_hex64(HEAP_PERSIST_SIZE);
    uart_puts(" scratch_capacity_bytes="); d5_hex64(HEAP_SCRATCH_SIZE);
    uart_puts(" scratch_used_bytes="); d5_hex64(heap_cells_used(HEAP_MODE_SCRATCH) * sizeof(cell_t));
    uart_puts(" atom_data_capacity_bytes="); d5_hex64(ATOM_DATA_SIZE);
    uart_puts(" atom_data_used_bytes="); d5_hex64(atom_store_bytes_used());
    uart_puts(" atom_index_capacity_slots="); d5_hex64(atom_store_index_capacity());
    uart_puts(" atom_index_used_slots="); d5_hex64(atom_store_index_occupancy());
    uart_puts(" catalog_metadata_bytes="); d5_hex64(sizeof(d5_catalog_t) * D5_CATALOG_KNOWN_COUNT);
    uart_puts(" slot_metadata_bytes="); d5_hex64(sizeof(d5_slot_t) * D5_SLOT_COUNT);
    uart_puts(" validation_staging_bytes="); d5_hex64(sizeof(d8_record_t));
    uart_puts(" result_staging_bytes="); d5_hex64(sizeof(g_result_cells) + sizeof(g_result_source) + sizeof(g_result_value));
    uart_puts(" refusal_staging_bytes=");
    d5_hex64(sizeof(g_nested_result_cells) + sizeof(g_nested_result_source)
             + sizeof(g_nested_result_value));
    uart_puts(" copy_mutations="); d5_hex64(copy_mutations);
    uart_puts(" copy_map_hwm="); d5_hex64(noun_copy_map_hwm());
    uart_puts(" text_bytes="); d5_hex64((uint64_t)(__text_end - __text_start));
    uart_puts(" rodata_bytes="); d5_hex64((uint64_t)(__rodata_end - __rodata_start));
    uart_puts(" bss_bytes="); d5_hex64((uint64_t)(__bss_end - __bss_start));
    uart_puts(" native_static_bytes="); d5_hex64(sizeof(g_d8_raw_catalog));
    uart_puts(" placement_claim=qemu-image-only\r\n");
}

static void d8_print_triple(const d8_record_t *record)
{
    uint8_t jam_hash[32];
    sha256_hash(g_d8_raw_catalog + record->raw_offset,
                record->jam_bytes, jam_hash);
    uart_puts("M38D8 TRIPLE catalog_index="); d5_hex64(record->catalog_index);
    uart_puts(" core_ref_sha256="); d5_digest_text(record->core_id);
    uart_puts(" nock_battery_sha256=");
    d5_digest_text(D8_BATTERY_IDENTITIES[record->catalog_index]);
    uart_puts(" resource_core_jam_bytes="); d5_hex64(record->jam_bytes);
    uart_puts(" resource_core_jam_sha256="); d5_digest_text(jam_hash);
    uart_puts("\r\n");
}

static void d8_print_rollback(const char *stage,
                              uint64_t scratch_before,
                              uint64_t persist_before,
                              uint64_t atom_bytes_before,
                              uint64_t atom_occupancy_before,
                              uint64_t publications_before,
                              const uint8_t semantic_before[32])
{
    uint8_t semantic_after[32];
    uint64_t scratch_after = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t persist_after = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atom_bytes_after = atom_store_bytes_used();
    uint64_t atom_occupancy_after = atom_store_index_occupancy();
    uint64_t publications_after = g_publications;
    d5_semantic_authority_digest(semantic_after);
    int clean = scratch_before == scratch_after
        && persist_before == persist_after
        && atom_bytes_before == atom_bytes_after
        && atom_occupancy_before == atom_occupancy_after
        && publications_before == publications_after
        && d5_same_bytes(semantic_before, semantic_after, 32)
        && d8_catalog_entries() == 0
        && d8_used_slots() == 0
        && d8_raw_catalog_is_zero();
    uart_puts("M38D8 ROLLBACK stage="); uart_puts(stage);
    uart_puts(" status="); uart_puts(clean ? "pass" : "fail");
    uart_puts(" scratch_before="); d5_hex64(scratch_before);
    uart_puts(" scratch_after="); d5_hex64(scratch_after);
    uart_puts(" persist_before="); d5_hex64(persist_before);
    uart_puts(" persist_after="); d5_hex64(persist_after);
    uart_puts(" atom_bytes_before="); d5_hex64(atom_bytes_before);
    uart_puts(" atom_bytes_after="); d5_hex64(atom_bytes_after);
    uart_puts(" atom_index_before="); d5_hex64(atom_occupancy_before);
    uart_puts(" atom_index_after="); d5_hex64(atom_occupancy_after);
    uart_puts(" publications_before="); d5_hex64(publications_before);
    uart_puts(" publications_after="); d5_hex64(publications_after);
    uart_puts(" catalog_entries_after="); d5_hex64(d8_catalog_entries());
    uart_puts(" handles_after="); d5_hex64(d8_used_slots());
    uart_puts(" raw_catalog_used_after="); d5_hex64(g_d8_raw_catalog_used);
    uart_puts(" transient_decoder_residue=");
    d5_hex64(heap_cells_used(HEAP_MODE_SCRATCH));
    uart_puts(" semantic_before_sha256="); d5_digest_text(semantic_before);
    uart_puts(" semantic_after_sha256="); d5_digest_text(semantic_after);
    uart_puts("\r\n");
}

static void d8_restore_and_refuse(const char *stage,
                                  d5_catalog_t catalog_before[D5_CATALOG_CAPACITY],
                                  d5_slot_t slots_before[D5_SLOT_COUNT],
                                  uint64_t scratch_before,
                                  uint64_t persist_before,
                                  uint64_t atom_bytes_before,
                                  uint64_t atom_occupancy_before,
                                  uint64_t publications_before,
                                  const uint8_t semantic_before[32])
{
    g_d7_batch_active = 0;
    heap_persist_abort_tx();
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        g_catalog[i] = catalog_before[i];
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        g_slots[i] = slots_before[i];
    g_publications = publications_before;
    if (noun_tx_active())
        noun_tx_abort();
    noun_test_copy_fail_after(-1);
    noun_test_atom_fail_after(-1);
    heap_set_mode(HEAP_MODE_SCRATCH);
    heap_scratch_reset();
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
    g_nested_result_arena.cell_count = 0;
    g_nested_result_arena.root = NOUN_ZERO;
    d8_clear_raw_catalog();
    d8_print_rollback(stage, scratch_before, persist_before,
                      atom_bytes_before, atom_occupancy_before,
                      publications_before, semantic_before);
    uart_puts("M38D8 REFUSE stage="); uart_puts(stage);
    uart_puts(" publications="); d5_hex64(g_publications);
    uart_puts("\r\nM38D8 TERMINAL status=refuse\r\n");
}

static int d8_force_atom_store_failure(void)
{
    uint64_t limbs[4] = {
        0x8d3c4a5b6e7f1021ULL, 0x23456789abcdef01ULL,
        0x1020304050607080ULL, 0xfedcba9876543210ULL
    };
    noun out;
    noun_test_atom_fail_after(0);
    int failed = !make_atom_checked(limbs, 4, &out);
    noun_test_atom_fail_after(-1);
    return failed;
}

void m38_resource_placement_experiment_boot(void)
{
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        nock_budget_finish();
        heap_persist_abort_tx();
        if (noun_tx_active())
            noun_tx_abort();
        noun_test_copy_fail_after(-1);
        noun_test_atom_fail_after(-1);
        heap_set_mode(HEAP_MODE_SCRATCH);
        heap_scratch_reset();
        d8_clear_raw_catalog();
        uart_puts("M38D8 REFUSE stage=evaluator-abort\r\n");
        uart_puts("M38D8 TERMINAL status=refuse\r\n");
        return;
    }
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        g_catalog[i] = (d5_catalog_t){0};
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        g_slots[i] = (d5_slot_t){.generation = 1};
    g_publications = 0;
    g_d7_batch_active = 0;
    g_d7_batch_publications = 0;
    g_d7_evaluator_ops_limit = 0;
    g_d7_result_stage_limit = 0;
    g_in_flight = 0;
    g_result_arena.cell_count = 0;
    g_result_arena.root = NOUN_ZERO;
    g_nested_result_arena.cell_count = 0;
    g_nested_result_arena.root = NOUN_ZERO;
    d8_clear_raw_catalog();
    noun_copy_map_hwm_reset();
    noun_test_copy_mutations_reset();
    noun_test_copy_fail_after(-1);
    noun_test_atom_fail_after(-1);
    heap_scratch_reset();
    heap_set_mode(HEAP_MODE_SCRATCH);

    d5_catalog_t catalog_before[D5_CATALOG_CAPACITY];
    d5_slot_t slots_before[D5_SLOT_COUNT];
    for (uint32_t i = 0; i < D5_CATALOG_CAPACITY; i++)
        catalog_before[i] = g_catalog[i];
    for (uint32_t i = 0; i < D5_SLOT_COUNT; i++)
        slots_before[i] = g_slots[i];
    uint64_t scratch_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t persist_before = heap_cells_used(HEAP_MODE_PERSIST);
    uint64_t atom_bytes_before = atom_store_bytes_used();
    uint64_t atom_occupancy_before = atom_store_index_occupancy();
    uint64_t publications_before = g_publications;
    uint8_t semantic_before[32];
    d5_semantic_authority_digest(semantic_before);

    noun input;
    d8_record_t records[D8_RECORD_COUNT] = {0};
    uint32_t active = 0, fault = 0;
    cue_bounded_status_t cue_status;
    if (!d5_decode_pill(&input, &cue_status)) {
        d8_restore_and_refuse("decode-validation", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    if (!d8_decode_input(input, records, &active, &fault)) {
        d8_restore_and_refuse("decode-validation", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    if (fault == D8_FAULT_DECODE_VALIDATION) {
        d8_restore_and_refuse("decode-validation", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    for (uint32_t i = 0; i < D8_RECORD_COUNT; i++) {
        if (!d8_validate_and_copy(&records[i])) {
            d8_restore_and_refuse("decode-validation", catalog_before, slots_before,
                                  scratch_before, persist_before, atom_bytes_before,
                                  atom_occupancy_before, publications_before,
                                  semantic_before);
            return;
        }
        if (fault == D8_FAULT_RAW_CATALOG_COPY && i == 0) {
            d8_restore_and_refuse("raw-catalog-copy", catalog_before, slots_before,
                                  scratch_before, persist_before, atom_bytes_before,
                                  atom_occupancy_before, publications_before,
                                  semantic_before);
            return;
        }
    }
    if (fault == D8_FAULT_ATOM_DATA_INDEX) {
        (void)d8_force_atom_store_failure();
        d8_restore_and_refuse("atom-data-index", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    d5_warm_fixed_atoms();

    d5_plan_t active_plan;
    uint8_t active_core_id[32];
    int active_catalog_index = -1;
    if (!d7_preflight(records[active].requests, records[active].request_count,
                      records[active].core, records[active].descriptor,
                      records[active].policy, active_core_id, &active_plan,
                      &active_catalog_index)
        || !d5_same_bytes(active_core_id, records[active].core_id, 32)
        || active_catalog_index != records[active].catalog_index) {
        d8_restore_and_refuse("decode-validation", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }

    g_d7_batch_active = 1;
    g_d7_batch_publications = 0;
    for (uint32_t i = 0; i < D8_RECORD_COUNT; i++) {
        if (!d7_admit_core((uint32_t)records[i].catalog_index,
                           records[i].core, records[i].core_id)) {
            d8_restore_and_refuse("persistent-copy", catalog_before, slots_before,
                                  scratch_before, persist_before, atom_bytes_before,
                                  atom_occupancy_before, publications_before,
                                  semantic_before);
            return;
        }
    }
    if (fault == D8_FAULT_PERSISTENT_COPY) {
        noun_test_copy_fail_after(0);
        (void)d7_commit_catalog();
        d8_restore_and_refuse("persistent-copy", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    if (fault == D8_FAULT_SCRATCH_ALLOCATION) {
        noun probe;
        noun_test_copy_fail_after(0);
        (void)noun_copy_checked(records[active].core, &probe);
        d8_restore_and_refuse("scratch-allocation", catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }

    d7_result_record_t results[64];
    uint32_t result_count = 0;
    int batch_ok = 1;
    for (uint32_t i = 0; i < records[active].request_count; i++) {
        d7_apply_control(records[active].controls, records[active].control_count, i);
        if (fault == D8_FAULT_RESULT_STAGING && i == 1)
            g_d7_result_stage_limit = 1;
        noun result = d7_run_one(&records[active].requests[i], records[active].core,
                                 records[active].core_id, &active_plan,
                                 active_catalog_index);
        if (result != g_result_arena.root && result != NOUN_ZERO)
            result = d5_result_stage(result);
        if (result_count >= 64
            || !d7_capture_result(records[active].requests[i].operation, result,
                                  &results[result_count])) {
            batch_ok = 0;
            break;
        }
        uint32_t status = results[result_count].status;
        result_count++;
        if (status == D5_STATUS_REFUSE) {
            batch_ok = 0;
            break;
        }
    }
    if (batch_ok && fault == D8_FAULT_PUBLICATION)
        batch_ok = 0;
    if (batch_ok && !d7_commit_catalog())
        batch_ok = 0;
    if (!batch_ok) {
        const char *stage = fault == D8_FAULT_PUBLICATION ? "publication"
            : fault == D8_FAULT_RESULT_STAGING ? "result-staging"
            : "resourceabi-operation";
        d8_restore_and_refuse(stage, catalog_before, slots_before,
                              scratch_before, persist_before, atom_bytes_before,
                              atom_occupancy_before, publications_before,
                              semantic_before);
        return;
    }
    g_d7_batch_active = 0;
    g_publications = publications_before + g_d7_batch_publications;
    if (noun_tx_active())
        noun_tx_commit();
    noun_test_copy_fail_after(-1);
    heap_set_mode(HEAP_MODE_SCRATCH);
    (void)heap_scratch_rewind(0);
    uint64_t copy_mutations = noun_test_copy_mutations();
    d8_print_triple(&records[0]);
    d8_print_triple(&records[1]);
    uart_puts("M38D8 ACTIVE catalog_index="); d5_hex64(records[active].catalog_index);
    uart_puts("\r\n");
    for (uint32_t i = 0; i < result_count; i++)
        d7_print_record(&results[i]);
    d8_print_placement("published", copy_mutations);
    uart_puts("M38D8 PUBLISHED catalog_entries="); d5_hex64(d8_catalog_entries());
    uart_puts(" handles="); d5_hex64(d8_used_slots());
    uart_puts(" transient_decoder_residue=");
    d5_hex64(heap_cells_used(HEAP_MODE_SCRATCH));
    uart_puts("\r\nM38D8 TERMINAL status=pass\r\n");
}

#endif
