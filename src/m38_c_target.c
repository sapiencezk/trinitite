#include <stddef.h>
#include <stdint.h>

#include "blake3.h"
#include "jam.h"
#include "nock.h"
#include "noun.h"
#include "uart.h"

#define IMAGE_SCHEMA 1u
#define POLICY_MAX_OPS 2000000ULL
#define POLICY_MAX_CELLS 128000ULL
#define POLICY_MAX_STACK 1024ULL
#define QUEUE_LIMIT 8ULL
#define WORKLIST_LIMIT 32ULL
#define TRACE_LIMIT 128ULL

static const uint64_t M38C_DIAGNOSTIC_FORMULA_LIMBS[4] = {
    0xd0dbcb8ed417d899ULL, 0xed39139a5bf9f62dULL,
    0x824a2bfb780036efULL, 0xd450f368dbee147eULL,
};
static const uint64_t M38C_OPERATIONAL_FORMULA_LIMBS[4] = {
    0x88d98b77b6e1f6ccULL, 0x81bcc00131f69a66ULL,
    0x1db48566fdb303beULL, 0x74c92efa44caf596ULL,
};

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

static void put_digest(noun value)
{
    const uint8_t *jammed;
    uint64_t length;
    uint8_t digest[32];
    if (jam_encode_bytes_identity(value, &jammed, &length) != 0) {
        uart_puts("digest-error");
        return;
    }
    blake3_hash(jammed, (size_t)length, digest);
    /* Host noun_hash renders the little-endian digest as a hex integer. */
    for (int i = 31; i >= 0; i--)
        put_hex_byte(digest[i]);
}

static int atom_tag(noun value, const uint8_t *bytes, size_t length)
{
    uint8_t got[64];
    if (length > sizeof got || !noun_is_atom(value))
        return 0;
    for (size_t i = 0; i < sizeof got; i++) got[i] = 0;
    if (noun_atom_read_fixed(value, got, sizeof got) == 0)
        return 0;
    for (size_t i = 0; i < length; i++)
        if (got[i] != bytes[i]) return 0;
    for (size_t i = length; i < sizeof got; i++)
        if (got[i] != 0) return 0;
    return 1;
}

static int direct_is(noun value, uint64_t expected)
{
    return noun_is_direct(value) && direct_val(value) == expected;
}

static noun field(noun value, uint32_t index, int *ok)
{
    noun current = value;
    for (uint32_t i = 0; i < index; i++) {
        if (!noun_is_cell(current)) { *ok = 0; return NOUN_ZERO; }
        current = ((cell_t *)(uintptr_t)cell_ptr(current))->tail;
    }
    if (!noun_is_cell(current)) { *ok = 0; return NOUN_ZERO; }
    return ((cell_t *)(uintptr_t)cell_ptr(current))->head;
}

static noun tail(noun value, int *ok)
{
    if (!noun_is_cell(value)) { *ok = 0; return NOUN_ZERO; }
    return ((cell_t *)(uintptr_t)cell_ptr(value))->tail;
}

static noun head(noun value, int *ok)
{
    if (!noun_is_cell(value)) { *ok = 0; return NOUN_ZERO; }
    return ((cell_t *)(uintptr_t)cell_ptr(value))->head;
}

static int stimuli_shape_valid(noun stimuli, noun expected_identity)
{
    static const uint8_t stimulus_tag[] = "38-stimul";
    uint64_t count = 0;

    while (stimuli != NOUN_ZERO) {
        int ok = 1;
        noun stimulus, body;
        if (++count > QUEUE_LIMIT || !noun_is_cell(stimuli)) return 0;
        stimulus = head(stimuli, &ok);
        stimuli = tail(stimuli, &ok);
        if (!ok || !noun_is_cell(stimulus)
            || !atom_tag(head(stimulus, &ok), stimulus_tag,
                         sizeof stimulus_tag - 1)) return 0;
        body = tail(stimulus, &ok);
        if (!ok || !noun_is_cell(body) || field(body, 0, &ok) != expected_identity
            || !noun_is_direct(field(body, 1, &ok))
            || !noun_is_direct(field(body, 2, &ok)) || !ok) return 0;
    }
    return 1;
}

static noun digest_atom(noun value)
{
    const uint8_t *jammed;
    uint64_t length;
    uint8_t digest[32];
    uint64_t limbs[4];
    if (jam_encode_bytes_identity(value, &jammed, &length) != 0)
        return NOUN_ZERO;
    blake3_hash(jammed, (size_t)length, digest);
    for (unsigned limb = 0; limb < 4; limb++) {
        limbs[limb] = 0;
        for (unsigned byte = 0; byte < 8; byte++)
            limbs[limb] |= (uint64_t)digest[limb * 8 + byte] << (byte * 8);
    }
    return make_atom(limbs, 4);
}

static noun expected_formula_digest(uint64_t mode)
{
    const uint64_t *limbs = mode == 0
        ? M38C_DIAGNOSTIC_FORMULA_LIMBS
        : M38C_OPERATIONAL_FORMULA_LIMBS;
    return make_atom(limbs, 4);
}

static noun runtime_bounds(void)
{
    return alloc_cell(direct(QUEUE_LIMIT),
           alloc_cell(direct(WORKLIST_LIMIT),
           alloc_cell(direct(TRACE_LIMIT), NOUN_ZERO)));
}

static int image_validate(noun image, noun *runtime_plan, noun *base_plan, noun *formula,
                          noun *state, noun *stimuli, uint64_t *mode)
{
    static const uint8_t image_tag[] = "m38-c-image";
    static const uint8_t plan_tag[] = "m38-c-plan";
    int ok = 1;
    noun outer, body, runtime, runtime_body;
    noun expected_body, expected_runtime, expected_formula;
    noun bounds;

    if (!noun_is_cell(image)) return 0;
    if (!atom_tag(head(image, &ok), image_tag, sizeof image_tag - 1)) return 0;
    outer = tail(image, &ok);
    if (!ok || !noun_is_cell(outer)) return 0;
    expected_body = head(outer, &ok);
    body = field(outer, 1, &ok);
    if (!ok || expected_body != digest_atom(body)) return 0;
    if (!direct_is(field(body, 0, &ok), IMAGE_SCHEMA)) return 0;

    runtime = field(body, 1, &ok);
    if (!ok || !noun_is_cell(runtime)
        || !atom_tag(head(runtime, &ok), plan_tag, sizeof plan_tag - 1)) return 0;
    runtime_body = tail(runtime, &ok);
    if (!ok || field(body, 2, &ok) != digest_atom(runtime)) return 0;
    expected_runtime = field(runtime_body, 0, &ok);
    *runtime_plan = runtime;
    *base_plan = field(runtime_body, 1, &ok);
    if (!ok || !noun_is_cell(*base_plan)) return 0;
    if (field(runtime_body, 3, &ok) != digest_atom(field(runtime_body, 2, &ok)))
        return 0;
    if (!atom_tag(head(*base_plan, &ok), (const uint8_t *)"38-plan", 7))
        return 0;
    if (expected_runtime != field(*base_plan, 1, &ok)) return 0;

    *formula = field(body, 3, &ok);
    expected_formula = field(body, 4, &ok);
    if (!ok || !noun_is_cell(*formula) || expected_formula != digest_atom(*formula)) return 0;
    bounds = field(body, 5, &ok);
    if (!ok || !direct_is(field(bounds, 0, &ok), POLICY_MAX_OPS)
        || !direct_is(field(bounds, 1, &ok), POLICY_MAX_CELLS)
        || !direct_is(field(bounds, 2, &ok), POLICY_MAX_STACK)) return 0;
    noun mode_noun = field(body, 6, &ok);
    if (!ok || !noun_is_direct(mode_noun)) return 0;
    *mode = direct_val(mode_noun);
    if (*mode > 1) return 0;
    if (expected_formula != expected_formula_digest(*mode)) return 0;
    *stimuli = field(body, 7, &ok);
    *state = field(body, 8, &ok);
    return ok && noun_is_cell(*state) && noun_is_atom(expected_formula)
        && stimuli_shape_valid(*stimuli, expected_runtime);
}

static void reject(const char *reason)
{
    uart_puts("M38C REFUSE ");
    uart_puts(reason);
    uart_puts("\r\n");
}

void m38_c_boot(void)
{
    int jumped = setjmp(nock_abort);
    if (jumped != 0) {
        nock_budget_finish();
        reject(jumped == NOCK_ABORT_BUDGET ? "budget" : "crash");
        return;
    }

    noun pill = pill_load();
    if (!pill) { reject("no-image"); return; }
    noun image = cue(pill);
    noun runtime_plan, base_plan, formula, state, stimuli;
    uint64_t mode;
    if (!image_validate(image, &runtime_plan, &base_plan, &formula, &state, &stimuli, &mode)) {
        reject("image-auth");
        return;
    }

    uart_puts("M38C READY mode=");
    uart_putc(mode ? 'o' : 'd');
    uart_puts(" image=");
    put_digest(image);
    uart_puts("\r\n");

    noun current = state;
    unsigned ordinal = 0;
    while (stimuli != NOUN_ZERO) {
        int ok = 1;
        noun stimulus = head(stimuli, &ok);
        stimuli = tail(stimuli, &ok);
        if (!ok || !noun_is_cell(stimulus)) { reject("stimulus"); return; }

        noun subject = alloc_cell(runtime_plan,
                         alloc_cell(current,
                         alloc_cell(stimulus,
                         alloc_cell(runtime_bounds(), NOUN_ZERO))));
        int slam_jump = setjmp(nock_abort);
        if (slam_jump != 0) {
            uint64_t ops = nock_ops_used();
            uint64_t cells = nock_cells_used();
            nock_budget_finish();
            if (slam_jump == NOCK_ABORT_BUDGET) {
                uart_puts("M38C REFUSE cap-edge ops=");
                put_hex_u64(ops);
                uart_puts(" cells=");
                put_hex_u64(cells);
                uart_puts("\r\n");
            } else {
                reject("slam-crash");
            }
            return;
        }
        nock_budget_set_limits(POLICY_MAX_OPS, POLICY_MAX_CELLS);
        noun product = nock(subject, formula);
        uint64_t ops = nock_ops_used();
        uint64_t cells = nock_cells_used();
        nock_budget_finish();

        static const uint8_t product_tag[] = "m38-product-v2";
        static const uint8_t commit_tag[] = "commit";
        noun product_tail = tail(product, &ok);
        noun status = field(product_tail, 1, &ok);
        if (!ok || !atom_tag(head(product, &ok), product_tag, sizeof product_tag - 1)
            || !atom_tag(status, commit_tag, sizeof commit_tag - 1)) {
            reject("atomic-refusal");
            return;
        }
        current = field(product_tail, 2, &ok);
        noun observations = field(product_tail, 3, &ok);
        if (!ok || !noun_is_cell(current)) { reject("product"); return; }
        uart_puts("M38C SLAM ");
        put_hex_u64((uint64_t)ordinal++);
        uart_puts(" status=commit ops=");
        put_hex_u64(ops);
        uart_puts(" cells=");
        put_hex_u64(cells);
        uart_puts(" state=");
        put_digest(current);
        uart_puts(" observations=");
        put_digest(observations);
        uart_puts("\r\n");
    }
    uart_puts("M38C PASS\r\n");
}
