#include <stddef.h>
#include "digital_out.h"
#include "digital_out_backend.h"

#define DIGITAL_OUT_AUDIT_CAP 64u

typedef struct {
    uint64_t ordinal;
    uint32_t operation;
    uint32_t value;
} digital_out_audit_t;

static digital_out_audit_t g_audit[DIGITAL_OUT_AUDIT_CAP];
static uint64_t g_audit_total;
static uint64_t g_audit_dropped;
static uint32_t g_shadow;
static int g_configured;
static int g_inhibited = 1;
static int g_reconcile_armed;
static int g_fatal;
static struct {
    uint64_t generation, incarnation, owner, sequence;
    int armed;
} g_m8_input_freshness;

static void audit(uint32_t operation, uint32_t value)
{
    uint64_t ordinal = ++g_audit_total;
    uint64_t slot = (ordinal - 1u) % DIGITAL_OUT_AUDIT_CAP;
    if (ordinal > DIGITAL_OUT_AUDIT_CAP)
        g_audit_dropped++;
    g_audit[slot].ordinal = ordinal;
    g_audit[slot].operation = operation;
    g_audit[slot].value = value;
}

static int configure_and_clear(int inhibit)
{
    audit(DIGITAL_OUT_OP_CONFIGURE, DIGITAL_OUT_GPIO_MASK);
    if (!digital_out_backend_configure_fixed_bank()) {
        g_configured = 0;
        g_inhibited = 1;
        g_fatal = 1;
        g_shadow = 0;
        return 0;
    }
    audit(DIGITAL_OUT_OP_CLEAR, DIGITAL_OUT_GPIO_MASK);
    if (!digital_out_backend_clear_fixed_bank()) {
        g_configured = 1;
        g_inhibited = 1;
        g_fatal = 1;
        g_shadow = 0;
        return 0;
    }
    g_configured = 1;
    g_inhibited = inhibit;
    g_reconcile_armed = 0;
    g_fatal = 0;
    g_shadow = 0;
    g_m8_input_freshness.armed = 0;
    return 1;
}

int digital_out_boot_safe(void)
{
    return configure_and_clear(1);
}

int digital_out_prepare_clean_pill(void)
{
    return configure_and_clear(0);
}

int digital_out_restore_safe(void)
{
    return configure_and_clear(1);
}

int digital_out_force_safe(void)
{
    audit(DIGITAL_OUT_OP_CLEAR, DIGITAL_OUT_GPIO_MASK);
    int ok = digital_out_backend_clear_fixed_bank();
    if (!ok)
        g_fatal = 1;
    g_shadow = 0;
    g_inhibited = 1;
    g_reconcile_armed = 0;
    g_m8_input_freshness.armed = 0;
    /* A successful clear proves the physical bank low even when an earlier
     * write failure remains latched.  Only lifecycle re-preparation clears
     * that fatal latch and permits a later command. */
    return ok;
}

void digital_out_note_legacy_external_sample(void)
{
    if (g_inhibited && !g_fatal)
        g_reconcile_armed = 1;
}

void digital_out_arm_closed_sample(uint64_t generation, uint64_t incarnation,
                                   uint64_t owner, uint64_t sequence)
{
    if (generation && incarnation && owner && sequence) {
        g_m8_input_freshness.generation = generation;
        g_m8_input_freshness.incarnation = incarnation;
        g_m8_input_freshness.owner = owner;
        g_m8_input_freshness.sequence = sequence;
        g_m8_input_freshness.armed = 1;
        if (g_inhibited && !g_fatal) g_reconcile_armed = 1;
    }
}

void digital_out_clear_closed_sample(void)
{
    g_m8_input_freshness.armed = 0;
}

int digital_out_apply_direct(uint64_t bank, uint64_t generation,
                             uint64_t incarnation, uint64_t output_owner,
                             uint64_t output_sequence)
{
    if (bank > 7 || !g_m8_input_freshness.armed
        || g_m8_input_freshness.generation != generation
        || g_m8_input_freshness.incarnation != incarnation
        || g_m8_input_freshness.owner != 4u
        || g_m8_input_freshness.sequence == 0
        || output_owner != 7u || output_sequence == 0)
        return 0;
    g_m8_input_freshness.armed = 0;
    return digital_out_apply(bank & 1u, (bank >> 1) & 1u, (bank >> 2) & 1u);
}

int digital_out_closed_sample_armed(void)
{
    return g_m8_input_freshness.armed;
}

int digital_out_apply(uint64_t p1, uint64_t p2, uint64_t alarm)
{
    if (p1 > 1 || p2 > 1 || alarm > 1)
        return 0;
    uint32_t desired = ((uint32_t)p1 << DIGITAL_OUT_GPIO_P1)
        | ((uint32_t)p2 << DIGITAL_OUT_GPIO_P2)
        | ((uint32_t)alarm << DIGITAL_OUT_GPIO_ALARM);
    uint32_t logical_bank =
        (uint32_t)p1 | ((uint32_t)p2 << 1) | ((uint32_t)alarm << 2);
    if (!g_configured || g_fatal) {
        digital_out_force_safe();
        return 0;
    }
    if (g_inhibited) {
        if (!g_reconcile_armed) {
            audit(DIGITAL_OUT_OP_REFUSE, desired);
            return 0;
        }
        g_inhibited = 0;
        g_reconcile_armed = 0;
    }
    if (desired == g_shadow) {
        audit(DIGITAL_OUT_OP_NOOP, desired);
        return 1;
    }
    /* Full-bank clear before any set prevents a P1/P2 transfer overlap. */
    audit(DIGITAL_OUT_OP_CLEAR, DIGITAL_OUT_GPIO_MASK);
    if (!digital_out_backend_clear_fixed_bank())
        goto fail;
    if (desired) {
        audit(DIGITAL_OUT_OP_SET, desired);
        if (!digital_out_backend_set_fixed_bank(logical_bank))
            goto fail;
    }
    g_shadow = desired;
    audit(DIGITAL_OUT_OP_SHADOW, desired);
    return 1;
fail:
    digital_out_force_safe();
    g_fatal = 1;
    return 0;
}

uint64_t digital_out_shadow(void)
{
    return g_shadow;
}

uint64_t digital_out_gpio_level(void)
{
    return digital_out_backend_level() & DIGITAL_OUT_GPIO_MASK;
}

uint64_t digital_out_operation_count(void)
{
    return g_audit_total;
}

uint64_t digital_out_audit_count(void)
{
    return g_audit_total < DIGITAL_OUT_AUDIT_CAP
        ? g_audit_total : DIGITAL_OUT_AUDIT_CAP;
}

uint64_t digital_out_audit_dropped(void)
{
    return g_audit_dropped;
}

uint64_t digital_out_state(void)
{
    return (uint64_t)(g_configured != 0)
        | ((uint64_t)(g_inhibited != 0) << 1)
        | ((uint64_t)(g_reconcile_armed != 0) << 2)
        | ((uint64_t)(g_fatal != 0) << 3)
        | ((uint64_t)(g_m8_input_freshness.armed != 0) << 4);
}

#ifdef DIGITAL_OUT_FAKE
uint64_t digital_out_fake_selftest(void)
{
    uint64_t failures = 0;
    digital_out_backend_fake_reset();
    g_audit_total = g_audit_dropped = 0;
    g_shadow = 0;
    g_configured = g_fatal = g_reconcile_armed = 0;
    g_inhibited = 1;
    if (!digital_out_prepare_clean_pill())
        failures++;
    uint64_t before = digital_out_backend_fake_operations();
    if (!digital_out_apply(1, 0, 0)
        || digital_out_shadow() != (1u << DIGITAL_OUT_GPIO_P1)
        || digital_out_backend_fake_operations() != before + 2)
        failures++;
    before = digital_out_backend_fake_operations();
    if (!digital_out_apply(1, 0, 0)
        || digital_out_backend_fake_operations() != before)
        failures++;
    digital_out_backend_fake_fail_at(before + 2);
    if (digital_out_apply(0, 1, 0)
        || digital_out_shadow() != 0
        || digital_out_gpio_level() != 0)
        failures++;
    for (uint64_t i = 0; i < DIGITAL_OUT_AUDIT_CAP + 8; i++)
        audit(DIGITAL_OUT_OP_NOOP, 0);
    if (digital_out_audit_count() != DIGITAL_OUT_AUDIT_CAP
        || digital_out_audit_dropped() == 0)
        failures++;

    /* A failed lifecycle/crash safe clear permanently refuses re-arming.
     * A later retry may reach low if the backend recovers, but must never set. */
    digital_out_backend_fake_reset();
    g_audit_total = g_audit_dropped = 0;
    g_shadow = 0;
    g_configured = g_fatal = g_reconcile_armed = 0;
    g_inhibited = 1;
    if (!digital_out_prepare_clean_pill()
        || !digital_out_apply(1, 0, 0))
        failures++;
    before = digital_out_backend_fake_operations();
    digital_out_backend_fake_fail_at(before + 1);
    digital_out_force_safe();
    if (digital_out_gpio_level() != (1u << DIGITAL_OUT_GPIO_P1))
        failures++;
    digital_out_note_legacy_external_sample();
    before = digital_out_backend_fake_operations();
    if (digital_out_apply(0, 1, 0)
        || digital_out_backend_fake_operations() != before + 1
        || digital_out_gpio_level() != 0)
        failures++;
    return failures;
}
#endif
