#include "digital_in.h"
#include "digital_in_backend.h"

static int g_configured;
static uint64_t g_reads;

int digital_in_prepare(void)
{
    g_configured = digital_in_backend_configure_fixed_bank();
    return g_configured;
}

int digital_in_read_once(uint32_t *logical_bank)
{
    uint32_t value = 0;
    g_reads++;
    if (!logical_bank || !g_configured
        || !digital_in_backend_read_fixed_bank(&value) || value > 31u) {
        if (logical_bank) *logical_bank = 0;
        return 0;
    }
    *logical_bank = value;
    return 1;
}

uint64_t digital_in_read_count(void) { return g_reads; }

#ifdef DIGITAL_IN_FAKE
int digital_in_test_set_logical_bank(uint32_t logical_bank)
{
    return digital_in_backend_fake_set_logical_bank(logical_bank);
}

void digital_in_test_fail_read_at(uint64_t ordinal)
{
    digital_in_backend_fake_fail_read_at(ordinal);
}

uint64_t digital_in_fake_selftest(void)
{
    uint64_t failures = 0;
    uint32_t bank = 0;
    digital_in_backend_fake_reset();
    g_reads = 0;
    if (!digital_in_prepare()) failures++;
    for (uint32_t value = 0; value < 32; value++) {
        if (!digital_in_test_set_logical_bank(value)
            || !digital_in_read_once(&bank) || bank != value)
            failures++;
    }
    if (g_reads != 32 || digital_in_backend_fake_reads() != 32) failures++;
    digital_in_backend_fake_fail_read_at(33);
    if (digital_in_read_once(&bank) || bank != 0) failures++;
    if (digital_in_test_set_logical_bank(32)) failures++;
    return failures;
}
#endif
