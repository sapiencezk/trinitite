#include "digital_in_backend.h"

static uint32_t g_bank;
static int g_configure_fail;
static uint64_t g_fail_read_at;
static uint64_t g_reads;

int digital_in_backend_configure_fixed_bank(void)
{
    return !g_configure_fail;
}

int digital_in_backend_read_fixed_bank(uint32_t *logical_bank)
{
    g_reads++;
    if (!logical_bank || (g_fail_read_at && g_reads == g_fail_read_at))
        return 0;
    *logical_bank = g_bank;
    return 1;
}

int digital_in_backend_fake_set_logical_bank(uint32_t logical_bank)
{
    if (logical_bank > 31u) return 0;
    g_bank = logical_bank;
    return 1;
}

void digital_in_backend_fake_reset(void)
{
    g_bank = 0;
    g_configure_fail = 0;
    g_fail_read_at = 0;
    g_reads = 0;
}

void digital_in_backend_fake_fail_configure(int fail) { g_configure_fail = !!fail; }
void digital_in_backend_fake_fail_read_at(uint64_t ordinal) { g_fail_read_at = ordinal; }
uint64_t digital_in_backend_fake_reads(void) { return g_reads; }
