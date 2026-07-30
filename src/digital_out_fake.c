#include <stdint.h>
#include "digital_out.h"
#include "digital_out_backend.h"

static uint32_t g_level;
static uint64_t g_operations;
static uint64_t g_fail_at;

static int operation(void)
{
    g_operations++;
    return g_fail_at == 0 || g_operations != g_fail_at;
}

static uint32_t gpio_mask_from_bank(uint32_t bank)
{
    return ((bank & 1u) << DIGITAL_OUT_GPIO_P1)
        | (((bank >> 1) & 1u) << DIGITAL_OUT_GPIO_P2)
        | (((bank >> 2) & 1u) << DIGITAL_OUT_GPIO_ALARM);
}

int digital_out_backend_configure_fixed_bank(void)
{
    return operation();
}

int digital_out_backend_clear_fixed_bank(void)
{
    int ok = operation();
    if (ok)
        g_level &= ~DIGITAL_OUT_GPIO_MASK;
    return ok;
}

int digital_out_backend_set_fixed_bank(uint32_t bank)
{
    int ok = operation();
    if (!ok || bank > 7u)
        return 0;
    g_level |= gpio_mask_from_bank(bank);
    return 1;
}

uint32_t digital_out_backend_level(void)
{
    return g_level;
}

void digital_out_backend_fake_reset(void)
{
    g_level = 0;
    g_operations = 0;
    g_fail_at = 0;
}

void digital_out_backend_fake_fail_at(uint64_t operation_at)
{
    g_fail_at = operation_at;
}

uint64_t digital_out_backend_fake_operations(void)
{
    return g_operations;
}
