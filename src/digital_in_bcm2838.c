#include <stdint.h>
#include "digital_in_backend.h"

#define BCM2838_GPIO_BASE 0xFE200000ULL
#define GPLEV0 0x34u

static volatile uint32_t *reg32(uint32_t offset)
{
    return (volatile uint32_t *)(uintptr_t)(BCM2838_GPIO_BASE + offset);
}

static uint32_t read32(uint32_t offset)
{
    __asm__ volatile("dsb sy" ::: "memory");
    return *reg32(offset);
}

static void write32(uint32_t offset, uint32_t value)
{
    *reg32(offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static void configure_input(uint32_t pin)
{
    uint32_t offset = (pin / 10u) * 4u;
    uint32_t shift = (pin % 10u) * 3u;
    uint32_t value = read32(offset);
    value &= ~(7u << shift);
    write32(offset, value);
}

int digital_in_backend_configure_fixed_bank(void)
{
    configure_input(5u);
    configure_input(6u);
    configure_input(13u);
    configure_input(19u);
    configure_input(26u);
    return 1;
}

int digital_in_backend_read_fixed_bank(uint32_t *logical_bank)
{
    if (!logical_bank) return 0;
    /* The production request path performs exactly this one GPLEV0 read. */
    uint32_t level = read32(GPLEV0);
    *logical_bank = ((level >> 5) & 1u)
        | (((level >> 6) & 1u) << 1)
        | (((level >> 13) & 1u) << 2)
        | (((level >> 19) & 1u) << 3)
        | (((level >> 26) & 1u) << 4);
    return 1;
}
