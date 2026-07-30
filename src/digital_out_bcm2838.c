#include <stdint.h>
#include "digital_out.h"
#include "digital_out_backend.h"

#define BCM2838_GPIO_BASE 0xFE200000ULL
#define GPFSEL1  0x04u
#define GPFSEL2  0x08u
#define GPSET0   0x1cu
#define GPCLR0   0x28u
#define GPLEV0   0x34u

static volatile uint32_t *reg32(uint32_t offset)
{
    return (volatile uint32_t *)(uintptr_t)(BCM2838_GPIO_BASE + offset);
}

static void write32(uint32_t offset, uint32_t value)
{
    *reg32(offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static uint32_t read32(uint32_t offset)
{
    __asm__ volatile("dsb sy" ::: "memory");
    return *reg32(offset);
}

static uint32_t gpio_mask_from_bank(uint32_t bank)
{
    return ((bank & 1u) << DIGITAL_OUT_GPIO_P1)
        | (((bank >> 1) & 1u) << DIGITAL_OUT_GPIO_P2)
        | (((bank >> 2) & 1u) << DIGITAL_OUT_GPIO_ALARM);
}

static void configure_output(uint32_t pin)
{
    uint32_t offset = (pin / 10u) * 4u;
    uint32_t shift = (pin % 10u) * 3u;
    uint32_t value = read32(offset);
    value &= ~(7u << shift);
    value |= 1u << shift;
    write32(offset, value);
}

int digital_out_backend_configure_fixed_bank(void)
{
    configure_output(DIGITAL_OUT_GPIO_P1);
    configure_output(DIGITAL_OUT_GPIO_P2);
    configure_output(DIGITAL_OUT_GPIO_ALARM);
    return 1;
}

int digital_out_backend_clear_fixed_bank(void)
{
    write32(GPCLR0, DIGITAL_OUT_GPIO_MASK);
    return 1;
}

int digital_out_backend_set_fixed_bank(uint32_t bank)
{
    if (bank > 7u)
        return 0;
    write32(GPSET0, gpio_mask_from_bank(bank));
    return 1;
}

uint32_t digital_out_backend_level(void)
{
    return read32(GPLEV0);
}
