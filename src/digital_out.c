#include <stdint.h>
#include "digital_out.h"

#define BCM2838_GPIO_BASE 0xFE200000ULL
#define GPCLR0   0x28u

#define DIGITAL_OUT_GPIO_P1       17u
#define DIGITAL_OUT_GPIO_P2       27u
#define DIGITAL_OUT_GPIO_ALARM    22u
#define DIGITAL_OUT_GPIO_MASK \
    ((1u << DIGITAL_OUT_GPIO_P1) | (1u << DIGITAL_OUT_GPIO_P2) | \
     (1u << DIGITAL_OUT_GPIO_ALARM))

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

static void configure_output(uint32_t pin)
{
    uint32_t offset = (pin / 10u) * 4u;
    uint32_t shift = (pin % 10u) * 3u;
    uint32_t value = read32(offset);
    value &= ~(7u << shift);
    value |= 1u << shift;
    write32(offset, value);
}

void digital_out_boot_safe(void)
{
    configure_output(DIGITAL_OUT_GPIO_P1);
    configure_output(DIGITAL_OUT_GPIO_P2);
    configure_output(DIGITAL_OUT_GPIO_ALARM);
    write32(GPCLR0, DIGITAL_OUT_GPIO_MASK);
}
