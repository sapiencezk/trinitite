#include <stdint.h>
#include "i2_admission_metrics.h"
#include "i2_admission_envelope.h"

extern uint8_t __bss_start[];
extern uint8_t __bss_end[];

i2_admission_metrics_t g_i2_admission_metrics;

void i2_admission_metrics_init(void)
{
    g_i2_admission_metrics.schema = I2_ADMISSION_METRICS_SCHEMA;
    g_i2_admission_metrics.bss_used_bytes =
        (uint64_t)(uintptr_t)__bss_end - (uint64_t)(uintptr_t)__bss_start;
    g_i2_admission_metrics.bss_reserved_bytes = I2_BSS_RESERVED_BYTES;
    g_i2_admission_metrics.bss_admitted_bytes = I2_BSS_ADMITTED_BYTES;
}

void i2_admission_metrics_max(uint64_t *field, uint64_t value)
{
    if (value > *field)
        *field = value;
}
