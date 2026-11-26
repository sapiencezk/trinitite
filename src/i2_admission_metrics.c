#include <stdint.h>
#include "i2_admission_metrics.h"

i2_admission_metrics_t g_i2_admission_metrics;

void i2_admission_metrics_max(uint64_t *field, uint64_t value)
{
    if (value > *field)
        *field = value;
}
