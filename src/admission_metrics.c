#include <stdint.h>
#include "admission_metrics.h"

admission_metrics_t g_admission_metrics;

void admission_metrics_max(uint64_t *field, uint64_t value)
{
    if (value > *field)
        *field = value;
}
