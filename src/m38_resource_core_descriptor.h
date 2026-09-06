#pragma once

#include <stdint.h>

/* Internal M38 numeric profile adapter.  The public ResourceRuntime API does
 * not expose labels, formulas, or admission policy. */
#define M38_RESOURCE_CORE_COUNT 2u

typedef struct M38ResourceCoreDescriptor {
    const uint8_t *core_id;
    const uint8_t *battery_id;
    const uint8_t *payload_id;
    const uint8_t *admission_id;
    const char *profile_id;
    uint32_t admission_index;
} M38ResourceCoreDescriptor;

extern const uint8_t m38_resource_core_ids[M38_RESOURCE_CORE_COUNT][32];
extern const uint8_t m38_resource_battery_ids[M38_RESOURCE_CORE_COUNT][32];
extern const uint8_t m38_resource_payload_ids[M38_RESOURCE_CORE_COUNT][32];
extern const uint8_t m38_resource_admission_ids[M38_RESOURCE_CORE_COUNT][32];

const M38ResourceCoreDescriptor *m38_resource_core_descriptor(uint32_t index);
int m38_resource_core_admitted(uint32_t index);
