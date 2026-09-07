#pragma once

#include <stdint.h>

/* Internal M38 numeric profile adapter.  The public ResourceRuntime API does
 * not expose labels, formulas, or admission policy. Forward sessions derive
 * and own these fields from the caller's checked admission record and core.
 * The static lookup below is retained for historical witnesses only. */
#define M38_RESOURCE_CORE_COUNT 2u

typedef struct M38ResourceCoreDescriptor {
    uint8_t core_id[32];
    uint8_t battery_id[32];
    uint8_t payload_id[32];
    uint8_t admission_id[32];
    const char *profile_id;
} M38ResourceCoreDescriptor;

/* Returns the immutable descriptor for an exact 32-byte core identity, or
 * NULL when the identity is outside the finite catalog. */
const M38ResourceCoreDescriptor *m38_resource_core_descriptor(
    const uint8_t core_id[32]);
