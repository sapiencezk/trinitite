#pragma once

#include <stdint.h>

#include "m26_plan_record.h"
#include "runtime_identity.h"

/* One immutable M34-R local projection selected at image compile time.
 * It contains no successor program, package, binding, source, PILL, or
 * application behavior identity. */
typedef struct {
    uint64_t device_id;
    uint64_t resource_id;
    uint64_t slot;
    uint64_t predecessor_generation;
    uint8_t predecessor_program[32];
    uint8_t predecessor_anchor[32];
    const m26_plan_record_t *transport_plan;
} m34_local_allocation_t;

const m34_local_allocation_t *m34_local_allocation(void);
int m34_local_allocation_matches(uint64_t device_id, uint64_t resource_id,
                                 uint64_t slot);
int m34_local_allocation_predecessor_matches(
    const runtime_identity_t *identity);
