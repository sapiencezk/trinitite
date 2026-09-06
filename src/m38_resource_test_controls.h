#pragma once

#include "m38_resource_runtime.h"

/* Wave B-only test controls.  This header is intentionally unavailable to a
 * normal Wave A/public-ABI compile unless M38_D8_WAVE_B_TEST_CONTROLS is set. */
typedef enum M38FaultPoint {
    M38_FAULT_NONE = 0,
    M38_FAULT_BROKER_BEGIN,
    M38_FAULT_CUE_CACHE_INSERT,
    M38_FAULT_SLOT_PUBLICATION,
    M38_FAULT_EVALUATOR_ABORT,
    M38_FAULT_ATOM_RESULT_STAGING,
    M38_FAULT_COLLECTIVE_COMMIT,
    M38_FAULT_RESTORE_COMMIT,
} M38FaultPoint;

void m38_resource_test_fail_next(ResourceRuntime *runtime,
                                 M38FaultPoint fault);
