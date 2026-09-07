#pragma once

#include "m38_resource_runtime.h"

/* Wave B-only test controls.  The fault vocabulary remains available to
 * source that needs to describe test points, but the setter declaration is
 * exposed only by a build that explicitly defines the Wave B control flag. */
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

#if defined(M38_D8_WAVE_B_TEST_CONTROLS)
void m38_resource_test_fail_next(ResourceRuntime *runtime,
                                 M38FaultPoint fault);
#endif

#if defined(M38_D8_WAVE_B_B2)
/* B2-only state preparation and busy-detection controls.  These mutate no
 * production state outside the qualification image and are not part of the
 * public runtime header. */
void m38_resource_test_invalidate_cache(ResourceSession *session,
                                        uint32_t catalog_index);
void m38_resource_test_hold_runtime_busy(ResourceRuntime *runtime);
void m38_resource_test_hold_session_busy(ResourceSession *session);
void m38_resource_test_release_busy(ResourceRuntime *runtime,
                                    ResourceSession *session);
#endif
