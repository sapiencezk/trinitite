#ifndef M54_REPLACEMENT_POLICY_H
#define M54_REPLACEMENT_POLICY_H
#include <stdint.h>
/* One source-selected assignment; all ordinals are one-based. This is not
 * an executable expression or a general migration description. */
typedef struct M54Policy {
    uint32_t slot, instance, type, algorithm, assignment, target, reference, failure;
} M54Policy;
#endif
