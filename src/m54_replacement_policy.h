#ifndef M54_REPLACEMENT_POLICY_H
#define M54_REPLACEMENT_POLICY_H
#include <stdint.h>
/* Shared M54/M56 source-selected assignment; all ordinals are one-based.
 * The retained name is an internal ABI, not an unsigned-only authority.
 * Each explicit caller separately fixes the value type. This record is not
 * an executable expression or a general migration description. */
typedef struct M54Policy {
    uint32_t slot, instance, type, algorithm, assignment, target, reference, failure;
} M54Policy;
#endif
