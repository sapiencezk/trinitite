#ifndef M49_CLOCK_ADAPTER_H
#define M49_CLOCK_ADAPTER_H
#include <stdint.h>
/* Pure arithmetic preflight for the supervisor's single timer ledger.
 * M44State.timer owns arm/cancel/queued expiry; no second mutable clock state
 * exists here. This temporary candidate supplies checked deadline/turn fields
 * to transaction preparation. IEC START/STOP/EO remains canonical Nock. */
typedef struct {
    uint64_t deadline_ms, not_before_turn;
} M49ClockArm;
/* Build checked time bounds without owning or mutating a timer. Occupancy
 * and publication belong exclusively to M44State.timer in the supervisor. */
int m49_clock_prepare_arm(uint64_t epoch, uint64_t generation,
    uint64_t now_ms, uint32_t duration_ms, uint64_t turn, M49ClockArm *candidate);
/* Convert one monotonic counter sample without wrap; refusal preserves out. */
int m49_clock_milliseconds(uint64_t ticks, uint64_t frequency, uint64_t *out);
#endif
