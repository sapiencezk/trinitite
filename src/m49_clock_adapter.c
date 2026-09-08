#include "m49_clock_adapter.h"
#include <stddef.h>
#include <limits.h>

static int identity(uint64_t epoch, uint64_t generation) {
    return epoch != 0 && generation != 0 && generation <= INT64_MAX;
}
int m49_clock_prepare_arm(uint64_t epoch, uint64_t generation,
    uint64_t now_ms, uint32_t duration_ms, uint64_t turn, M49ClockArm *candidate) {
    if (candidate == NULL || !identity(epoch,generation)
        || now_ms > UINT64_MAX - duration_ms || turn == UINT64_MAX) return 0;
    *candidate = (M49ClockArm){now_ms + duration_ms,turn + 1};
    return 1;
}
int m49_clock_milliseconds(uint64_t ticks, uint64_t frequency, uint64_t *out) {
    if (!out || !frequency || frequency > UINT64_MAX/1000u) return 0;
    uint64_t seconds=ticks/frequency;
    if (seconds > UINT64_MAX/1000u) return 0;
    uint64_t whole=seconds*1000u;
    uint64_t fraction=((ticks%frequency)*1000u)/frequency;
    if (whole > UINT64_MAX-fraction) return 0;
    *out=whole+fraction; return 1;
}
