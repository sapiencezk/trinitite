#ifndef COLD_MEDIA_FAKE_TEST_H
#define COLD_MEDIA_FAKE_TEST_H

#include <stdint.h>

typedef enum {
    COLD_MEDIA_FAKE_NONE = 0,
    COLD_MEDIA_FAKE_ABSENT,
    COLD_MEDIA_FAKE_READ_ONLY,
    COLD_MEDIA_FAKE_UNDERSIZED,
    COLD_MEDIA_FAKE_TIMEOUT,
    COLD_MEDIA_FAKE_COMMAND_CRC,
    COLD_MEDIA_FAKE_DATA_CRC,
    COLD_MEDIA_FAKE_READ_FAILURE,
    COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE,
    COLD_MEDIA_FAKE_BARRIER_FAILURE,
    COLD_MEDIA_FAKE_REMOVAL,
    COLD_MEDIA_FAKE_BIT_FLIP,
    /* A reset reported as a timeout; this fake does not model controller
     * state loss or recovery. */
    COLD_MEDIA_FAKE_RESET_TIMEOUT
} cold_media_fake_fault_t;

void cold_media_fake_fault_set(cold_media_fake_fault_t fault,
                               uint64_t transfer_boundary);
void cold_media_fake_fault_clear(void);
uint64_t cold_media_fake_smoketest(void);
uint64_t cold_media_fake_selftest(void);

#endif
