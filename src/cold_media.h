#pragma once

#include <stdint.h>

/*
 * Milestone 3 target-private cold media contract.
 *
 * Physical target: Raspberry Pi 4B, BCM2711 EMMC2, external SDHC/SDXC,
 * AArch64 PIO, 512-byte sectors.  This is deliberately not a block layer.
 */
#define COLD_MEDIA_SECTOR_BYTES 512u
#define COLD_MEDIA_LAYOUT_VERSION 1u
#define COLD_MEDIA_EXTENT_SECTORS 16386u

#ifndef COLD_MEDIA_START_LBA
#define COLD_MEDIA_START_LBA 1048576ULL
#endif

typedef enum {
    COLD_MEDIA_PHASE_NONE = 0,
    COLD_MEDIA_PHASE_PROBE,
    COLD_MEDIA_PHASE_LAYOUT,
    COLD_MEDIA_PHASE_BOOT_LOAD,
    COLD_MEDIA_PHASE_FORMAT,
    COLD_MEDIA_PHASE_OBJECT_HEADER,
    COLD_MEDIA_PHASE_PAYLOAD,
    COLD_MEDIA_PHASE_OBJECT_COMMIT,
    COLD_MEDIA_PHASE_DATA_BARRIER,
    COLD_MEDIA_PHASE_SUPERBLOCK,
    COLD_MEDIA_PHASE_SUPERBLOCK_BARRIER
} cold_media_phase_t;

typedef enum {
    COLD_MEDIA_OK = 0,
    COLD_MEDIA_DISABLED = 1,
    COLD_MEDIA_ABSENT = -1,
    COLD_MEDIA_READ_ONLY = -2,
    COLD_MEDIA_UNDERSIZED = -3,
    COLD_MEDIA_LAYOUT = -4,
    COLD_MEDIA_RANGE = -5,
    COLD_MEDIA_BUSY = -6,
    COLD_MEDIA_TIMEOUT = -7,
    COLD_MEDIA_COMMAND_CRC = -8,
    COLD_MEDIA_DATA_CRC = -9,
    COLD_MEDIA_READ_FAILURE = -10,
    COLD_MEDIA_WRITE_UNKNOWN = -11,
    COLD_MEDIA_BARRIER_FAILURE = -12,
    COLD_MEDIA_REMOVED = -13,
    COLD_MEDIA_RESET_REQUIRED = -14,
    COLD_MEDIA_UNSUPPORTED = -15
} cold_media_status_t;

typedef struct {
    uint64_t phase;
    int64_t status;
    uint64_t logical_offset;
    uint64_t physical_lba;
    uint64_t completed_sectors;
    uint64_t mutation_submitted;
} cold_media_diag_t;

cold_media_status_t cold_media_load_window(uint64_t deadline_tick);
cold_media_status_t cold_media_read(cold_media_phase_t phase,
                                    uint64_t logical_off, void *dst,
                                    uint64_t len, uint64_t deadline_tick);
cold_media_status_t cold_media_write(cold_media_phase_t phase,
                                     uint64_t logical_off, const void *src,
                                     uint64_t len, uint64_t deadline_tick);
cold_media_status_t cold_media_barrier(cold_media_phase_t phase,
                                       uint64_t deadline_tick);
int cold_media_active(void);
const cold_media_diag_t *cold_media_last_diag(void);
void cold_media_reset_session(void);

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
    COLD_MEDIA_FAKE_RESET
} cold_media_fake_fault_t;

void cold_media_fake_fault_set(cold_media_fake_fault_t fault,
                               uint64_t transfer_boundary);
void cold_media_fake_fault_clear(void);

/* Returns zero for non-fake builds and on a passing fake build. */
uint64_t cold_media_fake_selftest(void);
