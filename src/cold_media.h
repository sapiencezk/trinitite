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
    COLD_MEDIA_PHASE_SUPERBLOCK_BARRIER,
    /* Bounded read-after-write validation before TRI_DEPLOY can report
     * COLD_DEPLOY_COMMITTED. */
    COLD_MEDIA_PHASE_DEPLOY_VERIFY
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

#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0 \
    && defined(I3_LITE_LOG) && (defined(COLD_MEDIA_RPI4_SD) || defined(COLD_MEDIA_FAKE))
/* Row 212 PR 1c recorder ring (src/i3_ring.c) on sector media: rpi4-sd, and
 * the fake backend for the fault tests (tests/recorder_ring.py fault legs).
 *
 * Layout. The ring has its own extent, I3_RING_BYTES / 512 sectors from
 * COLD_MEDIA_RING_START_LBA, after the cold extent (descriptor sector plus
 * COLD_MEDIA_EXTENT_SECTORS). The two extents may not overlap (checked
 * here at build time) and the medium must hold the whole ring extent
 * (checked at the first ring access; if not, the ring stays off and the cold
 * store is unaffected). The on-media layout descriptor does not name the
 * ring extent: that would need a new descriptor version (deferred). Instead
 * the ring formats only an extent that is all zero or holds a whole header of
 * its own for another ring size (src/i3_ring.c); anything else is refused.
 * GAP (Steward's ruling): an all-zero range that belongs to another partition
 * is still formatted. No rpi4-sd image with I3_LITE_LOG on is deployed until a
 * layout descriptor version names the ring (docs/lite-checkpoint-writer.md).
 *
 * Session. Ring I/O shares the backend and its owner lock with the cold
 * store, but not its reset rule: a ring fault marks only the ring as needing
 * a reset (the ring stays off until the next boot). It never sets the cold
 * session's reset-required state, so a ring fault cannot stop the cold log.
 * If the controller itself fails, the cold store's own next transfer fails
 * and the cold rules apply as before.
 *
 * Deadlines. Every chunk of COLD_MEDIA_RING_CHUNK_SECTORS sectors gets its
 * own 5 s deadline, and the boot load stops after COLD_MEDIA_RING_LOAD_SECONDS
 * in total (then the ring stays off for that boot). The ring's RAM window is
 * the source of every write: each touched sector is written whole from it (no
 * read-modify-write). Not measured on the board. */
#ifndef COLD_MEDIA_RING_START_LBA
#define COLD_MEDIA_RING_START_LBA (COLD_MEDIA_START_LBA + 32768ULL)
#endif
#ifndef I3_RING_BYTES
#define I3_RING_BYTES 67108864ULL
#endif
#define COLD_MEDIA_RING_SECTORS ((uint64_t)(I3_RING_BYTES) / COLD_MEDIA_SECTOR_BYTES)
#define COLD_MEDIA_RING_CHUNK_SECTORS 512u
#ifndef COLD_MEDIA_RING_LOAD_SECONDS
#define COLD_MEDIA_RING_LOAD_SECONDS 60u
#endif
#define COLD_MEDIA_RING 1
_Static_assert(COLD_MEDIA_RING_START_LBA
                   >= COLD_MEDIA_START_LBA + 1 + COLD_MEDIA_EXTENT_SECTORS,
               "ring extent overlaps the cold extent");
_Static_assert(COLD_MEDIA_RING_START_LBA + COLD_MEDIA_RING_SECTORS
                   > COLD_MEDIA_RING_START_LBA,
               "ring extent wraps the LBA space");
cold_media_status_t cold_media_ring_load(uint8_t *window, uint64_t bytes);
cold_media_status_t cold_media_ring_write(const uint8_t *window, uint64_t off,
                                          uint64_t len);
cold_media_status_t cold_media_ring_barrier(void);
#endif
