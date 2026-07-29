#include <stdint.h>
#include "blake3.h"
#include "cold_media.h"
#include "memory.h"

#define DESC_MAGIC 0x31444D433249ULL
#define FAKE_SECTORS (COLD_MEDIA_EXTENT_SECTORS + 2u)

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint32_t version;
    uint32_t header_len;
    uint64_t start_lba;
    uint64_t extent_sectors;
    uint64_t logical_bytes;
    uint32_t sector_bytes;
    uint32_t flags;
    uint8_t checksum[32];
    uint8_t reserved[COLD_MEDIA_SECTOR_BYTES - 80];
} fake_descriptor_t;

static uint8_t g_fake[FAKE_SECTORS][COLD_MEDIA_SECTOR_BYTES];
static int g_fake_initialized;
static int g_fake_removed;
static cold_media_fake_fault_t g_fault;
static uint64_t g_fault_boundary;
static uint64_t g_transfer;

static uint8_t *fake_sector(uint64_t lba)
{
    if (lba < COLD_MEDIA_START_LBA - 1
        || lba > COLD_MEDIA_START_LBA + COLD_MEDIA_EXTENT_SECTORS)
        return 0;
    return g_fake[lba - (COLD_MEDIA_START_LBA - 1)];
}

static void initialize_fake(void)
{
    if (g_fake_initialized)
        return;
    g_fake_initialized = 1;
    for (uint64_t s = 0; s < FAKE_SECTORS; s++)
        for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
            g_fake[s][i] = 0;
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++) {
        g_fake[0][i] = 0xa5;
        g_fake[FAKE_SECTORS - 1][i] = 0x5a;
    }
    fake_descriptor_t *d =
        (fake_descriptor_t *)(void *)fake_sector(COLD_MEDIA_START_LBA);
    d->magic = DESC_MAGIC;
    d->version = COLD_MEDIA_LAYOUT_VERSION;
    d->header_len = 80;
    d->start_lba = COLD_MEDIA_START_LBA;
    d->extent_sectors = COLD_MEDIA_EXTENT_SECTORS;
    d->logical_bytes = COLD_SIZE;
    d->sector_bytes = COLD_MEDIA_SECTOR_BYTES;
    d->flags = 0;
    blake3_hash((const uint8_t *)d, 48, d->checksum);
}

static void restore_blank_media(void)
{
    initialize_fake();
    for (uint64_t s = 2; s + 1 < FAKE_SECTORS; s++)
        for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
            g_fake[s][i] = 0;
    cold_media_fake_fault_clear();
}

static int boundary(void)
{
    g_transfer++;
    return g_fault != COLD_MEDIA_FAKE_NONE
        && g_transfer == g_fault_boundary;
}

cold_media_status_t cold_media_fake_probe(
    uint64_t *capacity, int *read_only, uint64_t deadline)
{
    (void)deadline;
    initialize_fake();
    if (g_fault == COLD_MEDIA_FAKE_ABSENT || g_fake_removed)
        return COLD_MEDIA_ABSENT;
    *capacity = COLD_MEDIA_START_LBA + COLD_MEDIA_EXTENT_SECTORS;
    if (g_fault == COLD_MEDIA_FAKE_UNDERSIZED)
        *capacity = COLD_MEDIA_START_LBA + 1;
    *read_only = g_fault == COLD_MEDIA_FAKE_READ_ONLY;
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_fake_sector_read(
    uint64_t lba, uint8_t *dst, uint64_t deadline)
{
    (void)deadline;
    uint8_t *src = fake_sector(lba);
    if (!src || g_fake_removed)
        return COLD_MEDIA_REMOVED;
    if (boundary()) {
        if (g_fault == COLD_MEDIA_FAKE_TIMEOUT
            || g_fault == COLD_MEDIA_FAKE_RESET)
            return COLD_MEDIA_TIMEOUT;
        if (g_fault == COLD_MEDIA_FAKE_COMMAND_CRC)
            return COLD_MEDIA_COMMAND_CRC;
        if (g_fault == COLD_MEDIA_FAKE_DATA_CRC)
            return COLD_MEDIA_DATA_CRC;
        if (g_fault == COLD_MEDIA_FAKE_READ_FAILURE)
            return COLD_MEDIA_READ_FAILURE;
        if (g_fault == COLD_MEDIA_FAKE_REMOVAL) {
            g_fake_removed = 1;
            return COLD_MEDIA_REMOVED;
        }
    }
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
        dst[i] = src[i];
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_fake_sector_write(
    uint64_t lba, const uint8_t *src, uint64_t deadline, int *submitted)
{
    (void)deadline;
    uint8_t *dst = fake_sector(lba);
    *submitted = 0;
    if (!dst || g_fake_removed)
        return COLD_MEDIA_REMOVED;
    if (g_fault == COLD_MEDIA_FAKE_READ_ONLY)
        return COLD_MEDIA_READ_ONLY;
    int fire = boundary();
    if (fire && (g_fault == COLD_MEDIA_FAKE_TIMEOUT
                 || g_fault == COLD_MEDIA_FAKE_COMMAND_CRC
                 || g_fault == COLD_MEDIA_FAKE_RESET))
        return g_fault == COLD_MEDIA_FAKE_COMMAND_CRC
            ? COLD_MEDIA_COMMAND_CRC : COLD_MEDIA_TIMEOUT;
    *submitted = 1;
    uint64_t n = COLD_MEDIA_SECTOR_BYTES;
    if (fire && g_fault == COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE)
        n /= 2;
    for (uint64_t i = 0; i < n; i++)
        dst[i] = src[i];
    if (fire && g_fault == COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE)
        return COLD_MEDIA_WRITE_UNKNOWN;
    if (fire && g_fault == COLD_MEDIA_FAKE_REMOVAL) {
        g_fake_removed = 1;
        return COLD_MEDIA_REMOVED;
    }
    if (fire && g_fault == COLD_MEDIA_FAKE_BIT_FLIP)
        dst[COLD_MEDIA_SECTOR_BYTES / 2] ^= 1;
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_fake_barrier(uint64_t deadline)
{
    (void)deadline;
    if (g_fake_removed)
        return COLD_MEDIA_REMOVED;
    if (boundary() && g_fault == COLD_MEDIA_FAKE_BARRIER_FAILURE)
        return COLD_MEDIA_BARRIER_FAILURE;
    return COLD_MEDIA_OK;
}

void cold_media_fake_fault_set(cold_media_fake_fault_t fault,
                               uint64_t transfer_boundary)
{
    g_fault = fault;
    g_fault_boundary = transfer_boundary ? transfer_boundary : 1;
    g_transfer = 0;
    g_fake_removed = 0;
    cold_media_reset_session();
}

void cold_media_fake_fault_clear(void)
{
    g_fault = COLD_MEDIA_FAKE_NONE;
    g_fault_boundary = 0;
    g_transfer = 0;
    g_fake_removed = 0;
    cold_media_reset_session();
}

uint64_t cold_media_fake_selftest(void)
{
    uint64_t failures = 0;
    initialize_fake();
    cold_media_fake_fault_clear();

    uint8_t a[128], b[128], readback[128];
    for (unsigned i = 0; i < sizeof a; i++) {
        a[i] = (uint8_t)(i ^ 0x5a);
        b[i] = (uint8_t)(i ^ 0xa5);
    }
    if (cold_media_write(COLD_MEDIA_PHASE_SUPERBLOCK, 0, a, sizeof a, 0)
            != COLD_MEDIA_OK
        || cold_media_write(COLD_MEDIA_PHASE_SUPERBLOCK, 256, b, sizeof b, 0)
            != COLD_MEDIA_OK
        || cold_media_read(COLD_MEDIA_PHASE_LAYOUT, 0, readback,
                           sizeof readback, 0) != COLD_MEDIA_OK)
        failures++;
    for (unsigned i = 0; i < sizeof a; i++)
        if (readback[i] != a[i])
            failures++;
    if (fake_sector(COLD_MEDIA_START_LBA + 1)[0] ==
        fake_sector(COLD_MEDIA_START_LBA + 2)[0])
        failures++;
    if (cold_media_read(COLD_MEDIA_PHASE_LAYOUT, COLD_SIZE,
                        readback, 1, 0) != COLD_MEDIA_RANGE)
        failures++;
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++) {
        if (g_fake[0][i] != 0xa5
            || g_fake[FAKE_SECTORS - 1][i] != 0x5a)
            failures++;
    }

    cold_media_fake_fault_set(COLD_MEDIA_FAKE_ABSENT, 1);
    if (cold_media_load_window(0) != COLD_MEDIA_ABSENT)
        failures++;
    cold_media_fake_fault_set(COLD_MEDIA_FAKE_UNDERSIZED, 1);
    if (cold_media_load_window(0) != COLD_MEDIA_UNDERSIZED)
        failures++;
    cold_media_fake_fault_set(COLD_MEDIA_FAKE_READ_ONLY, 1);
    if (cold_media_load_window(0) != COLD_MEDIA_OK
        || cold_media_write(COLD_MEDIA_PHASE_PAYLOAD, 512, a,
                            sizeof a, 0) != COLD_MEDIA_READ_ONLY)
        failures++;
    cold_media_fake_fault_set(
        COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE,
        COLD_MEDIA_EXTENT_SECTORS + 2);
    if (cold_media_load_window(0) != COLD_MEDIA_OK
        || cold_media_write(COLD_MEDIA_PHASE_PAYLOAD, 512, a,
                            sizeof a, 0) != COLD_MEDIA_WRITE_UNKNOWN
        || cold_media_write(COLD_MEDIA_PHASE_PAYLOAD, 512, a,
                            sizeof a, 0) != COLD_MEDIA_RESET_REQUIRED)
        failures++;
    restore_blank_media();
    return failures;
}
