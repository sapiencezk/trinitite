#include <stdint.h>
#include "blake3.h"
#include "cold.h"
#include "cold_media.h"
#include "cold_media_fake_test.h"
#include "memory.h"
#include "noun.h"

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
static uint64_t g_bit_flip_byte = COLD_MEDIA_SECTOR_BYTES / 2;
static uint64_t g_transfer;
static int g_fault_effect_fired;

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

static int boundary(void)
{
    g_transfer++;
    return g_fault != COLD_MEDIA_FAKE_NONE
        && g_transfer == g_fault_boundary;
}

static void fault_effect(void)
{
    g_fault_effect_fired = 1;
}

cold_media_status_t cold_media_fake_probe(
    uint64_t *capacity, int *read_only, uint64_t deadline)
{
    (void)deadline;
    initialize_fake();
    if (g_fault == COLD_MEDIA_FAKE_ABSENT || g_fake_removed)
        return COLD_MEDIA_ABSENT;
    *capacity = COLD_MEDIA_START_LBA + COLD_MEDIA_EXTENT_SECTORS;
#if defined(COLD_MEDIA_RING)
    *capacity = COLD_MEDIA_RING_START_LBA + COLD_MEDIA_RING_SECTORS;
#endif
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
            || g_fault == COLD_MEDIA_FAKE_RESET_TIMEOUT) {
            fault_effect();
            return COLD_MEDIA_TIMEOUT;
        }
        if (g_fault == COLD_MEDIA_FAKE_COMMAND_CRC) {
            fault_effect();
            return COLD_MEDIA_COMMAND_CRC;
        }
        if (g_fault == COLD_MEDIA_FAKE_DATA_CRC) {
            fault_effect();
            return COLD_MEDIA_DATA_CRC;
        }
        if (g_fault == COLD_MEDIA_FAKE_READ_FAILURE
            || g_fault == COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE
            || g_fault == COLD_MEDIA_FAKE_BARRIER_FAILURE) {
            fault_effect();
            return COLD_MEDIA_READ_FAILURE;
        }
        if (g_fault == COLD_MEDIA_FAKE_REMOVAL) {
            fault_effect();
            g_fake_removed = 1;
            return COLD_MEDIA_REMOVED;
        }
    }
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
        dst[i] = src[i];
    if (g_fault == COLD_MEDIA_FAKE_BIT_FLIP
        && g_transfer == g_fault_boundary) {
        fault_effect();
        dst[g_bit_flip_byte] ^= 1;
    }
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
                 || g_fault == COLD_MEDIA_FAKE_READ_FAILURE
                 || g_fault == COLD_MEDIA_FAKE_BARRIER_FAILURE
                 || g_fault == COLD_MEDIA_FAKE_RESET_TIMEOUT)) {
        fault_effect();
        if (g_fault == COLD_MEDIA_FAKE_COMMAND_CRC)
            return COLD_MEDIA_COMMAND_CRC;
        if (g_fault == COLD_MEDIA_FAKE_READ_FAILURE
            || g_fault == COLD_MEDIA_FAKE_BARRIER_FAILURE)
            return COLD_MEDIA_READ_FAILURE;
        return COLD_MEDIA_TIMEOUT;
    }
    *submitted = 1;
    uint64_t n = COLD_MEDIA_SECTOR_BYTES;
    if (fire && (g_fault == COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE
                 || g_fault == COLD_MEDIA_FAKE_DATA_CRC))
        n /= 2;
    for (uint64_t i = 0; i < n; i++)
        dst[i] = src[i];
    if (fire && (g_fault == COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE
                 || g_fault == COLD_MEDIA_FAKE_DATA_CRC)) {
        fault_effect();
        return g_fault == COLD_MEDIA_FAKE_DATA_CRC
            ? COLD_MEDIA_DATA_CRC : COLD_MEDIA_WRITE_UNKNOWN;
    }
    if (fire && g_fault == COLD_MEDIA_FAKE_REMOVAL) {
        fault_effect();
        g_fake_removed = 1;
        return COLD_MEDIA_REMOVED;
    }
    if (fire && g_fault == COLD_MEDIA_FAKE_BIT_FLIP) {
        fault_effect();
        dst[g_bit_flip_byte] ^= 1;
    }
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_fake_barrier(uint64_t deadline)
{
    (void)deadline;
    if (g_fake_removed)
        return COLD_MEDIA_REMOVED;
    if (boundary()) {
        switch (g_fault) {
        case COLD_MEDIA_FAKE_TIMEOUT:
        case COLD_MEDIA_FAKE_RESET_TIMEOUT:
            fault_effect();
            return COLD_MEDIA_TIMEOUT;
        case COLD_MEDIA_FAKE_COMMAND_CRC:
        case COLD_MEDIA_FAKE_DATA_CRC:
        case COLD_MEDIA_FAKE_READ_FAILURE:
            fault_effect();
            return COLD_MEDIA_COMMAND_CRC;
        case COLD_MEDIA_FAKE_REMOVAL:
            fault_effect();
            g_fake_removed = 1;
            return COLD_MEDIA_REMOVED;
        case COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE:
        case COLD_MEDIA_FAKE_BARRIER_FAILURE:
        case COLD_MEDIA_FAKE_BIT_FLIP:
            fault_effect();
            return COLD_MEDIA_BARRIER_FAILURE;
        default:
            break;
        }
    }
    return COLD_MEDIA_OK;
}

static void arm_fault_at(cold_media_fake_fault_t fault,
                         uint64_t transfer_boundary, uint64_t bit_flip_byte)
{
    g_fault = fault;
    g_fault_boundary = transfer_boundary ? transfer_boundary : 1;
    g_bit_flip_byte = bit_flip_byte < COLD_MEDIA_SECTOR_BYTES
        ? bit_flip_byte : COLD_MEDIA_SECTOR_BYTES / 2;
    g_transfer = 0;
    g_fake_removed = 0;
    g_fault_effect_fired = 0;
}

static void arm_fault(cold_media_fake_fault_t fault,
                      uint64_t transfer_boundary)
{
    arm_fault_at(fault, transfer_boundary, COLD_MEDIA_SECTOR_BYTES / 2);
}

/* Arm a fault for the next transfers without resetting the media session
 * (test knob I3_CKPT_TEST=rebasefault, src/i3_host.c). */
void cold_media_fake_fault_arm(cold_media_fake_fault_t fault,
                               uint64_t transfer_boundary)
{
    arm_fault(fault, transfer_boundary);
}

#if defined(COLD_MEDIA_RING)
/* Row 212 PR 1c: the fake ring extent, for the ring fault legs of
 * tests/recorder_ring.py. It is separate from the cold extent and from its
 * transfer counter, so arming a cold fault never hits a ring transfer and
 * the reverse. It lives in .bss, so the ring must be small here. Test knob
 * I3_RING_TEST=fault I3_RING_TEST_AT=K: the K-th ring sector write (1-based)
 * writes half the sector and reports WRITE_UNKNOWN. */
_Static_assert(COLD_MEDIA_RING_SECTORS <= 2048u,
               "COLD_MEDIA=fake keeps the ring in .bss: I3_RING_BYTES <= 1 MiB");
static uint8_t g_fake_ring[COLD_MEDIA_RING_SECTORS][COLD_MEDIA_SECTOR_BYTES];
static uint64_t g_fake_ring_writes;

cold_media_status_t cold_media_fake_ring_read(uint64_t s, uint8_t *dst)
{
    if (s >= COLD_MEDIA_RING_SECTORS || g_fake_removed)
        return COLD_MEDIA_REMOVED;
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
        dst[i] = g_fake_ring[s][i];
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_fake_ring_write(uint64_t s, const uint8_t *src,
                                               int *submitted)
{
    uint64_t n = COLD_MEDIA_SECTOR_BYTES;
    *submitted = 0;
    if (s >= COLD_MEDIA_RING_SECTORS || g_fake_removed)
        return COLD_MEDIA_REMOVED;
    g_fake_ring_writes++;
    *submitted = 1;
#if defined(I3_RING_TEST_FAULT)
    if (g_fake_ring_writes == (uint64_t)(I3_RING_TEST_AT))
        n /= 2;
#endif
    for (uint64_t i = 0; i < n; i++)
        g_fake_ring[s][i] = src[i];
    return n == COLD_MEDIA_SECTOR_BYTES ? COLD_MEDIA_OK : COLD_MEDIA_WRITE_UNKNOWN;
}

cold_media_status_t cold_media_fake_ring_barrier(void)
{
    return g_fake_removed ? COLD_MEDIA_REMOVED : COLD_MEDIA_OK;
}
#endif
