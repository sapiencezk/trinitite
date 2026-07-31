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
            || g_fault == COLD_MEDIA_FAKE_RESET) {
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
                 || g_fault == COLD_MEDIA_FAKE_RESET)) {
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
        case COLD_MEDIA_FAKE_RESET:
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

void cold_media_fake_fault_set(cold_media_fake_fault_t fault,
                               uint64_t transfer_boundary)
{
    arm_fault(fault, transfer_boundary);
    cold_media_reset_session();
}

void cold_media_fake_fault_clear(void)
{
    g_fault = COLD_MEDIA_FAKE_NONE;
    g_fault_boundary = 0;
    g_bit_flip_byte = COLD_MEDIA_SECTOR_BYTES / 2;
    g_transfer = 0;
    g_fake_removed = 0;
    g_fault_effect_fired = 0;
    cold_media_reset_session();
}

void cold_media_fake_backend_reset(void)
{
    g_fake_removed = 0;
}

static int sentinels_ok(void)
{
    for (uint64_t i = 0; i < COLD_MEDIA_SECTOR_BYTES; i++)
        if (g_fake[0][i] != 0xa5
            || g_fake[FAKE_SECTORS - 1][i] != 0x5a)
            return 0;
    return 1;
}

static void reload_window_from_media(void)
{
    uint8_t *window = (uint8_t *)(uintptr_t)COLD_BASE;
    uint8_t *a = fake_sector(COLD_MEDIA_START_LBA + 1);
    uint8_t *b = fake_sector(COLD_MEDIA_START_LBA + 2);
    for (uint64_t i = 0; i < 256; i++) {
        window[i] = a[i];
        window[256 + i] = b[i];
    }
    uint64_t logical = 512;
    for (uint64_t lba = COLD_MEDIA_START_LBA + 3;
         logical < COLD_SIZE; lba++) {
        uint8_t *sector = fake_sector(lba);
        for (uint64_t i = 0;
             i < COLD_MEDIA_SECTOR_BYTES && logical < COLD_SIZE;
             i++, logical++)
            window[logical] = sector[i];
    }
}

static int activate_media(void)
{
    uint8_t ignored;
    return cold_media_read(
        COLD_MEDIA_PHASE_LAYOUT, 0, &ignored, 1, 0) == COLD_MEDIA_OK;
}

static int prepare_old_generation_for_slot(unsigned slot_parity)
{
    restore_blank_media();
    reload_window_from_media();
    if (!activate_media() || cold_format() != 0
        || cold_snap_save(direct(42)) != 0)
        return 0;
    /* A second retained snapshot flips the active A/B superblock. Both
     * parities must exercise the deployment selecting-slot readback. */
    if (slot_parity && cold_snap_save(direct(42)) != 0)
        return 0;
    return 1;
}

static int prepare_old_generation(void)
{
    return prepare_old_generation_for_slot(0);
}

static cold_result_t remount_probe(void)
{
    cold_media_fake_fault_clear();
    reload_window_from_media();
    if (!activate_media())
        return COLD_RESULT_ABSENT;
    return cold_probe();
}

static int load_expected(uint64_t expected)
{
    heap_scratch_reset();
    noun got = cold_snap_load();
    int ok = noun_is_direct(got) && direct_val(got) == expected;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return ok;
}

/* M7 TRI_DEPLOY has two append-only objects and a final selecting
 * superblock.  Pre-selection failures must retain the old snapshot; an
 * attempted final superblock or barrier is deliberately reported as an
 * old-or-new durability ambiguity, never as an ordinary failed activation. */
static uint64_t deployment_fault_matrix(void)
{
    uint64_t failures = 0;
    uint64_t hash = 0;
    static const cold_media_fake_fault_t deployment_faults[] = {
        /* Every physical deployment error class is exercised at every
         * read/write/barrier transfer boundary. */
        COLD_MEDIA_FAKE_TIMEOUT,
        COLD_MEDIA_FAKE_COMMAND_CRC,
        COLD_MEDIA_FAKE_DATA_CRC,
        COLD_MEDIA_FAKE_READ_FAILURE,
        COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE,
        COLD_MEDIA_FAKE_BARRIER_FAILURE,
        COLD_MEDIA_FAKE_REMOVAL,
        COLD_MEDIA_FAKE_BIT_FLIP,
        COLD_MEDIA_FAKE_RESET
    };
    /* These hit object magic/payload digest/header digest/commit and the
     * selecting-superblock header/checksum regions as the boundary loop
     * reaches their sectors.  256 retains the former middle-of-sector probe. */
    static const uint64_t corruption_bytes[] = { 0, 40, 64, 72, 104, 256 };
    int fence_seen[sizeof deployment_faults / sizeof deployment_faults[0]] = {0};
    int corruption_fenced[sizeof corruption_bytes / sizeof corruption_bytes[0]] = {0};
    int saw_old_pair = 0;
    int saw_new_pair = 0;
    int saw_no_valid_pair = 0;
    for (unsigned slot_parity = 0; slot_parity < 2; slot_parity++) {
        if (!prepare_old_generation_for_slot(slot_parity))
            return 1;
        uint64_t old_generation = cold_selected_generation();
        arm_fault(COLD_MEDIA_FAKE_NONE, 1);
        if (cold_store_deployment(direct(43), direct(44), &hash)
                != COLD_DEPLOY_COMMITTED
            || hash == 0 || g_transfer == 0)
            return 2;
        uint64_t transfer_boundaries = g_transfer;
        for (unsigned f = 0;
             f < sizeof deployment_faults / sizeof deployment_faults[0];
             f++) {
            unsigned bytes = deployment_faults[f] == COLD_MEDIA_FAKE_BIT_FLIP
                ? sizeof corruption_bytes / sizeof corruption_bytes[0] : 1;
            for (unsigned b = 0; b < bytes; b++) {
                for (uint64_t edge = 1; edge <= transfer_boundaries; edge++) {
                    if (!prepare_old_generation_for_slot(slot_parity)) {
                        failures |= 1ULL << 2;
                        continue;
                    }
                    old_generation = cold_selected_generation();
                    if (deployment_faults[f] == COLD_MEDIA_FAKE_BIT_FLIP)
                        arm_fault_at(deployment_faults[f], edge,
                                     corruption_bytes[b]);
                    else
                        arm_fault(deployment_faults[f], edge);
                    cold_deploy_result_t result = cold_store_deployment(
                        direct(43), direct(44), &hash);
                    int injected = g_fault_effect_fired;
                    cold_result_t remount = remount_probe();
                    int old_pair = remount == COLD_RESULT_VALID
                        && cold_selected_generation() == old_generation
                        && load_expected(42);
                    int new_pair = remount == COLD_RESULT_VALID
                        && cold_selected_generation() == old_generation + 2
                        && load_expected(44);
                    if (old_pair)
                        saw_old_pair = 1;
                    if (new_pair)
                        saw_new_pair = 1;
                    if (remount != COLD_RESULT_VALID)
                        saw_no_valid_pair = 1;
                    if (result == COLD_DEPLOY_DURABILITY_UNKNOWN) {
                        fence_seen[f] = 1;
                        if (deployment_faults[f] == COLD_MEDIA_FAKE_BIT_FLIP)
                            corruption_fenced[b] = 1;
                    }
                    /* An aligned append can share a sector with retained
                     * data. A failed deployment may therefore remount old,
                     * new, or no valid pair. The sole durable success claim
                     * is stronger: COMMITTED must remount the exact new pair. */
                    if (!injected
                        || (result == COLD_DEPLOY_COMMITTED && !new_pair)
                        || (result != COLD_DEPLOY_REJECTED
                            && result != COLD_DEPLOY_COMMITTED
                            && result != COLD_DEPLOY_DURABILITY_UNKNOWN)
                        || !sentinels_ok())
                        failures |= 1ULL << 4;
                }
            }
        }
    }
    for (unsigned f = 0;
         f < sizeof deployment_faults / sizeof deployment_faults[0]; f++)
        if (!fence_seen[f])
            failures |= 1ULL << (5 + f);
    for (unsigned b = 0;
         b < sizeof corruption_bytes / sizeof corruption_bytes[0]; b++)
        if (!corruption_fenced[b])
            failures |= 1ULL << (14 + b);
    if (!saw_old_pair || !saw_new_pair || !saw_no_valid_pair)
        failures |= 1ULL << 20;
    return failures;
}

static int digest_equal(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0;
    for (unsigned i = 0; i < 32; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

uint64_t cold_media_fake_smoketest(void)
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

uint64_t cold_media_fake_selftest(void)
{
    uint64_t failures = cold_media_fake_smoketest();
    uint64_t deployment_failures = deployment_fault_matrix();
    if (deployment_failures)
        failures |= deployment_failures << 23;
    /*
     * Exercise the real cold.c append path through this adapter at every
     * physical read/write/barrier boundary, then reconstruct the RAM window
     * from fake media and run the production selector/decoder.
     */
    if (!prepare_old_generation()) {
        restore_blank_media();
        return failures | (1ULL << 16);
    }
    arm_fault(COLD_MEDIA_FAKE_NONE, 1);
    if (cold_snap_save(direct(43)) != 0 || g_transfer == 0)
        failures |= 1ULL << 17;
    uint64_t transfer_boundaries = g_transfer;
    static const cold_media_fake_fault_t matrix[] = {
        COLD_MEDIA_FAKE_TIMEOUT,
        COLD_MEDIA_FAKE_COMMAND_CRC,
        COLD_MEDIA_FAKE_DATA_CRC,
        COLD_MEDIA_FAKE_READ_FAILURE,
        COLD_MEDIA_FAKE_PARTIAL_UNKNOWN_WRITE,
        COLD_MEDIA_FAKE_BARRIER_FAILURE,
        COLD_MEDIA_FAKE_REMOVAL,
        COLD_MEDIA_FAKE_BIT_FLIP,
        COLD_MEDIA_FAKE_RESET
    };
    for (unsigned f = 0; f < sizeof matrix / sizeof matrix[0]; f++) {
        for (uint64_t edge = 1; edge <= transfer_boundaries; edge++) {
            if (!prepare_old_generation()) {
                failures |= 1ULL << 18;
                continue;
            }
            arm_fault(matrix[f], edge);
            (void)cold_snap_save(direct(43));
            int injected = g_fault_effect_fired;
            if (remount_probe() != COLD_RESULT_VALID) {
                failures |= 1ULL << 19;
                continue;
            }
            uint64_t generation = cold_selected_generation();
            if (!injected
                || (generation == 2 && !load_expected(42))
                || (generation == 3 && !load_expected(43))
                || (generation != 2 && generation != 3)
                || !sentinels_ok())
                failures |= 1ULL << 20;
        }
    }

    /* Boot/load and save preflights must not mutate a physical byte. */
    static const cold_media_fake_fault_t preflight[] = {
        COLD_MEDIA_FAKE_ABSENT,
        COLD_MEDIA_FAKE_READ_ONLY,
        COLD_MEDIA_FAKE_UNDERSIZED
    };
    for (unsigned i = 0; i < sizeof preflight / sizeof preflight[0]; i++) {
        uint8_t before[32], after[32];
        if (!prepare_old_generation()) {
            failures |= 1ULL << 21;
            continue;
        }
        blake3_hash((const uint8_t *)g_fake, sizeof g_fake, before);
        cold_media_fake_fault_set(preflight[i], 1);
        cold_media_status_t status = cold_media_load_window(0);
        int expected_status =
            (preflight[i] == COLD_MEDIA_FAKE_ABSENT
             && status == COLD_MEDIA_ABSENT)
            || (preflight[i] == COLD_MEDIA_FAKE_UNDERSIZED
                && status == COLD_MEDIA_UNDERSIZED)
            || (preflight[i] == COLD_MEDIA_FAKE_READ_ONLY
                && status == COLD_MEDIA_OK
                && cold_snap_save(direct(43)) != 0);
        blake3_hash((const uint8_t *)g_fake, sizeof g_fake, after);
        if (!expected_status || digest_equal(before, after) == 0
            || !sentinels_ok())
            failures |= 1ULL << 22;
    }
    return failures;
}
