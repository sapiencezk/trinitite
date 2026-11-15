#include <stddef.h>
#include <stdint.h>
#include "blake3.h"
#include "cold_media.h"
#include "memory.h"
#include "runtime_stats.h"

#define COLD_MEDIA_DESC_MAGIC 0x31444D433249ULL /* "I2CMD1\0\0" LE */

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
} cold_media_descriptor_t;

typedef char cold_media_descriptor_size_check[
    sizeof(cold_media_descriptor_t) == COLD_MEDIA_SECTOR_BYTES ? 1 : -1];

#if defined(COLD_MEDIA_FAKE)
cold_media_status_t cold_media_fake_probe(uint64_t *, int *, uint64_t);
cold_media_status_t cold_media_fake_sector_read(
    uint64_t, uint8_t *, uint64_t);
cold_media_status_t cold_media_fake_sector_write(
    uint64_t, const uint8_t *, uint64_t, int *);
cold_media_status_t cold_media_fake_barrier(uint64_t);
void cold_media_fake_backend_reset(void);
#if defined(COLD_MEDIA_RING)
/* The fake ring extent (cold_media_fake.c): sector s of the ring. */
cold_media_status_t cold_media_fake_ring_read(uint64_t, uint8_t *);
cold_media_status_t cold_media_fake_ring_write(uint64_t, const uint8_t *, int *);
cold_media_status_t cold_media_fake_ring_barrier(void);
#endif
#define backend_probe cold_media_fake_probe
#define backend_read cold_media_fake_sector_read
#define backend_write cold_media_fake_sector_write
#define backend_barrier cold_media_fake_barrier
#define backend_reset cold_media_fake_backend_reset
#elif defined(COLD_MEDIA_RPI4_SD)
cold_media_status_t rpi4_sd_probe(uint64_t *, int *, uint64_t);
cold_media_status_t rpi4_sd_sector_read(uint64_t, uint8_t *, uint64_t);
cold_media_status_t rpi4_sd_sector_write(
    uint64_t, const uint8_t *, uint64_t, int *);
cold_media_status_t rpi4_sd_barrier(uint64_t);
void rpi4_sd_reset_session(void);
#define backend_probe rpi4_sd_probe
#define backend_read rpi4_sd_sector_read
#define backend_write rpi4_sd_sector_write
#define backend_barrier rpi4_sd_barrier
#define backend_reset rpi4_sd_reset_session
#else
static cold_media_status_t backend_probe(
    uint64_t *capacity, int *read_only, uint64_t deadline)
{
    (void)capacity;
    (void)read_only;
    (void)deadline;
    return COLD_MEDIA_DISABLED;
}
static cold_media_status_t backend_read(
    uint64_t lba, uint8_t *dst, uint64_t deadline)
{
    (void)lba;
    (void)dst;
    (void)deadline;
    return COLD_MEDIA_DISABLED;
}
static cold_media_status_t backend_write(
    uint64_t lba, const uint8_t *src, uint64_t deadline, int *submitted)
{
    (void)lba;
    (void)src;
    (void)deadline;
    *submitted = 0;
    return COLD_MEDIA_DISABLED;
}
static cold_media_status_t backend_barrier(uint64_t deadline)
{
    (void)deadline;
    return COLD_MEDIA_DISABLED;
}
static void backend_reset(void)
{
}
#endif

static cold_media_diag_t g_diag;
static uint8_t g_sector[COLD_MEDIA_SECTOR_BYTES];
static int g_initialized;
static int g_active;
static int g_window_loaded;
static int g_read_only;
static int g_owner;
static int g_reset_required;

static void diag_set(cold_media_phase_t phase, cold_media_status_t status,
                     uint64_t logical, uint64_t lba, uint64_t completed,
                     uint64_t submitted)
{
    g_diag.phase = (uint64_t)phase;
    g_diag.status = (int64_t)status;
    g_diag.logical_offset = logical;
    g_diag.physical_lba = lba;
    g_diag.completed_sectors = completed;
    g_diag.mutation_submitted = submitted;
    runtime_stats_set(RT_COUNT_MEDIA_PHASE, (uint64_t)phase);
    runtime_stats_set(RT_COUNT_MEDIA_STATUS, (uint64_t)(int64_t)status);
}

static int bytes_zero(const uint8_t *bytes, uint64_t len)
{
    uint8_t any = 0;
    for (uint64_t i = 0; i < len; i++)
        any |= bytes[i];
    return any == 0;
}

static cold_media_status_t validate_descriptor(
    const cold_media_descriptor_t *descriptor)
{
    uint8_t digest[32];
    blake3_hash((const uint8_t *)descriptor, 48, digest);
    uint8_t diff = 0;
    for (unsigned i = 0; i < 32; i++)
        diff |= digest[i] ^ descriptor->checksum[i];
    if (descriptor->magic != COLD_MEDIA_DESC_MAGIC
        || descriptor->version != COLD_MEDIA_LAYOUT_VERSION
        || descriptor->header_len != 80
        || descriptor->start_lba != COLD_MEDIA_START_LBA
        || descriptor->extent_sectors != COLD_MEDIA_EXTENT_SECTORS
        || descriptor->logical_bytes != COLD_SIZE
        || descriptor->sector_bytes != COLD_MEDIA_SECTOR_BYTES
        || descriptor->flags != 0 || diff
        || !bytes_zero(descriptor->reserved, sizeof descriptor->reserved))
        return COLD_MEDIA_LAYOUT;
    return COLD_MEDIA_OK;
}

#if defined(COLD_MEDIA_RING)
static uint64_t g_ring_capacity;
static int g_ring_reset_required; /* ring only, never the cold session */
#endif

static cold_media_status_t initialize(uint64_t deadline)
{
    if (g_initialized)
        return g_active ? COLD_MEDIA_OK : (cold_media_status_t)g_diag.status;
    g_initialized = 1;
    uint64_t capacity = 0;
    int read_only = 0;
    cold_media_status_t status = backend_probe(
        &capacity, &read_only, deadline);
    if (status == COLD_MEDIA_DISABLED) {
        diag_set(COLD_MEDIA_PHASE_PROBE, status, 0, 0, 0, 0);
        return status;
    }
    if (status != COLD_MEDIA_OK) {
        diag_set(COLD_MEDIA_PHASE_PROBE, status, 0,
                 COLD_MEDIA_START_LBA, 0, 0);
        return status;
    }
    if (capacity < COLD_MEDIA_START_LBA + COLD_MEDIA_EXTENT_SECTORS) {
        diag_set(COLD_MEDIA_PHASE_LAYOUT, COLD_MEDIA_UNDERSIZED, 0,
                 COLD_MEDIA_START_LBA, 0, 0);
        return COLD_MEDIA_UNDERSIZED;
    }
    status = backend_read(COLD_MEDIA_START_LBA, g_sector, deadline);
    if (status != COLD_MEDIA_OK) {
        diag_set(COLD_MEDIA_PHASE_LAYOUT, status, 0,
                 COLD_MEDIA_START_LBA, 0, 0);
        return status;
    }
    status = validate_descriptor(
        (const cold_media_descriptor_t *)(const void *)g_sector);
    if (status != COLD_MEDIA_OK) {
        diag_set(COLD_MEDIA_PHASE_LAYOUT, status, 0,
                 COLD_MEDIA_START_LBA, 0, 0);
        return status;
    }
    g_read_only = read_only;
#if defined(COLD_MEDIA_RING)
    g_ring_capacity = capacity;
#endif
    g_active = 1;
    diag_set(COLD_MEDIA_PHASE_LAYOUT, COLD_MEDIA_OK, 0,
             COLD_MEDIA_START_LBA, 1, 0);
    return COLD_MEDIA_OK;
}

static cold_media_status_t translate(
    uint64_t logical, uint64_t *lba, uint64_t *within, uint64_t *available)
{
    if (logical >= COLD_SIZE)
        return COLD_MEDIA_RANGE;
    if (logical < 256) {
        *lba = COLD_MEDIA_START_LBA + 1;
        *within = logical;
        *available = 256 - logical;
    } else if (logical < 512) {
        *lba = COLD_MEDIA_START_LBA + 2;
        *within = logical - 256;
        *available = 512 - logical;
    } else {
        uint64_t relative = logical - 512;
        *lba = COLD_MEDIA_START_LBA + 3
             + relative / COLD_MEDIA_SECTOR_BYTES;
        *within = relative % COLD_MEDIA_SECTOR_BYTES;
        *available = COLD_MEDIA_SECTOR_BYTES - *within;
    }
    return COLD_MEDIA_OK;
}

static int range_ok(uint64_t off, uint64_t len)
{
    return len != 0 && len <= COLD_SIZE && off <= COLD_SIZE - len;
}

static int deadline_expired(uint64_t deadline)
{
    return deadline != 0 && runtime_counter_now() >= deadline;
}

cold_media_status_t cold_media_read(cold_media_phase_t phase,
                                    uint64_t logical_off, void *dst,
                                    uint64_t len, uint64_t deadline)
{
    if (!dst || !range_ok(logical_off, len)) {
        diag_set(phase, COLD_MEDIA_RANGE, logical_off, 0, 0, 0);
        return COLD_MEDIA_RANGE;
    }
    cold_media_status_t status = initialize(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    if (g_reset_required) {
        diag_set(phase, COLD_MEDIA_RESET_REQUIRED,
                 logical_off, 0, 0, 0);
        return COLD_MEDIA_RESET_REQUIRED;
    }
    if (g_owner) {
        diag_set(phase, COLD_MEDIA_BUSY, logical_off, 0, 0, 0);
        return COLD_MEDIA_BUSY;
    }
    g_owner = 1;
    uint8_t *out = (uint8_t *)dst;
    uint64_t done = 0;
    uint64_t sectors = 0;
    uint64_t last_lba = 0;
    uint64_t start = runtime_counter_now();
    while (done < len) {
        uint64_t lba, within, available;
        if (deadline_expired(deadline)) {
            status = COLD_MEDIA_TIMEOUT;
            break;
        }
        status = translate(logical_off + done, &lba, &within, &available);
        if (status != COLD_MEDIA_OK)
            break;
        last_lba = lba;
        status = backend_read(lba, g_sector, deadline);
        if (status != COLD_MEDIA_OK)
            break;
        uint64_t n = len - done < available ? len - done : available;
        for (uint64_t i = 0; i < n; i++)
            out[done + i] = g_sector[within + i];
        done += n;
        sectors++;
    }
    g_owner = 0;
    if (status != COLD_MEDIA_OK)
        g_reset_required = 1;
    uint64_t end = runtime_counter_now();
    runtime_stats_record(
        RT_PHASE_MEDIA_READ, end >= start ? end - start : 0);
    runtime_stats_count(RT_COUNT_MEDIA_BYTES_READ, done);
    diag_set(phase, status, logical_off, last_lba, sectors, 0);
    return status;
}

cold_media_status_t cold_media_write(cold_media_phase_t phase,
                                     uint64_t logical_off, const void *src,
                                     uint64_t len, uint64_t deadline)
{
    if (!src || !range_ok(logical_off, len)) {
        diag_set(phase, COLD_MEDIA_RANGE, logical_off, 0, 0, 0);
        return COLD_MEDIA_RANGE;
    }
    cold_media_status_t status = initialize(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    if (g_reset_required) {
        diag_set(phase, COLD_MEDIA_RESET_REQUIRED,
                 logical_off, 0, 0, 0);
        return COLD_MEDIA_RESET_REQUIRED;
    }
    if (g_read_only) {
        diag_set(phase, COLD_MEDIA_READ_ONLY, logical_off, 0, 0, 0);
        return COLD_MEDIA_READ_ONLY;
    }
    if (g_owner) {
        diag_set(phase, COLD_MEDIA_BUSY, logical_off, 0, 0, 0);
        return COLD_MEDIA_BUSY;
    }
    g_owner = 1;
    const uint8_t *input = (const uint8_t *)src;
    uint64_t done = 0;
    uint64_t sectors = 0;
    uint64_t submitted_total = 0;
    uint64_t last_lba = 0;
    uint64_t start = runtime_counter_now();
    while (done < len) {
        uint64_t lba, within, available;
        if (deadline_expired(deadline)) {
            status = COLD_MEDIA_TIMEOUT;
            break;
        }
        status = translate(logical_off + done, &lba, &within, &available);
        if (status != COLD_MEDIA_OK)
            break;
        last_lba = lba;
        uint64_t n = len - done < available ? len - done : available;
        if (within != 0 || n != COLD_MEDIA_SECTOR_BYTES) {
            status = backend_read(lba, g_sector, deadline);
            if (status != COLD_MEDIA_OK)
                break; /* no mutation has begun for this sector */
        }
        for (uint64_t i = 0; i < n; i++)
            g_sector[within + i] = input[done + i];
        int submitted = 0;
        status = backend_write(lba, g_sector, deadline, &submitted);
        submitted_total += submitted ? 1u : 0u;
        if (status != COLD_MEDIA_OK) {
            if (submitted) {
                status = COLD_MEDIA_WRITE_UNKNOWN;
            }
            g_reset_required = 1;
            break; /* never retry a submitted mutation */
        }
        done += n;
        sectors++;
    }
    g_owner = 0;
    uint64_t end = runtime_counter_now();
    runtime_stats_record(
        RT_PHASE_MEDIA_WRITE, end >= start ? end - start : 0);
    runtime_stats_count(RT_COUNT_MEDIA_BYTES_WRITTEN, done);
    diag_set(phase, status, logical_off, last_lba, sectors, submitted_total);
    return status;
}

cold_media_status_t cold_media_barrier(cold_media_phase_t phase,
                                       uint64_t deadline)
{
    cold_media_status_t status = initialize(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    if (g_reset_required) {
        diag_set(phase, COLD_MEDIA_RESET_REQUIRED, 0, 0, 0, 0);
        return COLD_MEDIA_RESET_REQUIRED;
    }
    if (g_owner) {
        diag_set(phase, COLD_MEDIA_BUSY, 0, 0, 0, 0);
        return COLD_MEDIA_BUSY;
    }
    if (deadline_expired(deadline)) {
        diag_set(phase, COLD_MEDIA_TIMEOUT, 0, 0, 0, 0);
        return COLD_MEDIA_TIMEOUT;
    }
    g_owner = 1;
    uint64_t start = runtime_counter_now();
    status = backend_barrier(deadline);
    uint64_t end = runtime_counter_now();
    g_owner = 0;
    if (status != COLD_MEDIA_OK)
        g_reset_required = 1;
    runtime_stats_record(
        RT_PHASE_MEDIA_BARRIER, end >= start ? end - start : 0);
    diag_set(phase, status, 0, 0, 0, 0);
    return status;
}

cold_media_status_t cold_media_load_window(uint64_t deadline)
{
    if (g_window_loaded)
        return COLD_MEDIA_OK;
    cold_media_status_t status = initialize(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    uint64_t start = runtime_counter_now();
    status = cold_media_read(
        COLD_MEDIA_PHASE_BOOT_LOAD, 0,
        (void *)(uintptr_t)COLD_BASE, COLD_SIZE, deadline);
    uint64_t end = runtime_counter_now();
    runtime_stats_record_boot_load(end >= start ? end - start : 0);
    if (status == COLD_MEDIA_OK)
        g_window_loaded = 1;
    return status;
}

int cold_media_active(void)
{
    return g_active;
}

const cold_media_diag_t *cold_media_last_diag(void)
{
    return &g_diag;
}

void cold_media_reset_session(void)
{
    backend_reset();
    g_initialized = 0;
    g_active = 0;
    g_window_loaded = 0;
    g_read_only = 0;
    g_owner = 0;
    g_reset_required = 0;
#if defined(COLD_MEDIA_RING)
    g_ring_reset_required = 0;
#endif
    diag_set(COLD_MEDIA_PHASE_NONE, COLD_MEDIA_DISABLED, 0, 0, 0, 0);
}

#if defined(COLD_MEDIA_RING)
/* Row 212 PR 1c recorder ring extent (cold_media.h). The ring shares the
 * backend and the owner lock with the cold store but keeps its own
 * reset-required flag: a ring fault never sets g_reset_required, so later
 * cold I/O is not refused because of it (row 212 (2): a ring failure never
 * stops the node). Ring I/O does not touch the cold diag record either. */

static uint64_t ring_deadline(uint64_t seconds)
{
    uint64_t now = runtime_counter_now(), f = runtime_counter_freq();
    uint64_t a = f <= UINT64_MAX / seconds ? f * seconds : UINT64_MAX;
    return a <= UINT64_MAX - now ? now + a : UINT64_MAX;
}

static cold_media_status_t ring_range(uint64_t first, uint64_t count)
{
    if (count == 0 || first > COLD_MEDIA_RING_SECTORS
        || count > COLD_MEDIA_RING_SECTORS - first
        || COLD_MEDIA_RING_START_LBA + COLD_MEDIA_RING_SECTORS > g_ring_capacity)
        return COLD_MEDIA_RANGE;
    return COLD_MEDIA_OK;
}

static cold_media_status_t ring_begin(int write)
{
    cold_media_status_t status = initialize(ring_deadline(5));
    if (status != COLD_MEDIA_OK)
        return status;
    if (g_ring_reset_required)
        return COLD_MEDIA_RESET_REQUIRED;
    if (write && g_read_only)
        return COLD_MEDIA_READ_ONLY;
    if (g_owner)
        return COLD_MEDIA_BUSY;
    return COLD_MEDIA_OK;
}

cold_media_status_t cold_media_ring_load(uint8_t *window, uint64_t bytes)
{
    cold_media_status_t status = ring_begin(0);
    if (status != COLD_MEDIA_OK)
        return status;
    if (bytes != (uint64_t)(I3_RING_BYTES)
        || ring_range(0, COLD_MEDIA_RING_SECTORS) != COLD_MEDIA_OK)
        return COLD_MEDIA_UNDERSIZED;
    uint64_t total = ring_deadline(COLD_MEDIA_RING_LOAD_SECONDS), chunk = 0;
    g_owner = 1;
    for (uint64_t s = 0; s < COLD_MEDIA_RING_SECTORS; s++) {
        if (s % COLD_MEDIA_RING_CHUNK_SECTORS == 0)
            chunk = ring_deadline(5);
        if (deadline_expired(chunk) || deadline_expired(total)) {
            status = COLD_MEDIA_TIMEOUT;
            break;
        }
#if defined(COLD_MEDIA_FAKE)
        status = cold_media_fake_ring_read(s, window + s * COLD_MEDIA_SECTOR_BYTES);
#else
        status = backend_read(COLD_MEDIA_RING_START_LBA + s,
                              window + s * COLD_MEDIA_SECTOR_BYTES, chunk);
#endif
        if (status != COLD_MEDIA_OK)
            break;
    }
    g_owner = 0;
    if (status != COLD_MEDIA_OK)
        g_ring_reset_required = 1;
    return status;
}

cold_media_status_t cold_media_ring_write(const uint8_t *window, uint64_t off,
                                          uint64_t len)
{
    cold_media_status_t status = ring_begin(1);
    if (status != COLD_MEDIA_OK)
        return status;
    if (len == 0)
        return COLD_MEDIA_RANGE;
    uint64_t first = off / COLD_MEDIA_SECTOR_BYTES;
    uint64_t last = (off + len - 1) / COLD_MEDIA_SECTOR_BYTES;
    if (off + len < off || ring_range(first, last - first + 1) != COLD_MEDIA_OK)
        return COLD_MEDIA_RANGE;
    uint64_t chunk = 0;
    g_owner = 1;
    for (uint64_t s = first; s <= last; s++) {
        int submitted = 0;
        if ((s - first) % COLD_MEDIA_RING_CHUNK_SECTORS == 0)
            chunk = ring_deadline(5);
        if (deadline_expired(chunk)) {
            status = COLD_MEDIA_TIMEOUT;
            break;
        }
#if defined(COLD_MEDIA_FAKE)
        status = cold_media_fake_ring_write(s,
                                            window + s * COLD_MEDIA_SECTOR_BYTES,
                                            &submitted);
#else
        status = backend_write(COLD_MEDIA_RING_START_LBA + s,
                               window + s * COLD_MEDIA_SECTOR_BYTES,
                               chunk, &submitted);
#endif
        if (status != COLD_MEDIA_OK) {
            if (submitted)
                status = COLD_MEDIA_WRITE_UNKNOWN;
            break; /* never retry a submitted mutation */
        }
    }
    g_owner = 0;
    if (status != COLD_MEDIA_OK)
        g_ring_reset_required = 1;
    return status;
}

cold_media_status_t cold_media_ring_barrier(void)
{
    cold_media_status_t status = ring_begin(0);
    if (status != COLD_MEDIA_OK)
        return status;
    g_owner = 1;
#if defined(COLD_MEDIA_FAKE)
    status = cold_media_fake_ring_barrier();
#else
    status = backend_barrier(ring_deadline(5));
#endif
    g_owner = 0;
    if (status != COLD_MEDIA_OK)
        g_ring_reset_required = 1;
    return status;
}
#endif
