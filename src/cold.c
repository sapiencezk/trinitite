#include <stddef.h>
#include <stdint.h>
#include "cold.h"
#include "memory.h"
#include "noun.h"
#include "jam.h"
#include "blake3.h"
#include "bounded_cue.h"
#include "cold_media.h"
#include "runtime_stats.h"

#define COLD_MAGIC       0x32444C4F433249ULL /* "I2COLD2\0" LE */
#define COLD_VERSION     2u
#define COLD_SUPER_SIZE  128u
#define COLD_SLOT0       0u
#define COLD_SLOT1       256u
#define COLD_DATA0       0x1000u
#define COLD_COMMIT      0xC011D00DC0DE17EDULL
#define COLD_OBJ_MAGIC   0x324A424F433249ULL /* "I2COBJ2\0" LE */
#define COLD_OBJ_SIZE    112u

#define KIND_BLOB  1u
#define KIND_LOG   2u
#define KIND_SNAP  3u

#define JAM_SCRATCH_MAX (256u * 1024u)

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint32_t version;
    uint32_t header_len;
    uint64_t generation;
    uint64_t snap_generation;
    uint64_t snap_off;
    uint64_t data_head;
    uint64_t log_count;
    uint64_t commit;
    uint8_t checksum[32];
    uint8_t reserved[32];
} cold_super_t;

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint32_t version;
    uint32_t header_len;
    uint32_t kind;
    uint32_t reserved;
    uint64_t generation;
    uint64_t len;
    uint8_t payload_digest[32];
    uint8_t header_digest[32];
    uint64_t commit;
} cold_obj_hdr_t;

typedef char cold_super_size_check[
    sizeof(cold_super_t) == COLD_SUPER_SIZE ? 1 : -1];
typedef char cold_obj_size_check[
    sizeof(cold_obj_hdr_t) == COLD_OBJ_SIZE ? 1 : -1];

static uint8_t jam_scratch[JAM_SCRATCH_MAX];
/* append_obj() validates the currently selected object before writing. That
 * validation also uses jam_scratch, so preserve the new payload separately. */
static uint8_t append_scratch[JAM_SCRATCH_MAX];
static cold_result_t g_last_result = COLD_RESULT_EMPTY;
static uint64_t g_selected_generation;
static uint64_t g_selected_data_head;
static struct {
    cold_write_phase_t phase;
    int64_t after;
    int fired;
} g_fault;

static void cold_read(uint64_t off, void *dst, uint64_t n)
{
    const uint8_t *src = (const uint8_t *)(uintptr_t)(COLD_BASE + off);
    uint8_t *d = (uint8_t *)dst;
    for (uint64_t i = 0; i < n; i++)
        d[i] = src[i];
}

static void cold_write_raw(uint64_t off, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)(uintptr_t)(COLD_BASE + off);
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

static uint64_t media_deadline(void)
{
    uint64_t now = runtime_counter_now();
    uint64_t freq = runtime_counter_freq();
    uint64_t allowance =
        freq <= UINT64_MAX / 5 ? freq * 5 : UINT64_MAX;
    return allowance <= UINT64_MAX - now ? now + allowance : UINT64_MAX;
}

static cold_media_phase_t media_phase(cold_write_phase_t phase)
{
    switch (phase) {
    case COLD_WRITE_OBJECT_HEADER:
        return COLD_MEDIA_PHASE_OBJECT_HEADER;
    case COLD_WRITE_PAYLOAD:
        return COLD_MEDIA_PHASE_PAYLOAD;
    case COLD_WRITE_OBJECT_COMMIT:
        return COLD_MEDIA_PHASE_OBJECT_COMMIT;
    case COLD_WRITE_SUPERBLOCK:
        return COLD_MEDIA_PHASE_SUPERBLOCK;
    default:
        return COLD_MEDIA_PHASE_NONE;
    }
}

static int cold_write_phase(cold_write_phase_t phase, uint64_t off,
                            const void *src, uint64_t n)
{
    uint64_t writable = n;
    int completed = 1;
    if (g_fault.phase == phase && g_fault.after >= 0 && !g_fault.fired) {
        writable = (uint64_t)g_fault.after;
        if (writable > n)
            writable = n;
        g_fault.after -= (int64_t)writable;
        if (writable != n || g_fault.after == 0) {
            g_fault.fired = 1;
            completed = 0;
        }
    }
    if (writable)
        cold_write_raw(off, src, writable);
    if (writable && cold_media_active()
        && cold_media_write(media_phase(phase), off, src, writable,
                            media_deadline()) != COLD_MEDIA_OK)
        return 0;
    return completed;
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int bytes_zero(const uint8_t *a, size_t n)
{
    uint8_t any = 0;
    for (size_t i = 0; i < n; i++)
        any |= a[i];
    return any == 0;
}

static int align8_checked(uint64_t n, uint64_t *out)
{
    if (n > UINT64_MAX - 7)
        return 0;
    *out = (n + 7) & ~7ULL;
    return 1;
}

static uint64_t hash62_of(const uint8_t h[32])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)h[i] << (i * 8);
    v &= 0x3fffffffffffffffULL;
    return v ? v : 1;
}

static int media_blank(void)
{
    const uint64_t *words = (const uint64_t *)(uintptr_t)COLD_BASE;
    const uint64_t word_count = COLD_SIZE / sizeof(*words);
    for (uint64_t i = 0; i < word_count; i += 8)
        if (words[i + 0] != 0 || words[i + 1] != 0 ||
            words[i + 2] != 0 || words[i + 3] != 0 ||
            words[i + 4] != 0 || words[i + 5] != 0 ||
            words[i + 6] != 0 || words[i + 7] != 0)
            return 0;
    return 1;
}

static void super_checksum(cold_super_t *s)
{
    blake3_hash((const uint8_t *)s, 64, s->checksum);
}

static int super_checksum_ok(const cold_super_t *s)
{
    uint8_t digest[32];
    blake3_hash((const uint8_t *)s, 64, digest);
    return bytes_eq(digest, s->checksum, 32);
}

static void object_header_digest(cold_obj_hdr_t *h)
{
    blake3_hash((const uint8_t *)h, 72, h->header_digest);
}

static cold_result_t object_validate(const cold_super_t *s, uint64_t off,
                                     uint32_t required_kind,
                                     uint64_t required_generation,
                                     cold_obj_hdr_t *out)
{
    if (off < COLD_DATA0 || (off & 7) != 0)
        return COLD_RESULT_ALIGNMENT;
    if (off > COLD_SIZE - sizeof(cold_obj_hdr_t)
        || off > s->data_head - sizeof(cold_obj_hdr_t))
        return COLD_RESULT_OFFSET;
    cold_obj_hdr_t h;
    cold_read(off, &h, sizeof h);
    if (h.magic != COLD_OBJ_MAGIC || h.version != COLD_VERSION
        || h.header_len != sizeof h || h.reserved != 0)
        return COLD_RESULT_HEADER;
    if (required_kind && h.kind != required_kind)
        return COLD_RESULT_KIND;
    if (h.kind < KIND_BLOB || h.kind > KIND_SNAP)
        return COLD_RESULT_KIND;
    if (required_generation && h.generation != required_generation)
        return COLD_RESULT_GENERATION;
    if (h.len == 0 || h.len > JAM_SCRATCH_MAX)
        return COLD_RESULT_LENGTH;
    uint64_t end, aligned;
    if (off > UINT64_MAX - sizeof h - h.len)
        return COLD_RESULT_LENGTH;
    end = off + sizeof h + h.len;
    if (!align8_checked(end, &aligned) || aligned > s->data_head
        || aligned > COLD_SIZE)
        return COLD_RESULT_LENGTH;
    if (h.commit != COLD_COMMIT)
        return COLD_RESULT_COMMIT;
    uint8_t digest[32];
    blake3_hash((const uint8_t *)&h, 72, digest);
    if (!bytes_eq(digest, h.header_digest, 32))
        return COLD_RESULT_HEADER_DIGEST;
    cold_read(off + sizeof h, jam_scratch, h.len);
    blake3_hash(jam_scratch, (size_t)h.len, digest);
    if (!bytes_eq(digest, h.payload_digest, 32))
        return COLD_RESULT_PAYLOAD_DIGEST;
    if (out)
        *out = h;
    return COLD_RESULT_VALID;
}

static cold_result_t super_validate(uint64_t off, cold_super_t *out)
{
    cold_super_t s;
    cold_read(off, &s, sizeof s);
    if (s.magic != COLD_MAGIC || s.version != COLD_VERSION
        || s.header_len != sizeof s)
        return COLD_RESULT_HEADER;
    if (s.generation == 0 || s.generation == UINT64_MAX
        || s.commit != COLD_COMMIT
        || !bytes_zero(s.reserved, sizeof s.reserved)
        || !super_checksum_ok(&s))
        return COLD_RESULT_SUPERBLOCK;
    if (s.data_head < COLD_DATA0 || s.data_head > COLD_SIZE
        || (s.data_head & 7) != 0)
        return COLD_RESULT_OFFSET;
    if (s.snap_off != 0
        && (s.snap_off < COLD_DATA0 || s.snap_off >= s.data_head))
        return COLD_RESULT_OFFSET;
    if ((s.snap_off & 7) != 0)
        return COLD_RESULT_ALIGNMENT;

    uint64_t object_off = COLD_DATA0;
    uint64_t expected_generation = 2;
    uint64_t log_count = 0;
    uint64_t latest_snap_off = 0;
    uint64_t latest_snap_generation = 0;
    while (object_off < s.data_head) {
        cold_obj_hdr_t h;
        cold_result_t r = object_validate(
            &s, object_off, 0, expected_generation, &h);
        if (r != COLD_RESULT_VALID)
            return r;
        if (h.kind == KIND_LOG)
            log_count++;
        if (h.kind == KIND_SNAP) {
            latest_snap_off = object_off;
            latest_snap_generation = h.generation;
        }
        if (object_off == s.snap_off && h.kind != KIND_SNAP)
            return COLD_RESULT_KIND;
        if (!align8_checked(object_off + sizeof h + h.len, &object_off))
            return COLD_RESULT_LENGTH;
        if (expected_generation == UINT64_MAX)
            return COLD_RESULT_GENERATION;
        expected_generation++;
    }
    if (object_off != s.data_head
        || expected_generation != s.generation + 1)
        return COLD_RESULT_GENERATION;
    if (log_count != s.log_count)
        return COLD_RESULT_GENERATION;
    if (s.snap_off != latest_snap_off
        || s.snap_generation != latest_snap_generation)
        return COLD_RESULT_GENERATION;
    if (out)
        *out = s;
    return COLD_RESULT_VALID;
}

static cold_result_t select_super(cold_super_t *out, int *slot_out)
{
    cold_super_t a, b;
    cold_result_t ra = super_validate(COLD_SLOT0, &a);
    cold_result_t rb = super_validate(COLD_SLOT1, &b);
    if (ra == COLD_RESULT_VALID || rb == COLD_RESULT_VALID) {
        if (ra == COLD_RESULT_VALID && rb == COLD_RESULT_VALID
            && a.generation == b.generation
            && !bytes_eq((const uint8_t *)&a,
                         (const uint8_t *)&b, sizeof a)) {
            g_selected_generation = 0;
            g_selected_data_head = 0;
            g_last_result = COLD_RESULT_CORRUPT;
            return COLD_RESULT_CORRUPT;
        }
        int slot = 0;
        cold_super_t selected = a;
        if (ra != COLD_RESULT_VALID
            || (rb == COLD_RESULT_VALID && b.generation > a.generation)) {
            selected = b;
            slot = 1;
        }
        if (out)
            *out = selected;
        if (slot_out)
            *slot_out = slot;
        g_selected_generation = selected.generation;
        g_selected_data_head = selected.data_head;
        g_last_result = COLD_RESULT_VALID;
        return COLD_RESULT_VALID;
    }
    if (media_blank()) {
        g_selected_generation = 0;
        g_selected_data_head = 0;
        g_last_result = COLD_RESULT_EMPTY;
        return COLD_RESULT_EMPTY;
    }
    cold_super_t raw0, raw1;
    cold_read(COLD_SLOT0, &raw0, sizeof raw0);
    cold_read(COLD_SLOT1, &raw1, sizeof raw1);
    if ((raw0.magic == COLD_MAGIC && raw0.version != COLD_VERSION)
        || (raw1.magic == COLD_MAGIC && raw1.version != COLD_VERSION)) {
        g_last_result = COLD_RESULT_UNSUPPORTED;
        return COLD_RESULT_UNSUPPORTED;
    }
    g_last_result = COLD_RESULT_CORRUPT;
    return COLD_RESULT_CORRUPT;
}

int cold_format(void)
{
    uint8_t zero[256];
    for (size_t i = 0; i < sizeof zero; i++)
        zero[i] = 0;
    /*
     * Formatting is a logical reset. Bytes beyond data_head are unreachable
     * and cannot be selected by a validated superblock.
     */
    for (uint64_t off = 0; off < COLD_DATA0; off += sizeof zero) {
        cold_write_raw(off, zero, sizeof zero);
    }
    cold_super_t s = {0};
    s.magic = COLD_MAGIC;
    s.version = COLD_VERSION;
    s.header_len = sizeof s;
    s.generation = 1;
    s.data_head = COLD_DATA0;
    s.commit = COLD_COMMIT;
    super_checksum(&s);
    cold_write_raw(COLD_SLOT0, &s, sizeof s);
    if (cold_media_active()
        && (cold_media_write(COLD_MEDIA_PHASE_FORMAT, 0,
                             (const void *)(uintptr_t)COLD_BASE,
                             COLD_DATA0, media_deadline()) != COLD_MEDIA_OK
            || cold_media_barrier(COLD_MEDIA_PHASE_SUPERBLOCK_BARRIER,
                                  media_deadline()) != COLD_MEDIA_OK)) {
        g_selected_generation = 0;
        g_selected_data_head = 0;
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    g_selected_generation = 1;
    g_selected_data_head = COLD_DATA0;
    g_last_result = COLD_RESULT_VALID;
    return 0;
}

int cold_init(void)
{
    cold_media_status_t media = cold_media_load_window(media_deadline());
    if (media != COLD_MEDIA_OK && media != COLD_MEDIA_DISABLED) {
        g_selected_generation = 0;
        g_selected_data_head = 0;
        if (media == COLD_MEDIA_ABSENT || media == COLD_MEDIA_REMOVED)
            g_last_result = COLD_RESULT_ABSENT;
        else if (media == COLD_MEDIA_LAYOUT
                 || media == COLD_MEDIA_UNDERSIZED
                 || media == COLD_MEDIA_UNSUPPORTED)
            g_last_result = COLD_RESULT_UNSUPPORTED;
        else
            g_last_result = COLD_RESULT_CORRUPT;
        return g_last_result;
    }
    cold_result_t result = select_super(0, 0);
    if (result == COLD_RESULT_EMPTY) {
        if (cold_format() != 0)
            return g_last_result;
        /* documented all-zero initialization only */
        g_last_result = COLD_RESULT_EMPTY;
        return COLD_RESULT_EMPTY;
    }
    return result;
}

static int jam_bytes(noun n, const uint8_t **out, uint64_t *out_len)
{
    uint64_t checked_len;
    if (jam_size_checked(n, JAM_MAX_BYTES, &checked_len) != 0)
        return -1;
    noun a = jam(n);
    if (noun_is_direct(a)) {
        uint64_t v = direct_val(a);
        uint64_t nbytes = 0;
        for (int i = 0; i < 8; i++) {
            jam_scratch[i] = (uint8_t)(v & 0xff);
            if (jam_scratch[i])
                nbytes = (uint64_t)i + 1;
            v >>= 8;
        }
        if (nbytes == 0)
            nbytes = 1;
        *out = jam_scratch;
        *out_len = nbytes;
        return 0;
    }
    if (!noun_is_indirect(a))
        return -1;
    atom_t *at = atom_store_get(indirect_hash(a));
    if (!at)
        return -1;
    uint64_t nbytes = at->size * 8;
    const uint8_t *bytes = (const uint8_t *)at->limbs;
    while (nbytes > 1 && bytes[nbytes - 1] == 0)
        nbytes--;
    if (nbytes > JAM_SCRATCH_MAX || nbytes > checked_len)
        return -1;
    for (uint64_t i = 0; i < nbytes; i++)
        jam_scratch[i] = bytes[i];
    *out = jam_scratch;
    *out_len = nbytes;
    return 0;
}

static int append_obj(uint32_t kind, const uint8_t *payload, uint64_t len,
                      uint64_t *off_out)
{
    if (!payload || len == 0 || len > JAM_SCRATCH_MAX) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    for (uint64_t i = 0; i < len; i++)
        append_scratch[i] = payload[i];
    payload = append_scratch;

    cold_super_t old;
    int old_slot;
    if (select_super(&old, &old_slot) != COLD_RESULT_VALID)
        return -1;
    if (old.generation == UINT64_MAX) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    uint64_t new_head;
    if (old.data_head > UINT64_MAX - sizeof(cold_obj_hdr_t) - len
        || !align8_checked(old.data_head + sizeof(cold_obj_hdr_t) + len,
                           &new_head)
        || new_head > COLD_SIZE) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    uint64_t generation = old.generation + 1;
    cold_obj_hdr_t h = {0};
    h.magic = COLD_OBJ_MAGIC;
    h.version = COLD_VERSION;
    h.header_len = sizeof h;
    h.kind = kind;
    h.generation = generation;
    h.len = len;
    blake3_hash(payload, (size_t)len, h.payload_digest);
    object_header_digest(&h);
    h.commit = 0;
    uint64_t off = old.data_head;
    if (!cold_write_phase(COLD_WRITE_OBJECT_HEADER, off, &h, sizeof h)
        || !cold_write_phase(COLD_WRITE_PAYLOAD, off + sizeof h, payload, len)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    uint64_t commit = COLD_COMMIT;
    if (!cold_write_phase(COLD_WRITE_OBJECT_COMMIT,
                          off + offsetof(cold_obj_hdr_t, commit),
                          &commit, sizeof commit)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    if (cold_media_active()
        && cold_media_barrier(COLD_MEDIA_PHASE_DATA_BARRIER,
                              media_deadline()) != COLD_MEDIA_OK) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    cold_super_t next = old;
    next.generation = generation;
    next.data_head = new_head;
    if (kind == KIND_LOG)
        next.log_count++;
    if (kind == KIND_SNAP) {
        next.snap_generation = generation;
        next.snap_off = off;
    }
    for (size_t i = 0; i < sizeof next.checksum; i++)
        next.checksum[i] = 0;
    super_checksum(&next);
    uint64_t next_slot = old_slot == 0 ? COLD_SLOT1 : COLD_SLOT0;
    if (!cold_write_phase(COLD_WRITE_SUPERBLOCK, next_slot,
                          &next, sizeof next)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    if (cold_media_active()
        && cold_media_barrier(COLD_MEDIA_PHASE_SUPERBLOCK_BARRIER,
                              media_deadline()) != COLD_MEDIA_OK) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    g_selected_generation = generation;
    g_selected_data_head = new_head;
    g_last_result = COLD_RESULT_VALID;
    if (off_out)
        *off_out = off;
    return 0;
}

static int decode_object(const cold_super_t *s, uint64_t off,
                         uint32_t kind, int heap_mode, noun *out)
{
    cold_obj_hdr_t h;
    cold_result_t r = object_validate(s, off, kind, 0, &h);
    if (r != COLD_RESULT_VALID) {
        g_last_result = r;
        return -1;
    }
    /* object_validate left the verified payload in jam_scratch */
    cue_bounded_limits_t limits = cue_i2_limits;
    limits.max_input_bytes = JAM_SCRATCH_MAX;
    cue_bounded_status_t cue_status = cue_bounded_bytes(
        jam_scratch, h.len, &limits, heap_mode, out);
    if (cue_status != CUE_BOUNDED_OK) {
        g_last_result = COLD_RESULT_CUE;
        return -1;
    }
    return 0; /* noun transaction remains active */
}

uint64_t cold_store(noun n)
{
    const uint8_t *bytes;
    uint64_t len, off;
    if (jam_bytes(n, &bytes, &len) != 0
        || append_obj(KIND_BLOB, bytes, len, &off) != 0)
        return 0;
    cold_super_t s;
    cold_obj_hdr_t h;
    if (select_super(&s, 0) != COLD_RESULT_VALID
        || object_validate(&s, off, KIND_BLOB, 0, &h) != COLD_RESULT_VALID)
        return 0;
    return hash62_of(h.payload_digest);
}

static int append_plan(const cold_super_t *old, uint64_t len,
                       uint64_t *off_out, uint64_t *head_out)
{
    uint64_t head;
    if (!old || !off_out || !head_out || len == 0 || len > JAM_SCRATCH_MAX
        || old->generation > UINT64_MAX - 2
        || old->data_head > UINT64_MAX - sizeof(cold_obj_hdr_t) - len
        || !align8_checked(old->data_head + sizeof(cold_obj_hdr_t) + len,
                           &head)
        || head > COLD_SIZE) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    *off_out = old->data_head;
    *head_out = head;
    return 0;
}

static int append_obj_unselected(const cold_super_t *old, uint32_t kind,
                                 const uint8_t *payload, uint64_t len,
                                 uint64_t generation, uint64_t off,
                                 uint64_t head)
{
    if (!old || !payload || len == 0 || len > JAM_SCRATCH_MAX
        || generation == 0 || off < COLD_DATA0 || head <= off) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    cold_obj_hdr_t h = {0};
    h.magic = COLD_OBJ_MAGIC;
    h.version = COLD_VERSION;
    h.header_len = sizeof h;
    h.kind = kind;
    h.generation = generation;
    h.len = len;
    blake3_hash(payload, (size_t)len, h.payload_digest);
    object_header_digest(&h);
    if (!cold_write_phase(COLD_WRITE_OBJECT_HEADER, off, &h, sizeof h)
        || !cold_write_phase(COLD_WRITE_PAYLOAD, off + sizeof h, payload, len)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    uint64_t commit = COLD_COMMIT;
    if (!cold_write_phase(COLD_WRITE_OBJECT_COMMIT,
                          off + offsetof(cold_obj_hdr_t, commit),
                          &commit, sizeof commit)
        || (cold_media_active()
            && cold_media_barrier(COLD_MEDIA_PHASE_DATA_BARRIER,
                                  media_deadline()) != COLD_MEDIA_OK)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    cold_super_t provisional = *old;
    provisional.generation = generation;
    provisional.data_head = head;
    if (object_validate(&provisional, off, kind, generation, 0)
        != COLD_RESULT_VALID) {
        g_last_result = COLD_RESULT_PAYLOAD_DIGEST;
        return -1;
    }
    return 0;
}

int cold_store_deployment(noun pill_blob, noun supervisor_snapshot,
                          uint64_t *pill_hash_out)
{
    uint64_t pill_len, snapshot_len;
    const uint8_t *bytes;
    cold_super_t old, next;
    int old_slot;
    uint64_t pill_off, pill_head, snapshot_off, snapshot_head;
    uint8_t pill_digest[32];

    /* Plan both object extents before writing a byte. */
    if (jam_size_checked(pill_blob, JAM_MAX_BYTES, &pill_len) != 0
        || jam_size_checked(supervisor_snapshot, JAM_MAX_BYTES, &snapshot_len) != 0
        || select_super(&old, &old_slot) != COLD_RESULT_VALID
        || append_plan(&old, pill_len, &pill_off, &pill_head) != 0) {
        return -1;
    }
    cold_super_t after_pill = old;
    after_pill.generation = old.generation + 1;
    after_pill.data_head = pill_head;
    if (append_plan(&after_pill, snapshot_len, &snapshot_off, &snapshot_head)
        != 0)
        return -1;

    if (jam_bytes(pill_blob, &bytes, &pill_len) != 0) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    blake3_hash(bytes, (size_t)pill_len, pill_digest);
    if (append_obj_unselected(&old, KIND_BLOB, bytes, pill_len,
                              old.generation + 1, pill_off, pill_head) != 0)
        return -1;
    /* The blob is read-verified before the snapshot and selection write. */
    if (object_validate(&after_pill, pill_off, KIND_BLOB,
                        old.generation + 1, 0) != COLD_RESULT_VALID)
        return -1;

    if (jam_bytes(supervisor_snapshot, &bytes, &snapshot_len) != 0) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    if (append_obj_unselected(&after_pill, KIND_SNAP, bytes, snapshot_len,
                              old.generation + 2, snapshot_off,
                              snapshot_head) != 0)
        return -1;

    next = after_pill;
    next.generation = old.generation + 2;
    next.data_head = snapshot_head;
    next.snap_generation = old.generation + 2;
    next.snap_off = snapshot_off;
    for (size_t i = 0; i < sizeof next.checksum; i++) next.checksum[i] = 0;
    super_checksum(&next);
    uint64_t next_slot = old_slot == 0 ? COLD_SLOT1 : COLD_SLOT0;
    if (!cold_write_phase(COLD_WRITE_SUPERBLOCK, next_slot,
                          &next, sizeof next)
        || (cold_media_active()
            && cold_media_barrier(COLD_MEDIA_PHASE_SUPERBLOCK_BARRIER,
                                  media_deadline()) != COLD_MEDIA_OK)) {
        g_last_result = COLD_RESULT_WRITE_FAULT;
        return -1;
    }
    g_selected_generation = next.generation;
    g_selected_data_head = next.data_head;
    g_last_result = COLD_RESULT_VALID;
    if (pill_hash_out)
        *pill_hash_out = hash62_of(pill_digest);
    return 0;
}

uint64_t cold_jam_hash(noun n)
{
    const uint8_t *bytes;
    uint64_t len;
    uint8_t digest[32];
    if (jam_bytes(n, &bytes, &len) != 0)
        return 0;
    blake3_hash(bytes, (size_t)len, digest);
    return hash62_of(digest);
}

noun cold_load(uint64_t hash62)
{
    cold_super_t s;
    if (hash62 == 0 || select_super(&s, 0) != COLD_RESULT_VALID)
        return NOUN_ZERO;
    uint64_t off = COLD_DATA0;
    while (off < s.data_head) {
        cold_obj_hdr_t h;
        cold_result_t r = object_validate(&s, off, 0, 0, &h);
        if (r != COLD_RESULT_VALID) {
            g_last_result = r;
            return NOUN_ZERO;
        }
        if (h.kind == KIND_BLOB && hash62_of(h.payload_digest) == hash62) {
            noun out;
            if (decode_object(&s, off, KIND_BLOB,
                              HEAP_MODE_PERSIST, &out) != 0)
                return NOUN_ZERO;
            noun_tx_commit();
            return out;
        }
        if (!align8_checked(off + sizeof h + h.len, &off))
            break;
    }
    g_last_result = COLD_RESULT_ABSENT;
    return NOUN_ZERO;
}

int cold_log(noun event)
{
    const uint8_t *bytes;
    uint64_t len;
    return jam_bytes(event, &bytes, &len) == 0
        ? append_obj(KIND_LOG, bytes, len, 0) : -1;
}

uint64_t cold_log_len(void)
{
    cold_super_t s;
    return select_super(&s, 0) == COLD_RESULT_VALID ? s.log_count : 0;
}

noun cold_log_at(uint64_t index)
{
    cold_super_t s;
    if (select_super(&s, 0) != COLD_RESULT_VALID || index >= s.log_count)
        return NOUN_ZERO;
    uint64_t off = COLD_DATA0;
    uint64_t seen = 0;
    while (off < s.data_head) {
        cold_obj_hdr_t h;
        cold_result_t r = object_validate(&s, off, 0, 0, &h);
        if (r != COLD_RESULT_VALID) {
            g_last_result = r;
            return NOUN_ZERO;
        }
        if (h.kind == KIND_LOG && seen++ == index) {
            noun out;
            if (decode_object(&s, off, KIND_LOG,
                              HEAP_MODE_PERSIST, &out) != 0)
                return NOUN_ZERO;
            noun_tx_commit();
            return out;
        }
        if (!align8_checked(off + sizeof h + h.len, &off))
            break;
    }
    return NOUN_ZERO;
}

int cold_snap_save(noun root)
{
    const uint8_t *bytes;
    uint64_t len;
    uint64_t jam_start = runtime_counter_now();
    if (jam_bytes(root, &bytes, &len) != 0) {
        g_last_result = COLD_RESULT_LENGTH;
        return -1;
    }
    uint64_t jam_end = runtime_counter_now();
    runtime_stats_record(RT_PHASE_CHECKPOINT_JAM,
                         jam_end >= jam_start ? jam_end - jam_start : 0);
    runtime_stats_set(RT_COUNT_CHECKPOINT_BYTES, len);
    uint64_t append_start = runtime_counter_now();
    int result = append_obj(KIND_SNAP, bytes, len, 0);
    uint64_t append_end = runtime_counter_now();
    runtime_stats_record(
        RT_PHASE_CHECKPOINT_COLD_APPEND,
        append_end >= append_start ? append_end - append_start : 0);
    if (result == 0) {
        runtime_stats_set(
            RT_COUNT_CHECKPOINT_GENERATION, g_selected_generation);
        runtime_stats_set(RT_COUNT_COLD_DATA_HEAD, g_selected_data_head);
    }
    return result;
}

int cold_snap_decode(noun *out)
{
    cold_super_t s;
    if (!out || select_super(&s, 0) != COLD_RESULT_VALID)
        return -1;
    if (s.snap_off == 0) {
        g_last_result = COLD_RESULT_ABSENT;
        return -1;
    }
    if (decode_object(&s, s.snap_off, KIND_SNAP,
                      HEAP_MODE_SCRATCH, out) != 0)
        return -1;
    g_last_result = COLD_RESULT_VALID;
    return 0;
}

noun cold_snap_load(void)
{
    noun out;
    if (cold_snap_decode(&out) != 0)
        return NOUN_ZERO;
    noun_tx_commit();
    return out;
}

cold_result_t cold_probe(void)
{
    return select_super(0, 0);
}

cold_result_t cold_last_result(void)
{
    return g_last_result;
}

uint64_t cold_selected_generation(void)
{
    return g_selected_generation;
}

uint64_t cold_data_head(void)
{
    return g_selected_data_head;
}

void cold_fault_set(cold_write_phase_t phase, int64_t after_bytes)
{
    g_fault.phase = phase;
    g_fault.after = after_bytes;
    g_fault.fired = 0;
}

void cold_fault_clear(void)
{
    g_fault.phase = COLD_WRITE_NONE;
    g_fault.after = -1;
    g_fault.fired = 0;
}

const char *cold_result_name(cold_result_t result)
{
    switch (result) {
    case COLD_RESULT_VALID: return "valid";
    case COLD_RESULT_EMPTY: return "empty";
    case COLD_RESULT_ABSENT: return "absent";
    case COLD_RESULT_CORRUPT: return "corrupt";
    case COLD_RESULT_UNSUPPORTED: return "unsupported";
    case COLD_RESULT_SUPERBLOCK: return "superblock";
    case COLD_RESULT_OFFSET: return "offset";
    case COLD_RESULT_ALIGNMENT: return "alignment";
    case COLD_RESULT_HEADER: return "header";
    case COLD_RESULT_KIND: return "kind";
    case COLD_RESULT_LENGTH: return "length";
    case COLD_RESULT_HEADER_DIGEST: return "header-digest";
    case COLD_RESULT_PAYLOAD_DIGEST: return "payload-digest";
    case COLD_RESULT_GENERATION: return "generation";
    case COLD_RESULT_COMMIT: return "commit";
    case COLD_RESULT_CUE: return "cue";
    case COLD_RESULT_SHAPE: return "shape";
    case COLD_RESULT_IDENTITY: return "identity";
    case COLD_RESULT_ALLOC: return "alloc";
    case COLD_RESULT_WRITE_FAULT: return "write-fault";
    default: return "unknown";
    }
}

static int selftest_load(uint64_t expected)
{
    heap_scratch_reset();
    noun got = cold_snap_load();
    int ok = noun_is_direct(got) && direct_val(got) == expected;
    heap_set_mode(HEAP_MODE_PERSIST);
    heap_scratch_reset();
    return ok;
}

uint64_t cold_m2_selftest(void)
{
    uint64_t failures = 0;
    cold_super_t s, bad_s;
    cold_obj_hdr_t h, bad_h;
    int slot;
    uint64_t slot_off;

    cold_fault_clear();
    cold_format();
    if (cold_snap_save(direct(42)) != 0
        || select_super(&s, &slot) != COLD_RESULT_VALID
        || s.snap_off == 0) {
        cold_format();
        return UINT64_MAX;
    }
    slot_off = slot ? COLD_SLOT1 : COLD_SLOT0;
    cold_read(s.snap_off, &h, sizeof h);

    bad_s = s;
    bad_s.checksum[0] ^= 1;
    cold_write_raw(slot_off, &bad_s, sizeof bad_s);
    if (super_validate(slot_off, 0) != COLD_RESULT_SUPERBLOCK)
        failures |= 1ULL << 0;
    cold_write_raw(slot_off, &s, sizeof s);

    bad_s = s;
    bad_s.snap_off++;
    super_checksum(&bad_s);
    cold_write_raw(slot_off, &bad_s, sizeof bad_s);
    if (super_validate(slot_off, 0) != COLD_RESULT_ALIGNMENT)
        failures |= 1ULL << 1;
    cold_write_raw(slot_off, &s, sizeof s);

    bad_s = s;
    bad_s.snap_off = COLD_SIZE;
    super_checksum(&bad_s);
    cold_write_raw(slot_off, &bad_s, sizeof bad_s);
    if (super_validate(slot_off, 0) != COLD_RESULT_OFFSET)
        failures |= 1ULL << 2;
    cold_write_raw(slot_off, &s, sizeof s);

    bad_h = h;
    bad_h.kind = KIND_BLOB;
    object_header_digest(&bad_h);
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_KIND)
        failures |= 1ULL << 3;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.len = JAM_SCRATCH_MAX + 1;
    object_header_digest(&bad_h);
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_LENGTH)
        failures |= 1ULL << 4;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.payload_digest[0] ^= 1;
    object_header_digest(&bad_h);
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_PAYLOAD_DIGEST)
        failures |= 1ULL << 5;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.header_digest[0] ^= 1;
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_HEADER_DIGEST)
        failures |= 1ULL << 6;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.generation++;
    object_header_digest(&bad_h);
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_GENERATION)
        failures |= 1ULL << 7;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.commit = 0;
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_COMMIT)
        failures |= 1ULL << 8;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_h = h;
    bad_h.magic ^= 1;
    object_header_digest(&bad_h);
    cold_write_raw(s.snap_off, &bad_h, sizeof bad_h);
    if (super_validate(slot_off, 0) != COLD_RESULT_HEADER)
        failures |= 1ULL << 9;
    cold_write_raw(s.snap_off, &h, sizeof h);

    bad_s = s;
    bad_s.commit = 0;
    super_checksum(&bad_s);
    cold_write_raw(slot_off, &bad_s, sizeof bad_s);
    if (super_validate(slot_off, 0) != COLD_RESULT_SUPERBLOCK)
        failures |= 1ULL << 10;
    cold_write_raw(slot_off, &s, sizeof s);

    /* Nonblank corrupt and unsupported media must not be auto-formatted. */
    cold_format();
    cold_read(COLD_SLOT0, &s, sizeof s);
    s.checksum[0] ^= 1;
    cold_write_raw(COLD_SLOT0, &s, sizeof s);
    if (cold_init() != COLD_RESULT_CORRUPT
        || ((cold_super_t *)(uintptr_t)(COLD_BASE + COLD_SLOT0))->magic
            != COLD_MAGIC)
        failures |= 1ULL << 11;

    cold_format();
    cold_read(COLD_SLOT0, &s, sizeof s);
    s.version = COLD_VERSION + 1;
    cold_write_raw(COLD_SLOT0, &s, sizeof s);
    if (cold_init() != COLD_RESULT_UNSUPPORTED
        || ((cold_super_t *)(uintptr_t)(COLD_BASE + COLD_SLOT0))->version
            != COLD_VERSION + 1)
        failures |= 1ULL << 12;

    /* Every byte cut in every write phase selects old or fully committed new. */
    static const struct {
        cold_write_phase_t phase;
        uint64_t size;
    } phases[] = {
        { COLD_WRITE_OBJECT_HEADER, COLD_OBJ_SIZE },
        { COLD_WRITE_PAYLOAD, 2 },
        { COLD_WRITE_OBJECT_COMMIT, 8 },
        { COLD_WRITE_SUPERBLOCK, COLD_SUPER_SIZE }
    };
    for (size_t p = 0; p < sizeof phases / sizeof phases[0]; p++) {
        for (uint64_t cut = 0; cut <= phases[p].size; cut++) {
            cold_format();
            if (cold_snap_save(direct(42)) != 0) {
                failures |= 1ULL << (16 + p);
                continue;
            }
            cold_fault_set(phases[p].phase, (int64_t)cut);
            if (cold_snap_save(direct(43)) == 0)
                failures |= 1ULL << (20 + p);
            cold_fault_clear();
            if (cold_probe() != COLD_RESULT_VALID) {
                failures |= 1ULL << (24 + p);
                continue;
            }
            uint64_t generation = cold_selected_generation();
            if ((generation == 2 && !selftest_load(42))
                || (generation == 3 && !selftest_load(43))
                || (generation != 2 && generation != 3))
                failures |= 1ULL << (28 + p);
        }
    }

    cold_fault_clear();
    cold_format();
    return failures;
}
