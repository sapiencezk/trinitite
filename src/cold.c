#include <stdint.h>
#include "cold.h"
#include "memory.h"
#include "noun.h"
#include "jam.h"
#include "blake3.h"

#define COLD_MAGIC    0x54524E54C01DC01DULL  /* "TRNT" + cold marker */
#define COLD_VERSION  1ULL
#define COLD_DATA0    0x1000ULL              /* first object offset */

#define KIND_BLOB  1ULL
#define KIND_LOG   2ULL
#define KIND_SNAP  3ULL

typedef struct {
    uint64_t magic;
    uint64_t version;
    uint64_t epoch;
    uint64_t snap_off;     /* 0 = none; else offset of snap object hdr */
    uint64_t log_count;
    uint64_t data_head;    /* next free offset from COLD_BASE */
    uint64_t _pad[2];
} cold_super_t;

typedef struct {
    uint8_t  hash[32];     /* BLAKE3-256 of payload */
    uint64_t len;          /* payload bytes */
    uint64_t kind;
    uint64_t hash62;       /* denormalized key for scan */
} cold_obj_hdr_t;

/* ── RAM backend ─────────────────────────────────────────────────────────── */

static void cold_read(uint64_t off, void *dst, uint64_t n)
{
    const uint8_t *src = (const uint8_t *)(uintptr_t)(COLD_BASE + off);
    uint8_t *d = (uint8_t *)dst;
    for (uint64_t i = 0; i < n; i++)
        d[i] = src[i];
}

static void cold_write(uint64_t off, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)(uintptr_t)(COLD_BASE + off);
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

static uint64_t align8(uint64_t n)
{
    return (n + 7ULL) & ~7ULL;
}

/* ── jam atom → raw bytes in a static scratch (max 256 KB) ───────────────── */

#define JAM_SCRATCH_MAX  (256U * 1024U)
static uint8_t jam_scratch[JAM_SCRATCH_MAX];

static int jam_bytes(noun n, const uint8_t **out, uint64_t *out_len)
{
    noun a = jam(n);
    if (noun_is_direct(a)) {
        uint64_t val = direct_val(a);
        uint64_t nbytes = 0;
        uint8_t tmp[8];
        for (int i = 0; i < 8; i++) {
            tmp[i] = (uint8_t)(val & 0xFF);
            if (tmp[i]) nbytes = (uint64_t)i + 1;
            val >>= 8;
        }
        if (nbytes == 0) nbytes = 1;
        for (uint64_t i = 0; i < nbytes; i++)
            jam_scratch[i] = tmp[i];
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
    if (nbytes > JAM_SCRATCH_MAX)
        return -1;
    for (uint64_t i = 0; i < nbytes; i++)
        jam_scratch[i] = bytes[i];
    *out = jam_scratch;
    *out_len = nbytes;
    return 0;
}

static uint64_t hash62_of(const uint8_t h[32])
{
    uint64_t hash62 = 0;
    for (int i = 0; i < 8; i++)
        hash62 |= (uint64_t)h[i] << (i * 8);
    hash62 &= 0x3FFFFFFFFFFFFFFFULL;
    if (hash62 == 0)
        hash62 = 1;
    return hash62;
}

static int hash_eq32(const uint8_t a[32], const uint8_t b[32])
{
    for (int i = 0; i < 32; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/* ── format / init ───────────────────────────────────────────────────────── */

int cold_format(void)
{
    /* Zero superblock page */
    uint8_t z = 0;
    for (uint64_t i = 0; i < COLD_DATA0; i++)
        cold_write(i, &z, 1);

    cold_super_t s;
    s.magic     = COLD_MAGIC;
    s.version   = COLD_VERSION;
    s.epoch     = 1;
    s.snap_off  = 0;
    s.log_count = 0;
    s.data_head = COLD_DATA0;
    s._pad[0] = s._pad[1] = 0;
    cold_write(0, &s, sizeof(s));
    return 0;
}

int cold_init(void)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));
    if (s.magic != COLD_MAGIC || s.version != COLD_VERSION ||
        s.data_head < COLD_DATA0 || s.data_head > COLD_SIZE)
        return cold_format();
    return 0;
}

/* ── object scan / append ────────────────────────────────────────────────── */

/* Find object with hash62; set *off to header offset. Returns 1 if found. */
static int find_hash(uint64_t hash62, uint64_t *off_out)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));
    uint64_t off = COLD_DATA0;
    while (off + sizeof(cold_obj_hdr_t) <= s.data_head) {
        cold_obj_hdr_t h;
        cold_read(off, &h, sizeof(h));
        if (h.len > COLD_SIZE || off + sizeof(h) + h.len > s.data_head)
            break;
        if (h.hash62 == hash62) {
            *off_out = off;
            return 1;
        }
        off = align8(off + sizeof(h) + h.len);
    }
    return 0;
}

static int append_obj(uint64_t kind, const uint8_t *payload, uint64_t len,
                      uint64_t *off_out)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));

    uint8_t h[32];
    blake3_hash(payload, (size_t)len, h);
    uint64_t h62 = hash62_of(h);

    /* Idempotent: blob with same hash already present */
    uint64_t existing;
    if (kind == KIND_BLOB && find_hash(h62, &existing)) {
        cold_obj_hdr_t eh;
        cold_read(existing, &eh, sizeof(eh));
        if (hash_eq32(eh.hash, h) && eh.len == len) {
            if (off_out) *off_out = existing;
            return 0;
        }
    }

    uint64_t need = align8(sizeof(cold_obj_hdr_t) + len);
    if (s.data_head + need > COLD_SIZE)
        return -1;

    cold_obj_hdr_t hdr;
    for (int i = 0; i < 32; i++)
        hdr.hash[i] = h[i];
    hdr.len    = len;
    hdr.kind   = kind;
    hdr.hash62 = h62;

    uint64_t off = s.data_head;
    cold_write(off, &hdr, sizeof(hdr));
    if (len)
        cold_write(off + sizeof(hdr), payload, len);

    s.data_head = align8(off + sizeof(hdr) + len);
    s.epoch++;
    if (kind == KIND_LOG)
        s.log_count++;
    if (kind == KIND_SNAP)
        s.snap_off = off;
    cold_write(0, &s, sizeof(s));

    if (off_out) *off_out = off;
    return 0;
}

static noun load_at_off(uint64_t off)
{
    cold_obj_hdr_t h;
    cold_read(off, &h, sizeof(h));
    if (h.len == 0 || h.len > JAM_SCRATCH_MAX)
        return NOUN_ZERO;
    cold_read(off + sizeof(h), jam_scratch, h.len);

    /* zero-pad to limb boundary for make_atom / cue path */
    uint64_t padded = align8(h.len);
    for (uint64_t i = h.len; i < padded && i < JAM_SCRATCH_MAX; i++)
        jam_scratch[i] = 0;

    uint64_t nlimbs = padded / 8;
    if (nlimbs == 0) nlimbs = 1;
    while (nlimbs > 1 && ((uint64_t *)jam_scratch)[nlimbs - 1] == 0)
        nlimbs--;

    noun jam_atom = make_atom((uint64_t *)jam_scratch, nlimbs);
    return cue(jam_atom);
}

/* ── public API ──────────────────────────────────────────────────────────── */

uint64_t cold_store(noun n)
{
    const uint8_t *bytes;
    uint64_t len;
    if (jam_bytes(n, &bytes, &len) != 0)
        return 0;
    uint64_t off;
    if (append_obj(KIND_BLOB, bytes, len, &off) != 0)
        return 0;
    cold_obj_hdr_t h;
    cold_read(off, &h, sizeof(h));
    return h.hash62;
}

noun cold_load(uint64_t hash62)
{
    if (hash62 == 0)
        return NOUN_ZERO;
    uint64_t off;
    if (!find_hash(hash62, &off))
        return NOUN_ZERO;
    return load_at_off(off);
}

int cold_log(noun event)
{
    const uint8_t *bytes;
    uint64_t len;
    if (jam_bytes(event, &bytes, &len) != 0)
        return -1;
    return append_obj(KIND_LOG, bytes, len, 0);
}

uint64_t cold_log_len(void)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));
    return s.log_count;
}

noun cold_log_at(uint64_t i)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));
    if (i >= s.log_count)
        return NOUN_ZERO;

    uint64_t off = COLD_DATA0;
    uint64_t seen = 0;
    while (off + sizeof(cold_obj_hdr_t) <= s.data_head) {
        cold_obj_hdr_t h;
        cold_read(off, &h, sizeof(h));
        if (h.len > COLD_SIZE || off + sizeof(h) + h.len > s.data_head)
            break;
        if (h.kind == KIND_LOG) {
            if (seen == i)
                return load_at_off(off);
            seen++;
        }
        off = align8(off + sizeof(h) + h.len);
    }
    return NOUN_ZERO;
}

int cold_snap_save(noun root)
{
    const uint8_t *bytes;
    uint64_t len;
    if (jam_bytes(root, &bytes, &len) != 0)
        return -1;
    /* RAM snap only — NVFLUSH (semihost) is explicit so bare QEMU tests
     * do not execute HLT #0xF000 without -semihosting. */
    return append_obj(KIND_SNAP, bytes, len, 0);
}

noun cold_snap_load(void)
{
    cold_super_t s;
    cold_read(0, &s, sizeof(s));
    if (s.snap_off == 0)
        return NOUN_ZERO;
    return load_at_off(s.snap_off);
}
