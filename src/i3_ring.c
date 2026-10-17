/* SPDX-License-Identifier: MIT */
/*
 * Row 212 PR 1c: the recorder ring (i3_ring.h has the layout). The working
 * copy is a RAM window of I3_RING_BYTES at I3_RING_WINDOW_BASE (memory.h);
 * each change is mirrored to the media:
 *   COLD_MEDIA=rpi4-sd  write-through by whole sectors to the ring extent
 *                       (cold_media_ring_*, cold_media.h; loaded whole at
 *                       boot, 5 s per 256 KiB chunk, 60 s in total),
 *   COLD_MEDIA=fake     the same path on the fake backend's ring extent
 *                       (RAM, for the fault tests; the ring must be small),
 *   COLD_MEDIA=semihost the changed bytes go to the host file build/ring.img
 *                       at each i3_ring_flush (QEMU tests reload it with
 *                       -device loader at the window address),
 *   COLD_MEDIA=ram      RAM only (volatile).
 *
 * Faults. A ring media fault (load, write or barrier) is logged
 * (`I3H ring media fault op=... status=...`) and turns the ring off for the
 * rest of the boot (`I3H ring off reason=media`). It never sets the cold
 * session's reset state (cold_media.c), so the cold log and the node go on.
 *
 * Order per record: free space (evict oldest segments, wrap), and if that
 * moved the tail or the head: write the wrap marker, barrier, commit the
 * header (header sector, barrier). Then write the record, barrier, commit
 * the header. A commit always goes to the other header slot, so the
 * previous header stays on the media until the new one has landed.
 *
 * What this does and does not guarantee. Writes are whole sectors from the
 * window. The first sector of a record can hold the end of the last
 * committed record, so a torn write of that sector can damage that record.
 * The writer keeps the oldest live record's sector out of every write (it
 * evicts until the record ends below the tail's sector), so a torn write
 * cannot reach it. Boot checks the newest valid header's chain; if it is
 * broken it tries the other slot, then the longest valid prefix from the
 * tail of either slot (and commits that). It formats only an extent that is
 * all zero (status=fresh) or holds a whole header of its own for another ring
 * size (status=reformat), and never after a chain check fails. Its own magic
 * with no header or record to trust is status=corrupt; anything else is
 * status=foreign. Both leave the media as it is and run without the ring.
 * GAP (Steward's ruling): a zero range that belongs to someone else is still
 * formatted; see docs/lite-checkpoint-writer.md. Not measured on the board: SD append time, torn-write
 * behaviour of real cards, wear, and the boot load time.
 */
#include <stddef.h>
#include <stdint.h>
#include "cold.h"
#if defined(COLD_LITE_LOG)
#include "i3_ring.h"
#include "blake3.h"
#include "cold_media.h"
#include "memory.h"
#include "platform.h"
#include "runtime_stats.h"
#include "uart.h"

#define RING_R       ((uint64_t)(I3_RING_BYTES))
#define RING_BASE    I3_RING_WINDOW_BASE
#define RING_SLOT    512u
#define RING_DATA0   1024u
#define RING_SECTOR  512u
#define RING_MAGIC   0x0031474E49523349ULL /* "I3RING1\0" LE */
#define REC_MAGIC    0x52523349u           /* "I3RR" LE */
#define REC_HDR      64u
#define REC_GENESIS  1u
#define REC_CKPT     2u
#define REC_INPUT    3u
#define REC_WRAP     4u
#define CKPT_META    72u /* D || kernel-blake3 || job_sum (u64 LE) */

_Static_assert(RING_R % 512u == 0, "I3_RING_BYTES is a multiple of 512");
_Static_assert(RING_R >= 4096u, "I3_RING_BYTES >= 4096");
_Static_assert(RING_R <= 0x08000000ULL, "I3_RING_BYTES <= 128 MiB (window)");
_Static_assert(I3_RING_EVERY > 0 && I3_RING_EVERY % I3_CHECKPOINT_EVERY == 0,
               "I3_RING_EVERY is a multiple of I3_CHECKPOINT_EVERY");

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint32_t version;
    uint32_t header_len;
    uint64_t ring_bytes;
    uint64_t gen;
    uint64_t head;
    uint64_t tail;
    uint64_t tail_seq;
    uint64_t next_seq;
    uint64_t wraps;
    uint64_t evicted;
    uint64_t last_n;
    uint64_t zero;
    uint8_t checksum[32];
} ring_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t kind;
    uint64_t seq;
    uint64_t n;
    uint64_t len;
    uint8_t digest[32];
} ring_rec_t;

_Static_assert(sizeof(ring_hdr_t) == 128, "ring header 128 bytes");
_Static_assert(sizeof(ring_rec_t) == REC_HDR, "record header 64 bytes");

static uint8_t *const W = (uint8_t *)(uintptr_t)RING_BASE;
static ring_hdr_t g_h;
static unsigned g_slot;      /* slot of the committed header */
static int g_ok;             /* ring usable this boot */
static int g_open;           /* the ring was opened or formatted this boot */
static int g_gap;            /* inputs are missing: skip until the next checkpoint */
static uint8_t g_kb[32];
static uint64_t g_lo = UINT64_MAX, g_hi; /* semihost: changed data bytes */
static int g_hdr_dirty;
#if defined(COLD_MEDIA_SEMIHOST)
static int g_flushed_once;
#endif
#if defined(I3_RING_TEST_TORN)
static int g_torn_fired;
#endif

static void put_u64(uint64_t n)
{
    char buf[20];
    uint32_t used = 0;
    do {
        buf[used++] = (char)('0' + (n % 10));
        n /= 10;
    } while (n);
    while (used)
        uart_putc(buf[--used]);
}

static void copy(void *dst, const void *src, uint64_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < n; i++)
        d[i] = s[i];
}

static int eq32(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (int i = 0; i < 32; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

static uint64_t align8(uint64_t n) { return (n + 7u) & ~7ULL; }

#if defined(COLD_MEDIA_RING)
static void media_fault(const char *op, cold_media_status_t st,
                        uint64_t off, uint64_t len)
{
    int64_t v = (int64_t)st;
    uart_puts("I3H ring media fault op=");
    uart_puts(op);
    uart_puts(" status=");
    if (v < 0) {
        uart_putc('-');
        put_u64((uint64_t)(-v));
    } else {
        put_u64((uint64_t)v);
    }
    uart_puts(" off=");
    put_u64(off);
    uart_puts(" len=");
    put_u64(len);
    uart_puts("\r\nI3H ring off reason=media\r\n");
    g_ok = 0;
}
#endif

/* Mirror [off, off+len) of the window to the media. 0 (ring off) on a fault. */
static int sync(uint64_t off, uint64_t len)
{
    if (len == 0)
        return 1;
    if (off < RING_DATA0) {
        g_hdr_dirty = 1;
    } else {
        if (off < g_lo) g_lo = off;
        if (off + len > g_hi) g_hi = off + len;
    }
#if defined(COLD_MEDIA_RING)
    cold_media_status_t st = cold_media_ring_write(W, off, len);
    if (st != COLD_MEDIA_OK) {
        media_fault("write", st, off, len);
        return 0;
    }
#endif
    return 1;
}

static int barrier(void)
{
#if defined(COLD_MEDIA_RING)
    cold_media_status_t st = cold_media_ring_barrier();
    if (st != COLD_MEDIA_OK) {
        media_fault("barrier", st, 0, 0);
        return 0;
    }
#endif
    return 1;
}

static int hdr_own(unsigned slot, uint64_t *gen)
{
    ring_hdr_t h;
    copy(&h, W + slot * RING_SLOT, sizeof h);
    if (h.magic != RING_MAGIC || h.version != 1)
        return 0;
    *gen = h.gen;
    return 1;
}

/* A header slot the ring wrote whole: magic, version, length, zero field,
 * generation and checksum are right. Its ring size may differ from RING_R. */
static int hdr_sound(unsigned slot, ring_hdr_t *out)
{
    ring_hdr_t h;
    uint8_t dig[32];
    copy(&h, W + slot * RING_SLOT, sizeof h);
    if (h.magic != RING_MAGIC || h.version != 1 || h.header_len != sizeof h
        || h.zero != 0 || h.gen == 0 || h.gen == UINT64_MAX)
        return 0;
    blake3_hash((const uint8_t *)&h, 96, dig);
    if (!eq32(dig, h.checksum))
        return 0;
    *out = h;
    return 1;
}

static int hdr_valid(unsigned slot, ring_hdr_t *out)
{
    ring_hdr_t h;
    if (!hdr_sound(slot, &h) || h.ring_bytes != RING_R)
        return 0;
    if (h.head < RING_DATA0 || h.head > RING_R || (h.head & 7)
        || h.tail < RING_DATA0 || h.tail >= RING_R || (h.tail & 7)
        || h.tail_seq > h.next_seq)
        return 0;
    *out = h;
    return 1;
}

static int hdr_commit(void)
{
    if (!g_ok)
        return 0;
    g_h.gen++;
    blake3_hash((const uint8_t *)&g_h, 96, g_h.checksum);
    unsigned slot = g_slot ^ 1u;
    copy(W + slot * RING_SLOT, &g_h, sizeof g_h);
    if (!sync(slot * RING_SLOT, RING_SLOT) || !barrier())
        return 0;
    g_slot = slot;
    return 1;
}

static void rec_at(uint64_t p, ring_rec_t *r) { copy(r, W + p, sizeof *r); }

static uint64_t rec_size(const ring_rec_t *r) { return align8(REC_HDR + r->len); }

/* Where the record after one ending at q starts (q itself is not head). */
static uint64_t norm(uint64_t q)
{
    ring_rec_t r;
    if (RING_R - q < REC_HDR)
        return RING_DATA0;
    rec_at(q, &r);
    if (r.magic == REC_MAGIC && r.kind == REC_WRAP)
        return RING_DATA0;
    return q;
}

static int empty(void) { return g_h.tail_seq == g_h.next_seq; }

/* Walk the live records of g_h from its tail. Returns how many records in a
 * row are valid (the longest valid prefix); *intact is 1 when all of them are
 * and the chain ends at head with last_n. */
static uint64_t walk(int *intact, uint64_t *segments, uint64_t *last_n,
                     uint64_t *end)
{
    uint64_t p = g_h.tail, seq = g_h.tail_seq, segs = 0, ln = 0, good = 0;
    uint64_t q = p, limit = g_h.next_seq;
    *intact = 0;
    *segments = 0;
    *last_n = 0;
    *end = p;
    if (empty()) {
        *intact = g_h.head == g_h.tail;
        return 0;
    }
    if (g_h.next_seq - g_h.tail_seq > RING_R / REC_HDR)
        limit = g_h.tail_seq + RING_R / REC_HDR;
    while (seq < limit) {
        ring_rec_t r;
        uint8_t dig[32];
        if (p < RING_DATA0 || RING_R - p < REC_HDR)
            break;
        rec_at(p, &r);
        if (r.magic != REC_MAGIC || r.seq != seq || r.len > RING_R
            || p + rec_size(&r) > RING_R
            || (r.kind != REC_GENESIS && r.kind != REC_CKPT && r.kind != REC_INPUT)
            || (seq == g_h.tail_seq && r.kind == REC_INPUT))
            break;
        blake3_hash(W + p + REC_HDR, (size_t)r.len, dig);
        if (!eq32(dig, r.digest))
            break;
        if (r.kind != REC_INPUT)
            segs++;
        ln = r.n;
        q = p + rec_size(&r);
        seq++;
        good++;
        if (seq == g_h.next_seq) {
            *intact = (q == g_h.head || norm(q) == g_h.head) && ln == g_h.last_n;
            break;
        }
        p = q == g_h.head ? q : norm(q);
    }
    *segments = segs;
    *last_n = ln;
    *end = q;
    return good;
}

/* Fresh header; gen continues above every generation seen on the media. */
static void format(uint64_t gen_floor)
{
    for (uint64_t i = 0; i < RING_DATA0; i++)
        W[i] = 0;
    g_h.magic = RING_MAGIC;
    g_h.version = 1;
    g_h.header_len = sizeof g_h;
    g_h.ring_bytes = RING_R;
    g_h.gen = gen_floor;
    g_h.head = g_h.tail = RING_DATA0;
    g_h.tail_seq = g_h.next_seq = 0;
    g_h.wraps = g_h.evicted = g_h.last_n = g_h.zero = 0;
    g_slot = 1; /* first commit goes to slot 0 */
    (void)hdr_commit();
}

/* The next segment start after the oldest one: 0 when there is none. */
static int next_seg(uint64_t *off, uint64_t *seq)
{
    uint64_t p = g_h.tail, s = g_h.tail_seq;
    for (;;) {
        ring_rec_t r;
        rec_at(p, &r);
        uint64_t q = p + rec_size(&r);
        s++;
        if (s >= g_h.next_seq)
            return 0;
        q = q == g_h.head ? q : norm(q);
        rec_at(q, &r);
        if (r.kind == REC_GENESIS || r.kind == REC_CKPT) {
            *off = q;
            *seq = s;
            return 1;
        }
        p = q;
    }
}

static void ring_fail(uint64_t n, const char *why)
{
    uart_puts("I3H ring skip event=");
    put_u64(n);
    uart_puts(" reason=");
    uart_puts(why);
    uart_puts("\r\n");
}

/* A record of size bytes at head fits below the tail without touching the
 * tail's sector (a torn write of a shared sector cannot hit the oldest
 * record). */
static int fits_below_tail(uint64_t size)
{
    uint64_t end = (g_h.head + size + RING_SECTOR - 1) & ~(uint64_t)(RING_SECTOR - 1);
    return end <= (g_h.tail & ~(uint64_t)(RING_SECTOR - 1));
}

#if defined(I3_RING_TEST_TORN)
/* Test knob (tests/recorder_ring.py torn leg): at the first wrap that needs a
 * marker, the marker never lands; the moved header is committed and flushed,
 * then the node stops dead (a power cut between the two writes). */
static void torn_stop(uint64_t n)
{
    (void)cold_nv_flush();
    i3_ring_flush();
    uart_puts("I3H ring test torn-wrap event=");
    put_u64(n);
    uart_puts(" gen=");
    put_u64(g_h.gen);
    uart_puts("\r\nI3H terminal=test-torn\r\n");
    for (;;)
        __asm__ volatile("wfe");
}
#endif

/* Append one record (payload a || b). 1 on success. */
static int put(uint32_t kind, uint64_t n, const uint8_t *a, uint64_t alen,
               const uint8_t *b, uint64_t blen, uint64_t *evicted_now)
{
    uint64_t size = align8(REC_HDR + alen + blen), moved = 0;
    if (!g_ok)
        return 0;
    if (size + RING_SECTOR > RING_R - RING_DATA0) {
        ring_fail(n, "size");
        return 0;
    }
    if (empty())
        g_h.head = g_h.tail = RING_DATA0;
    for (;;) {
        if (empty() || g_h.head > g_h.tail) {
            if (g_h.head + size <= RING_R)
                break;
            /* wrap: the end of the window cannot hold this record */
            if (RING_R - g_h.head >= REC_HDR) {
                ring_rec_t w = {REC_MAGIC, REC_WRAP, 0, 0, 0, {0}};
#if defined(I3_RING_TEST_TORN)
                if (!g_torn_fired) {
                    g_torn_fired = 1;
                } else
#endif
                {
                    copy(W + g_h.head, &w, sizeof w);
                    /* The marker is durable before the header that relies
                     * on it can land. */
                    if (!sync(g_h.head, sizeof w) || !barrier())
                        return 0;
                }
            }
            g_h.head = RING_DATA0;
            g_h.wraps++;
            moved = 1;
            if (empty())
                g_h.tail = RING_DATA0;
            continue;
        }
        /* head <= tail, not empty: free space is [head, tail's sector) */
        if (fits_below_tail(size))
            break;
        uint64_t off, seq;
        if (next_seg(&off, &seq)) {
            g_h.tail = off;
            g_h.tail_seq = seq;
        } else if (kind == REC_CKPT || kind == REC_GENESIS) {
            /* only the current segment is left: a new one replaces it */
            g_h.tail_seq = g_h.next_seq;
            g_h.head = g_h.tail = RING_DATA0;
        } else {
            ring_fail(n, "full");
            return 0;
        }
        g_h.evicted++;
        (*evicted_now)++;
        moved = 1;
    }
    if (moved && !hdr_commit())
        return 0;
#if defined(I3_RING_TEST_TORN)
    if (g_torn_fired == 1) {
        g_torn_fired = 2;
        torn_stop(n);
    }
#endif
    uint64_t at = g_h.head;
    ring_rec_t r;
    r.magic = REC_MAGIC;
    r.kind = kind;
    r.seq = g_h.next_seq;
    r.n = n;
    r.len = alen + blen;
    copy(W + at + REC_HDR, a, alen);
    if (blen)
        copy(W + at + REC_HDR + alen, b, blen);
    for (uint64_t i = REC_HDR + alen + blen; i < size; i++)
        W[at + i] = 0;
    blake3_hash(W + at + REC_HDR, (size_t)(alen + blen), r.digest);
    copy(W + at, &r, sizeof r);
    if (!sync(at, size) || !barrier())
        return 0;
    if (empty()) {
        g_h.tail = at;
        g_h.tail_seq = r.seq;
    }
    g_h.next_seq++;
    g_h.head = at + size;
    g_h.last_n = n;
    return hdr_commit();
}

static int window_zero(void)
{
    const uint64_t *w = (const uint64_t *)(const void *)W;
    uint64_t any = 0;
    for (uint64_t i = 0; i < RING_R / 8u; i++)
        any |= w[i];
    return any == 0;
}

/* Open the ring from the header slots: the newest whose chain is intact,
 * else the other one, else the longest valid prefix of either (committed
 * over the broken slot). Never formats. Returns the status word, 0 if
 * nothing usable was found. */
static const char *open_slots(const ring_hdr_t h[2], const int v[2],
                              uint64_t gen_max, uint64_t *segments)
{
    unsigned first = (v[0] && (!v[1] || h[0].gen >= h[1].gen)) ? 0u : 1u;
    unsigned order[2] = {first, first ^ 1u};
    uint64_t ln, end;
    int intact;
    for (int k = 0; k < 2; k++) {
        unsigned s = order[k];
        if (!v[s])
            continue;
        g_h = h[s];
        g_slot = s;
        (void)walk(&intact, segments, &ln, &end);
        if (intact) {
            /* The next commit goes over the other slot: lift gen above it. */
            g_h.gen = gen_max;
            return k == 0 ? "ok" : "torn-older";
        }
    }
    for (int k = 0; k < 2; k++) {
        unsigned s = order[k];
        if (!v[s])
            continue;
        g_h = h[s];
        g_slot = s;
        uint64_t good = walk(&intact, segments, &ln, &end);
        if (good == 0)
            continue;
        g_h.next_seq = g_h.tail_seq + good;
        g_h.head = end;
        g_h.last_n = ln;
        g_h.gen = gen_max;
        g_slot = s ^ 1u; /* the commit goes over the broken slot s */
        if (!hdr_commit())
            return "fail";
        return "torn-prefix";
    }
    return 0;
}

/* Our ring, but nothing on it can be trusted: leave the media as it is for
 * off-device inspection and run without the ring (one off line, one hint). */
static void off_corrupt(void)
{
    g_ok = 0;
    uart_puts("I3H ring boot status=corrupt\r\nI3H ring off reason=corrupt\r\n"
              "I3H ring hint: media kept as is; copy the ring extent off and read it "
              "with tools/ring_image.py show, then zero the extent to start a new ring\r\n");
}

void i3_ring_boot(uint64_t log_len, const uint8_t kernel_blake3[32])
{
    ring_hdr_t h[2], o;
    int v[2];
    uint64_t segments = 0, gen_max = 0, g;
    const char *status = "ok";
    copy(g_kb, kernel_blake3, 32);
    g_ok = 1;
    g_open = 0;
    g_gap = 0;
#if defined(COLD_MEDIA_RING)
    {
        cold_media_status_t st = COLD_MEDIA_DISABLED;
        uint64_t t0 = runtime_counter_now(), t1;
        if (!cold_media_active()
            || (st = cold_media_ring_load(W, RING_R)) != COLD_MEDIA_OK) {
            if (cold_media_active())
                media_fault("load", st, 0, RING_R);
            g_ok = 0;
            uart_puts("I3H ring boot status=media\r\n");
            return;
        }
        t1 = runtime_counter_now();
        uart_puts("I3H ring load bytes=");
        put_u64(RING_R);
        uart_puts(" ticks=");
        put_u64(t1 >= t0 ? t1 - t0 : 0);
        uart_puts(" freq=");
        put_u64(runtime_counter_freq());
        uart_puts("\r\n");
    }
#endif
    v[0] = hdr_valid(0, &h[0]);
    v[1] = hdr_valid(1, &h[1]);
    for (unsigned s = 0; s < 2; s++)
        if (hdr_own(s, &g) && g < (1ULL << 62) && g > gen_max)
            gen_max = g;
    if (v[0] || v[1]) {
        status = open_slots(h, v, gen_max, &segments);
        if (!status) {
            /* Our ring, but no record can be trusted. */
            off_corrupt();
            return;
        }
    } else if (window_zero()) {
        status = "fresh";
        format(0);
    } else if ((hdr_sound(0, &o) && o.ring_bytes != RING_R)
               || (hdr_sound(1, &o) && o.ring_bytes != RING_R)) {
        /* A whole header of ours for another ring size (the build changed
         * I3_RING_BYTES): the only case that reformats over non-zero data. */
        status = "reformat";
        uart_puts("I3H ring reformat old_bytes=");
        put_u64(o.ring_bytes);
        uart_puts(" new_bytes=");
        put_u64(RING_R);
        uart_puts("\r\n");
        format(gen_max);
    } else if (hdr_own(0, &g) || hdr_own(1, &g)) {
        /* Our magic and version, but no header slot to trust. */
        off_corrupt();
        return;
    } else {
        /* Not blank and not ours: never format data the ring did not create. */
        g_ok = 0;
        uart_puts("I3H ring boot status=foreign\r\nI3H ring off reason=foreign\r\n");
        return;
    }
    if (g_ok)
        g_open = 1;
    if (g_ok) {
        if (empty())
            g_gap = log_len != 0; /* genesis only before event 1 */
        else
            g_gap = g_h.last_n != log_len;
    }
    uart_puts("I3H ring boot status=");
    uart_puts(g_ok ? status : "fail");
    uart_puts(" bytes=");
    put_u64(RING_R);
    uart_puts(" every=");
    put_u64(I3_RING_EVERY);
    uart_puts(" records=");
    put_u64(empty() ? 0 : g_h.next_seq - g_h.tail_seq);
    uart_puts(" segments=");
    put_u64(segments);
    uart_puts(" last=");
    put_u64(g_h.last_n);
    uart_puts(" wraps=");
    put_u64(g_h.wraps);
    uart_puts(" evicted=");
    put_u64(g_h.evicted);
    uart_puts(" gen=");
    put_u64(g_h.gen);
    uart_puts(" gap=");
    put_u64((uint64_t)g_gap);
    uart_puts("\r\n");
}

void i3_ring_input(uint64_t n, const uint8_t *bytes, uint64_t len)
{
    uint64_t ev = 0;
    if (!g_ok || g_gap)
        return;
    if (empty()) {
        if (n != 1) {
            g_gap = 1;
            return;
        }
        if (!put(REC_GENESIS, 0, g_kb, 32, 0, 0, &ev)) {
            g_gap = 1;
            return;
        }
    } else if (n != g_h.last_n + 1) {
        ring_fail(n, "sequence");
        g_gap = 1;
        return;
    }
    if (!put(REC_INPUT, n, bytes, len, 0, 0, &ev))
        g_gap = 1;
}

void i3_ring_checkpoint(uint64_t n, const uint8_t d[32], uint64_t job_sum,
                        const uint8_t *jam, uint64_t len)
{
    uint8_t meta[CKPT_META];
    uint64_t ev = 0;
    if (!g_ok) {
        ring_fail(n, "off");
        return;
    }
    copy(meta, d, 32);
    copy(meta + 32, g_kb, 32);
    for (int i = 0; i < 8; i++)
        meta[64 + i] = (uint8_t)(job_sum >> (8 * i));
    if (!put(REC_CKPT, n, meta, CKPT_META, jam, len, &ev)) {
        g_gap = 1;
        return;
    }
    g_gap = 0;
    uart_puts("I3H ring ckpt event=");
    put_u64(n);
    uart_puts(" bytes=");
    put_u64(align8(REC_HDR + CKPT_META + len));
    uart_puts(" head=");
    put_u64(g_h.head);
    uart_puts(" tail=");
    put_u64(g_h.tail);
    uart_puts(" evicted=");
    put_u64(ev);
    uart_puts(" wraps=");
    put_u64(g_h.wraps);
    uart_puts("\r\n");
}

#if defined(COLD_MEDIA_SEMIHOST)
/* Angel semihosting, as cold_nv.c (only once cold_nv_arm armed it). */
#define SYS_OPEN  0x01
#define SYS_CLOSE 0x02
#define SYS_WRITE 0x05
#define SYS_SEEK  0x0A

static uint64_t semihost(uint64_t op, void *arg)
{
    register uint64_t x0 asm("x0") = op;
    register uint64_t x1 asm("x1") = (uint64_t)(uintptr_t)arg;
    asm volatile("hlt #0xf000" : "+r"(x0) : "r"(x1) : "memory");
    return x0;
}

static const char g_ring_path[] = "build/ring.img";

static int sh_open(int mode)
{
    struct { const char *p; uint64_t mode, len; } a;
    a.p = g_ring_path;
    a.mode = (uint64_t)mode;
    a.len = sizeof g_ring_path - 1;
    return (int)semihost(SYS_OPEN, &a);
}

static int sh_write(int fd, uint64_t off, uint64_t len)
{
    struct { uint64_t fd, pos; } s;
    s.fd = (uint64_t)(uint32_t)fd;
    s.pos = off;
    if (semihost(SYS_SEEK, &s) != 0)
        return 0;
    while (len) {
        uint64_t n = len > 65536u ? 65536u : len;
        struct { uint64_t fd; const void *buf; uint64_t len; } w;
        w.fd = (uint64_t)(uint32_t)fd;
        w.buf = W + off;
        w.len = n;
        if (semihost(SYS_WRITE, &w) != 0)
            return 0;
        off += n;
        len -= n;
    }
    return 1;
}

static void sh_close(int fd)
{
    uint64_t f = (uint64_t)(uint32_t)fd;
    semihost(SYS_CLOSE, &f);
}
#endif

void i3_ring_flush(void)
{
#if defined(COLD_MEDIA_SEMIHOST)
    int fd, ok;
    /* Nothing is written for a ring that was not opened this boot (foreign
     * or corrupt data stays as it is). */
    if (!g_open || !cold_nv_enabled()
        || (!g_hdr_dirty && g_lo == UINT64_MAX && g_flushed_once))
        return;
    if (!g_flushed_once) {
        /* First flush of a boot: the whole used extent (all of it once
         * the ring has wrapped), so the file reloads to this window. */
        uint64_t extent = g_h.wraps ? RING_R : g_h.head;
        fd = sh_open(5 /* wb */);
        /* The data first, then the header that refers to it. */
        ok = fd >= 0
             && (extent <= RING_DATA0 || sh_write(fd, RING_DATA0, extent - RING_DATA0))
             && sh_write(fd, 0, RING_DATA0);
    } else {
        /* The data first, then the header that refers to it. */
        fd = sh_open(3 /* r+b */);
        ok = fd >= 0
             && (g_lo == UINT64_MAX || sh_write(fd, g_lo, g_hi - g_lo))
             && sh_write(fd, 0, RING_DATA0);
    }
    if (fd >= 0)
        sh_close(fd);
    if (ok) {
        g_flushed_once = 1;
        g_hdr_dirty = 0;
        g_lo = UINT64_MAX;
        g_hi = 0;
    }
#endif
}
#endif
