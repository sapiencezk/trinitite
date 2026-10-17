/* SPDX-License-Identifier: MIT */
/*
 * Row 212 PR 1c: the recorder ring (i3_ring.h has the layout). The working
 * copy is a RAM window of I3_RING_BYTES; each change is mirrored to the media:
 *   COLD_MEDIA=rpi4-sd  write-through by whole sectors to the ring extent
 *                       (cold_media_ring_*; loaded whole at boot),
 *   COLD_MEDIA=semihost the changed bytes go to the host file build/ring.img
 *                       at each i3_ring_flush (QEMU tests reload it with
 *                       -device loader at the window address),
 *   COLD_MEDIA=ram|fake RAM only (volatile).
 * Order per record: free space (evict oldest segments, wrap), commit the
 * header if that moved the tail or head, write the record, barrier, commit
 * the header. A torn record is past the committed head; a torn header leaves
 * the other slot (the previous state). Not measured on the board: SD append
 * time, torn-write behaviour, wear.
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
#define RING_BASE    (PLATFORM_DRAM_BASE + 0x30000000ULL)
#define RING_SLOT    512u
#define RING_DATA0   1024u
#define RING_MAGIC   0x0031474E49523349ULL /* "I3RING1\0" LE */
#define REC_MAGIC    0x52523349u           /* "I3RR" LE */
#define REC_HDR      64u
#define REC_GENESIS  1u
#define REC_CKPT     2u
#define REC_INPUT    3u
#define REC_WRAP     4u

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
static int g_gap;            /* inputs are missing: skip until the next checkpoint */
static uint8_t g_kb[32];
static uint64_t g_lo = UINT64_MAX, g_hi; /* semihost: changed data bytes */
static int g_hdr_dirty, g_flushed_once;

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

#if defined(COLD_MEDIA_RPI4_SD)
static uint64_t deadline(void)
{
    uint64_t now = runtime_counter_now(), f = runtime_counter_freq();
    uint64_t a = f <= UINT64_MAX / 5 ? f * 5 : UINT64_MAX;
    return a <= UINT64_MAX - now ? now + a : UINT64_MAX;
}
#endif

/* Mirror [off, off+len) of the window to the media. */
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
#if defined(COLD_MEDIA_RPI4_SD)
    if (cold_media_ring_write(W, off, len, deadline()) != COLD_MEDIA_OK)
        return 0;
#endif
    return 1;
}

static int barrier(void)
{
#if defined(COLD_MEDIA_RPI4_SD)
    return cold_media_ring_barrier(deadline()) == COLD_MEDIA_OK;
#else
    return 1;
#endif
}

static int hdr_valid(unsigned slot, ring_hdr_t *out)
{
    ring_hdr_t h;
    uint8_t dig[32];
    copy(&h, W + slot * RING_SLOT, sizeof h);
    if (h.magic != RING_MAGIC || h.version != 1 || h.header_len != sizeof h
        || h.ring_bytes != RING_R || h.zero != 0 || h.gen == 0)
        return 0;
    blake3_hash((const uint8_t *)&h, 96, dig);
    if (!eq32(dig, h.checksum))
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

/* Walk the live records; count segments. 1 when the chain is intact. */
static int chain_ok(uint64_t *records, uint64_t *segments, uint64_t *last_n)
{
    uint64_t p = g_h.tail, seq = g_h.tail_seq, segs = 0, ln = 0;
    if (empty()) {
        *records = 0; *segments = 0; *last_n = 0;
        return g_h.head == g_h.tail;
    }
    if (g_h.next_seq - g_h.tail_seq > RING_R / REC_HDR)
        return 0;
    while (seq < g_h.next_seq) {
        ring_rec_t r;
        uint8_t dig[32];
        rec_at(p, &r);
        if (r.magic != REC_MAGIC || r.seq != seq || r.len > RING_R
            || p + rec_size(&r) > RING_R
            || (r.kind != REC_GENESIS && r.kind != REC_CKPT && r.kind != REC_INPUT)
            || (seq == g_h.tail_seq && r.kind == REC_INPUT))
            return 0;
        blake3_hash(W + p + REC_HDR, (size_t)r.len, dig);
        if (!eq32(dig, r.digest))
            return 0;
        if (r.kind != REC_INPUT)
            segs++;
        ln = r.n;
        uint64_t q = p + rec_size(&r);
        seq++;
        if (seq == g_h.next_seq) {
            if (q != g_h.head && norm(q) != g_h.head)
                return 0;
            break;
        }
        p = q == g_h.head ? q : norm(q);
    }
    *records = g_h.next_seq - g_h.tail_seq;
    *segments = segs;
    *last_n = ln;
    return ln == g_h.last_n;
}

static void format(void)
{
    for (uint64_t i = 0; i < RING_DATA0; i++)
        W[i] = 0;
    g_h.magic = RING_MAGIC;
    g_h.version = 1;
    g_h.header_len = sizeof g_h;
    g_h.ring_bytes = RING_R;
    g_h.gen = 0;
    g_h.head = g_h.tail = RING_DATA0;
    g_h.tail_seq = g_h.next_seq = 0;
    g_h.wraps = g_h.evicted = g_h.last_n = g_h.zero = 0;
    g_slot = 1; /* first commit goes to slot 0 */
    g_ok = hdr_commit();
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

/* Append one record (payload a || b). 1 on success. */
static int put(uint32_t kind, uint64_t n, const uint8_t *a, uint64_t alen,
               const uint8_t *b, uint64_t blen, uint64_t *evicted_now)
{
    uint64_t size = align8(REC_HDR + alen + blen), moved = 0;
    if (!g_ok)
        return 0;
    if (size > RING_R - RING_DATA0) {
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
                copy(W + g_h.head, &w, sizeof w);
                if (!sync(g_h.head, sizeof w)) { g_ok = 0; return 0; }
            }
            g_h.head = RING_DATA0;
            g_h.wraps++;
            moved = 1;
            if (empty())
                g_h.tail = RING_DATA0;
            continue;
        }
        /* head <= tail, not empty: free space is [head, tail) */
        if (g_h.head + size <= g_h.tail)
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
    if (moved && !hdr_commit()) { g_ok = 0; return 0; }
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
    if (!sync(at, size) || !barrier()) { g_ok = 0; return 0; }
    if (empty()) {
        g_h.tail = at;
        g_h.tail_seq = r.seq;
    }
    g_h.next_seq++;
    g_h.head = at + size;
    g_h.last_n = n;
    if (!hdr_commit()) { g_ok = 0; return 0; }
    return 1;
}

void i3_ring_boot(uint64_t log_len, const uint8_t kernel_blake3[32])
{
    ring_hdr_t a, b;
    uint64_t records = 0, segments = 0, last_n = 0;
    const char *status = "ok";
    copy(g_kb, kernel_blake3, 32);
    g_ok = 1;
    g_gap = 0;
#if defined(COLD_MEDIA_RPI4_SD)
    if (!cold_media_active()
        || cold_media_ring_load(W, RING_R, deadline()) != COLD_MEDIA_OK) {
        g_ok = 0;
        uart_puts("I3H ring boot status=media\r\n");
        return;
    }
#endif
    int va = hdr_valid(0, &a), vb = hdr_valid(1, &b);
    if (va || vb) {
        if (va && (!vb || a.gen >= b.gen)) { g_h = a; g_slot = 0; }
        else { g_h = b; g_slot = 1; }
        if (!chain_ok(&records, &segments, &last_n)) {
            status = "corrupt-reformat";
            format();
        }
    } else {
        int zero = 1;
        for (uint64_t i = 0; i < RING_DATA0; i++)
            zero &= W[i] == 0;
        status = zero ? "fresh" : "corrupt-reformat";
        format();
    }
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
    uart_puts(" gap=");
    put_u64((uint64_t)g_gap);
    uart_puts("\r\n");
    (void)records;
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

void i3_ring_checkpoint(uint64_t n, const uint8_t d[32],
                        const uint8_t *jam, uint64_t len)
{
    uint8_t meta[64];
    uint64_t ev = 0, before;
    if (!g_ok)
        return;
    copy(meta, d, 32);
    copy(meta + 32, g_kb, 32);
    before = g_h.head;
    if (!put(REC_CKPT, n, meta, 64, jam, len, &ev)) {
        g_gap = 1;
        return;
    }
    g_gap = 0;
    uart_puts("I3H ring ckpt event=");
    put_u64(n);
    uart_puts(" bytes=");
    put_u64(align8(REC_HDR + 64 + len));
    uart_puts(" head=");
    put_u64(g_h.head);
    uart_puts(" tail=");
    put_u64(g_h.tail);
    uart_puts(" evicted=");
    put_u64(ev);
    uart_puts(" wraps=");
    put_u64(g_h.wraps);
    uart_puts("\r\n");
    (void)before;
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
    if (!cold_nv_enabled() || (!g_hdr_dirty && g_lo == UINT64_MAX && g_flushed_once))
        return;
    if (!g_flushed_once) {
        /* First flush of a boot: the whole used extent (all of it once
         * the ring has wrapped), so the file reloads to this window. */
        uint64_t extent = g_h.wraps ? RING_R : g_h.head;
        fd = sh_open(5 /* wb */);
        ok = fd >= 0 && sh_write(fd, 0, extent < RING_DATA0 ? RING_DATA0 : extent);
    } else {
        fd = sh_open(3 /* r+b */);
        ok = fd >= 0 && sh_write(fd, 0, RING_DATA0)
             && (g_lo == UINT64_MAX || sh_write(fd, g_lo, g_hi - g_lo));
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
