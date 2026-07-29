#include <stddef.h>
#include <stdint.h>
#include "i2_ingress.h"
#include "blake3.h"
#include "bounded_cue.h"
#include "memory.h"
#include "uart.h"

#define I2_FRAME_HEADER_SIZE 56u
#define I2_FRAME_MAX_PAYLOAD UART_RXBUF_SIZE

typedef enum {
    RX_SCAN = 0,
    RX_HEADER,
    RX_PAYLOAD,
    RX_READY
} rx_state_t;

static const uint8_t g_magic[8] = {
    'I', '2', 'F', 'N', '\r', '\n', 0x1a, '\n'
};

static struct {
    rx_state_t state;
    uint32_t alignment_pad;
    uint8_t header[I2_FRAME_HEADER_SIZE];
    uint32_t have;
    uint32_t magic_have;
    uint64_t payload_len;
    uint64_t frame_deadline;
    uint64_t byte_deadline;
    uint64_t rejects[I2_RX_REASON_COUNT];
    i2_rx_reason_t last_reason;
} g_rx;

static uint64_t counter_now(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static uint64_t counter_freq(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v ? v : 54000000ULL;
}

static uint64_t add_ticks(uint64_t now, uint64_t ticks)
{
    if (UINT64_MAX - now < ticks)
        return UINT64_MAX;
    return now + ticks;
}

static uint64_t interbyte_ticks(void)
{
    return counter_freq() / 4; /* 250 ms */
}

static uint64_t total_ticks(void)
{
    uint64_t f = counter_freq();
    return f > UINT64_MAX / 5 ? UINT64_MAX : f * 5; /* 5 s */
}

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(value >> (i * 8));
}

static void reset_scan(void)
{
    g_rx.state = RX_SCAN;
    g_rx.have = 0;
    g_rx.magic_have = 0;
    g_rx.payload_len = 0;
    g_rx.frame_deadline = 0;
    g_rx.byte_deadline = 0;
}

static void reject(i2_rx_reason_t reason)
{
    if (reason > I2_RX_REASON_NONE && reason < I2_RX_REASON_COUNT) {
        if (g_rx.rejects[reason] != UINT64_MAX)
            g_rx.rejects[reason]++;
        g_rx.last_reason = reason;
    }
    reset_scan();
}

void i2_rx_init(void)
{
    for (int i = 0; i < I2_RX_REASON_COUNT; i++)
        g_rx.rejects[i] = 0;
    g_rx.last_reason = I2_RX_REASON_NONE;
    reset_scan();
}

void i2_rx_check_timeout(uint64_t now)
{
    if ((g_rx.state == RX_SCAN && g_rx.magic_have != 0)
        || g_rx.state == RX_HEADER || g_rx.state == RX_PAYLOAD) {
        if ((g_rx.byte_deadline && now >= g_rx.byte_deadline)
            || (g_rx.frame_deadline && now >= g_rx.frame_deadline))
            reject(I2_RX_REASON_TIMEOUT);
    }
}

void i2_rx_feed_byte(uint8_t byte, uint64_t now)
{
    i2_rx_check_timeout(now);
    if (g_rx.state == RX_READY)
        return;

    if (g_rx.state == RX_SCAN) {
        if (byte == g_magic[g_rx.magic_have]) {
            if (g_rx.magic_have == 0) {
                g_rx.frame_deadline = add_ticks(now, total_ticks());
                g_rx.byte_deadline = add_ticks(now, interbyte_ticks());
            }
            g_rx.header[g_rx.magic_have++] = byte;
            if (g_rx.magic_have == sizeof g_magic) {
                g_rx.state = RX_HEADER;
                g_rx.have = sizeof g_magic;
            }
        } else {
            g_rx.magic_have = byte == g_magic[0] ? 1u : 0u;
            if (g_rx.magic_have) {
                g_rx.header[0] = byte;
                g_rx.frame_deadline = add_ticks(now, total_ticks());
                g_rx.byte_deadline = add_ticks(now, interbyte_ticks());
            } else {
                g_rx.frame_deadline = 0;
                g_rx.byte_deadline = 0;
            }
        }
        return;
    }

    g_rx.byte_deadline = add_ticks(now, interbyte_ticks());
    if (g_rx.state == RX_HEADER) {
        g_rx.header[g_rx.have++] = byte;
        if (g_rx.have != I2_FRAME_HEADER_SIZE)
            return;
        if (le16(g_rx.header + 8) != 1 || le16(g_rx.header + 10) != 0) {
            reject(I2_RX_REASON_VERSION);
            return;
        }
        if (le16(g_rx.header + 12) != I2_FRAME_HEADER_SIZE
            || le16(g_rx.header + 14) != 0) {
            reject(I2_RX_REASON_HEADER);
            return;
        }
        g_rx.payload_len = le64(g_rx.header + 16);
        if (g_rx.payload_len == 0
            || g_rx.payload_len > I2_FRAME_MAX_PAYLOAD) {
            reject(I2_RX_REASON_LENGTH);
            return;
        }
        g_rx.have = 0;
        g_rx.state = RX_PAYLOAD;
        return;
    }

    if (g_rx.state == RX_PAYLOAD) {
        ((uint8_t *)(uintptr_t)UART_RXBUF_BASE)[g_rx.have++] = byte;
        if (g_rx.have == g_rx.payload_len) {
            uint8_t digest[32];
            blake3_hash((const uint8_t *)(uintptr_t)UART_RXBUF_BASE,
                        (size_t)g_rx.payload_len, digest);
            uint8_t diff = 0;
            for (int i = 0; i < 32; i++)
                diff |= digest[i] ^ g_rx.header[24 + i];
            if (diff) {
                reject(I2_RX_REASON_DIGEST);
                return;
            }
            g_rx.state = RX_READY;
            g_rx.frame_deadline = 0;
            g_rx.byte_deadline = 0;
        }
    }
}

int i2_rx_poll(uint32_t byte_budget)
{
    uint64_t now = counter_now();
    i2_rx_check_timeout(now);
    if (g_rx.state == RX_READY)
        return 1;
    for (uint32_t i = 0; i < byte_budget; i++) {
        uint8_t byte;
        if (!uart_getc_nb(&byte))
            break;
        now = counter_now();
        i2_rx_feed_byte(byte, now);
        if (g_rx.state == RX_READY)
            return 1;
    }
    return 0;
}

int i2_rx_take(noun *out)
{
    if (!out || g_rx.state != RX_READY)
        return 0;
    cue_bounded_limits_t limits = cue_i2_limits;
    limits.max_input_bytes = I2_FRAME_MAX_PAYLOAD;
    cue_bounded_status_t status = cue_bounded_bytes(
        (const uint8_t *)(uintptr_t)UART_RXBUF_BASE, g_rx.payload_len,
        &limits, HEAP_MODE_SCRATCH, out);
    if (status != CUE_BOUNDED_OK) {
        reject(I2_RX_REASON_CUE);
        return 0;
    }
    reset_scan();
    return 1;
}

int i2_rx_ready(void)
{
    return g_rx.state == RX_READY;
}

uint64_t i2_rx_reject_count(i2_rx_reason_t reason)
{
    if (reason <= I2_RX_REASON_NONE || reason >= I2_RX_REASON_COUNT)
        return 0;
    return g_rx.rejects[reason];
}

i2_rx_reason_t i2_rx_last_reason(void)
{
    return g_rx.last_reason;
}

const char *i2_rx_reason_name(i2_rx_reason_t reason)
{
    static const char *names[] = {
        "none", "version", "header", "length", "digest", "cue", "timeout"
    };
    if ((unsigned)reason >= sizeof(names) / sizeof(names[0]))
        return "unknown";
    return names[reason];
}

static void test_frame(uint8_t frame[I2_FRAME_HEADER_SIZE + 2],
                       uint64_t payload_len)
{
    for (size_t i = 0; i < I2_FRAME_HEADER_SIZE + 2; i++)
        frame[i] = 0;
    for (size_t i = 0; i < sizeof g_magic; i++)
        frame[i] = g_magic[i];
    put16(frame + 8, 1);
    put16(frame + 10, 0);
    put16(frame + 12, I2_FRAME_HEADER_SIZE);
    put16(frame + 14, 0);
    put64(frame + 16, payload_len);
    frame[I2_FRAME_HEADER_SIZE + 0] = 0x50; /* jam(42) */
    frame[I2_FRAME_HEADER_SIZE + 1] = 0x15;
    if (payload_len == 2)
        blake3_hash(frame + I2_FRAME_HEADER_SIZE, 2, frame + 24);
}

static void feed_test_bytes(const uint8_t *bytes, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        i2_rx_feed_byte(bytes[i], 100 + i);
}

uint64_t i2_rx_selftest(void)
{
    uint64_t failures = 0;
    uint8_t frame[I2_FRAME_HEADER_SIZE + 2];

    test_frame(frame, 2);
    /* Every partial magic/header boundary and payload position must time out. */
    for (uint64_t cut = 1; cut < sizeof frame; cut++) {
        i2_rx_init();
        feed_test_bytes(frame, cut);
        i2_rx_check_timeout(UINT64_MAX);
        if (i2_rx_ready() || i2_rx_last_reason() != I2_RX_REASON_TIMEOUT)
            failures++;
    }

    i2_rx_init();
    test_frame(frame, 0);
    feed_test_bytes(frame, I2_FRAME_HEADER_SIZE);
    if (i2_rx_last_reason() != I2_RX_REASON_LENGTH)
        failures++;

    i2_rx_init();
    test_frame(frame, UINT64_MAX);
    feed_test_bytes(frame, I2_FRAME_HEADER_SIZE);
    if (i2_rx_last_reason() != I2_RX_REASON_LENGTH)
        failures++;

    i2_rx_init();
    test_frame(frame, I2_FRAME_MAX_PAYLOAD + 1);
    feed_test_bytes(frame, I2_FRAME_HEADER_SIZE);
    if (i2_rx_last_reason() != I2_RX_REASON_LENGTH)
        failures++;

    i2_rx_init();
    test_frame(frame, 2);
    frame[8] = 2;
    feed_test_bytes(frame, I2_FRAME_HEADER_SIZE);
    if (i2_rx_last_reason() != I2_RX_REASON_VERSION)
        failures++;

    i2_rx_init();
    test_frame(frame, 2);
    frame[12] = 55;
    feed_test_bytes(frame, I2_FRAME_HEADER_SIZE);
    if (i2_rx_last_reason() != I2_RX_REASON_HEADER)
        failures++;

    i2_rx_init();
    test_frame(frame, 2);
    frame[24] ^= 1;
    feed_test_bytes(frame, sizeof frame);
    if (i2_rx_last_reason() != I2_RX_REASON_DIGEST)
        failures++;

    /* A validly framed malformed cue rejects without ratcheting allocators. */
    i2_rx_init();
    test_frame(frame, 2);
    frame[I2_FRAME_HEADER_SIZE] = 0x07; /* backref to current/future bit */
    frame[I2_FRAME_HEADER_SIZE + 1] = 0;
    blake3_hash(frame + I2_FRAME_HEADER_SIZE, 2, frame + 24);
    uint64_t cells_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms_before = atom_store_bytes_used();
    feed_test_bytes(frame, sizeof frame);
    noun decoded;
    if (i2_rx_take(&decoded)
        || i2_rx_last_reason() != I2_RX_REASON_CUE
        || heap_cells_used(HEAP_MODE_SCRATCH) != cells_before
        || atom_store_bytes_used() != atoms_before)
        failures++;

    /* One rejection must resynchronize to two immediately following frames. */
    i2_rx_init();
    test_frame(frame, 2);
    frame[24] ^= 1;
    feed_test_bytes(frame, sizeof frame);
    test_frame(frame, 2);
    feed_test_bytes(frame, sizeof frame);
    if (!i2_rx_ready() || !i2_rx_take(&decoded)
        || !noun_is_direct(decoded) || direct_val(decoded) != 42)
        failures++;
    if (noun_tx_active())
        noun_tx_abort();
    test_frame(frame, 2);
    feed_test_bytes(frame, sizeof frame);
    if (!i2_rx_ready() || !i2_rx_take(&decoded)
        || !noun_is_direct(decoded) || direct_val(decoded) != 42)
        failures++;
    if (noun_tx_active())
        noun_tx_abort();
    i2_rx_init();
    return failures;
}

typedef struct {
    uint8_t *bytes;
    uint64_t bit;
} test_bits_t;

static void test_bit(test_bits_t *w, int bit)
{
    if (bit)
        w->bytes[w->bit >> 3] |= (uint8_t)(1u << (w->bit & 7));
    w->bit++;
}

static uint64_t nested_zero_jam(uint8_t *bytes, uint32_t depth)
{
    for (size_t i = 0; i < 256; i++)
        bytes[i] = 0;
    test_bits_t w = { .bytes = bytes, .bit = 0 };
    for (uint32_t i = 0; i < depth; i++) {
        test_bit(&w, 1); test_bit(&w, 0); /* cell */
        test_bit(&w, 0); test_bit(&w, 1); /* head atom 0 */
    }
    test_bit(&w, 0); test_bit(&w, 1);     /* final tail atom 0 */
    return (w.bit + 7) / 8;
}

static int cue_expect(const uint8_t *bytes, uint64_t len,
                      cue_bounded_limits_t limits,
                      cue_bounded_status_t expected)
{
    noun out;
    cue_bounded_status_t actual = cue_bounded_bytes(
        bytes, len, &limits, HEAP_MODE_SCRATCH, &out);
    if (actual == CUE_BOUNDED_OK && noun_tx_active())
        noun_tx_abort();
    return actual == expected;
}

uint64_t cue_bounded_selftest(void)
{
    uint64_t failures = 0;
    uint8_t bytes[256];
    cue_bounded_limits_t limits;
    uint64_t cells_before = heap_cells_used(HEAP_MODE_SCRATCH);
    uint64_t atoms_before = atom_store_bytes_used();

    bytes[0] = 0;
    limits = cue_i2_limits;
    if (!cue_expect(bytes, 1, limits, CUE_BOUNDED_TRUNCATED))
        failures++;
    bytes[0] = 0x07;
    if (!cue_expect(bytes, 1, limits, CUE_BOUNDED_BACKREF))
        failures++;

    uint64_t len = nested_zero_jam(bytes, 255);
    if (!cue_expect(bytes, len, limits, CUE_BOUNDED_OK))
        failures++;
    len = nested_zero_jam(bytes, 256);
    if (!cue_expect(bytes, len, limits, CUE_BOUNDED_DEPTH))
        failures++;

    len = nested_zero_jam(bytes, 2);
    limits = cue_i2_limits;
    limits.max_cells = 1;
    if (!cue_expect(bytes, len, limits, CUE_BOUNDED_CELLS))
        failures++;
    limits = cue_i2_limits;
    limits.max_nodes = 1;
    if (!cue_expect(bytes, len, limits, CUE_BOUNDED_NODES))
        failures++;
    limits = cue_i2_limits;
    limits.max_cache_entries = 1;
    if (!cue_expect(bytes, len, limits, CUE_BOUNDED_CACHE))
        failures++;

    bytes[0] = 0x0c; /* jam(1) */
    limits = cue_i2_limits;
    limits.max_atom_bytes = 0;
    if (!cue_expect(bytes, 1, limits, CUE_BOUNDED_ATOM))
        failures++;
    limits = cue_i2_limits;
    limits.max_total_atom_bytes = 0;
    if (!cue_expect(bytes, 1, limits, CUE_BOUNDED_ATOM))
        failures++;
    limits = cue_i2_limits;
    limits.max_work = 1;
    if (!cue_expect(bytes, 1, limits, CUE_BOUNDED_WORK))
        failures++;
    limits = cue_i2_limits;
    if (!cue_expect(bytes, limits.max_input_bytes + 1, limits,
                    CUE_BOUNDED_INPUT))
        failures++;

    bytes[0] = 0x50; bytes[1] = 0x15; /* jam(42) */
    noun out;
    if (cue_bounded_bytes(bytes, 2, &cue_i2_limits,
                          HEAP_MODE_SCRATCH, &out) != CUE_BOUNDED_OK
        || !noun_is_direct(out) || direct_val(out) != 42
        || !noun_tx_active())
        failures++;
    if (noun_tx_active())
        noun_tx_abort();

    if (heap_cells_used(HEAP_MODE_SCRATCH) != cells_before
        || atom_store_bytes_used() != atoms_before)
        failures++;
    return failures;
}
