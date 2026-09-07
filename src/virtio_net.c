#include <stdint.h>

#include "platform.h"
#include "virtio_net.h"

#define MMIO(off) (*(volatile uint32_t *)(uintptr_t)(PLATFORM_VIRTIO_MMIO_BASE + (off)))

#define REG_MAGIC 0x000u
#define REG_VERSION 0x004u
#define REG_DEVICE_ID 0x008u
#define REG_DEVICE_FEATURES 0x010u
#define REG_DEVICE_FEATURES_SEL 0x014u
#define REG_DRIVER_FEATURES 0x020u
#define REG_DRIVER_FEATURES_SEL 0x024u
#define REG_QUEUE_SEL 0x030u
#define REG_QUEUE_NUM_MAX 0x034u
#define REG_QUEUE_NUM 0x038u
#define REG_QUEUE_READY 0x044u
#define REG_QUEUE_NOTIFY 0x050u
#define REG_INTERRUPT_STATUS 0x060u
#define REG_STATUS 0x070u
#define REG_QUEUE_DESC_LOW 0x080u
#define REG_QUEUE_DESC_HIGH 0x084u
#define REG_QUEUE_AVAIL_LOW 0x090u
#define REG_QUEUE_AVAIL_HIGH 0x094u
#define REG_QUEUE_USED_LOW 0x0a0u
#define REG_QUEUE_USED_HIGH 0x0a4u
#define REG_CONFIG_GENERATION 0x0fcu
#define REG_CONFIG 0x100u

#define STATUS_ACK 1u
#define STATUS_DRIVER 2u
#define STATUS_FEATURES_OK 8u
#define STATUS_DRIVER_OK 4u
#define STATUS_FAILED 128u
#define FEATURE_MAC (1ULL << 5)
#define FEATURE_VERSION_1 (1ULL << 32)
#define DESC_F_WRITE 2u
#define DESC_F_NEXT 1u
#define RING_COUNT PLATFORM_VIRTIO_MMIO_QUEUE_SIZE
#define RX_BUFFER_BYTES PLATFORM_NATIVE_MTU
#define RX_NET_HEADER_BYTES 12u
#define TX_NET_HEADER_BYTES 12u
#define TX_POLL_BUDGET 256u

typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed, aligned(16))) vring_desc_t;

typedef struct {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[RING_COUNT];
    uint16_t used_event;
} __attribute__((packed, aligned(2))) vring_avail_t;

typedef struct {
    uint32_t id;
    uint32_t len;
} vring_used_elem_t;

typedef struct {
    uint16_t flags;
    uint16_t idx;
    vring_used_elem_t ring[RING_COUNT];
    uint16_t avail_event;
} __attribute__((packed, aligned(4))) vring_used_t;

static vring_desc_t g_rx_desc[RING_COUNT] __attribute__((aligned(4096)));
static vring_avail_t g_rx_avail __attribute__((aligned(4096)));
static vring_used_t g_rx_used __attribute__((aligned(4096)));
static uint8_t g_rx_buf[RING_COUNT][RX_BUFFER_BYTES] __attribute__((aligned(16)));
static vring_desc_t g_tx_desc[RING_COUNT] __attribute__((aligned(4096)));
static vring_avail_t g_tx_avail __attribute__((aligned(4096)));
static vring_used_t g_tx_used __attribute__((aligned(4096)));
static uint8_t g_tx_buf[RX_BUFFER_BYTES] __attribute__((aligned(16)));
static uint16_t g_rx_used_seen;
static uint16_t g_rx_posted_mask;
static uint16_t g_tx_used_seen;
static uint16_t g_tx_avail_idx;
static int g_ready;
static int g_tx_busy;
#ifdef M23_TEST_CONTROLS
static int g_tx_completion_hidden;
static int g_test_rx_bad;
static int g_test_rx_overadvance;
static int g_test_rx_overlong;
static int g_test_tx_bad;
static int g_test_tx_overlong;
#endif
static uint64_t g_rx_packets;
static uint64_t g_tx_packets;
static uint64_t g_last_error;

static void barrier(void) { __asm__ volatile("dmb ish" ::: "memory"); }
static void cpu_relax_tx(void) { __asm__ volatile("yield" ::: "memory"); }
static void cpu_relax_rx(void) { __asm__ volatile("yield" ::: "memory"); }

static void queue_address(uint32_t queue, const void *desc,
                          const void *avail, const void *used)
{
    MMIO(REG_QUEUE_SEL) = queue;
    MMIO(REG_QUEUE_NUM) = RING_COUNT;
    uint64_t d = (uint64_t)(uintptr_t)desc, a = (uint64_t)(uintptr_t)avail;
    uint64_t u = (uint64_t)(uintptr_t)used;
    MMIO(REG_QUEUE_DESC_LOW) = (uint32_t)d; MMIO(REG_QUEUE_DESC_HIGH) = (uint32_t)(d >> 32);
    MMIO(REG_QUEUE_AVAIL_LOW) = (uint32_t)a; MMIO(REG_QUEUE_AVAIL_HIGH) = (uint32_t)(a >> 32);
    MMIO(REG_QUEUE_USED_LOW) = (uint32_t)u; MMIO(REG_QUEUE_USED_HIGH) = (uint32_t)(u >> 32);
    MMIO(REG_QUEUE_READY) = 1;
}

static void notify(uint32_t queue) { barrier(); MMIO(REG_QUEUE_NOTIFY) = queue; }

static void status_fail(uint64_t error)
{
    g_last_error = error;
    /* The build gate rejects native-on-rpi4b, but keep this failure path
     * non-destructive if a test calls the driver without an MMIO aperture. */
    if (PLATFORM_VIRTIO_MMIO_BASE != 0)
        MMIO(REG_STATUS) = MMIO(REG_STATUS) | STATUS_FAILED;
}

static int configure_queue(uint32_t queue)
{
    MMIO(REG_QUEUE_SEL) = queue;
    if (MMIO(REG_QUEUE_NUM_MAX) < RING_COUNT) return 0;
    return 1;
}

int virtio_net_init(void)
{
    g_ready = 0; g_tx_busy = 0; g_rx_used_seen = 0; g_tx_used_seen = 0;
    g_rx_posted_mask = 0;
    g_tx_avail_idx = 0; g_rx_packets = 0; g_tx_packets = 0; g_last_error = 0;
#ifdef M23_TEST_CONTROLS
    g_tx_completion_hidden = 0;
    g_test_rx_bad = 0; g_test_rx_overadvance = 0; g_test_rx_overlong = 0;
    g_test_tx_bad = 0; g_test_tx_overlong = 0;
#endif
    if (PLATFORM_VIRTIO_MMIO_BASE == 0 || MMIO(REG_MAGIC) != 0x74726976u
        || MMIO(REG_VERSION) != 2u || MMIO(REG_DEVICE_ID) != 1u) {
        status_fail(1); return -1;
    }
    MMIO(REG_STATUS) = 0; MMIO(REG_STATUS) = STATUS_ACK | STATUS_DRIVER;
    uint64_t features = 0;
    MMIO(REG_DEVICE_FEATURES_SEL) = 0; features |= MMIO(REG_DEVICE_FEATURES);
    MMIO(REG_DEVICE_FEATURES_SEL) = 1; features |= (uint64_t)MMIO(REG_DEVICE_FEATURES) << 32;
    if ((features & (FEATURE_MAC | FEATURE_VERSION_1)) != (FEATURE_MAC | FEATURE_VERSION_1)) {
        status_fail(2); return -1;
    }
    MMIO(REG_DRIVER_FEATURES_SEL) = 0; MMIO(REG_DRIVER_FEATURES) = (uint32_t)FEATURE_MAC;
    MMIO(REG_DRIVER_FEATURES_SEL) = 1; MMIO(REG_DRIVER_FEATURES) = (uint32_t)(FEATURE_VERSION_1 >> 32);
    barrier(); MMIO(REG_STATUS) = MMIO(REG_STATUS) | STATUS_FEATURES_OK;
    if (!(MMIO(REG_STATUS) & STATUS_FEATURES_OK)) { status_fail(3); return -1; }
    if (!configure_queue(0) || !configure_queue(1)) { status_fail(4); return -1; }
    for (uint32_t i = 0; i < RING_COUNT; i++) {
        g_rx_desc[i].addr = (uint64_t)(uintptr_t)g_rx_buf[i];
        g_rx_desc[i].len = RX_BUFFER_BYTES; g_rx_desc[i].flags = DESC_F_WRITE; g_rx_desc[i].next = 0;
        g_rx_avail.ring[i] = (uint16_t)i;
    }
    g_rx_posted_mask = (uint16_t)((1u << RING_COUNT) - 1u);
    g_rx_avail.flags = 0; g_rx_avail.idx = RING_COUNT; g_rx_used.flags = 0; g_rx_used.idx = 0;
    for (uint32_t i = 0; i < RING_COUNT; i++) { g_rx_used.ring[i].id = 0; g_rx_used.ring[i].len = 0; }
    queue_address(0, g_rx_desc, &g_rx_avail, &g_rx_used); notify(0);
    g_tx_desc[0].addr = (uint64_t)(uintptr_t)g_tx_buf; g_tx_desc[0].len = 0;
    g_tx_desc[0].flags = 0; g_tx_desc[0].next = 0;
    g_tx_avail.flags = 0; g_tx_avail.idx = 0; g_tx_used.flags = 0; g_tx_used.idx = 0;
    queue_address(1, g_tx_desc, &g_tx_avail, &g_tx_used);
    MMIO(REG_STATUS) = MMIO(REG_STATUS) | STATUS_DRIVER_OK;
    barrier(); g_ready = 1; return 0;
}

int virtio_net_config_mac(uint8_t out[6])
{
    if (!out || !g_ready) return -1;
    volatile uint8_t *config = (volatile uint8_t *)(uintptr_t)(PLATFORM_VIRTIO_MMIO_BASE + REG_CONFIG);
    for (uint32_t i = 0; i < 6; i++) out[i] = config[i];
    return 0;
}

static int recycle_rx(uint32_t id)
{
    if (id >= RING_COUNT || (g_rx_posted_mask & (uint16_t)(1u << id)) != 0) {
        g_last_error = 10;
        g_ready = 0;
        return -1;
    }
    g_rx_avail.ring[g_rx_avail.idx % RING_COUNT] = (uint16_t)id;
    g_rx_avail.idx++;
    g_rx_posted_mask |= (uint16_t)(1u << id);
    notify(0);
    return 0;
}

virtio_net_status_t virtio_net_receive(uint8_t *out, uint32_t out_cap,
                                       uint32_t *out_len)
{
    if (!g_ready) return VIRTIO_NET_NOT_READY;
    uint16_t used = g_rx_used.idx;
    barrier();
#ifdef M23_TEST_CONTROLS
    if (used == g_rx_used_seen && !g_test_rx_bad && !g_test_rx_overadvance
        && !g_test_rx_overlong) {
        cpu_relax_rx(); return VIRTIO_NET_NO_PACKET;
    }
#else
    if (used == g_rx_used_seen) { cpu_relax_rx(); return VIRTIO_NET_NO_PACKET; }
#endif
    uint16_t delta = (uint16_t)(used - g_rx_used_seen);
#ifdef M23_TEST_CONTROLS
    int test_rx_bad = g_test_rx_bad;
    int test_rx_overadvance = g_test_rx_overadvance;
    int test_rx_overlong = g_test_rx_overlong;
    g_test_rx_bad = 0; g_test_rx_overadvance = 0; g_test_rx_overlong = 0;
    if (test_rx_bad) delta = 1;
    if (test_rx_overadvance) delta = RING_COUNT + 1u;
    if (test_rx_overlong) delta = 1;
#endif
    if (delta > RING_COUNT) {
        g_last_error = 9;
        g_ready = 0;
        return VIRTIO_NET_MALFORMED;
    }
    uint16_t batch_ids = 0;
    for (uint16_t offset = 0; offset < delta; offset++) {
        vring_used_elem_t candidate = g_rx_used.ring[
            (g_rx_used_seen + offset) % RING_COUNT];
#ifdef M23_TEST_CONTROLS
        if (test_rx_bad && offset == 0) {
            candidate.id = RING_COUNT;
            candidate.len = 0;
        }
        if (test_rx_overlong && offset == 0) {
            candidate.id = 0;
            candidate.len = g_rx_desc[0].len + 1u;
        }
#endif
        uint16_t bit = candidate.id < RING_COUNT
            ? (uint16_t)(1u << candidate.id) : 0;
        if (candidate.id >= RING_COUNT || bit == 0
            || (g_rx_posted_mask & bit) == 0 || (batch_ids & bit) != 0
            || candidate.len < RX_NET_HEADER_BYTES
            || candidate.len > g_rx_desc[candidate.id].len
            || candidate.len - RX_NET_HEADER_BYTES > out_cap) {
            g_last_error = 5;
            g_ready = 0;
            return VIRTIO_NET_MALFORMED;
        }
        batch_ids |= bit;
    }
    vring_used_elem_t elem = g_rx_used.ring[g_rx_used_seen % RING_COUNT];
    g_rx_used_seen++;
    g_rx_posted_mask &= (uint16_t)~(uint16_t)(1u << elem.id);
    uint32_t len = elem.len - RX_NET_HEADER_BYTES;
    for (uint32_t i = 0; i < len; i++) out[i] = g_rx_buf[elem.id][RX_NET_HEADER_BYTES + i];
    if (recycle_rx(elem.id) != 0) return VIRTIO_NET_MALFORMED;
    barrier();
    if (out_len) *out_len = len;
    g_rx_packets++;
    return VIRTIO_NET_OK;
}

static int reap_tx(void)
{
    uint16_t used = g_tx_used.idx;
    barrier();
    if (used == g_tx_used_seen) return 0;
    if (!g_tx_busy) {
        g_last_error = 8;
        g_ready = 0;
        return -1;
    }
#ifdef M23_TEST_CONTROLS
    if (g_tx_completion_hidden) return 0;
#endif
    vring_used_elem_t elem = g_tx_used.ring[g_tx_used_seen % RING_COUNT];
#ifdef M23_TEST_CONTROLS
    int test_tx_bad = g_test_tx_bad;
    int test_tx_overlong = g_test_tx_overlong;
    g_test_tx_bad = 0; g_test_tx_overlong = 0;
    if (test_tx_bad) { elem.id = 1; elem.len = 0; }
    if (test_tx_overlong) { elem.id = 0; elem.len = g_tx_desc[0].len + 1u; }
#endif
    if ((uint16_t)(used - g_tx_used_seen) > RING_COUNT
        || (uint16_t)(used - g_tx_used_seen) != 1u
        || elem.id != 0u || elem.len > g_tx_desc[0].len) {
        g_last_error = 8;
        g_ready = 0;
        return -1;
    }
    g_tx_used_seen = used; g_tx_busy = 0;
    return 1;
}

virtio_net_status_t virtio_net_send(const uint8_t *frame, uint32_t len)
{
    if (!g_ready) return VIRTIO_NET_NOT_READY;
    if (!frame || len == 0 || len + TX_NET_HEADER_BYTES > RX_BUFFER_BYTES) return VIRTIO_NET_MALFORMED;
    if (reap_tx() < 0) return VIRTIO_NET_DEVICE_FAILURE;
    if (g_tx_busy) { g_last_error = 6; return VIRTIO_NET_RING_FULL; }
    for (uint32_t i = 0; i < TX_NET_HEADER_BYTES; i++) g_tx_buf[i] = 0;
    for (uint32_t i = 0; i < len; i++) g_tx_buf[TX_NET_HEADER_BYTES + i] = frame[i];
    g_tx_desc[0].len = TX_NET_HEADER_BYTES + len;
    g_tx_avail.ring[g_tx_avail_idx % RING_COUNT] = 0;
    g_tx_avail_idx++; g_tx_avail.idx = g_tx_avail_idx; g_tx_busy = 1; notify(1);
    for (uint32_t i = 0; i < TX_POLL_BUDGET; i++) {
        cpu_relax_tx();
        if (reap_tx() < 0) return VIRTIO_NET_DEVICE_FAILURE;
        if (!g_tx_busy) { g_tx_packets++; return VIRTIO_NET_OK; }
    }
    g_last_error = 7; return VIRTIO_NET_DEVICE_FAILURE;
}

#if defined(M37_IEC_SERVICE) || defined(M39_RESOURCE_WITNESS)
virtio_net_status_t virtio_net_submit(const uint8_t *frame, uint32_t len)
{
    if (!g_ready) return VIRTIO_NET_NOT_READY;
    if (!frame || len == 0 || len + TX_NET_HEADER_BYTES > RX_BUFFER_BYTES)
        return VIRTIO_NET_MALFORMED;
    if (reap_tx() < 0) return VIRTIO_NET_DEVICE_FAILURE;
    if (g_tx_busy) { g_last_error = 6; return VIRTIO_NET_RING_FULL; }
    for (uint32_t i = 0; i < TX_NET_HEADER_BYTES; i++) g_tx_buf[i] = 0;
    for (uint32_t i = 0; i < len; i++) g_tx_buf[TX_NET_HEADER_BYTES + i] = frame[i];
    g_tx_desc[0].len = TX_NET_HEADER_BYTES + len;
    g_tx_avail.ring[g_tx_avail_idx % RING_COUNT] = 0;
    g_tx_avail_idx++; g_tx_avail.idx = g_tx_avail_idx; g_tx_busy = 1; notify(1);
    /* The caller must poll virtio_net_tx_complete().  In particular, a
     * descriptor being visible in the avail ring is not a provider cause. */
    return VIRTIO_NET_OK;
}
#endif

int virtio_net_tx_complete(void)
{
    if (!g_ready) return -1;
    if (reap_tx() < 0) return -1;
    return g_tx_busy ? 0 : 1;
}

uint64_t virtio_net_rx_packets(void) { return g_rx_packets; }
uint64_t virtio_net_tx_packets(void) { return g_tx_packets; }
uint64_t virtio_net_last_error(void) { return g_last_error; }
uint64_t virtio_net_debug_reg(uint32_t offset) { return MMIO(offset); }
uint64_t virtio_net_debug_status(void) { return MMIO(REG_STATUS); }
uint64_t virtio_net_debug_queue_ready(uint32_t queue)
{
    MMIO(REG_QUEUE_SEL) = queue; return MMIO(REG_QUEUE_READY);
}
uint64_t virtio_net_debug_tx_used(void) { return g_tx_used.idx; }
uint64_t virtio_net_debug_tx_avail(void) { return g_tx_avail.idx; }
uint64_t virtio_net_debug_tx_packets(void) { return g_tx_packets; }
#ifdef M23_TEST_CONTROLS
int virtio_net_test_hold_tx(void)
{
    if (!g_ready) return -1;
    if (g_tx_busy) { g_last_error = 6; return -1; }
    g_tx_completion_hidden = 1;
    return 0;
}

int virtio_net_test_release_tx(void)
{
    if (!g_ready) return -1;
    g_tx_completion_hidden = 0;
    return 0;
}

int virtio_net_test_corrupt_rx_used(void)
{
    if (!g_ready) return -1;
    g_test_rx_bad = 1;
    return 0;
}

int virtio_net_test_overadvance_rx_used(void)
{
    if (!g_ready) return -1;
    g_test_rx_overadvance = 1;
    return 0;
}

int virtio_net_test_overlong_rx_used(void)
{
    if (!g_ready) return -1;
    g_test_rx_overlong = 1;
    return 0;
}

int virtio_net_test_corrupt_tx_used(void)
{
    if (!g_ready || !g_tx_busy) return -1;
    g_test_tx_bad = 1;
    return 0;
}

int virtio_net_test_overlong_tx_used(void)
{
    if (!g_ready || !g_tx_busy) return -1;
    g_test_tx_overlong = 1;
    return 0;
}
#endif
