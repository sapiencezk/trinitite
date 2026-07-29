#include <stdint.h>
#include "cold_media.h"
#include "runtime_stats.h"

/*
 * Raspberry Pi 4B / BCM2711 EMMC2 target-private PIO path.
 *
 * The deployment contract boots from the same SD card and requires firmware
 * to leave EMMC2 powered, pinned, and clocked.  This driver deliberately does
 * not grow a mailbox, GPIO, DMA, IRQ, or generic block subsystem.
 */
#define EMMC2_BASE 0xFE340000ULL

#define SD_BLKSIZECNT 0x04u
#define SD_ARG1       0x08u
#define SD_CMDTM      0x0cu
#define SD_RESP0      0x10u
#define SD_RESP1      0x14u
#define SD_RESP2      0x18u
#define SD_RESP3      0x1cu
#define SD_DATA       0x20u
#define SD_STATUS     0x24u
#define SD_CONTROL1   0x2cu
#define SD_INTERRUPT  0x30u

#define STATUS_CMD_INHIBIT  (1u << 0)
#define STATUS_DAT_INHIBIT  (1u << 1)
#define STATUS_CARD_PRESENT (1u << 16)
#define STATUS_WRITE_SWITCH (1u << 19)

#define CONTROL1_CLK_INT_EN (1u << 0)
#define CONTROL1_CLK_STABLE (1u << 1)
#define CONTROL1_CLK_SD_EN  (1u << 2)
#define CONTROL1_RESET_CMD  (1u << 25)
#define CONTROL1_RESET_DAT  (1u << 26)

#define INT_CMD_DONE    (1u << 0)
#define INT_DATA_DONE   (1u << 1)
#define INT_WRITE_READY (1u << 4)
#define INT_READ_READY  (1u << 5)
#define INT_ERROR       (1u << 15)
#define INT_CMD_TIMEOUT (1u << 16)
#define INT_CMD_CRC     (1u << 17)
#define INT_DATA_TIMEOUT (1u << 20)
#define INT_DATA_CRC    (1u << 21)
#define INT_ERROR_MASK  (INT_ERROR | 0xffff0000u)

#define CMD_INDEX(n)       ((uint32_t)(n) << 24)
#define CMD_RSP_NONE       (0u << 16)
#define CMD_RSP_136        (1u << 16)
#define CMD_RSP_48         (2u << 16)
#define CMD_RSP_48_BUSY    (3u << 16)
#define CMD_CRC_CHECK      (1u << 19)
#define CMD_INDEX_CHECK    (1u << 20)
#define CMD_DATA_PRESENT   (1u << 21)
#define CMD_READ           (1u << 4)

#define CMD0  (CMD_INDEX(0) | CMD_RSP_NONE)
#define CMD2  (CMD_INDEX(2) | CMD_RSP_136 | CMD_CRC_CHECK)
#define CMD3  (CMD_INDEX(3) | CMD_RSP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define CMD7  (CMD_INDEX(7) | CMD_RSP_48_BUSY | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define CMD8  (CMD_INDEX(8) | CMD_RSP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define CMD9  (CMD_INDEX(9) | CMD_RSP_136 | CMD_CRC_CHECK)
#define CMD13 (CMD_INDEX(13) | CMD_RSP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define CMD16 (CMD_INDEX(16) | CMD_RSP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define CMD17 (CMD_INDEX(17) | CMD_RSP_48 | CMD_CRC_CHECK \
               | CMD_INDEX_CHECK | CMD_DATA_PRESENT | CMD_READ)
#define CMD24 (CMD_INDEX(24) | CMD_RSP_48 | CMD_CRC_CHECK \
               | CMD_INDEX_CHECK | CMD_DATA_PRESENT)
#define CMD55 (CMD_INDEX(55) | CMD_RSP_48 | CMD_CRC_CHECK | CMD_INDEX_CHECK)
#define ACMD41 (CMD_INDEX(41) | CMD_RSP_48)

static uint32_t g_rca;
static uint64_t g_capacity;
static int g_high_capacity;
static int g_ready;
static uint32_t g_last_interrupt;

static volatile uint32_t *reg(uint32_t off)
{
    return (volatile uint32_t *)(uintptr_t)(EMMC2_BASE + off);
}

static uint32_t read32(uint32_t off)
{
    return *reg(off);
}

static void write32(uint32_t off, uint32_t value)
{
    *reg(off) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}

static uint64_t bounded_deadline(uint64_t deadline)
{
    if (deadline)
        return deadline;
    uint64_t now = runtime_counter_now();
    uint64_t freq = runtime_counter_freq();
    uint64_t allowance =
        freq <= UINT64_MAX / 2 ? freq * 2 : UINT64_MAX;
    return allowance <= UINT64_MAX - now ? now + allowance : UINT64_MAX;
}

static int expired(uint64_t deadline)
{
    return runtime_counter_now() >= deadline;
}

static cold_media_status_t interrupt_status(uint32_t irpt,
                                            cold_media_status_t fallback)
{
    g_last_interrupt = irpt;
    if (irpt & (INT_CMD_TIMEOUT | INT_DATA_TIMEOUT))
        return COLD_MEDIA_TIMEOUT;
    if (irpt & INT_CMD_CRC)
        return COLD_MEDIA_COMMAND_CRC;
    if (irpt & INT_DATA_CRC)
        return COLD_MEDIA_DATA_CRC;
    return fallback;
}

static cold_media_status_t wait_status_clear(uint32_t bits,
                                             uint64_t deadline)
{
    while (read32(SD_STATUS) & bits) {
        if (!(read32(SD_STATUS) & STATUS_CARD_PRESENT))
            return COLD_MEDIA_REMOVED;
        if (expired(deadline))
            return COLD_MEDIA_TIMEOUT;
    }
    return COLD_MEDIA_OK;
}

static cold_media_status_t wait_interrupt(uint32_t wanted,
                                          uint64_t deadline)
{
    for (;;) {
        uint32_t irpt = read32(SD_INTERRUPT);
        if (irpt & INT_ERROR_MASK) {
            write32(SD_INTERRUPT, irpt);
            return interrupt_status(irpt, COLD_MEDIA_READ_FAILURE);
        }
        if (irpt & wanted) {
            write32(SD_INTERRUPT, wanted);
            return COLD_MEDIA_OK;
        }
        if (!(read32(SD_STATUS) & STATUS_CARD_PRESENT))
            return COLD_MEDIA_REMOVED;
        if (expired(deadline))
            return COLD_MEDIA_TIMEOUT;
    }
}

static cold_media_status_t command(uint32_t cmd, uint32_t arg,
                                   uint64_t deadline, uint32_t *response)
{
    uint32_t inhibit = STATUS_CMD_INHIBIT;
    if (cmd & CMD_DATA_PRESENT)
        inhibit |= STATUS_DAT_INHIBIT;
    cold_media_status_t status = wait_status_clear(inhibit, deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    write32(SD_INTERRUPT, 0xffffffffu);
    write32(SD_ARG1, arg);
    write32(SD_CMDTM, cmd);
    status = wait_interrupt(INT_CMD_DONE, deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    if (response)
        *response = read32(SD_RESP0);
    return COLD_MEDIA_OK;
}

static void reset_lines(uint64_t deadline)
{
    uint32_t control = read32(SD_CONTROL1);
    control |= CONTROL1_RESET_CMD | CONTROL1_RESET_DAT;
    write32(SD_CONTROL1, control);
    while (read32(SD_CONTROL1)
           & (CONTROL1_RESET_CMD | CONTROL1_RESET_DAT)) {
        if (expired(deadline))
            break;
    }
    write32(SD_INTERRUPT, 0xffffffffu);
}

static uint32_t csd_bits(const uint32_t csd[4], unsigned low,
                         unsigned width)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < width; i++) {
        unsigned bit = low + i;
        unsigned word = 3u - bit / 32u;
        value |= ((csd[word] >> (bit & 31u)) & 1u) << i;
    }
    return value;
}

static cold_media_status_t read_capacity(uint64_t deadline)
{
    cold_media_status_t status =
        command(CMD9, g_rca << 16, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    uint32_t raw[4] = {
        read32(SD_RESP0), read32(SD_RESP1),
        read32(SD_RESP2), read32(SD_RESP3)
    };
    uint32_t csd[4] = {
        (raw[3] << 8) | (raw[2] >> 24),
        (raw[2] << 8) | (raw[1] >> 24),
        (raw[1] << 8) | (raw[0] >> 24),
        raw[0] << 8
    };
    uint32_t structure = csd_bits(csd, 126, 2);
    if (structure == 1) {
        uint64_t c_size = csd_bits(csd, 48, 22);
        g_capacity = (c_size + 1) * 1024;
    } else if (structure == 0) {
        uint64_t read_bl_len = csd_bits(csd, 80, 4);
        uint64_t c_size = csd_bits(csd, 62, 12);
        uint64_t c_mult = csd_bits(csd, 47, 3);
        if (read_bl_len > 31 || c_mult > 7)
            return COLD_MEDIA_UNSUPPORTED;
        uint64_t bytes = (c_size + 1)
                       << (c_mult + 2 + read_bl_len);
        g_capacity = bytes / COLD_MEDIA_SECTOR_BYTES;
    } else {
        return COLD_MEDIA_UNSUPPORTED;
    }
    return g_capacity ? COLD_MEDIA_OK : COLD_MEDIA_UNSUPPORTED;
}

static cold_media_status_t initialize_card(uint64_t deadline)
{
    if (g_ready)
        return COLD_MEDIA_OK;
    if (!(read32(SD_STATUS) & STATUS_CARD_PRESENT))
        return COLD_MEDIA_ABSENT;
    uint32_t control = read32(SD_CONTROL1);
    if ((control & (CONTROL1_CLK_INT_EN | CONTROL1_CLK_STABLE
                    | CONTROL1_CLK_SD_EN))
        != (CONTROL1_CLK_INT_EN | CONTROL1_CLK_STABLE
            | CONTROL1_CLK_SD_EN))
        return COLD_MEDIA_UNSUPPORTED;

    reset_lines(deadline);
    cold_media_status_t status = command(CMD0, 0, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    uint32_t response = 0;
    status = command(CMD8, 0x1aau, deadline, &response);
    if (status != COLD_MEDIA_OK || (response & 0xfffu) != 0x1aau)
        return COLD_MEDIA_UNSUPPORTED;

    uint32_t ocr = 0;
    do {
        status = command(CMD55, 0, deadline, 0);
        if (status != COLD_MEDIA_OK)
            return status;
        status = command(ACMD41, 0x40ff8000u, deadline, &ocr);
        if (status != COLD_MEDIA_OK)
            return status;
        if (expired(deadline))
            return COLD_MEDIA_TIMEOUT;
    } while (!(ocr & (1u << 31)));
    g_high_capacity = (ocr & (1u << 30)) != 0;

    status = command(CMD2, 0, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    status = command(CMD3, 0, deadline, &response);
    if (status != COLD_MEDIA_OK)
        return status;
    g_rca = response >> 16;
    if (!g_rca)
        return COLD_MEDIA_UNSUPPORTED;
    status = read_capacity(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    status = command(CMD7, g_rca << 16, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    if (!g_high_capacity) {
        status = command(CMD16, COLD_MEDIA_SECTOR_BYTES, deadline, 0);
        if (status != COLD_MEDIA_OK)
            return status;
    }
    g_ready = 1;
    return COLD_MEDIA_OK;
}

static cold_media_status_t address_arg(uint64_t lba, uint32_t *arg)
{
    if (lba >= g_capacity)
        return COLD_MEDIA_RANGE;
    if (g_high_capacity) {
        if (lba > UINT32_MAX)
            return COLD_MEDIA_RANGE;
        *arg = (uint32_t)lba;
    } else {
        if (lba > UINT32_MAX / COLD_MEDIA_SECTOR_BYTES)
            return COLD_MEDIA_RANGE;
        *arg = (uint32_t)(lba * COLD_MEDIA_SECTOR_BYTES);
    }
    return COLD_MEDIA_OK;
}

cold_media_status_t rpi4_sd_probe(
    uint64_t *capacity, int *read_only, uint64_t deadline)
{
    deadline = bounded_deadline(deadline);
    cold_media_status_t status = initialize_card(deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    *capacity = g_capacity;
    /* SDHCI exposes the mechanical switch level; low is protected. */
    *read_only = (read32(SD_STATUS) & STATUS_WRITE_SWITCH) == 0;
    return COLD_MEDIA_OK;
}

cold_media_status_t rpi4_sd_sector_read(
    uint64_t lba, uint8_t *dst, uint64_t deadline)
{
    deadline = bounded_deadline(deadline);
    if (!g_ready)
        return COLD_MEDIA_RESET_REQUIRED;
    uint32_t arg;
    cold_media_status_t status = address_arg(lba, &arg);
    if (status != COLD_MEDIA_OK)
        return status;
    write32(SD_BLKSIZECNT, COLD_MEDIA_SECTOR_BYTES | (1u << 16));
    status = command(CMD17, arg, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    status = wait_interrupt(INT_READ_READY, deadline);
    if (status != COLD_MEDIA_OK)
        return status;
    uint32_t *words = (uint32_t *)(void *)dst;
    for (unsigned i = 0; i < COLD_MEDIA_SECTOR_BYTES / 4; i++)
        words[i] = read32(SD_DATA);
    status = wait_interrupt(INT_DATA_DONE, deadline);
    return status;
}

cold_media_status_t rpi4_sd_sector_write(
    uint64_t lba, const uint8_t *src, uint64_t deadline, int *submitted)
{
    deadline = bounded_deadline(deadline);
    *submitted = 0;
    if (!g_ready)
        return COLD_MEDIA_RESET_REQUIRED;
    if ((read32(SD_STATUS) & STATUS_WRITE_SWITCH) == 0)
        return COLD_MEDIA_READ_ONLY;
    uint32_t arg;
    cold_media_status_t status = address_arg(lba, &arg);
    if (status != COLD_MEDIA_OK)
        return status;
    write32(SD_BLKSIZECNT, COLD_MEDIA_SECTOR_BYTES | (1u << 16));
    status = command(CMD24, arg, deadline, 0);
    if (status != COLD_MEDIA_OK)
        return status;
    *submitted = 1; /* do not retry after the card accepted CMD24 */
    status = wait_interrupt(INT_WRITE_READY, deadline);
    if (status != COLD_MEDIA_OK)
        return COLD_MEDIA_WRITE_UNKNOWN;
    const uint32_t *words = (const uint32_t *)(const void *)src;
    for (unsigned i = 0; i < COLD_MEDIA_SECTOR_BYTES / 4; i++)
        write32(SD_DATA, words[i]);
    status = wait_interrupt(INT_DATA_DONE, deadline);
    return status == COLD_MEDIA_OK ? status : COLD_MEDIA_WRITE_UNKNOWN;
}

cold_media_status_t rpi4_sd_barrier(uint64_t deadline)
{
    deadline = bounded_deadline(deadline);
    if (!g_ready)
        return COLD_MEDIA_RESET_REQUIRED;
    for (;;) {
        uint32_t card = 0;
        cold_media_status_t status =
            command(CMD13, g_rca << 16, deadline, &card);
        if (status != COLD_MEDIA_OK)
            return status;
        uint32_t state = (card >> 9) & 0xfu;
        if ((card & (1u << 8)) && state == 4)
            return COLD_MEDIA_OK;
        if (expired(deadline))
            return COLD_MEDIA_TIMEOUT;
    }
}
