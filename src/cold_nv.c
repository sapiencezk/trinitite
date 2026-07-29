#include <stdint.h>
#include "memory.h"
#include "uart.h"

/*
 * Cold-store NV flush via ARM semihosting (QEMU: -semihosting).
 *
 * Working storage remains the COLD_BASE RAM window. On flush, the whole
 * 8MB region is written to a host file (default "cold.img") so a subsequent
 * QEMU boot with -device loader,file=cold.img,addr=0x07100000 reloads it.
 *
 * Real SDHCI backend can replace cold_nv_flush later; cold_read/write API
 * stays the same (memcpy into COLD_BASE, then optional flush).
 */

/* Angel semihosting (AArch64): HLT #0xF000, x0=op, x1=&params */
#define SYS_OPEN   0x01
#define SYS_CLOSE  0x02
#define SYS_WRITE  0x05
#define SYS_FLEN   0x0C
#define SYS_ISTTY  0x09

/* OPEN modes (binary): 0=r, 4=w truncate, 8=a */
#define OPEN_W     4

/* Host path relative to QEMU process cwd (repo root for make/smoke). */
static const char g_nv_path[] = "build/cold.img";
/* Only attempt semihost after explicit enable (CKPT!/NVFLUSH under -semihosting).
 * Bare QEMU tests must never execute HLT #0xF000. */
static int g_nv_armed;

static uint64_t semihost(uint64_t op, void *arg)
{
    register uint64_t x0 asm("x0") = op;
    register uint64_t x1 asm("x1") = (uint64_t)(uintptr_t)arg;
    asm volatile("hlt #0xf000" : "+r"(x0) : "r"(x1) : "memory");
    return x0;
}

static int semihost_open(const char *path, int mode)
{
    struct {
        const char *path;
        uint64_t    mode;
        uint64_t    len;
    } a;
    uint64_t n = 0;
    while (path[n])
        n++;
    a.path = path;
    a.mode = (uint64_t)mode;
    a.len  = n;
    return (int)semihost(SYS_OPEN, &a);
}

static int semihost_write(int fd, const void *buf, uint64_t len)
{
    struct {
        uint64_t    fd;
        const void *buf;
        uint64_t    len;
    } a;
    a.fd  = (uint64_t)(uint32_t)fd;
    a.buf = buf;
    a.len = len;
    /* returns bytes *not* written; 0 = all written */
    return (int)semihost(SYS_WRITE, &a);
}

static void semihost_close(int fd)
{
    uint64_t f = (uint64_t)(uint32_t)fd;
    semihost(SYS_CLOSE, &f);
}

void cold_nv_arm(void)
{
    g_nv_armed = 1;
}

int cold_nv_flush(void)
{
    if (!g_nv_armed)
        return -1;

    int fd = semihost_open(g_nv_path, OPEN_W);
    if (fd < 0)
        return -1;

    const uint8_t *base = (const uint8_t *)(uintptr_t)COLD_BASE;
    uint64_t left = COLD_SIZE;
    uint64_t off  = 0;
    const uint64_t CHUNK = 64ULL * 1024ULL;
    while (left) {
        uint64_t n = left > CHUNK ? CHUNK : left;
        int not_written = semihost_write(fd, base + off, n);
        if (not_written != 0) {
            semihost_close(fd);
            return -1;
        }
        off  += n;
        left -= n;
    }
    semihost_close(fd);
    return 0;
}

int cold_nv_enabled(void)
{
    return g_nv_armed;
}
