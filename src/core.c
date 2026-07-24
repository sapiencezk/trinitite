#include <stdint.h>
#include "core.h"
#include "memory.h"

/* Defined in boot.s .data */
extern volatile uint64_t cores_ready;

/* secondary_entry in boot.s — written into the firmware spin table */
extern void secondary_entry(void);

/*
 * RPi3/4 firmware spin-table slots (also what QEMU raspi* emulates):
 *   core 1 @ 0xe0, core 2 @ 0xe8, core 3 @ 0xf0
 * Equivalent to 0xd8 + 8 * core_id.
 */
#define SPIN_TABLE_BASE  0xD8ULL

#define MBOX_SIZE 16   /* power of 2; capacity SIZE-1 */

typedef struct {
    volatile uint32_t head;
    volatile uint32_t tail;
    uint64_t slot[MBOX_SIZE];
} core_mbox_t;

static volatile uint8_t  core_running[NCORES];
static volatile uint64_t core_heartbeat[NCORES];
static volatile uint8_t  core_released[NCORES];  /* spin-table done once */
static core_mbox_t       core_mbox[NCORES];

static inline void dmb(void)
{
    __asm__ volatile("dmb sy" ::: "memory");
}

static inline void dsb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline void sev(void)
{
    __asm__ volatile("sev" ::: "memory");
}

static inline void wfe(void)
{
    __asm__ volatile("wfe" ::: "memory");
}

uint64_t core_id(void)
{
    uint64_t mpidr;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    return mpidr & 0xFF;
}

static int mbox_push(uint64_t id, uint64_t code)
{
    core_mbox_t *m = &core_mbox[id];
    uint32_t h = m->head;
    uint32_t n = (h + 1u) % MBOX_SIZE;
    if (n == m->tail)
        return 0;
    m->slot[h] = code;
    dmb();
    m->head = n;
    return 1;
}

static int mbox_pop(uint64_t id, uint64_t *out)
{
    core_mbox_t *m = &core_mbox[id];
    uint32_t t = m->tail;
    if (t == m->head)
        return 0;
    *out = m->slot[t];
    dmb();
    m->tail = (t + 1u) % MBOX_SIZE;
    return 1;
}

/* First start: free the core from the firmware spin-table. */
static void spin_table_release(uint64_t id)
{
    if (id < 1 || id >= NCORES)
        return;
    if (core_released[id])
        return;
    volatile uint64_t *slot =
        (volatile uint64_t *)(uintptr_t)(SPIN_TABLE_BASE + 8ULL * id);
    *slot = (uint64_t)(uintptr_t)secondary_entry;
    dsb();
    sev();
    core_released[id] = 1;
}

void core_start(uint64_t id)
{
    if (id < 1 || id >= NCORES)
        return;
    /* Fresh run: drop any stale mailbox traffic and reset HB. */
    core_mbox[id].head = 0;
    core_mbox[id].tail = 0;
    core_heartbeat[id] = 0;
    dmb();
    core_running[id] = 1;
    dmb();
    spin_table_release(id);
    sev();
}

void core_stop(uint64_t id)
{
    if (id < 1 || id >= NCORES)
        return;
    core_running[id] = 0;
    dmb();
    sev();
}

int core_send(uint64_t id, uint64_t code)
{
    if (id < 1 || id >= NCORES)
        return 0;
    if (!mbox_push(id, code))
        return 0;
    dmb();
    sev();
    return 1;
}

uint64_t core_heartbeat_get(uint64_t id)
{
    if (id >= NCORES)
        return 0;
    return core_heartbeat[id];
}

void core_secondary_main(uint64_t id)
{
    /* Core 0 has already finished BSS by the time spin-table fires. */
    while (!cores_ready)
        wfe();

    for (;;) {
        while (!core_running[id])
            wfe();

        while (core_running[id]) {
            uint64_t code;
            if (mbox_pop(id, &code)) {
                (void)code;
                core_heartbeat[id]++;
            } else {
                wfe();
            }
        }
    }
}
