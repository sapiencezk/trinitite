#include <stdint.h>
#include "net.h"
#include "noun.h"
#include "kernel.h"
#include "trace.h"

static int      g_loopback = 1;   /* default ON for QEMU/tests */
static uint64_t tx_count[3];
static uint64_t rx_count[3];

void net_set_loopback(int on)
{
    g_loopback = on ? 1 : 0;
}

int net_loopback(void)
{
    return g_loopback;
}

void net_stats_clear(void)
{
    for (int i = 0; i < 3; i++) {
        tx_count[i] = 0;
        rx_count[i] = 0;
    }
}

uint64_t net_stat_tx(uint32_t fam)
{
    return fam < 3 ? tx_count[fam] : 0;
}

uint64_t net_stat_rx(uint32_t fam)
{
    return fam < 3 ? rx_count[fam] : 0;
}

static void net_tx(uint32_t fam, uint64_t rx_cord, noun payload)
{
    if (fam < 3)
        tx_count[fam]++;
    trace_rec(T_NTX, fam);

    if (!g_loopback)
        return;

    /* Event: [rx-tag payload] */
    noun ev = alloc_cell(direct(rx_cord), payload);
    evq_enq(ev);
    if (fam < 3)
        rx_count[fam]++;
    trace_rec(T_NRX, fam);
}

void net_handle_etx(noun data)
{
    net_tx(NET_FAM_ETH, CORD_ERX, data);
}

void net_handle_mtx(noun data)
{
    net_tx(NET_FAM_MB, CORD_MRX, data);
}

void net_handle_ctx(noun data)
{
    /* data should be [id payload]; still loop back the cell as-is */
    if (!noun_is_cell(data) && !noun_is_atom(data))
        return;
    net_tx(NET_FAM_CAN, CORD_CRX, data);
}
