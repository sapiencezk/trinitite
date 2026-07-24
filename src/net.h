#pragma once
#include <stdint.h>
#include "noun.h"

/*
 * Phase 8 — industrial networking stubs (no real NIC/Modbus/CAN).
 *
 * Effects (TX):
 *   %etx  7894117   data = frame atom
 *   %mtx  7894125   data = PDU atom
 *   %ctx  7894115   data = [id data-atom]
 *
 * Loopback injects events onto the Phase 2 queue:
 *   [%erx frame]  [%mrx pdu]  [%crx [id data]]
 *
 * Families for NSTAT/NRX@: 0=eth 1=modbus 2=can
 */

#define NET_FAM_ETH  0u
#define NET_FAM_MB   1u
#define NET_FAM_CAN  2u

#define CORD_ETX  7894117ULL
#define CORD_ERX  7893605ULL
#define CORD_MTX  7894125ULL
#define CORD_MRX  7893613ULL
#define CORD_CTX  7894115ULL
#define CORD_CRX  7893603ULL

void     net_set_loopback(int on);
int      net_loopback(void);
void     net_stats_clear(void);
uint64_t net_stat_tx(uint32_t fam);
uint64_t net_stat_rx(uint32_t fam);

void net_handle_etx(noun data);
void net_handle_mtx(noun data);
void net_handle_ctx(noun data);
