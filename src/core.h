#pragma once
#include <stdint.h>
#include "memory.h"

/*
 * Phase 4 — multi-core bring-up (dumb).
 *
 * Core 0: Forth / Nock / UART (unchanged).
 * Cores 1–3: C workers with private stacks + SPSC mailboxes.
 * No Nock, no Forth, no noun heap on secondaries.
 */

/* Set by boot.s after BSS zero; secondaries wait for this. */
extern volatile uint64_t cores_ready;

uint64_t core_id(void);
void     core_start(uint64_t id);                 /* id in 1..3 */
void     core_stop(uint64_t id);
int      core_send(uint64_t id, uint64_t code);   /* 1 ok, 0 full/bad */
uint64_t core_heartbeat_get(uint64_t id);

/* Secondary entry — never returns. Called from boot.s with core id. */
void core_secondary_main(uint64_t id) __attribute__((noreturn));
