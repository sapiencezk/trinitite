#pragma once
#include <stdint.h>
#include "noun.h"

/*
 * Phase 5 — RAM-backed content-addressed cold store.
 *
 * Layout at COLD_BASE (see memory.h):
 *   superblock @ +0
 *   objects    @ +0x1000  append-only [hdr|payload|pad]
 *
 * Hash key exposed to Forth: 62-bit BLAKE3 prefix (same idea as indirect atoms).
 * Backend is memcpy into guest RAM; swap cold_read/write for SD later.
 */

int      cold_init(void);                 /* validate or format */
int      cold_format(void);               /* wipe region */

/* Store jammed noun; returns 62-bit hash (never 0 on success). 0 on error. */
uint64_t cold_store(noun n);

/* Load by 62-bit hash; returns noun or 0 if missing. */
noun     cold_load(uint64_t hash62);

/* Append-only event log */
int      cold_log(noun event);            /* 0 ok */
uint64_t cold_log_len(void);
noun     cold_log_at(uint64_t i);         /* 0 if OOB */

/* Single snapshot root */
int      cold_snap_save(noun root);       /* 0 ok */
noun     cold_snap_load(void);            /* 0 if none */
