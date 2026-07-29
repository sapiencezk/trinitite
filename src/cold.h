#pragma once
#include <stdint.h>
#include "noun.h"

/*
 * Phase 5 — content-addressed cold store.
 *
 * Layout at COLD_BASE (see memory.h):
 *   superblock @ +0
 *   objects    @ +0x1000  append-only [hdr|payload|pad]
 *
 * Working storage is always the COLD_BASE RAM window (memcpy).
 * Optional NV flush (semihosting → host file "cold.img") makes snaps
 * survive QEMU reboot when the file is reloaded at COLD_BASE via loader.
 * Real SDHCI can replace cold_nv_flush later without API change.
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
int      cold_snap_save(noun root);       /* 0 ok; flushes NV if available */
noun     cold_snap_load(void);            /* 0 if none */

/* NV flush of entire COLD_BASE window (0 ok, -1 unavailable/fail).
 * Requires cold_nv_arm() first (CKPT!/NVFLUSH arms) so bare QEMU never HLTs. */
void     cold_nv_arm(void);
int      cold_nv_flush(void);
int      cold_nv_enabled(void);
