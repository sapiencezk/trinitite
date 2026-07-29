#pragma once

#include <stdint.h>
#include "noun.h"

typedef enum {
    COLD_RESULT_VALID = 0,
    COLD_RESULT_EMPTY = 1,
    COLD_RESULT_ABSENT = 2,
    COLD_RESULT_CORRUPT = -1,
    COLD_RESULT_UNSUPPORTED = -2,
    COLD_RESULT_SUPERBLOCK = -3,
    COLD_RESULT_OFFSET = -4,
    COLD_RESULT_ALIGNMENT = -5,
    COLD_RESULT_HEADER = -6,
    COLD_RESULT_KIND = -7,
    COLD_RESULT_LENGTH = -8,
    COLD_RESULT_HEADER_DIGEST = -9,
    COLD_RESULT_PAYLOAD_DIGEST = -10,
    COLD_RESULT_GENERATION = -11,
    COLD_RESULT_COMMIT = -12,
    COLD_RESULT_CUE = -13,
    COLD_RESULT_SHAPE = -14,
    COLD_RESULT_IDENTITY = -15,
    COLD_RESULT_ALLOC = -16,
    COLD_RESULT_WRITE_FAULT = -17
} cold_result_t;

typedef enum {
    COLD_WRITE_NONE = 0,
    COLD_WRITE_OBJECT_HEADER = 1,
    COLD_WRITE_PAYLOAD = 2,
    COLD_WRITE_OBJECT_COMMIT = 3,
    COLD_WRITE_SUPERBLOCK = 4
} cold_write_phase_t;

int cold_init(void);   /* auto-initialize only an exactly all-zero image */
int cold_format(void); /* explicit destructive format */
cold_result_t cold_probe(void);
cold_result_t cold_last_result(void);
const char *cold_result_name(cold_result_t result);
uint64_t cold_selected_generation(void);
uint64_t cold_data_head(void);

uint64_t cold_store(noun n);
noun cold_load(uint64_t hash62);
int cold_log(noun event);
uint64_t cold_log_len(void);
noun cold_log_at(uint64_t i);

int cold_snap_save(noun root);
noun cold_snap_load(void);    /* standalone/Forth wrapper; commits decode */
int cold_snap_decode(noun *out); /* SCRATCH decode; leaves noun_tx active */

void cold_fault_set(cold_write_phase_t phase, int64_t after_bytes);
void cold_fault_clear(void);

/* Focused fail-closed/torn-write device-code regression probe. */
uint64_t cold_m2_selftest(void);

void cold_nv_arm(void);
int cold_nv_flush(void);
int cold_nv_enabled(void);
