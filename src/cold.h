#pragma once

#include <stdint.h>
#include "noun.h"

/* Row 212 PR 1c (running log + SD recorder ring): compiled only with
 * I3_CHECKPOINT_EVERY > 0 and I3_LITE_LOG (nested flag, default off), so the
 * flag-off and the 1b flag-on images are unchanged. */
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0 && defined(I3_LITE_LOG)
#define COLD_LITE_LOG 1
#endif

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
uint64_t cold_data_head(void);

uint64_t cold_store(noun n);
/* Return the exact 62-bit identity of the canonical jam payload without
 * appending a blob, in the hash domain cold_store() uses. */
uint64_t cold_jam_hash(noun n);
noun cold_load(uint64_t hash62);
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
#include "bounded_cue.h"
/* Row 212 checkpoint verify: cold_load, but the noun is decoded into SCRATCH
 * (the caller resets scratch), so a read-back costs no persist cells, and
 * (row 317 (3), Q7) cued with `limits`, the checkpoint cue bound.
 * Compiled only with the checkpoint flag, so flag-off images are unchanged. */
noun cold_load_scratch(uint64_t hash62, const cue_bounded_limits_t *limits);
/* cold_store through the checkpoint writer's own jam (ckpt_jam.h). */
uint64_t cold_store_ckpt(noun n);
/* Q8: the cue limits LOG entries decode with (the host's live admission). */
void cold_set_log_limits(const cue_bounded_limits_t *limits);
/* Q8: the heap LOG entries decode into (HEAP_MODE_SCRATCH by default). */
void cold_set_log_heap_mode(int heap_mode);
/* cold_load_scratch into the given heap. */
noun cold_load_limits(uint64_t hash62, const cue_bounded_limits_t *limits, int heap_mode);
/* Row 212 PR 1b: walk the BLOBs of at most max_len payload bytes in media
 * order, each decoded into SCRATCH, for the checkpoint header search. */
int cold_blob_scan(uint64_t max_len, int (*fn)(void *ctx, noun blob), void *ctx);
#endif
#if defined(COLD_LITE_LOG)
/* Row 212 (2) as amended, running log (PR 1c). The superblock's 32 reserved
 * bytes carry the log base: index B (entries 1..B are dropped), a media
 * offset (an object boundary or data_head; entry B+1 is the first LOG object
 * at or after it), a row 213
 * job-cell sum (row 221 (7): the jobs of the entries after B up to the
 * checkpoint whose verify moved the base there; audit only, boot does not
 * load it and counts from the base), and a check word over the 64 checksummed
 * superblock bytes plus those three fields. All zero = no base (B = 0).
 * Dropped entries still sit in the chain until compaction. The I3 host never
 * reads them again (replay and log_len start at the base). */
typedef struct {
    uint64_t index;    /* B */
    uint64_t off;      /* entry B+1 is the first LOG object at or after it */
    uint64_t job_sum;  /* row 221 (7): jobs after B at the move; audit only */
    uint64_t len;      /* logical log length: B + entries at or after off */
} cold_log_base_t;
int cold_log_base(cold_log_base_t *out);
/* Move the base to new_index (>= the current one, <= the logical length) in
 * one superblock write, carried by the append of `marker` (a small BLOB, the
 * audit record of the move). Returns 0 on success; on failure nothing moved. */
int cold_log_rebase(uint64_t new_index, uint64_t job_sum, noun marker);
#endif
int cold_log(noun event);
uint64_t cold_log_len(void);
noun cold_log_next(uint64_t *cursor); /* boot replay: sequential, SCRATCH decode */




void cold_nv_arm(void);
int cold_nv_flush(void);
int cold_nv_enabled(void);
