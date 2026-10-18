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

/* With an active cold-media backend, TRI_DEPLOY has one physical durability
 * boundary. COLD_DEPLOY_COMMITTED is returned only after the exact selected
 * object chain and selecting superblock were read back and validated from
 * media. COLD_DEPLOY_REJECTED is reserved for validation/preflight before any
 * deployment object is appended. Once a physical deployment append is
 * attempted, any failure is COLD_DEPLOY_DURABILITY_UNKNOWN: an 8-byte-aligned
 * append can share a sector with retained data, so remount may find the old
 * pair, the new pair, or no valid pair. With inactive RAM/semihost media,
 * COMMITTED means only volatile in-window logical acceptance; it makes no
 * physical readback or durable-media claim. */
typedef enum {
    COLD_DEPLOY_REJECTED = -1,
    COLD_DEPLOY_COMMITTED = 0,
    COLD_DEPLOY_DURABILITY_UNKNOWN = 1
} cold_deploy_result_t;

int cold_init(void);   /* auto-initialize only an exactly all-zero image */
int cold_format(void); /* explicit destructive format */
cold_result_t cold_probe(void);
cold_result_t cold_last_result(void);
const char *cold_result_name(cold_result_t result);
uint64_t cold_selected_generation(void);
uint64_t cold_data_head(void);

uint64_t cold_store(noun n);
/* M7 TRI_DEPLOY commit: append/verify one PILL blob and one supervisor
 * snapshot under one final superblock write. COLD_DEPLOY_REJECTED means no
 * physical deployment append was attempted. COLD_DEPLOY_DURABILITY_UNKNOWN
 * means active physical deployment media was touched but COMMITTED could not
 * be established by readback; a caller must fence, not report an ordinary
 * failed activation or assume that the retained old pair remains bootable. */
cold_deploy_result_t cold_store_deployment(noun pill_blob,
                                           noun supervisor_snapshot,
                                           uint64_t *pill_hash_out);
/* Return the exact 62-bit identity of the canonical jam payload without
 * appending a blob.  M7 uses this to compare a restored blob in the same
 * hash domain used by cold_store(). */
uint64_t cold_jam_hash(noun n);
noun cold_load(uint64_t hash62);
#if defined(I3_CHECKPOINT_EVERY) && I3_CHECKPOINT_EVERY > 0
/* Row 212 checkpoint verify: cold_load, but the noun is decoded into SCRATCH
 * (the caller resets scratch), so a read-back costs no persist cells.
 * Compiled only with the checkpoint flag, so flag-off images are unchanged. */
noun cold_load_scratch(uint64_t hash62);
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
 * reads them again (replay and log_len start at the base), but cold_log_len
 * and cold_log_at still count and read them by physical index, as the Forth
 * words LOGLEN and LOG@ do (forth.s, cold_loglen and cold_logat). */
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
noun cold_log_at(uint64_t i);
noun cold_log_next(uint64_t *cursor); /* boot replay: sequential, SCRATCH decode */

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
