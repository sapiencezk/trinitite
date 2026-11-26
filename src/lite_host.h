#pragma once

#include "memory.h"
#include "noun.h"

/*
 * The lite node's host. Cue, kick, bounded poke/peek, persist wrapper sample.
 * There is no UART ovum ingress: without the diagnostic driver the host
 * boots, replays its log, and waits.
 */
#define LITE_PILL_SHAPE_NOCKAPP 2u
#define LITE_PLAN_BASE (PILL_BASE + 0x01000000ULL)
/* Diagnostic application bundle slot: [u64 jam_len][64 hex expected sha256][jam].
 * 0x03000000 clears the 16 MiB plan region (LITE_PLAN_BASE + LITE_CUE_MAX_INPUT_BYTES)
 * and sits below HEAP_SCRATCH_BASE and MMIO. */
#define LITE_APP_BASE (PILL_BASE + 0x03000000ULL)
#define LITE_APP_SHA256_HEX_LEN 64u

typedef struct {
    int parse;
    int jumped;
    uint64_t ops;
    uint64_t cells;
    uint64_t stack;
    uint64_t ticks;
    uint64_t effect_len;
    uint64_t abort_reason;
    noun effects;
    noun product;
    int persist_ok;
    uint64_t persist_ticks;
    uint64_t persist_copy_map_hwm;
    uint64_t persist_copy_map_capacity;
} lite_host_result_t;

void lite_host_boot(void);
int lite_host_ready(void);
int lite_host_poke(noun cause, lite_host_result_t *out);
int lite_host_peek(noun path, lite_host_result_t *out);
int lite_host_persist(lite_host_result_t *out);
/* Row 199: `/state-hash` and its event number N; 0 when stopped or not ready.
 * Row 328: the kernel's /state-hash is a Tip5 noun digest, one atom below
 * p^5 < 2^320, read as LITE_DIGEST_BYTES little-endian bytes. */
#define LITE_DIGEST_BYTES 40
int lite_host_state_hash(uint64_t *event, uint8_t hash[LITE_DIGEST_BYTES], lite_host_result_t *out);
int lite_host_cue_bytes(const uint8_t *bytes, uint64_t len, noun *out);
/* Admission-gated application load. `expected_sha256` is a 64-char ASCII hex
 * digest; all-zero means "no gate". SHA-256 runs natively (outside Nock) and a
 * mismatch refuses before cue/poke. On pass the bundle is cued and poked as
 * [%load-bundle noun]. Returns 1 iff the poke parsed. */
int lite_host_load_app(const uint8_t *jam, uint64_t jam_len,
                     const char *expected_sha256, lite_host_result_t *out);
const char *lite_host_abort_name(int jumped, uint64_t reason);
/* Row 221 (row 212 (c)), only with LITE_COMPACT (memory.h): the driver calls
 * lite_host_handoff once it has handed off a step's effects and reset scratch;
 * a pending compaction (after a verified checkpoint) runs there. The L1
 * test harness cues its plan into scratch and names it as a root. */
void lite_host_handoff(void);
int lite_host_cue_bytes_scratch(const uint8_t *bytes, uint64_t len, noun *out);
void lite_host_harness_root(noun plan);
