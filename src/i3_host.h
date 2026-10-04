#pragma once

#include "memory.h"
#include "noun.h"

/*
 * I3 lite-node host. Cue, kick, bounded poke/peek, persist wrapper sample.
 * UART ovum ingress is a later L item; T1 boots then wfe.
 */
#define I3_PILL_SHAPE_NOCKAPP 2u
#define I3_PLAN_BASE (PILL_BASE + 0x01000000ULL)
/* Diagnostic application bundle slot: [u64 jam_len][64 hex expected sha256][jam].
 * 0x03000000 clears the 16 MiB plan region (I3_PLAN_BASE + I3_CUE_MAX_INPUT_BYTES)
 * and sits below HEAP_SCRATCH_BASE and MMIO. */
#define I3_APP_BASE (PILL_BASE + 0x03000000ULL)
#define I3_APP_SHA256_HEX_LEN 64u

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
} i3_host_result_t;

void i3_host_boot(void);
int i3_host_ready(void);
int i3_host_poke(noun cause, i3_host_result_t *out);
int i3_host_peek(noun path, i3_host_result_t *out);
int i3_host_persist(i3_host_result_t *out);
int i3_host_cue_bytes(const uint8_t *bytes, uint64_t len, noun *out);
/* Admission-gated application load. `expected_sha256` is a 64-char ASCII hex
 * digest; all-zero means "no gate". SHA-256 runs natively (outside Nock) and a
 * mismatch refuses before cue/poke. On pass the bundle is cued and poked as
 * [%load-bundle noun]. Returns 1 iff the poke parsed. */
int i3_host_load_app(const uint8_t *jam, uint64_t jam_len,
                     const char *expected_sha256, i3_host_result_t *out);
const char *i3_host_abort_name(int jumped, uint64_t reason);
