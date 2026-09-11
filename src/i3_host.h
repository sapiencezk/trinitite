#pragma once

#include "memory.h"
#include "noun.h"

/*
 * I3 lite-node host. Cue, kick, bounded poke/peek, persist wrapper sample.
 * UART ovum ingress is a later L item; T1 boots then wfe.
 */
#define I3_PILL_SHAPE_NOCKAPP 2u
#define I3_PLAN_BASE (PILL_BASE + 0x01000000ULL)

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
const char *i3_host_abort_name(int jumped, uint64_t reason);
