#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m25_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile);
int m25_target_active(void);
int m25_target_init(void);
int m25_target_restart_source(void);
int m25_target_input(uint64_t a, uint64_t b);
int m25_target_poll(void);
int m25_target_step(void);
uint64_t m25_target_queue_len(void);
uint64_t m25_target_sink_value(void);
uint64_t m25_target_next_sequence(void);
uint64_t m25_target_high_water(void);
uint64_t m25_target_last_error(void);
int m25_target_checkpoint_capture(void);
int m25_target_checkpoint_restore(void);
