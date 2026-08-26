#pragma once

#include <stdint.h>
#include "noun.h"
#include "runtime_identity.h"

int m26_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile);
int m26_target_active(void);
int m26_target_init(void);
int m26_target_restart_source(void);
int m26_target_input(uint64_t a, uint64_t b);
int m26_target_poll(void);
int m26_target_step(void);
int m26_target_service_tick(void);
int m26_target_test_cnf_failure(uint64_t kind);
int m26_target_test_cnf_release(void);
uint64_t m26_target_queue_len(void);
uint64_t m26_target_sink_value(void);
uint64_t m26_target_next_sequence(void);
uint64_t m26_target_high_water(void);
uint64_t m26_target_last_error(void);
int m26_target_checkpoint_capture(void);
int m26_target_checkpoint_restore(void);
int m26_target_set_running(int running);
int m26_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out);
void m26_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile);
int m26_target_identity_matches(const runtime_identity_t *identity);
int m26_target_native_ready(void);
