#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m37_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile);
int m37_target_init(void);
int m37_target_set_running(int running);
int m37_target_input(uint64_t value);
int m37_target_service_tick(void);
int m37_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out);
void m37_target_publish_gate(noun gate, const runtime_identity_t *identity,
                             uint8_t capability_profile);
uint64_t m37_target_queue_len(void);
uint64_t m37_target_output(void);
uint64_t m37_target_sequence(void);
uint64_t m37_target_high_water(void);
uint64_t m37_target_error(void);
uint64_t m37_target_root_commits(void);
uint64_t m37_target_publications(void);
int m37_target_test_hold_processing(int enabled);
int m37_target_test_clear_error(void);
int m37_target_test_rate_exhaust(void);
int m37_target_test_rate_reset(void);
int m37_target_test_allocation_pressure(void);
int m37_target_test_allocation_release(void);
