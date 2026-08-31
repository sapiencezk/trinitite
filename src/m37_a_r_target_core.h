#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m37_a_r_target_boot(noun, const runtime_identity_t *, uint8_t);
int m37_a_r_target_init(void);
int m37_a_r_target_set_running(int);
int m37_a_r_target_input(uint64_t type, uint64_t value);
int m37_a_r_target_service_tick(void);
int m37_a_r_target_recover_tx(void);
uint64_t m37_a_r_target_queue_len(void);
uint64_t m37_a_r_target_output(void);
uint64_t m37_a_r_target_sequence(void);
uint64_t m37_a_r_target_high_water(void);
uint64_t m37_a_r_target_error(void);
uint64_t m37_a_r_target_root_commits(void);
uint64_t m37_a_r_target_publications(void);
int m37_a_r_target_prepare_gate(noun, const runtime_identity_t *, uint8_t, noun *);
void m37_a_r_target_publish_gate(noun, const runtime_identity_t *, uint8_t);
int m37_a_r_target_test_hold_processing(int);
int m37_a_r_target_test_clear_error(void);
int m37_a_r_target_test_rate_exhaust(void);
int m37_a_r_target_test_rate_reset(void);
int m37_a_r_target_test_allocation_pressure(void);
int m37_a_r_target_test_allocation_release(void);
void m37_a_r_target_test_hold_tx(void);
void m37_a_r_target_test_release_tx(void);
void m37_a_r_target_test_lost_completion(void);
void m37_a_r_target_test_release_lost_completion(void);
