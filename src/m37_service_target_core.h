#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m37_service_target_boot(noun, const runtime_identity_t *, uint8_t);
int m37_service_target_prepare_gate(noun, const runtime_identity_t *, uint8_t, noun *);
void m37_service_target_publish_gate(noun, const runtime_identity_t *, uint8_t);
int m37_service_target_init(void);
int m37_service_target_set_running(int);
int m37_service_target_application_input(uint64_t kind, uint64_t qi, uint64_t token,
                                         uint64_t value, uint64_t status);
int m37_service_target_tick(void);
int m37_service_target_recover_tx(void);

uint64_t m37_service_target_output_field(uint64_t field);
uint64_t m37_service_target_output_valid(void);
void m37_service_target_output_pop(void);
uint64_t m37_service_target_phase(void);
uint64_t m37_service_target_sequence(void);
uint64_t m37_service_target_pending(void);
uint64_t m37_service_target_intent_valid(void);
uint64_t m37_service_target_intent_token(void);
uint64_t m37_service_target_intent_value(void);
uint64_t m37_service_target_plan_bound(void);
uint64_t m37_service_target_error(void);
uint64_t m37_service_target_root_commits(void);
uint64_t m37_service_target_publications(void);
uint64_t m37_service_target_terminal_fence(void);
uint64_t m37_service_target_tx_state(void);

void m37_service_target_test_pre_submit_failure(void);
void m37_service_target_test_release_pre_submit(void);
void m37_service_target_test_lost_completion(void);
void m37_service_target_test_release_lost_completion(void);
void m37_service_target_test_delayed_completion(void);
void m37_service_target_test_release_delayed_completion(void);
int m37_service_target_test_exhaust_pending(void);
