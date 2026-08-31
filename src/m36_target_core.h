#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

/* M36-T's post-commissioning target path.  Initial boot remains the retained
 * M26 predecessor; M29 switches to these functions only at its local
 * publication boundary. */
int m36_target_init(void);
int m36_target_restart_source(void);
int m36_target_input(uint64_t a, uint64_t b);
int m36_target_service_tick(void);
uint64_t m36_target_queue_len(void);
uint64_t m36_target_sink_value(void);
uint64_t m36_target_next_sequence(void);
uint64_t m36_target_high_water(void);
uint64_t m36_target_last_error(void);
int m36_target_set_running(int running);
int m36_target_prepare_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile, noun *out);
void m36_target_publish_gate(noun gate, const runtime_identity_t *identity,
                            uint8_t capability_profile);
int m36_target_identity_matches(const runtime_identity_t *identity);
int m36_target_native_ready(void);
