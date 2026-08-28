#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m29_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile);
int m29_target_service_tick(void);
int m29_target_checkpoint_capture(void);
int m29_target_checkpoint_restore(void);
#ifdef M29_TEST_CONTROLS
/* Qualification-only mutation: alter one cached replay field without
 * recomputing the checkpoint integrity digest. */
int m29_target_test_checkpoint_tamper(void);
#endif
uint64_t m29_target_selected(void);
uint64_t m29_target_generation(void);
uint64_t m29_target_terminal(void);
uint64_t m29_target_pending(void);
uint64_t m29_target_pending_attempts(void);
uint64_t m29_target_pending_tx_state(void);
uint64_t m29_target_response_sequence(void);
#ifdef M32_TEST_CONTROLS
uint64_t m29_target_diag_management_rx(void);
uint64_t m29_target_diag_decode_ok(void);
uint64_t m29_target_diag_decode_failures(void);
uint64_t m29_target_diag_accepted(void);
uint64_t m29_target_diag_refused(void);
uint64_t m29_target_diag_last_sequence(void);
uint64_t m29_target_diag_last_operation(void);
uint64_t m29_target_diag_last_offset(void);
uint64_t m29_target_diag_last_digest(uint64_t index);
uint64_t m29_target_diag_cache_hits(void);
uint64_t m29_target_diag_cache_misses(void);
uint64_t m29_target_diag_cache_conflicts(void);
uint64_t m29_target_diag_cache_presence(void);
uint64_t m29_target_diag_cache_used(void);
uint64_t m29_target_diag_execute_count(void);
uint64_t m29_target_diag_pending_replays(void);
uint64_t m29_target_diag_pending_refusals(void);
uint64_t m29_target_diag_pending_operation(void);
uint64_t m29_target_diag_pending_digest(uint64_t index);
uint64_t m29_target_diag_stage_open(void);
uint64_t m29_target_diag_stage_sealed(void);
uint64_t m29_target_diag_stage_received(void);
uint64_t m29_target_diag_stage_chunks(void);
uint64_t m29_target_diag_lease_start(void);
uint64_t m29_target_diag_lease_remaining(void);
uint64_t m29_target_diag_lease_expired(void);
uint64_t m29_target_diag_operation_high(void);
#endif
