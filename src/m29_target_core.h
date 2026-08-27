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
