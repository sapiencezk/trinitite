#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

int m27_target_boot(noun gate, const runtime_identity_t *identity,
                    uint8_t capability_profile);
int m27_target_service_tick(void);
int m27_target_checkpoint_capture(void);
int m27_target_checkpoint_restore(void);
uint64_t m27_target_selected(void);
uint64_t m27_target_generation(void);
uint64_t m27_target_terminal(void);
