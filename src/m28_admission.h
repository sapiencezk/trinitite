#pragma once

#include <stdint.h>
#include "i2_admission_policy.h"

/* M28's exact finite catalog.  It contains predecessor identities for the
 * two resources and one successor identity per authorized transition.  It
 * stores hashes only; successor PILL bytes are delivered by commissioning. */
int m28_admission_program_known(const uint8_t program_hash[32]);
int m28_admission_lookup(const uint8_t program_hash[32],
                         const uint8_t executable_anchor[32],
                         const uint8_t pill_digest[32],
                         const uint8_t limits_hash[32],
                         const i2_admission_catalog_entry_t **out);
