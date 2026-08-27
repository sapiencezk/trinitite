#pragma once

#include <stdint.h>

#include "i2_admission_policy.h"

/* The bootstrap image carries only this grammar/capability envelope.  The
 * authenticated CommissioningPolicyV1 supplies successor identities at
 * transaction time; there is deliberately no resident program catalog. */
int m29_admission_program_known(const uint8_t program_hash[32]);
int m29_admission_lookup(const uint8_t program_hash[32],
                         const uint8_t executable_anchor[32],
                         const uint8_t pill_digest[32],
                         const uint8_t limits_hash[32],
                         const i2_admission_catalog_entry_t **out);
