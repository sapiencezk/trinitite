#pragma once

#include <stdint.h>
#include "i2_admission_policy.h"

/* M27's finite authority admits only the exact A and B executable identities.
 * This catalog is compiled only into the fixed node-22 commissioning image;
 * it contains metadata, never successor PILL bytes. */
int m27_admission_program_known(const uint8_t program_hash[32]);
int m27_admission_lookup(const uint8_t program_hash[32],
                         const uint8_t executable_anchor[32],
                         const uint8_t pill_digest[32],
                         const uint8_t limits_hash[32],
                         const i2_admission_catalog_entry_t **out);
