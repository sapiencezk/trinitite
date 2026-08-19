#pragma once

#include <stdint.h>
#include "noun.h"
#include "runtime_identity.h"
#include "i2_admission_envelope.h"

#define I2_M10_MAX_CHUNK_BYTES I2_MAX_CHUNK_BYTES
#define I2_M10_MAX_CHUNKS I2_MAX_CHUNKS
#define I2_M10_MAX_STAGE_BYTES I2_MAX_STAGE_BYTES

int i2_admission_program_known(const uint8_t program_hash[32]);
int i2_admission_match_header(const uint8_t program_hash[32],
                              const uint8_t executable_anchor[32],
                              const uint8_t pill_digest[32],
                              uint8_t capability);
int i2_admission_lookup(const uint8_t program_hash[32],
                        const uint8_t executable_anchor[32],
                        const uint8_t pill_digest[32],
                        uint8_t capability,
                        const uint8_t limits_hash[32],
                        const i2_m10_catalog_entry_t **out);
int i2_admission_limits_hash(noun gate, uint8_t out[32]);
int i2_admission_pill_digest(const uint8_t *base, uint64_t pill_bytes,
                             uint8_t out[32]);
/* True when program+anchor+capability name exactly one catalog entry and
 * that entry's limits hash matches. Used to bind a restored snapshot gate
 * to the stored PILL's catalog row before publication. */
int i2_admission_identity_limits_match(const uint8_t program_hash[32],
                                       const uint8_t executable_anchor[32],
                                       uint8_t capability,
                                       const uint8_t limits_hash[32]);
/* True when the program hash is a recorded historical M10 identity.
 * Historical identities are never admitted. */
int i2_admission_historical_m10(const uint8_t program_hash[32]);
void i2_admission_refuse_identity(const uint8_t program_hash[32]);
