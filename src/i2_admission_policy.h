#pragma once

#include <stdint.h>
#include "noun.h"
#include "runtime_identity.h"
#include "i2_admission_envelope.h"

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
                        const i2_admission_catalog_entry_t **out);
int i2_admission_limits_hash(noun gate, uint8_t out[32]);
/* SHA-256 of the canonical DeploymentBinding reconstructed from the
 * already-validated candidate gate and identities.  The helper deliberately
 * receives policy resource/generation rather than discovering either from a
 * target or catalog. */
int i2_candidate_binding_digest(noun gate, uint64_t resource_id,
                                uint64_t generation,
                                const uint8_t package_hash[32],
                                const uint8_t battery_hash[32],
                                uint8_t out[32]);
int i2_admission_pill_digest(const uint8_t *base, uint64_t pill_bytes,
                             uint8_t out[32]);
/* True when program+anchor+capability name exactly one catalog entry and
 * that entry's limits hash matches. Used to bind a restored snapshot gate
 * to the stored PILL's catalog row before publication. */
int i2_admission_identity_limits_match(const uint8_t program_hash[32],
                                       const uint8_t executable_anchor[32],
                                       uint8_t capability,
                                       const uint8_t limits_hash[32]);

/* M25's exact two-image catalog is separate from the frozen M21 envelope. */
int m25_admission_lookup(const uint8_t program_hash[32],
                         const uint8_t executable_anchor[32],
                         const uint8_t pill_digest[32],
                         const uint8_t limits_hash[32],
                         const i2_admission_catalog_entry_t **out);
int m25_admission_program_known(const uint8_t program_hash[32]);
/* True when the program hash reaches the isolated historical refusal fence.
 * Historical identities are never admitted. */
int i2_admission_historical_refusal(const uint8_t program_hash[32]);
void i2_admission_refuse_identity(const uint8_t program_hash[32]);
