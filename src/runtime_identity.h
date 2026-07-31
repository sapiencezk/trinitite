#pragma once

#include <stdint.h>
#include "noun.h"

#define RUNTIME_IDENTITY_RECORD_SIZE 152u
#define RUNTIME_CAPABILITY_PROFILE_NONE        0u
#define RUNTIME_CAPABILITY_PROFILE_DIGITAL_OUT 1u
#define RUNTIME_CAPABILITY_PROFILE_M7_DIGITAL_OUT 2u

typedef struct {
    uint32_t pill_container_version;
    uint16_t package_schema[2];
    uint16_t kernel_kver[2];
    uint16_t runtime_abi[2];
    uint16_t host_abi[2];
    uint16_t program_schema[2];
    uint16_t algorithm_abi[2];
    uint16_t formula_abi[2];
    uint16_t deployment_schema[2];
    uint64_t generation;
    uint8_t package_hash[32];
    uint8_t battery_hash[32];
    uint8_t program_hash[32];
} runtime_identity_t;

typedef enum {
    PILL_I2_OK = 0,
    PILL_I2_NOT_I2,
    PILL_I2_ABSENT,
    PILL_I2_HEADER,
    PILL_I2_VERSION,
    PILL_I2_LENGTH,
    PILL_I2_DIGEST,
    PILL_I2_IDENTITY,
    PILL_I2_CUE,
    PILL_I2_GATE,
    PILL_I2_ALLOC
} pill_i2_status_t;

int runtime_identity_parse(const uint8_t record[RUNTIME_IDENTITY_RECORD_SIZE],
                           runtime_identity_t *out);
int runtime_identity_supported(const runtime_identity_t *identity);
int runtime_identity_equal(const runtime_identity_t *a,
                           const runtime_identity_t *b);
int runtime_identity_validate_gate(noun gate, const runtime_identity_t *identity,
                                   uint64_t *incarnation_out);
int runtime_identity_to_noun(const runtime_identity_t *identity, noun *out);
int runtime_identity_from_noun(noun n, runtime_identity_t *out);

int runtime_identity_live(void);
const runtime_identity_t *runtime_identity_get(void);
uint8_t runtime_identity_capability_profile(void);
void runtime_identity_set(const runtime_identity_t *identity);
void runtime_identity_set_capability_profile(uint8_t profile);
void runtime_identity_clear(void);

/* Strict PILL2 load. Success returns a decoded, identity-validated gate.
 * Only NOT_I2/ABSENT may reach the isolated I1 compatibility probe. */
pill_i2_status_t pill_i2_load(noun *gate_out);
/* Candidate variant for atomic clean installation. It deliberately leaves
 * the decoded noun transaction active and does not publish RuntimeIdentity. */
pill_i2_status_t pill_i2_load_candidate(noun *gate_out,
                                        runtime_identity_t *identity_out,
                                        uint8_t *capability_out);
/* Validate a PILL2 byte buffer without changing the live RuntimeIdentity or
 * PILL globals.  Successful cue leaves the noun transaction active; the
 * caller must commit only when the enclosing candidate is accepted, or
 * abort it after a side-effect-free seal probe. */
pill_i2_status_t pill_i2_validate_buffer(const uint8_t *base,
                                         uint64_t available,
                                         int heap_mode,
                                         noun *gate_out,
                                         runtime_identity_t *identity_out,
                                         uint8_t *capability_out);
const char *pill_i2_status_name(pill_i2_status_t status);
