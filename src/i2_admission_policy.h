#pragma once

#include <stdint.h>
#include "noun.h"
#include "runtime_identity.h"

#define I2_M10_MAX_CHUNK_BYTES 4096u
#define I2_M10_MAX_CHUNKS 32u
#define I2_M10_MAX_STAGE_BYTES 131066u

typedef struct {
    const char *catalog_id;
    const char *display_label;
    uint8_t program_hash[32];
    uint8_t executable_anchor[32];
    uint8_t pill_digest[32];
    uint8_t limits_hash[32];
    uint8_t capability_profile;
    uint8_t bootstrap;
    uint32_t pill_bytes;
} i2_m10_catalog_entry_t;

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
