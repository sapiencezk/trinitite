#include <stddef.h>
#include "i2_admission_policy.h"
#include "blake3.h"
#include "jam.h"
#include "memory.h"

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int take(noun n, noun *head, noun *tail)
{
    if (!noun_is_cell(n) || !head || !tail)
        return 0;
    cell_t *c = (cell_t *)(uintptr_t)cell_ptr(n);
    *head = c->head;
    *tail = c->tail;
    return 1;
}

#ifdef I2_M11
#include "i2_m11_catalog.inc"
#else
#include "i2_m10_catalog.inc"
#endif

int i2_admission_program_known(const uint8_t program_hash[32])
{
    if (!program_hash)
        return 0;
    for (unsigned i = 0; i < I2_M10_CATALOG_COUNT; i++)
        if (bytes_eq(I2_M10_CATALOG[i].program_hash, program_hash, 32))
            return 1;
    return 0;
}

int i2_admission_match_header(const uint8_t program_hash[32],
                              const uint8_t executable_anchor[32],
                              const uint8_t pill_digest[32],
                              uint8_t capability)
{
    if (!program_hash || !executable_anchor || !pill_digest)
        return 0;
    for (unsigned i = 0; i < I2_M10_CATALOG_COUNT; i++) {
        const i2_m10_catalog_entry_t *entry = &I2_M10_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)
            && bytes_eq(entry->pill_digest, pill_digest, 32))
            return 1;
    }
    return 0;
}

int i2_admission_lookup(const uint8_t program_hash[32],
                        const uint8_t executable_anchor[32],
                        const uint8_t pill_digest[32],
                        uint8_t capability,
                        const uint8_t limits_hash[32],
                        const i2_m10_catalog_entry_t **out)
{
    if (!program_hash || !executable_anchor || !pill_digest || !limits_hash)
        return 0;
    const i2_m10_catalog_entry_t *found = 0;
    unsigned matches = 0;
    for (unsigned i = 0; i < I2_M10_CATALOG_COUNT; i++) {
        const i2_m10_catalog_entry_t *entry = &I2_M10_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)
            && bytes_eq(entry->pill_digest, pill_digest, 32)
            && bytes_eq(entry->limits_hash, limits_hash, 32)) {
            found = entry;
            matches++;
        }
    }
    if (matches != 1)
        return 0;
    if (out)
        *out = found;
    return 1;
}

int i2_admission_limits_hash(noun gate, uint8_t out[32])
{
    noun battery, sample, zero, state, tag, rest, header, state_tail;
    noun program, dynamic, versions, rid, generation, incarnation;
    noun battery_hash, program_hash, limits;
    const uint8_t *encoded;
    uint64_t encoded_len;
    if (!out)
        return 0;
    if (!take(gate, &battery, &sample)
        || !take(sample, &zero, &state)
        || !take(state, &tag, &rest)
        || !take(rest, &header, &state_tail)
        || !take(state_tail, &program, &dynamic)
        || !take(header, &versions, &rest)
        || !take(rest, &rid, &rest)
        || !take(rest, &generation, &rest)
        || !take(rest, &incarnation, &rest)
        || !take(rest, &battery_hash, &rest)
        || !take(rest, &program_hash, &limits)
        || jam_encode_bytes_checked(limits, &encoded, &encoded_len) != 0)
        return 0;
    blake3_hash(encoded, (size_t)encoded_len, out);
    return 1;
}

int i2_admission_pill_digest(const uint8_t *base, uint64_t pill_bytes,
                             uint8_t out[32])
{
    if (!base || !out || pill_bytes == 0)
        return 0;
    blake3_hash(base, (size_t)pill_bytes, out);
    return 1;
}

int i2_admission_identity_limits_match(const uint8_t program_hash[32],
                                       const uint8_t executable_anchor[32],
                                       uint8_t capability,
                                       const uint8_t limits_hash[32])
{
    if (!program_hash || !executable_anchor || !limits_hash)
        return 0;
    const i2_m10_catalog_entry_t *found = 0;
    unsigned matches = 0;
    for (unsigned i = 0; i < I2_M10_CATALOG_COUNT; i++) {
        const i2_m10_catalog_entry_t *entry = &I2_M10_CATALOG[i];
        if (entry->capability_profile == capability
            && bytes_eq(entry->program_hash, program_hash, 32)
            && bytes_eq(entry->executable_anchor, executable_anchor, 32)) {
            found = entry;
            matches++;
        }
    }
    if (matches != 1 || !found)
        return 0;
    return bytes_eq(found->limits_hash, limits_hash, 32);
}
