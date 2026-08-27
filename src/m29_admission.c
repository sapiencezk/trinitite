#include "m29_admission.h"

static int nonzero(const uint8_t *bytes)
{
    uint8_t value = 0;
    if (!bytes) return 0;
    for (unsigned i = 0; i < 32; i++) value |= bytes[i];
    return value != 0;
}

int m29_admission_program_known(const uint8_t program_hash[32])
{
    /* This is an envelope predicate, never an identity catalog. */
    return nonzero(program_hash);
}

int m29_admission_lookup(const uint8_t program_hash[32],
                         const uint8_t executable_anchor[32],
                         const uint8_t pill_digest[32],
                         const uint8_t limits_hash[32],
                         const i2_admission_catalog_entry_t **out)
{
    (void)out;
    /* Full authorization is performed by the authenticated transferred
     * policy after cueing the candidate.  These checks retain the ordinary
     * PILL identity/capability envelope without pre-resident successor data. */
    return nonzero(program_hash) && nonzero(executable_anchor)
        && nonzero(pill_digest)
        && (!limits_hash || nonzero(limits_hash));
}
