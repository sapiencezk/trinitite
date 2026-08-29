#include "m34_local_allocation.h"

#include "m26_plan_record.h"

/* These are the retained M26 predecessor facts.  They are deliberately
 * independent of every M34 successor identity; the successor arrives only
 * in the authenticated commissioning transfer. */
#if M24_NODE_ID == 11
static const m34_local_allocation_t M34_LOCAL_ALLOCATION = {
    .device_id = 11, .resource_id = 1, .slot = 1,
    .predecessor_generation = 1,
    .predecessor_program = {
        0x77,0x0b,0x73,0x7b,0x49,0x4c,0xbb,0xdc,
        0x14,0x1c,0xa1,0x4d,0x2e,0xf4,0xd1,0xcc,
        0xa0,0xef,0xaa,0x2f,0xc1,0x16,0xba,0x2c,
        0xb0,0x91,0x44,0x52,0x75,0xc8,0x67,0x45,
    },
    .predecessor_anchor = {
        0x96,0x9c,0x64,0x82,0xa8,0xa0,0xa2,0x22,
        0x29,0x41,0x83,0xc4,0xee,0xce,0x6f,0xc8,
        0x0c,0xe8,0x93,0x98,0x7e,0x74,0x38,0x64,
        0x18,0x5e,0x66,0x41,0xcc,0x1e,0x52,0xed,
    },
    .transport_plan = &m26_admitted_plan,
};
#elif M24_NODE_ID == 22
static const m34_local_allocation_t M34_LOCAL_ALLOCATION = {
    .device_id = 22, .resource_id = 2, .slot = 2,
    .predecessor_generation = 1,
    .predecessor_program = {
        0x77,0x0b,0x73,0x7b,0x49,0x4c,0xbb,0xdc,
        0x14,0x1c,0xa1,0x4d,0x2e,0xf4,0xd1,0xcc,
        0xa0,0xef,0xaa,0x2f,0xc1,0x16,0xba,0x2c,
        0xb0,0x91,0x44,0x52,0x75,0xc8,0x67,0x45,
    },
    .predecessor_anchor = {
        0x96,0x9c,0x64,0x82,0xa8,0xa0,0xa2,0x22,
        0x29,0x41,0x83,0xc4,0xee,0xce,0x6f,0xc8,
        0x0c,0xe8,0x93,0x98,0x7e,0x74,0x38,0x64,
        0x18,0x5e,0x66,0x41,0xcc,0x1e,0x52,0xed,
    },
    .transport_plan = &m26_admitted_plan,
};
#else
#error "M34-R local allocation requires compiled node 11 or 22"
#endif

static int bytes_equal(const uint8_t *left, const uint8_t *right, uint64_t length)
{
    uint8_t different = 0;
    if (!left || !right) return 0;
    for (uint64_t i = 0; i < length; i++) different |= left[i] ^ right[i];
    return different == 0;
}

const m34_local_allocation_t *m34_local_allocation(void)
{
    return &M34_LOCAL_ALLOCATION;
}

int m34_local_allocation_matches(uint64_t device_id, uint64_t resource_id,
                                 uint64_t slot)
{
    const m34_local_allocation_t *allocation = m34_local_allocation();
    return allocation && allocation->device_id == device_id
        && allocation->resource_id == resource_id
        && allocation->slot == slot;
}

int m34_local_allocation_predecessor_matches(const runtime_identity_t *identity)
{
    const m34_local_allocation_t *allocation = m34_local_allocation();
    return allocation && identity
        && identity->generation == allocation->predecessor_generation
        && bytes_equal(identity->program_hash, allocation->predecessor_program, 32)
        && bytes_equal(identity->package_hash, allocation->predecessor_anchor, 32);
}
