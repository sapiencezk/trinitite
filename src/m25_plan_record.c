#include "m25_plan_record.h"

/* SHA-256 of the canonical repair-era CommunicationDeploymentPlan.  The key
 * bytes are intentionally absent; the native driver owns its local key
 * material under the admitted key ID. */
const m25_plan_record_t m25_admitted_plan = {
    .plan_digest = {
        0xe4,0x71,0xfc,0x94,0xcb,0xff,0x08,0x66,
        0x84,0x22,0xfd,0x2c,0xdc,0xde,0x96,0x5e,
        0x7b,0x52,0x49,0x2f,0xe5,0x1c,0x7d,0xe6,
        0x15,0x07,0x70,0x89,0x0e,0xbb,0xd4,0xdb,
    },
    .source_device_id = 11,
    .target_device_id = 22,
    .source_resource_id = 1,
    .target_resource_id = 2,
    .publish_instance = 8,
    .subscribe_instance = 9,
    .source_application_instance = 5,
    .target_application_instance = 6,
    .source_event = {2, 3},
    .source_ordinal = {8, 9},
    .source_data = {3, 4},
    .target_event = 1,
    .target_data = 1,
    .epoch = 1,
    .key_id = 1,
    .binding_id = {
        0xba,0x59,0xa8,0x09,0x5c,0x82,0x51,0x8f,
        0x5b,0x67,0xdf,0x9d,0x2d,0x1f,0xcc,0x06,
    },
    .schema_digest = {
        0x73,0x2d,0x9c,0xb1,0x71,0x79,0x81,0x30,
        0xe8,0x32,0xdb,0x68,0x2a,0x4a,0x2c,0xc4,
        0x5c,0x44,0x1c,0x5f,0xf9,0xfe,0xaf,0x69,
        0x5f,0xa9,0x5d,0x96,0x7d,0x60,0x85,0x55,
    },
};

int m25_plan_record_validate(void)
{
    return m25_admitted_plan.source_device_id != m25_admitted_plan.target_device_id
        && m25_admitted_plan.source_resource_id != m25_admitted_plan.target_resource_id
        && m25_admitted_plan.publish_instance != m25_admitted_plan.subscribe_instance
        && m25_admitted_plan.source_application_instance != m25_admitted_plan.target_application_instance
        && m25_admitted_plan.epoch != 0
        && m25_admitted_plan.key_id != 0
        && m25_admitted_plan.source_event[0] != m25_admitted_plan.source_event[1]
        && m25_admitted_plan.source_data[0] != m25_admitted_plan.source_data[1];
}

int m25_plan_record_source_association(uint64_t event, uint64_t ordinal,
                                       uint64_t data)
{
    for (unsigned i = 0; i < 2; i++) {
        if (event == m25_admitted_plan.source_event[i]
            && ordinal == m25_admitted_plan.source_ordinal[i]
            && data == m25_admitted_plan.source_data[i])
            return 1;
    }
    return 0;
}
