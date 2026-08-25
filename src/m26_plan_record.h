#pragma once

#include <stdint.h>

/* Static local projection of both M26 directions.  The outgoing identity is
 * selected by M24_NODE_ID; the reverse identity is the only accepted RX
 * identity.  No peer registry or application-name dispatch is represented. */
typedef struct {
    uint8_t plan_digest[32];
    uint32_t source_device_id;
    uint32_t target_device_id;
    uint32_t source_resource_id;
    uint32_t target_resource_id;
    uint32_t publish_instance;
    uint32_t subscribe_instance;
    uint32_t source_application_instance;
    uint32_t target_application_instance;
    uint32_t source_event[2];
    uint32_t source_ordinal[2];
    uint32_t source_data[2];
    uint32_t target_event;
    uint32_t target_data;
    uint64_t epoch;
    uint32_t key_id;
    uint8_t binding_id[16];
    uint8_t schema_digest[32];
    uint8_t reverse_binding_id[16];
    uint8_t reverse_schema_digest[32];
} m26_plan_record_t;

extern const m26_plan_record_t m26_admitted_plan;

int m26_plan_record_validate(void);
int m26_plan_record_source_association(uint64_t event, uint64_t ordinal,
                                       uint64_t data);
