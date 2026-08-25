#pragma once

#include <stdint.h>

/* Immutable projection of the one admitted M25 CommunicationDeploymentPlan.
 * This record is generated/admitted data, not a provider registry.  The
 * native engine consumes it; application/service identities do not appear as
 * engine policy constants. */
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
} m25_plan_record_t;

extern const m25_plan_record_t m25_admitted_plan;

int m25_plan_record_validate(void);
int m25_plan_record_source_association(uint64_t event, uint64_t ordinal,
                                       uint64_t data);
