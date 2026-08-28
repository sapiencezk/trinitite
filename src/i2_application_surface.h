#pragma once

#include <stdint.h>

#include "noun.h"

#define I2_SURFACE_MAX_INGRESS_SAMPLES 2u
#define I2_SURFACE_MAX_PUBLICATIONS 2u

typedef struct {
    uint64_t instance;
    uint64_t event;
    uint32_t sample_count;
    uint64_t sample_id[I2_SURFACE_MAX_INGRESS_SAMPLES];
    uint64_t sample_type[I2_SURFACE_MAX_INGRESS_SAMPLES];
} i2_ingress_attachment_t;

typedef struct {
    uint64_t source_instance;
    uint64_t source_event;
    uint64_t source_ordinal;
    uint64_t source_data;
    uint64_t source_type;
    uint64_t source_service;
    uint64_t target_service;
    uint64_t target_instance;
    uint64_t target_event;
    uint64_t target_data;
    uint64_t target_type;
} i2_publication_attachment_t;

typedef struct {
    i2_ingress_attachment_t ingress;
    uint32_t publication_count;
    i2_publication_attachment_t publications[I2_SURFACE_MAX_PUBLICATIONS];
} i2_application_service_surface_t;

/* Reconstruct only from the decoded candidate gate.  This function allocates
 * nothing and does not publish, copy, or mutate a runtime root. */
int i2_application_surface_from_gate(noun gate,
                                     i2_application_service_surface_t *out);
int i2_application_surface_tag_matches(noun tag, const char *text,
                                       uint32_t length);
int i2_application_surface_publication_matches(
    const i2_application_service_surface_t *surface,
    uint64_t source_instance, uint64_t source_event, uint64_t source_ordinal,
    uint64_t source_data, uint64_t source_type, uint64_t source_service,
    uint64_t target_service, uint64_t target_instance, uint64_t target_event,
    uint64_t target_data, uint64_t target_type);
