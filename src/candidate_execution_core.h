#pragma once

#include <stdint.h>

#include "m37_a_adapter.h"
#include "noun.h"
#include "runtime_identity.h"

#define CANDIDATE_EXECUTION_FIFO_CAPACITY 16u
#define CANDIDATE_EXECUTION_DESCRIPTOR_FIELDS 11u
#define CANDIDATE_EXECUTION_ROUTE_CAPACITY 8u

typedef struct {
    m37_a_transport_binding_t binding;
    uint64_t publication[CANDIDATE_EXECUTION_DESCRIPTOR_FIELDS];
    uint64_t ingress_instance;
    uint64_t ingress_event;
    uint64_t ingress_sample;
    uint64_t ingress_type;
    uint64_t route_count;
    uint64_t routes[CANDIDATE_EXECUTION_ROUTE_CAPACITY][5];
} NativeExecutionSurface;

typedef struct {
    noun gate;
    runtime_identity_t identity;
    NativeExecutionSurface surface;
} candidate_execution_prepared_t;

typedef struct {
    uint64_t type;
    uint64_t value;
} candidate_execution_ingress_t;

typedef struct {
    uint8_t payload[M37_A_MAX_PAYLOAD];
    uint32_t payload_len;
    uint64_t sequence;
} candidate_execution_intent_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
    uint64_t sequence;
} candidate_execution_delivery_t;

int candidate_execution_core_prepare(
    const NativeExecutionSurface *surface, noun gate,
    const runtime_identity_t *identity, candidate_execution_prepared_t *out);
int candidate_execution_core_activate(
    const candidate_execution_prepared_t *prepared);
int candidate_execution_core_init(void);
int candidate_execution_core_set_running(int running);
int candidate_execution_core_submit(const candidate_execution_ingress_t *ingress);
int candidate_execution_core_pump(void);
int candidate_execution_core_take_intent(candidate_execution_intent_t *out);
int candidate_execution_core_deliver(const candidate_execution_delivery_t *delivery);
uint64_t candidate_execution_core_queue_len(void);
uint64_t candidate_execution_core_output(void);
uint64_t candidate_execution_core_sequence(void);
uint64_t candidate_execution_core_high_water(void);
uint64_t candidate_execution_core_error(void);
uint64_t candidate_execution_core_root_commits(void);
uint64_t candidate_execution_core_publications(void);
int candidate_execution_core_test_hold_processing(int enabled);
int candidate_execution_core_test_clear_error(void);
int candidate_execution_core_test_rate_exhaust(void);
int candidate_execution_core_test_rate_reset(void);
int candidate_execution_core_test_allocation_pressure(void);
int candidate_execution_core_test_allocation_release(void);
