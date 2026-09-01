#pragma once

#include <stdint.h>

#include "m37_a_r_adapter.h"
#include "noun.h"
#include "runtime_identity.h"

#define M37_A_R_FIFO_CAPACITY 16u
#define M37_A_R_DESCRIPTOR_FIELDS 11u
#define M37_A_R_ROUTE_CAPACITY 8u
#define M37_A_R_ERROR_TERMINAL_FENCE 11u

typedef struct {
    m37_a_r_transport_binding_t binding;
    uint64_t publication[M37_A_R_DESCRIPTOR_FIELDS];
    uint64_t ingress_instance, ingress_event, ingress_sample, ingress_type;
    uint64_t route_count;
    uint64_t routes[M37_A_R_ROUTE_CAPACITY][5];
} M37ARNativeExecutionSurface;

typedef struct {
    noun gate;
    runtime_identity_t identity;
    M37ARNativeExecutionSurface surface;
} m37_a_r_prepared_t;

typedef struct { uint64_t type, value; } m37_a_r_ingress_t;

typedef struct {
    uint8_t payload[M37_A_R_MAX_PAYLOAD];
    uint32_t payload_len;
    uint64_t sequence;
} m37_a_r_intent_t;

typedef struct {
    const uint8_t *payload;
    uint32_t payload_len;
    uint64_t sequence;
} candidate_execution_delivery_r_t;

int candidate_execution_core_r_prepare(
    const M37ARNativeExecutionSurface *, noun, const runtime_identity_t *,
    m37_a_r_prepared_t *);
int candidate_execution_core_r_cold_boot(void);
int candidate_execution_core_r_activate(const m37_a_r_prepared_t *);
int candidate_execution_core_r_init(void);
int candidate_execution_core_r_set_running(int);
int candidate_execution_core_r_submit(const m37_a_r_ingress_t *);
int candidate_execution_core_r_forward_provider(uint64_t type, uint64_t value,
                                                uint64_t sequence);
int candidate_execution_core_r_pump(void);
int candidate_execution_core_r_deliver(const candidate_execution_delivery_r_t *);
int candidate_execution_core_r_recover_tx(void);
uint64_t candidate_execution_core_r_queue_len(void);
uint64_t candidate_execution_core_r_output(void);
uint64_t candidate_execution_core_r_transport_value(void);
uint64_t candidate_execution_core_r_sequence(void);
uint64_t candidate_execution_core_r_high_water(void);
uint64_t candidate_execution_core_r_error(void);
uint64_t candidate_execution_core_r_pending(void);
uint64_t candidate_execution_core_r_tx_pending(void);
uint64_t candidate_execution_core_r_root_commits(void);
uint64_t candidate_execution_core_r_publications(void);
uint64_t candidate_execution_core_r_terminal_fence(void);
int candidate_execution_core_r_test_hold_processing(int);
int candidate_execution_core_r_test_clear_error(void);
int candidate_execution_core_r_test_rate_exhaust(void);
int candidate_execution_core_r_test_rate_reset(void);
int candidate_execution_core_r_test_allocation_pressure(void);
int candidate_execution_core_r_test_allocation_release(void);
