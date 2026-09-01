#pragma once

#include <stdint.h>

/* The IEC Service candidate emits these as opaque provider facts.  The
 * native layer is allowed to transport the already-typed pair, but has no
 * knowledge of FB declarations, IEC event names, or lifecycle semantics. */
typedef struct {
    uint64_t type;
    uint64_t value;
    uint64_t sequence;
} m37_opaque_provider_fact_t;

enum {
    M37_SERVICE_OBS_ERROR = 0,
    M37_SERVICE_OBS_SEQUENCE = 1,
    M37_SERVICE_OBS_PENDING = 2,
    M37_SERVICE_OBS_TX_PENDING = 3,
    M37_SERVICE_OBS_TERMINAL = 4,
    M37_SERVICE_OBS_PUBLICATIONS = 5,
    M37_SERVICE_OBS_ROOT_COMMITS = 6,
};

int m37_service_facade_forward_intent(const m37_opaque_provider_fact_t *fact);
int m37_service_facade_forward(uint64_t type, uint64_t value, uint64_t sequence);
int m37_service_facade_poll_completion(void);
uint64_t m37_service_facade_observation(uint64_t field);
