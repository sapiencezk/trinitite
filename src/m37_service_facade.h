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

int m37_service_facade_forward_intent(const m37_opaque_provider_fact_t *fact);
int m37_service_facade_forward(uint64_t type, uint64_t value, uint64_t sequence);
int m37_service_facade_poll_completion(void);
