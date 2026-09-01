/* Opaque M37 IEC-Service/native bridge.
 *
 * This file is intentionally a facade, not a second service interpreter.  A
 * candidate/Nock step supplies the typed pair and the frozen M37-A-R target
 * boundary remains the sole owner of transport, authentication, sequencing,
 * and recovery. */
#include "m37_service_facade.h"

#ifdef M37_IEC_SERVICE

#include "m37_a_r_target_core.h"

int m37_service_facade_forward_intent(const m37_opaque_provider_fact_t *fact)
{
    if (!fact || fact->type != 4u || fact->value > 65535u ||
        !fact->sequence || fact->sequence == UINT64_MAX)
        return -1;
    /* The pair is opaque here: no declaration or event identity is decoded. */
    return m37_a_r_target_forward_provider(fact->type, fact->value,
                                            fact->sequence);
}

int m37_service_facade_forward(uint64_t type, uint64_t value, uint64_t sequence)
{
    m37_opaque_provider_fact_t fact = {type, value, sequence};
    return m37_service_facade_forward_intent(&fact);
}

int m37_service_facade_poll_completion(void)
{
    /* Polling is deliberately delegated wholesale to the frozen target. */
    return m37_a_r_target_service_tick();
}

#else

int m37_service_facade_forward_intent(const m37_opaque_provider_fact_t *fact)
{
    (void)fact;
    return -1;
}

int m37_service_facade_forward(uint64_t type, uint64_t value, uint64_t sequence)
{
    (void)type;
    (void)value;
    (void)sequence;
    return -1;
}

int m37_service_facade_poll_completion(void)
{
    return 0;
}

#endif
