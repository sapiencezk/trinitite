/* Opaque M37 IEC-Service/native bridge.
 *
 * This file is intentionally a facade, not a second service interpreter.  A
 * candidate/Nock step supplies the typed pair and the frozen M37-A-R target
 * boundary remains the sole owner of transport, authentication, sequencing,
 * and recovery. */
#include "m37_service_facade.h"

#ifdef M37_IEC_SERVICE

#include "m37_a_r_target_core.h"

static uint64_t g_observation[7];

static void capture_observation(void)
{
    g_observation[M37_SERVICE_OBS_ERROR] = m37_a_r_target_error();
    g_observation[M37_SERVICE_OBS_SEQUENCE] = m37_a_r_target_sequence();
    g_observation[M37_SERVICE_OBS_PENDING] = m37_a_r_target_pending();
    g_observation[M37_SERVICE_OBS_TX_PENDING] = m37_a_r_target_tx_pending();
    g_observation[M37_SERVICE_OBS_TERMINAL] = m37_a_r_target_terminal_fence();
    g_observation[M37_SERVICE_OBS_PUBLICATIONS] = m37_a_r_target_publications();
    g_observation[M37_SERVICE_OBS_ROOT_COMMITS] = m37_a_r_target_root_commits();
}

int m37_service_facade_forward_intent(const m37_opaque_provider_fact_t *fact)
{
    if (!fact || fact->type != 4u || fact->value > 65535u ||
        !fact->sequence || fact->sequence == UINT64_MAX)
        return -1;
    /* The pair is opaque here: no declaration or event identity is decoded. */
    int result = m37_a_r_target_forward_provider(fact->type, fact->value,
                                                  fact->sequence);
    if (result != 0) capture_observation();
    return result;
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

uint64_t m37_service_facade_observation(uint64_t field)
{
    return field < 7u ? g_observation[field] : UINT64_MAX;
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

uint64_t m37_service_facade_observation(uint64_t field)
{
    (void)field;
    return UINT64_MAX;
}

#endif
