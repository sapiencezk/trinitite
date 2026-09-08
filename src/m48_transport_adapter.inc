/* Operational adapter seam; included after the retained publication codec. */
#if defined(M48_RESIDENT)
#include "m48_resident_driver.h"
static uint32_t m48_pending_epoch, m48_pending_valid;
static M48IOStatus m48_native_status(m37_a_r_native_status_t status) {
    if (status==M37_A_R_NATIVE_OK) return M48_READY;
    if (status==M37_A_R_NATIVE_NO_PACKET || status==M37_A_R_NATIVE_RING_FULL)
        return M48_EMPTY;
    return M48_REFUSED;
}
static M48IOStatus m48_native_receive(void *context,uint32_t epoch,
                                      uint64_t *token,uint32_t *value) {
    (void)context;
    if (!provider_enabled || !epoch || !token || !value) return M48_REFUSED;
    transport.epoch=epoch;
    m37_a_r_datagram_t datagram={0};
    m37_a_r_native_status_t status=m37_a_r_adapter_receive(&transport,&datagram);
    if (status!=M37_A_R_NATIVE_OK) return m48_native_status(status);
    uint64_t mark=heap_scratch_mark(); int mode=heap_get_mode();
    heap_set_mode(HEAP_MODE_SCRATCH);
    uint32_t decoded=0;
    int valid=datagram.sequence && !(datagram.sequence>>63) && publication_read(&datagram,&decoded);
    int rewound=heap_scratch_rewind(mark); heap_set_mode(mode);
    if (!valid || !rewound) return M48_REFUSED;
    *token=datagram.sequence; *value=decoded;
    return M48_READY;
}
static M48IOStatus m48_native_submit(void *context,uint32_t epoch,
                                     uint64_t token,uint32_t value) {
    (void)context;
    if (!provider_enabled || !epoch || !token || token>>63 || value>65535u)
        return M48_REFUSED;
    /* The driver has already committed the claim. Any failure below remains
     * a single attempted submission, never a reason to claim again. */
    m48_pending_valid=0;
    uint64_t mark=heap_scratch_mark(); int mode=heap_get_mode();
    heap_set_mode(HEAP_MODE_SCRATCH);
    int begun=noun_tx_begin(HEAP_MODE_SCRATCH);
    int built=begun && publication_build(value);
    if (begun) noun_tx_abort(); /* pending_data already owns the encoded bytes */
    int rewound=heap_scratch_rewind(mark); heap_set_mode(mode);
    if (!built || !rewound) {
        return M48_REFUSED;
    }
    transport.epoch=epoch; m48_pending_epoch=epoch;
    pending_token=token; pending_value=value; completion_observed=0;
    m48_pending_valid=1;
    m37_a_r_native_status_t status=m37_a_r_adapter_submit(&transport,pending_data,pending_bytes,token);
    return m48_native_status(status);
}
static M48IOStatus m48_native_completion(void *context,uint32_t epoch,
                                         uint64_t token,uint32_t value) {
    (void)context;
    if (!provider_enabled || !m48_pending_valid || epoch!=m48_pending_epoch ||
        token!=pending_token || value!=pending_value) return M48_REFUSED;
    transport.epoch=epoch;
    m37_a_r_native_status_t status=m37_a_r_adapter_poll_completion(
        &transport,pending_data,pending_bytes,token);
    return m48_native_status(status);
}
static M48IOStatus m48_native_release_ready(void *context) {
    (void)context;
    return m37_a_r_adapter_tx_pending()?M48_REFUSED:M48_READY;
}
int m48_transport_init(M48Adapter *out) {
    if (!out || !provider_enabled || m37_a_r_adapter_init(&transport)) return 0;
    m48_pending_valid=0; m48_pending_epoch=0;
    *out=(M48Adapter){0,m48_native_receive,m48_native_completion,m48_native_submit,m48_native_release_ready};
    return 1;
}
#endif
