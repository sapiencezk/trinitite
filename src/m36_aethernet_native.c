#include "m36_aethernet_native.h"

#include "m25_aethernet_native.h"

#ifdef M36_TEST_CONTROLS
static int g_test_send_status;
#endif

/* The physical qemu-virt endpoint is the retained bounded IPv6/UDP adapter.
 * Keeping this translation unit separate prevents the M36 target from
 * importing M25's wire/profile logic while retaining the proven virtio
 * ownership and shared management demultiplex seam. */
int m36_native_init(void)
{
#ifdef M36_TEST_CONTROLS
    g_test_send_status = 0;
#endif
    return m25_native_init();
}

m36_native_status_t m36_native_receive(m36_native_datagram_t *out)
{
    return (m36_native_status_t)m25_native_receive(
        (m25_native_datagram_t *)(uintptr_t)out);
}

m36_native_status_t m36_native_send(const uint8_t *payload, uint32_t payload_len)
{
#ifdef M36_TEST_CONTROLS
    if (g_test_send_status != 0) {
        /* Hold the injected refusal until M36TXR explicitly releases it.
         * A one-shot status can be consumed by the service loop before the
         * UART observer samples M36ERR@, allowing an unintended retry to
         * hide the refusal and weakening the no-mutation witness. */
        return (m36_native_status_t)g_test_send_status;
    }
#endif
    return (m36_native_status_t)m25_native_send(payload, payload_len);
}

int m36_native_tx_pending(void)
{
    return m25_native_tx_pending();
}

#ifdef M36_TEST_CONTROLS
int m36_native_test_pending(void)
{
    g_test_send_status = M36_NATIVE_RING_FULL;
    return 0;
}

int m36_native_test_failure(void)
{
    g_test_send_status = M36_NATIVE_DEVICE;
    return 0;
}

int m36_native_test_release(void)
{
    g_test_send_status = 0;
    return 0;
}
#endif
