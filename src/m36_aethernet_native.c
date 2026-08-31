#include "m36_aethernet_native.h"

#include "m25_aethernet_native.h"

/* The physical qemu-virt endpoint is the retained bounded IPv6/UDP adapter.
 * Keeping this translation unit separate prevents the M36 target from
 * importing M25's wire/profile logic while retaining the proven virtio
 * ownership and shared management demultiplex seam. */
int m36_native_init(void)
{
    return m25_native_init();
}

m36_native_status_t m36_native_receive(m36_native_datagram_t *out)
{
    return (m36_native_status_t)m25_native_receive(
        (m25_native_datagram_t *)(uintptr_t)out);
}

m36_native_status_t m36_native_send(const uint8_t *payload, uint32_t payload_len)
{
    return (m36_native_status_t)m25_native_send(payload, payload_len);
}

int m36_native_tx_pending(void)
{
    return m25_native_tx_pending();
}
