#pragma once
#include <stddef.h>
#include <stdint.h>
void m39_resource_boot(void);
#if defined(M44_TWO_RESOURCE)
/* Exclusive boot modes reuse the same cold-boot runtime storage. The caller
 * must select exactly one mode before runtime initialization. */
void *m44_boot_control(void);
void *m44_boot_workspace(void);
void *m44_boot_session_storage(void);
void *m44_boot_catalog_storage(uint32_t slot, uint32_t part);
#endif

#if defined(M47_MANAGED_SERVICES)
#include "noun.h"
int m47_transport_config(noun);
int m47_transport_start(void);
uint32_t m47_transport_action(uint32_t operation,uint32_t slot,uint32_t instance_id,
                              uint32_t kind,uint32_t epoch,uint64_t token,uint32_t argument);
#endif

#if defined(M48_RESIDENT)
#include "m48_resident_driver.h"
/* Singleton retained transport, cold boot once after transport config.
 * Returned callbacks share the witness's static codec/device state; they do
 * not create independent transport instances. No handshake or blocking wait. */
int m48_transport_init(M48Adapter *out);
#endif
