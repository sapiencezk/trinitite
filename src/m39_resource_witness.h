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
