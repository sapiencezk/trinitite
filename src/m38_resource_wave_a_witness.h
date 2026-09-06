#pragma once

/* Test-only QEMU choreography.  This header is not part of the public
 * ResourceRuntime API and is included only by the Wave A image entry point. */
void m38_resource_wave_a_boot(void);

#if defined(M38_D8_B0_OBSERVABILITY)
void m38_resource_b0_boot(void);
#endif
