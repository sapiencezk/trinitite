#pragma once

#include <stdint.h>

/*
 * Target-private M6 seam. Exactly one of the BCM2838 or deterministic fake
 * implementations is linked. This is not an application ABI.
 */
#define DIGITAL_OUT_GPIO_P1       17u
#define DIGITAL_OUT_GPIO_P2       27u
#define DIGITAL_OUT_GPIO_ALARM    22u
#define DIGITAL_OUT_GPIO_MASK \
    ((1u << DIGITAL_OUT_GPIO_P1) | (1u << DIGITAL_OUT_GPIO_P2) | \
     (1u << DIGITAL_OUT_GPIO_ALARM))

/* bank bit 0=P1, bit 1=P2, bit 2=ALARM; no arbitrary GPIO mask crosses. */
int      digital_out_backend_configure_fixed_bank(void);
int      digital_out_backend_clear_fixed_bank(void);
int      digital_out_backend_set_fixed_bank(uint32_t bank);
uint32_t digital_out_backend_level(void);

#ifdef DIGITAL_OUT_FAKE
void     digital_out_backend_fake_reset(void);
void     digital_out_backend_fake_fail_at(uint64_t operation);
uint64_t digital_out_backend_fake_operations(void);
#endif
