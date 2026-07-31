#pragma once

#include <stdint.h>

/* Target-private fixed M8 bank.  No arbitrary pin, mask, or register API. */
int digital_in_backend_configure_fixed_bank(void);
int digital_in_backend_read_fixed_bank(uint32_t *logical_bank);

#ifdef DIGITAL_IN_FAKE
int digital_in_backend_fake_set_logical_bank(uint32_t logical_bank);
void digital_in_backend_fake_reset(void);
void digital_in_backend_fake_fail_configure(int fail);
void digital_in_backend_fake_fail_read_at(uint64_t ordinal);
uint64_t digital_in_backend_fake_reads(void);
#endif
