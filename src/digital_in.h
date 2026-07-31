#pragma once

#include <stdint.h>

int digital_in_prepare(void);
int digital_in_read_once(uint32_t *logical_bank);
uint64_t digital_in_read_count(void);

#ifdef DIGITAL_IN_FAKE
int digital_in_test_set_logical_bank(uint32_t logical_bank);
uint64_t digital_in_fake_selftest(void);
#endif
