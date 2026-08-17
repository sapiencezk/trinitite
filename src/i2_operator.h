#pragma once

#include <stdint.h>
#include "noun.h"

#define I2_OPERATOR_MAX_PAYLOAD 8192u
#define I2_OPERATOR_LEASE_TICKS_SEC 5u

void i2_operator_init(void);
int  i2_operator_is_noun(noun n);
int  i2_operator_handle(noun request);
void i2_operator_poll(void);
int  i2_operator_busy(void);
void i2_operator_set_recovery(unsigned selected);
unsigned i2_operator_recovery(void);
uint64_t i2_operator_selftest(void);
uint64_t i2_operator_query_storm(uint64_t count);
void i2_operator_boot(void);
