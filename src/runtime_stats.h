#pragma once
#include <stdint.h>

/* The generic timer: CNTVCT_EL0 ticks and their frequency (CNTFRQ_EL0,
 * 54 MHz when the firmware leaves it zero). */
uint64_t runtime_counter_now(void);
uint64_t runtime_counter_freq(void);
