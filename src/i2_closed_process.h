#pragma once

#include <stdint.h>
#include "noun.h"

typedef struct {
    uint64_t timer_owner;
    uint64_t input_bank_owner;
    uint64_t output_bank_owner;
} i2_closed_process_roles_t;

int i2_closed_process_roles_from_program(
    noun program, i2_closed_process_roles_t *out);
int i2_closed_process_roles_from_gate(
    noun gate, i2_closed_process_roles_t *out);
void i2_closed_process_roles_clear(void);
int i2_closed_process_roles_publish(const i2_closed_process_roles_t *roles);
int i2_closed_process_roles_live(i2_closed_process_roles_t *out);
int i2_closed_process_roles_refresh(noun gate);
int i2_closed_process_is_owner(uint64_t owner);
uint64_t i2_closed_process_selftest(void);
