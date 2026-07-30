#pragma once

#include <stdint.h>

enum digital_out_operation {
    DIGITAL_OUT_OP_CONFIGURE = 1,
    DIGITAL_OUT_OP_CLEAR = 2,
    DIGITAL_OUT_OP_SET = 3,
    DIGITAL_OUT_OP_NOOP = 4,
    DIGITAL_OUT_OP_REFUSE = 5,
    DIGITAL_OUT_OP_SHADOW = 6
};

/* Safe-state/lifecycle surface owned by the target host. */
int  digital_out_boot_safe(void);
int  digital_out_prepare_clean_pill(void);
int  digital_out_restore_safe(void);
void digital_out_force_safe(void);
void digital_out_note_external_sample(void);

/* Post-commit activation of one complete logical [P1 P2 ALARM] bank. */
int digital_out_apply(uint64_t p1, uint64_t p2, uint64_t alarm);

/* Read-only bounded diagnostics. */
uint64_t digital_out_shadow(void);
uint64_t digital_out_gpio_level(void);
uint64_t digital_out_operation_count(void);
uint64_t digital_out_audit_count(void);
uint64_t digital_out_audit_dropped(void);

#ifdef DIGITAL_OUT_FAKE
uint64_t digital_out_fake_selftest(void);
#endif
