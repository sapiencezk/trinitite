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
/* Return non-zero only when the backend clear completed and the output bank
 * is therefore safe to claim.  The inhibit/shadow transition is performed
 * even on failure.  A successful clear proves safe-low but does not clear a
 * prior fatal write latch; lifecycle preparation owns that recovery. */
int digital_out_force_safe(void);
void digital_out_note_legacy_external_sample(void);
void digital_out_arm_closed_sample(uint64_t generation, uint64_t incarnation,
                                   uint64_t owner, uint64_t sequence);
void digital_out_clear_closed_sample(void);

/* Post-commit activation of one complete logical [P1 P2 ALARM] bank. */
int digital_out_apply(uint64_t p1, uint64_t p2, uint64_t alarm);
int digital_out_apply_direct(uint64_t bank, uint64_t generation,
                             uint64_t incarnation, uint64_t output_owner,
                             uint64_t output_sequence);
int digital_out_closed_sample_armed(void);

/* Read-only bounded diagnostics. */
uint64_t digital_out_shadow(void);
uint64_t digital_out_gpio_level(void);
uint64_t digital_out_operation_count(void);
uint64_t digital_out_audit_count(void);
uint64_t digital_out_audit_dropped(void);

#ifdef DIGITAL_OUT_FAKE
uint64_t digital_out_fake_selftest(void);
#endif
