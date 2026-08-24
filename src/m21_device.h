#pragma once

#include <stdint.h>

#include "noun.h"
#include "runtime_identity.h"

/* The literal M21 target authority: one plan, two slots, no registry. */
int m21_device_boot(noun source_gate, const runtime_identity_t *source_id,
                    uint8_t capability_profile);
int m21_device_active(void);
int m21_device_enqueue_source_bool(uint64_t a, uint64_t b);
int m21_device_step(void);
uint64_t m21_device_sink_input(uint64_t variable_id);
uint64_t m21_device_queue_len(uint64_t slot);
uint64_t m21_device_last_error(void);
int m21_device_checkpoint_capture(void);
int m21_device_checkpoint_restore(void);
int m21_device_checkpoint_tamper_refuses(void);
/* Focused hostile controls: no raw ingress or stale carrier can change the
 * live two-slot root.  The full-tail and root-reservation probes execute a
 * real source bridge fault, verify its terminal retirement, then restore the
 * private setup root used by the probe. */
int m21_device_raw_ingress_refuses(void);
int m21_device_stale_carrier_refuses(void);
int m21_device_destination_full_refuses(void);
int m21_device_publish_reservation_fault_refuses(void);
