/* M26 is a bounded duplex specialization of the proven M25 resource seam.
 * The included implementation is compiled under a separate symbol namespace
 * and M26 plan record.  The conditional changes in m25_target_core.c only
 * enable the second static direction; the M25 build remains unchanged. */
#define M26_DUPLEX 1
#define M25_TARGET 1
#define m25_target_boot m26_target_boot
#define m25_target_active m26_target_active
#define m25_target_init m26_target_init
#define m25_target_restart_source m26_target_restart_source
#define m25_target_input m26_target_input
#define m25_target_poll m26_target_poll
#define m25_target_step m26_target_step
#define m25_target_service_tick m26_target_service_tick
#define m25_target_test_cnf_failure m26_target_test_cnf_failure
#define m25_target_test_cnf_release m26_target_test_cnf_release
#define m25_target_queue_len m26_target_queue_len
#define m25_target_sink_value m26_target_sink_value
#define m25_target_next_sequence m26_target_next_sequence
#define m25_target_high_water m26_target_high_water
#define m25_target_last_error m26_target_last_error
#define m25_target_checkpoint_capture m26_target_checkpoint_capture
#define m25_target_checkpoint_restore m26_target_checkpoint_restore
#define m25_target_set_running m26_target_set_running
#define m25_target_prepare_gate m26_target_prepare_gate
#define m25_target_publish_gate m26_target_publish_gate
#define m25_target_identity_matches m26_target_identity_matches
#define m25_target_native_ready m26_target_native_ready
#define m25_plan_record_t m26_plan_record_t
#define m25_admitted_plan m26_admitted_plan
#define m25_plan_record_validate m26_plan_record_validate
#define m25_plan_record_source_association m26_plan_record_source_association
#define m25_target_core_h_m26_seen 1
#include "m26_plan_record.h"
#include "m25_target_core.c"
