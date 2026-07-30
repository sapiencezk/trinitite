#pragma once

#include <stdint.h>
#include "noun.h"

/* M7 target-side bounded supervisor surface.  The manager decision is a
 * Nock formula; these values are the IEC Table-6/7 numbers published by the
 * M7 static-resource profile. */
enum {
    M7_MODE_IDLE = 0,
    M7_MODE_RUNNING = 1,
    M7_MODE_STOPPING = 2,
    M7_MODE_STOPPED = 3
};

enum {
    M7_STATUS_RDY = 0,
    M7_STATUS_BAD_PARAMS = 1,
    M7_STATUS_LOCAL_TERMINATION = 2,
    M7_STATUS_SYSTEM_TERMINATION = 3,
    M7_STATUS_NOT_READY = 4,
    M7_STATUS_UNSUPPORTED_CMD = 5,
    M7_STATUS_UNSUPPORTED_TYPE = 6,
    M7_STATUS_NO_SUCH_OBJECT = 7,
    M7_STATUS_INVALID_OBJECT = 8,
    M7_STATUS_INVALID_OPERATION = 9,
    M7_STATUS_INVALID_STATE = 10,
    M7_STATUS_OVERFLOW = 11
};

/* Static object tags are numeric handles for the trusted Forth lab bridge;
 * the canonical manager OBJECT on the wire remains a jammed noun. */
enum {
    M7_OBJECT_MANAGER = 1,
    M7_OBJECT_RESOURCE = 2,
    M7_OBJECT_APPLICATION = 3,
    M7_OBJECT_INVENTORY = 4,
    M7_OBJECT_IDENTITY = 5,
    M7_OBJECT_STATE = 6,
    M7_OBJECT_FB_INVENTORY = 7,
    M7_OBJECT_FB_STATUS = 8,
    M7_OBJECT_TYPE_DECLARATION = 9,
    M7_OBJECT_FB_TYPE_DECLARATION = 10,
    M7_OBJECT_FB_INSTANCE_DEFINITION = 11,
    M7_OBJECT_CONNECTION_DEFINITION = 12,
    M7_OBJECT_DATA_TYPE_NAME = 13,
    M7_OBJECT_FB_TYPE_NAME = 14,
    M7_OBJECT_FB_INSTANCE_REFERENCE = 15,
    M7_OBJECT_CONNECTION_START_POINT = 16,
    M7_OBJECT_APPLICATION_NAME = 17,
    M7_OBJECT_ALL_DATA_TYPES = 18,
    M7_OBJECT_ALL_FB_TYPES = 19,
    M7_OBJECT_EVENT_INPUT = 20,
    M7_OBJECT_EVENT_OUTPUT = 21,
    M7_OBJECT_DATA_INPUT = 22,
    M7_OBJECT_DATA_OUTPUT = 23,
    M7_OBJECT_PARAMETER_REFERENCE = 24,
    M7_OBJECT_REFERENCED_PARAMETER = 25,
    M7_OBJECT_PARAMETER = 26,
    M7_OBJECT_COUNT = 26
};

int      m7_init(noun gate);
/* True only for the exact M7 RuntimeIdentity/Host ABI cut.  Kernel ingress
 * fencing and management scheduling are deliberately scoped to this identity;
 * M6 is not an uninitialised M7 resource. */
int      m7_identity_active(void);
int      m7_manager_init(int qi);
int      m7_ready(void);
uint64_t m7_mode(void);
uint64_t m7_incarnation(void);
uint64_t m7_req_plus(void);
uint64_t m7_confirmations(void);
uint64_t m7_qo(void);
uint64_t m7_last_status(void);
uint64_t m7_last_restart(void);
noun     m7_object(uint64_t kind, uint64_t object_id);
noun     m7_last_result_noun(void);

/* The pure MANAGER formula is a persistent live root.  Kernel semispace
 * promotion and deployment publication retain it alongside the application
 * gate so a later flip cannot overwrite the formula while it is still in
 * use. */
noun     m7_formula_root(void);
int      m7_supervisor_retain_roots(noun *formula_out, noun *result_out);
void     m7_supervisor_publish_roots(noun formula, noun result);
void     m7_formula_publish(noun formula);
void     m7_result_publish(noun result);
void     m7_restore_state_commit(uint64_t mode, noun reason,
                                 uint64_t incarnation,
                                 uint64_t manager_initialized,
                                 uint64_t last_status, uint64_t qo);
void     m7_restore_discard(void);

/* Receipt is deliberately not REQ+.  A queued request is evaluated only by
 * m7_scheduler_boundary(), called after a complete application transaction. */
int      m7_manager_request(uint64_t command, noun object);
int      m7_manager_request_bytes(uint64_t command, const uint8_t *object,
                                   uint64_t object_len);
int      m7_scheduler_boundary(void);
int      m7_force_stop(void);
int      m7_reset(void);
/* Trusted-lab QEMU fault seam; not a MANAGER, deployment, or app surface. */
int      m7_test_copy_fail_after(uint64_t cells);

/* TRI_DEPLOY bounded protocol. Stage storage is volatile and fixed-size;
 * successful SEAL does not alter live roots. */
int      m7_deploy_begin(uint64_t stage_id, uint64_t total, noun digest);
int      m7_deploy_chunk(uint64_t stage_id, uint64_t offset,
                         const uint8_t *bytes, uint64_t len);
int      m7_deploy_seal(void);
int      m7_deploy_activate(void);
int      m7_deploy_query(void);
int      m7_deploy_abort(void);
noun     m7_current_pill_digest(void);
int      m7_checkpoint_save(void);

/* Boot selected M7 supervisor snapshot.  0 = selected M7 snapshot loaded,
 * 1 = no M7 snapshot, negative = selected snapshot rejected closed. */
int      m7_boot_snapshot(void);
