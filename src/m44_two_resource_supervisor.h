#pragma once
#include "m44_resource_transaction.h"
#if defined(M44_TWO_RESOURCE)
#define M44_FIFO_CAPACITY 16u
#define M44_MAX_VALUES 16u
#define M44_MAX_BOUNDARIES 128u
#define M44_SAVED_BYTES 16384u
typedef struct {
  uint32_t id, type, raw;
} M44Value;
typedef struct {
  uint32_t event, count, sequence;
  M44Value values[16];
} M44Row;
typedef struct {
  uint32_t event, count;
  M44Value values[16];
} M44Boundary;
typedef struct {
  uint8_t identity[32], core_identity[2][32], payload_identity[2][32],
      admission_identity[2][32];
  uint32_t source_slot, source_event, target_slot, target_event, value_count,
      batch_bound;
  uint32_t source_ids[16], target_ids[16], types[16];
  uint32_t ingress_count[2], output_count[2], signed_values[2];
#if defined(M49_MANAGED_DELAY)
  uint32_t time_values[2];
#endif
  M44Boundary ingress[2][128], outputs[2][128];
} M44Descriptor;
typedef struct {
  uint32_t bytes;
  uint8_t jam[M44_SAVED_BYTES];
} M44Saved;
#if defined(M47_MANAGED_SERVICES)
typedef struct { uint32_t slot, kind, instance_id; } M47ProviderBinding;
enum { M47_SERVICE_NEW=0, M47_SERVICE_OPEN=1, M47_SERVICE_RELEASED=2 };
enum { M47_TX_NONE=0, M47_TX_COMMITTED=1, M47_TX_CLAIMED=2, M47_TX_COMPLETION_QUEUED=3 };
enum { M47_RX_NONE=0, M47_RX_DELIVERY_QUEUED=1, M47_RX_INDICATED=2, M47_RX_RESPONSE_QUEUED=3 };
/* phase, tx_state and rx_state use the three separate enums above. */
typedef struct {
  uint32_t phase, tx_state, tx_value, rx_state, release_queued;
  uint64_t tx_token, rx_highwater, rx_token;
} M47ProviderLedger;
#endif
#if defined(M49_MANAGED_DELAY)
typedef struct { uint32_t slot, instance_id; } M49TimerBinding;
enum { M49_TIMER_FREE=0, M49_TIMER_ARMED=1, M49_TIMER_QUEUED=2 };
typedef struct {
  uint32_t phase, duration_ms;
  uint64_t generation, highwater, deadline_ms, not_before_turn;
} M49TimerLedger;
#endif
typedef struct {
  uint32_t cursor, sequence, fault, fenced, counts[2], output_count;
  M44Row queues[2][16], outputs[32];
  uint32_t output_slots[32];
#if defined(M45_MANAGED_LIFECYCLE)
  uint32_t lifecycle, epoch;
#endif
#if defined(M47_MANAGED_SERVICES)
  M47ProviderLedger providers[2];
#endif
#if defined(M49_MANAGED_DELAY)
  M49TimerLedger timer;
#endif
} M44State;
typedef enum {
  M44_FAULT_NONE = 0,
  M44_FAULT_EVALUATION = 1,
  M44_FAULT_PRODUCT = 2,
  M44_FAULT_DELIVERY_RESERVATION = 3,
  M44_FAULT_PUBLICATION = 4
} M44Fault;
typedef enum {
  M44_OK = 0,
  M44_INVALID = 1,
  M44_BUSY = 2,
  M44_FENCED = 3,
  M44_FULL = 4,
  M44_NO_WORK = 5,
  M44_RETIRED = 6,
  M44_PUBLICATION = 7
} M44Status;
/* The descriptor must already be authenticated against both admitted payloads
 * by the boot decoder. Initialization copies all inputs before claiming D8.
 * Slots are one-based. Storage is singleton, cold-boot-owned. */
M44Status m44_supervisor_init(ResourceSession *, const M44Descriptor *,
                              const M44Saved handles[2]);
#if defined(M47_MANAGED_SERVICES)
/* Boot authenticates the full source wrapper; init checks retained signatures.
 * Claim commits before transport submission. Refusal/uncertainty after claim
 * does not permit another claim or automatic submission retry. */
M44Status m47_supervisor_init(ResourceSession *, const M44Descriptor *,
                             const M44Saved handles[2],
                             const M47ProviderBinding bindings[2]);
/* Adapter-owned external observation, deliberately outside IEC rollback.
 * A captured, not-yet-admitted receive blocks release and reset. The trusted
 * adapter clears the hold only after successful queue publication. */
M44Status m47_provider_receive_hold(uint32_t slot,uint32_t epoch,uint32_t pending);
uint32_t m47_provider_receive_holds(void);
M44Status m47_provider_claim(uint32_t slot, uint32_t epoch, uint64_t token);
M44Status m47_provider_enqueue(uint32_t slot, uint32_t epoch, const M44Row *row);
#endif
#if defined(M49_MANAGED_DELAY)
/* Boot only, validates private timer boundary signatures before claiming. */
M44Status m49_supervisor_init(ResourceSession *, const M44Descriptor *,
    const M44Saved handles[2], const M47ProviderBinding bindings[2], M49TimerBinding timer);
/* Trusted monotonic sample, once before dispatch per resident turn. Expiry
 * admission is allowed while STOPPED; queue refusal retains timer ownership. */
M44Status m49_supervisor_clock(uint32_t epoch, uint64_t now_ms, uint64_t turn);
#endif
M44Status m44_supervisor_enqueue(uint32_t slot, const M44Row *);
M44Status m44_supervisor_dispatch(void);
M44Status m44_supervisor_capture(uint32_t *token);
M44Status m44_supervisor_restore(uint32_t token);
const M44State *m44_supervisor_state(void);
M44Status m44_supervisor_inspect(M44ResourceInspection *);
M44Status m44_supervisor_restore_checked(uint32_t token,
                                         const uint8_t descriptor_identity[32],
                                         uint64_t capability);
size_t m44_supervisor_storage_bytes(void);
#if defined(M45_MANAGED_LIFECYCLE)
typedef enum {
  M45_RDY = 0, M45_NOT_READY = 4, M45_UNSUPPORTED_CMD = 5,
  M45_NO_SUCH_OBJECT = 7, M45_INVALID_STATE = 10, M45_OVERFLOW = 11
} M45Status;
/* Boot-only: handles must be freshly loaded admitted initial resources.
 * Initialization performs no IEC execution. */
M44Status m45_supervisor_init(ResourceSession *, const M44Descriptor *,
                             const M44Saved handles[2]);
uint32_t m45_supervisor_is_managed(void);
M45Status m45_supervisor_manage(uint32_t command, uint32_t target);
#if defined(M44_G0_TEST_CONTROLS)
uint32_t m45_supervisor_test_busy_mask(void);
void m45_supervisor_test_epoch(uint32_t epoch);
/* Combined broker/copy fault injection is outside qualification support. */
M44Status m45_supervisor_test_resource_control(uint32_t point);
#endif
#endif
#if defined(M44_G0_TEST_CONTROLS)
void m44_supervisor_test_fault(uint32_t copy_point,
                               uint32_t retirement_failure);
void m44_supervisor_test_sequence(uint32_t sequence);
void m44_supervisor_test_busy(void);
uint32_t m44_supervisor_test_busy_mask(void);
#endif
#endif

#if defined(M46_LIVE_REPLACEMENT)
/* Boot-only managed initialization with the trusted-boot-authorized source-shape digest.
 * Deployment generations start at one; tickets never repeat within a boot. */
M44Status m46_supervisor_init(ResourceSession *session,
                              const M44Descriptor *descriptor,
                              const M44Saved handles[2],
                              const uint8_t compatibility[32]);
/* Stage requires RUNNING at the exact deployment generation. It copies the
 * descriptor and handles, claims the candidate, and compares source shape,
 * topology, interfaces, and the complete numeric payload except algorithm
 * bodies. A post-claim incompatibility privately closes the candidate;
 * pre-claim refusal retains caller ownership. Staging never copies live state.
 */
M44Status m46_supervisor_stage(ResourceSession *candidate,
                               const M44Descriptor *descriptor,
                               const M44Saved handles[2],
                               const uint8_t compatibility[32],
                               uint32_t expected_generation,
                               uint32_t *out_token);
/* At a complete dispatch boundary copy latest logical state to the candidate,
 * preserving all supervisor state. Commit replaces the entire authority and
 * retires the old session without failure or allocation. On refusal the
 * active deployment and staged candidate remain available. */
M44Status m46_supervisor_activate(uint32_t token, uint32_t expected_generation);
M44Status m46_supervisor_cancel(uint32_t token, uint32_t expected_generation);
ResourceSession *m46_supervisor_active_session(void);
const M44Descriptor *m46_supervisor_active_descriptor(void);
M44Status m46_supervisor_diagnostics(M46ResourceDiagnostics *out);
uint32_t m46_supervisor_generation(void);
uint32_t m46_supervisor_candidate_token(void);
#if defined(M44_G0_TEST_CONTROLS)
/* 1: prepare refusal, 2: copy-one, 3: copy-all, 5: actual prepare
 * reentry probe then prepare refusal. Other values are ignored. */
void m46_supervisor_test_fault(uint32_t point);
uint32_t m46_supervisor_test_busy_mask(void);
void m46_supervisor_test_generation(uint32_t generation);
void m46_supervisor_test_ticket_serial(uint32_t serial);
#endif
#endif
