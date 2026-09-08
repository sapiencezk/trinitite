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
  M44Boundary ingress[2][128], outputs[2][128];
} M44Descriptor;
typedef struct {
  uint32_t bytes;
  uint8_t jam[M44_SAVED_BYTES];
} M44Saved;
typedef struct {
  uint32_t cursor, sequence, fault, fenced, counts[2], output_count;
  M44Row queues[2][16], outputs[32];
  uint32_t output_slots[32];
#if defined(M45_MANAGED_LIFECYCLE)
  uint32_t lifecycle, epoch;
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
