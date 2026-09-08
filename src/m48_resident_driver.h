#pragma once
#include "m44_two_resource_supervisor.h"
#if defined(M47_MANAGED_SERVICES)
/* Callbacks run synchronously once per eligible stage and must not block.
 * Callbacks must not reenter the driver or supervisor, and must validate the
 * supplied epoch/token/value against native observations.
 * READY means a validated matching observation, not merely a send attempt.
 * receive copies a decoded UINT16 and nonzero 63-bit token before returning.
 * submit is invoked exactly once after claim, including on REFUSED. */
typedef enum { M48_READY=0, M48_EMPTY=1, M48_REFUSED=2 } M48IOStatus;
typedef struct {
  void *context;
  M48IOStatus (*receive)(void *,uint32_t epoch,uint64_t *token,uint32_t *value);
  M48IOStatus (*completion)(void *,uint32_t epoch,uint64_t token,uint32_t value);
  M48IOStatus (*submit)(void *,uint32_t epoch,uint64_t token,uint32_t value);
  /* READY only when shared physical transport has no pending TX. */
  M48IOStatus (*release_ready)(void *);
#if defined(M51_CONTROLLER)
  /* Optional matching completion with retained service status 0..2. READY
   * captures status once with epoch/token/value; later queue pressure cannot
   * poll it again. Invalid READY status is captured but stops driver stages;
   * its retained claim requires cold-boot recovery. Null retains the original
   * success-only adapter contract. */
  M48IOStatus (*completion_result)(void *,uint32_t epoch,uint64_t token,
                                  uint32_t value,uint32_t *status);
#endif
} M48Adapter;
typedef enum { M48_LOCAL_NONE=0, M48_LOCAL_INGRESS=1,
               M48_LOCAL_MANAGE=2, M48_LOCAL_RELEASE=3 } M48LocalKind;
typedef struct {
  M48LocalKind kind;
  uint32_t epoch,slot,command,target;
  M44Row row;
} M48LocalRequest;
#define M48_SKIPPED UINT32_MAX
/* Each status is M44Status except local MANAGE (M45Status), and the three
 * IO fields (M48IOStatus). Invalid local epoch/kind returns M44_INVALID even
 * for MANAGE. SKIPPED means the stage was not attempted. */
typedef struct {
  uint32_t local,completion_poll,receive_poll,completion_admit,receive_admit;
  uint32_t response_admit,dispatch,claim,submit;
} M48TurnResult;
typedef struct {
  M47ProviderBinding bindings[2];
  M48Adapter adapter;
  uint32_t initialized,rx_valid,rx_epoch,rx_value;
  uint64_t rx_token;
  uint32_t tx_valid,tx_observed,tx_epoch,tx_value;
  uint64_t tx_token;
#if defined(M51_CONTROLLER)
  uint32_t tx_status;
#endif
#if defined(M49_MANAGED_DELAY)
  /* Optional M49 boot hook, once after admissions and before dispatch.
   * It may publish one trusted expiry through the supervisor. Null retains
   * M48 behavior. The hook must be nonblocking and must not reenter driver. */
  M44Status (*before_dispatch)(void *);
  void *before_dispatch_context;
  uint32_t before_dispatch_status;
#endif
} M48ResidentDriver;
/* Cold boot only, after successful supervisor initialization; no IEC execution.
 * No allocation, singleton authority remains owned by the supervisor. */
M44Status m48_resident_init(M48ResidentDriver *,const M47ProviderBinding[2],
                            const M48Adapter *);
/* Order: local, observe completion/RX, admit completion/RX/RSP, dispatch,
 * claim+submit. STOP disables dispatch only; IDLE disables provider stages.
 * Caller owns requests until this call returns; refused ingress is not queued.
 * RELEASE queues existing private release and requires RUNNING to dispatch.
 * A retained receive blocks release/reset until admission commits. */
M48TurnResult m48_resident_turn(M48ResidentDriver *,const M48LocalRequest *);
#endif
