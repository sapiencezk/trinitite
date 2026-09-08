#pragma once

#include "m38_resource_runtime.h"

/* Private, compiled-in two-resource authority seam. These are not D8 wire
 * operations. All calls require the same external serialized executor as D8.
 * Claim is permanent for the session's cold-boot lifetime and blocks public
 * dispatch/reset/dispose. The owner token is a trusted supervisor C object.
 * No transaction or borrowed noun remains open across a function return. */
#if defined(M44_TWO_RESOURCE)
typedef struct M44PublicationHooks {
    /* Runs with broker ownership before persistent copying. The result is
     * borrowed for this callback only. Copy samples/Jam into bounded inactive
     * C storage. False refuses without resource or supervisor publication.
     * Reentrant runtime calls refuse. Never change live supervisor authority. */
    int (*prepare)(void *context, noun staged_result);
    /* Only an infallible fixed-store/root flip: no allocation, serialization,
     * runtime calls, callbacks, failure or longjmp. Runs after all resource
     * roots are installed, before broker release/any external observation. */
    void (*commit)(void *context);
    void *context;
} M44PublicationHooks;

M38Status m44_resource_claim(ResourceSession *session, const void *owner, const noun handles[2]);

/* POKE and PEEK only. Hooks participate in successful POKE publication;
 * ordinary D8 refusals retain their existing OK + refusal-view meaning. */
M38Status m44_resource_dispatch(ResourceSession *session, const void *owner,
    noun request, const M44PublicationHooks *hooks,
    const ResourceResultView **out_view);

/* Exactly two distinct owned handles in one session. restore=0 snapshots
 * both; restore=1 validates both exact latest snapshots then restores both.
 * The private result is [cord("m44-resource-group-v1") list-of-two-D8-results].
 * Failed group validation returns non-OK and preserves both result owners,
 * snapshot authorities and supervisor state. */
M38Status m44_resource_group(ResourceSession *session, const void *owner,
    int restore, const noun handles[2], const noun snapshots[2],
    const M44PublicationHooks *hooks, const ResourceResultView **out_view);

#if defined(M45_MANAGED_LIFECYCLE)
/* Private atomic aggregate initialize. Copy the immutable, admitted compiler
 * initializer image (explicit ECC IDs and typed raw values), without executing
 * an algorithm or interpreting IEC defaults. Preserve handle identities; advance
 * both snapshot nonces and revoke snapshots only on successful publication.
 * Result has the same two RESTORE receipts as the private M44 group operation. */
M38Status m45_resource_reinitialize(ResourceSession *session, const void *owner,
    const noun handles[2], const M44PublicationHooks *hooks,
    const ResourceResultView **out_view);
#endif

/* Zero-slot publication for enqueue or terminal queue-head retirement. Preserves D8
 * result owners/generations; all persistent copying precedes the fixed-store
 * supervisor commit. A failed enqueue preserves the usable prior root; failed
 * terminal retirement requires fencing that root to prevent implicit retry. */
M38Status m44_resource_publish(ResourceSession *session, const void *owner,
    const M44PublicationHooks *hooks);

/* Read-only typed diagnostic copy. No result promotion, snapshot issuance or
 * executable work or noun allocation. Claim permanently binds exactly two
 * resident slots; results are in ascending slot order. The same external
 * serialization and busy fences apply. */
typedef struct {
    uint32_t active, value_count, types[16], values[16];
} M44InstanceInspection;
typedef struct {
    uint64_t capability, generations[2], snapshot_nonces[2];
    uint32_t instance_counts[2];
    M44InstanceInspection instances[2][8];
} M44ResourceInspection;
M38Status m44_resource_inspect(ResourceSession *session, const void *owner,
    M44ResourceInspection *out);

#if defined(M44_G0_TEST_CONTROLS)
/* Qualification-only copy faults: 1 after all copies, 2 after first group
 * candidate copy. Called from prepare, consumed by the corresponding stage. */
void m44_resource_test_fail_publication(ResourceSession *session, uint32_t point);
#if defined(M45_MANAGED_LIFECYCLE)
/* Qualification only: 1 arms one broker-begin refusal; 2 exhausts both snapshot
 * nonces to exercise reset's boundary. No production fault/counter setters. */
M38Status m45_resource_test_control(ResourceSession *session, const void *owner,
    uint32_t point);
#endif
#endif
#endif
