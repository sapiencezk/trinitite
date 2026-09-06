#pragma once

#include <stddef.h>
#include <stdint.h>

#include "noun.h"

typedef struct ResourceRuntime ResourceRuntime;
typedef struct ResourceSession ResourceSession;

typedef struct SupervisorAdmissionEntry {
    /* Borrowed caller storage: each byte range must remain readable,
     * unchanged, and non-overlapping through the return from every
     * m38_resource_session_init that consumes this catalog. */
    const uint8_t *record_jam;
    size_t record_jam_bytes;
    const uint8_t *resource_core_jam;
    size_t resource_core_jam_bytes;
} SupervisorAdmissionEntry;

typedef struct SupervisorAdmissionCatalog {
    /* The catalog object and entries array are caller-owned borrowed input.
     * Successful session init copies the bounded canonical fields and Jam
     * bytes; callers may release or overwrite them after that call returns. */
    const SupervisorAdmissionEntry *entries;
    uint32_t entry_count;
} SupervisorAdmissionCatalog;

typedef uint64_t SessionCapability;

typedef enum ResultOwner {
    M38_RESULT_OWNER_NONE = 0,
    M38_RESULT_OWNER_PRIMARY = 1,
    M38_RESULT_OWNER_REFUSAL = 2,
} ResultOwner;

typedef struct ResourceResultView {
    /* The view object and root_slot address are session-owned and stable only
     * until session reset/dispose.  A primary slot is invalidated by the next
     * accepted primary publication; a refusal slot by the next ordinary
     * refusal.  Any non-OK call preserves both slots.  Promotion may rewrite
     * *root_slot: callers must reread it after each runtime operation and must
     * externally serialize any value that must survive that invalidation. */
    const noun *root_slot;
    uint64_t generation;
    uint8_t wire_status;
    ResultOwner owner;
} ResourceResultView;

/* The runtime never owns caller storage and never exposes its internal
 * numeric ResourceCore/profile representation.  The Wave A witness is a
 * separate test-only translation unit. */

typedef enum M38Status {
    M38_STATUS_OK = 0,
    M38_STATUS_INVALID_ARGUMENT = 1,
    M38_STATUS_STORAGE_TOO_SMALL = 2,
    M38_STATUS_STORAGE_MISALIGNED = 3,
    M38_STATUS_STORAGE_OVERLAP = 4,
    M38_STATUS_RUNTIME_UNINITIALIZED = 5,
    M38_STATUS_RUNTIME_BUSY = 6,
    M38_STATUS_SESSION_REGISTRY_FULL = 7,
    M38_STATUS_CAPABILITY_INVALID = 8,
    M38_STATUS_CAPABILITY_EXHAUSTED = 9,
    M38_STATUS_CATALOG_INVALID = 10,
    M38_STATUS_CATALOG_BOUNDS = 11,
    M38_STATUS_CATALOG_DUPLICATE = 12,
    M38_STATUS_SESSION_CLOSED = 13,
    M38_STATUS_SESSION_BUSY = 14,
    M38_STATUS_REQUEST_INVALID = 15,
    M38_STATUS_BROKER_BEGIN = 16,
    M38_STATUS_CUE_CACHE_INSERT = 17,
    M38_STATUS_SLOT_PUBLICATION = 18,
    M38_STATUS_EVALUATOR_ABORT = 19,
    M38_STATUS_ATOM_RESULT_STAGING = 20,
    M38_STATUS_COLLECTIVE_COMMIT = 21,
    M38_STATUS_RESTORE_COMMIT = 22,
    M38_STATUS_RUNTIME_ALREADY_INITIALIZED = 23,
    M38_STATUS_INTERNAL = 24,
} M38Status;

/* Runtime initialization claims the process-wide serialized noun/Nock domain
 * for a cold boot.  The caller retains ownership of both storage regions and
 * must keep them alive until every registered session has been disposed.  The
 * process-global lease is cold-boot-owned; this API makes no same-process
 * release/reinitialization claim. */
M38Status m38_resource_runtime_init(
    void *control_storage, size_t control_storage_bytes,
    void *init_workspace, size_t init_workspace_bytes,
    ResourceRuntime **out_runtime);

/* The output catalog is a borrowed view over caller-owned entries and Jam
 * bytes.  Its storage must remain live through session-init return; no public
 * call retains those borrowed nouns or byte ranges after successful copying. */
M38Status m38_supervisor_admission_catalog_make(
    SupervisorAdmissionCatalog *out_catalog,
    const SupervisorAdmissionEntry *entries, uint32_t entry_count);

/* Session storage is caller-owned and must remain allocated, aligned, and
 * untouched from successful init through reset/dispose.  The catalog is
 * borrowed only for this call and is copied before it returns. */
M38Status m38_resource_session_init(
    ResourceRuntime *runtime,
    void *storage, size_t storage_bytes,
    const SupervisorAdmissionCatalog *catalog,
    ResourceSession **out_session, SessionCapability *out_capability);

/* On entry, out_view is cleared after it is confirmed non-NULL.  Only an
 * accepted request or ordinary wire refusal returns OK with a non-NULL view;
 * busy, unsafe-noun, and injected/native fault paths return a non-OK status
 * and publish no refusal.  Requests are borrowed for this one transaction;
 * callers own any external serialization or byte/scalar encoding needed to
 * carry values across publication invalidation.  This operation and its
 * result-view reads require one external serialized executor; callers must
 * not retain a raw movable noun from root_slot across a later
 * operation/promotion. */
M38Status m38_resource_session_dispatch(
    ResourceSession *session, noun request,
    const ResourceResultView **out_view);

M38Status m38_resource_session_reset(ResourceRuntime *runtime,
                                     ResourceSession *session);
M38Status m38_resource_session_dispose(ResourceRuntime *runtime,
                                       ResourceSession *session);

/* Reset invalidates live handles, snapshots, and both result slots but
 * preserves the copied catalog and capability.  Dispose unregisters and
 * closes the session; reinitialization then requires fresh caller storage and
 * a fresh capability.  Lifecycle calls participate in the same external
 * serialization/transaction requirement as dispatch. */

size_t m38_resource_runtime_storage_bytes(void);
size_t m38_resource_runtime_control_storage_bytes(void);
size_t m38_resource_runtime_init_workspace_bytes(void);
size_t m38_resource_runtime_storage_alignment(void);
size_t m38_resource_session_storage_bytes(void);
size_t m38_resource_session_storage_alignment(void);
