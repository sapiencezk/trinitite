#pragma once

#include <stddef.h>
#include <stdint.h>

#include "noun.h"

typedef struct ResourceRuntime ResourceRuntime;
typedef struct ResourceSession ResourceSession;

typedef struct SupervisorAdmissionEntry {
    const uint8_t *record_jam;
    size_t record_jam_bytes;
    const uint8_t *resource_core_jam;
    size_t resource_core_jam_bytes;
} SupervisorAdmissionEntry;

typedef struct SupervisorAdmissionCatalog {
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
    const noun *root_slot;
    uint64_t generation;
    uint8_t wire_status;
    ResultOwner owner;
} ResourceResultView;

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

M38Status m38_resource_runtime_init(
    void *control_storage, size_t control_storage_bytes,
    void *init_workspace, size_t init_workspace_bytes,
    ResourceRuntime **out_runtime);

M38Status m38_supervisor_admission_catalog_make(
    SupervisorAdmissionCatalog *out_catalog,
    const SupervisorAdmissionEntry *entries, uint32_t entry_count);

M38Status m38_resource_session_init(
    ResourceRuntime *runtime,
    void *storage, size_t storage_bytes,
    const SupervisorAdmissionCatalog *catalog,
    ResourceSession **out_session, SessionCapability *out_capability);

M38Status m38_resource_session_dispatch(
    ResourceSession *session, noun request,
    const ResourceResultView **out_view);

M38Status m38_resource_session_reset(ResourceRuntime *runtime,
                                     ResourceSession *session);
M38Status m38_resource_session_dispose(ResourceRuntime *runtime,
                                       ResourceSession *session);

size_t m38_resource_runtime_storage_bytes(void);
size_t m38_resource_runtime_control_storage_bytes(void);
size_t m38_resource_runtime_init_workspace_bytes(void);
size_t m38_resource_runtime_storage_alignment(void);
size_t m38_resource_session_storage_bytes(void);
size_t m38_resource_session_storage_alignment(void);

/* Test-only fault selection.  It is deliberately not a dispatch input. */
typedef enum M38FaultPoint {
    M38_FAULT_NONE = 0,
    M38_FAULT_BROKER_BEGIN,
    M38_FAULT_CUE_CACHE_INSERT,
    M38_FAULT_SLOT_PUBLICATION,
    M38_FAULT_EVALUATOR_ABORT,
    M38_FAULT_ATOM_RESULT_STAGING,
    M38_FAULT_COLLECTIVE_COMMIT,
    M38_FAULT_RESTORE_COMMIT,
} M38FaultPoint;

void m38_resource_test_fail_next(ResourceRuntime *runtime,
                                 M38FaultPoint fault);

/* QEMU entry point for the separately built Wave A witness. */
void m38_resource_wave_a_boot(void);
