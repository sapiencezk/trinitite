#pragma once

#include <stdint.h>

#include "noun.h"

typedef struct {
    uint64_t magic;
    const uint64_t *issuer;
    uint32_t profile;
    uint32_t authenticated;
} m23_adapter_attestation_t;

enum {
    M23_STATE_UNARMED = 0,
    M23_STATE_ARMED = 1,
    M23_STATE_EXHAUSTED = 2,
    M23_STATE_CLOSED = 3,
    M23_ERR_NONE = 0,
    M23_ERR_NOT_INITIALIZED = 1,
    M23_ERR_ADAPTER_ATTESTATION = 2,
    M23_ERR_NO_FRAME = 3,
    M23_ERR_FRAME_LENGTH = 4,
    M23_ERR_INGRESS_WORK_LIMIT = 5,
    M23_ERR_CUE = 6,
    M23_ERR_PRODUCT_TAG = 7,
    M23_ERR_VERSION = 8,
    M23_ERR_PROFILE = 9,
    M23_ERR_MESSAGE_KIND = 10,
    M23_ERR_SENDER = 11,
    M23_ERR_RECEIVER = 12,
    M23_ERR_BINDING = 13,
    M23_ERR_SCHEMA = 14,
    M23_ERR_KEY_ID = 15,
    M23_ERR_EPOCH = 16,
    M23_ERR_SEQUENCE_ZERO = 17,
    M23_ERR_REPLAY = 18,
    M23_ERR_FIFO_FULL = 19,
    M23_ERR_RESERVATION = 20,
    M23_ERR_PUBLICATION_TAG = 21,
    M23_ERR_PUBLICATION_VERSION = 22,
    M23_ERR_PUBLICATION_EVENT = 23,
    M23_ERR_PUBLICATION_TYPE = 24,
    M23_ERR_PUBLICATION_VALUE = 25,
    M23_ERR_PUBLICATION_SHAPE = 26,
    M23_ERR_CHECKPOINT_BUSY = 27,
    M23_ERR_RAW_M21_CARRIER = 28,
    M23_ERR_BARE_INTERNAL_EI = 29,
    M23_ERR_CHECKPOINT_INVALID = 34,
    M23_ERR_SESSION_UNARMED = 35,
    M23_ERR_STALE_EPOCH = 36,
    M23_ERR_EPOCH_NOT_NEWER = 37,
    M23_ERR_SEQUENCE_EXHAUSTED = 38,
    M23_ERR_CLOSED = 39,
    M23_ERR_OUTBOUND_RATE_LIMIT = 40
};

int m23_provider_core_init(void);
int m23_provider_core_arm(void);
int m23_provider_core_cold(void);
int m23_provider_core_restart_clean(void);
int m23_provider_core_close(void);
int m23_provider_core_receive_framed(void);
int m23_provider_core_step(void);
int m23_provider_core_rotate(void);
int m23_provider_core_checkpoint_save(void);
int m23_provider_core_checkpoint_restore(void);
#ifdef M23_TEST_CONTROLS
int m23_provider_core_checkpoint_tamper(void);
#endif
int m23_provider_core_complete_egress(void);
#ifdef M23_TEST_CONTROLS
int m23_provider_core_set_next_max_minus_one(void);
int m23_provider_core_test_outbound_burst(void);
#endif
uint64_t m23_provider_core_queue_len(void);
uint64_t m23_provider_core_high_water(void);
uint64_t m23_provider_core_next_sequence(void);
uint64_t m23_provider_core_epoch(void);
uint64_t m23_provider_core_state(void);
uint64_t m23_provider_core_indication(void);
uint64_t m23_provider_core_indication_sequence(void);
uint64_t m23_provider_core_last_error(void);
uint64_t m23_provider_core_cue_calls(void);
