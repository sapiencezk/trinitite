#pragma once

#include <stdint.h>

#include "noun.h"

/*
 * The framed ingress is an adapter boundary, not an authenticator.  The
 * caller must present this typed, image-owned attestation before a decoded
 * noun can enter M22 admission.  UART bytes cannot manufacture its issuer
 * identity or pointer value.
 */
typedef struct {
    uint64_t magic;
    const uint64_t *issuer;
    uint32_t profile;
    uint32_t authenticated;
} m22_adapter_attestation_t;

enum {
    M22_ERR_NONE = 0,
    M22_ERR_NOT_INITIALIZED = 1,
    M22_ERR_ADAPTER_ATTESTATION = 2,
    M22_ERR_NO_FRAME = 3,
    M22_ERR_FRAME_LENGTH = 4,
    M22_ERR_FRAME_RATE = 5,
    M22_ERR_CUE = 6,
    M22_ERR_FRAME_VERSION = 30,
    M22_ERR_FRAME_HEADER = 31,
    M22_ERR_FRAME_DIGEST = 32,
    M22_ERR_FRAME_TIMEOUT = 33,
    M22_ERR_PRODUCT_TAG = 7,
    M22_ERR_VERSION = 8,
    M22_ERR_PROFILE = 9,
    M22_ERR_MESSAGE_KIND = 10,
    M22_ERR_SENDER = 11,
    M22_ERR_RECEIVER = 12,
    M22_ERR_BINDING = 13,
    M22_ERR_SCHEMA = 14,
    M22_ERR_KEY_ID = 15,
    M22_ERR_EPOCH = 16,
    M22_ERR_SEQUENCE_ZERO = 17,
    M22_ERR_REPLAY = 18,
    M22_ERR_FIFO_FULL = 19,
    M22_ERR_RESERVATION = 20,
    M22_ERR_PUBLICATION_TAG = 21,
    M22_ERR_PUBLICATION_VERSION = 22,
    M22_ERR_PUBLICATION_EVENT = 23,
    M22_ERR_PUBLICATION_TYPE = 24,
    M22_ERR_PUBLICATION_VALUE = 25,
    M22_ERR_PUBLICATION_SHAPE = 26,
    M22_ERR_CHECKPOINT_BUSY = 27,
    M22_ERR_RAW_M21_CARRIER = 28,
    M22_ERR_BARE_INTERNAL_EI = 29
};

int m22_provider_core_init(void);
/* Poll the existing I2 framed ingress, then cross the same attested admission
 * function a future authenticated network adapter would call. */
int m22_provider_core_receive_framed(void);
int m22_provider_core_admit(noun product,
                            const m22_adapter_attestation_t *attestation);
int m22_provider_core_unattested_probe(void);
int m22_provider_core_step(void);
int m22_provider_core_checkpoint(void);
void m22_provider_core_reservation_fault_once(void);
uint64_t m22_provider_core_queue_len(void);
uint64_t m22_provider_core_high_water(void);
uint64_t m22_provider_core_indication(void);
uint64_t m22_provider_core_indication_sequence(void);
uint64_t m22_provider_core_last_error(void);
uint64_t m22_provider_core_cue_calls(void);
