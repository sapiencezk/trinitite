#pragma once

#include <stdint.h>
#include "noun.h"
#include "bounded_cue.h"

typedef enum {
    I2_RX_REASON_NONE = 0,
    I2_RX_REASON_VERSION,
    I2_RX_REASON_HEADER,
    I2_RX_REASON_LENGTH,
    I2_RX_REASON_DIGEST,
    I2_RX_REASON_CUE,
    I2_RX_REASON_TIMEOUT,
    I2_RX_REASON_COUNT
} i2_rx_reason_t;

void i2_rx_init(void);
/* Consume at most byte_budget UART bytes. Returns 1 when a verified payload
 * is ready for bounded cue, otherwise 0. */
int i2_rx_poll(uint32_t byte_budget);
/* Decode the ready payload into SCRATCH. Success leaves noun_tx active. */
int i2_rx_take(noun *out);
/* M22 uses the same framed scanner with a stricter, caller-supplied Cue
 * profile.  The caller must keep the ready frame bounded before invoking it. */
int i2_rx_take_limited(noun *out, const cue_bounded_limits_t *limits);
uint64_t i2_rx_payload_len(void);
uint64_t i2_rx_reject_total(void);
uint64_t i2_rx_cue_calls(void);
/* Drop a ready frame without Cue; used only after an adapter-side cheap check. */
void i2_rx_discard_ready(void);

/* Deterministic parser hooks used by focused tests. */
void i2_rx_feed_byte(uint8_t byte, uint64_t now);
void i2_rx_check_timeout(uint64_t now);
int i2_rx_ready(void);

uint64_t i2_rx_reject_count(i2_rx_reason_t reason);
i2_rx_reason_t i2_rx_last_reason(void);
const char *i2_rx_reason_name(i2_rx_reason_t reason);

/* Focused device-code regression probes; return zero on success. */
uint64_t i2_rx_selftest(void);
uint64_t cue_bounded_selftest(void);

#define I2_FRAME_HEADER_SIZE 56u
int i2_frame_encode(const uint8_t *payload, uint64_t len,
                    uint8_t *out, uint64_t out_cap, uint64_t *out_len);
