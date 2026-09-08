#pragma once
#include <stdint.h>
#define M48_REPORT_CAPACITY 16384u
#define M48_REPORT_DRAIN_BUDGET 32u
/* Serialized resident-loop ownership. A report is invisible to drain until
 * end succeeds; overflow discards the entire report. No allocation or waits. */
int m48_report_begin(void);
void m48_report_putc(char byte);
void m48_report_puts(const char *text);
/* 1 publishes a complete report, 0 means no capture or whole-record overflow.
 * After overflow the caller may begin a new, short diagnostic report. */
int m48_report_end(void);
/* At most 32 bytes / 32 UART attempts; stops at the first full-UART result.
 * Returns bytes sent (zero when UART is already full or no report is ready). */
uint32_t m48_report_drain(void);
int m48_report_idle(void);
int m48_report_capturing(void);
