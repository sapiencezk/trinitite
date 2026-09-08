#include "m48_report.h"
#include "uart.h"
static uint8_t m48_report_bytes[M48_REPORT_CAPACITY];
static uint32_t m48_report_length,m48_report_position;
static int m48_report_capture_active,m48_report_overflow;
int m48_report_idle(void) { return !m48_report_capture_active && m48_report_position==m48_report_length; }
int m48_report_capturing(void) { return m48_report_capture_active; }
int m48_report_begin(void) {
    if (!m48_report_idle()) return 0;
    m48_report_length=m48_report_position=0; m48_report_overflow=0; m48_report_capture_active=1;
    return 1;
}
void m48_report_putc(char byte) {
    if (!m48_report_capture_active || m48_report_overflow) return;
    if (m48_report_length==M48_REPORT_CAPACITY) { m48_report_overflow=1; return; }
    m48_report_bytes[m48_report_length++]=(uint8_t)byte;
}
void m48_report_puts(const char *text) {
    if (!m48_report_capture_active || m48_report_overflow || !text) return;
    /* Stop on m48_report_overflow, so even an oversized string takes bounded work. */
    while (*text && !m48_report_overflow) m48_report_putc(*text++);
}
int m48_report_end(void) {
    if (!m48_report_capture_active) return 0;
    m48_report_capture_active=0;
    if (m48_report_overflow) { m48_report_length=m48_report_position=0; return 0; }
    return 1;
}
uint32_t m48_report_drain(void) {
    uint32_t sent=0;
    if (m48_report_capture_active) return 0;
    while (m48_report_position<m48_report_length && sent<M48_REPORT_DRAIN_BUDGET) {
        if (!uart_putc_nb(m48_report_bytes[m48_report_position])) break;
        m48_report_position++; sent++;
    }
    return sent;
}
