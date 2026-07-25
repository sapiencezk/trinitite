#pragma once
#include <stdint.h>
void uart_init(void);
void uart_putc(char c);
char uart_getc(void);
/* 1 if RX FIFO has at least one byte; 0 if empty (non-blocking). */
int  uart_rx_ready(void);
/* Non-blocking getc: returns 1 and stores byte, or 0 if RX empty. */
int  uart_getc_nb(uint8_t *out);
void uart_puts(const char *s);
void uart_read_bytes(uint8_t *buf, uint64_t n);
void uart_write_bytes(const uint8_t *buf, uint64_t n);
