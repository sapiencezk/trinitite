#pragma once
#include <stdint.h>
void uart_init(void);
void uart_putc(char c);
/* 1 if RX FIFO has at least one byte; 0 if empty (non-blocking). */
/* Non-blocking getc: returns 1 and stores byte, or 0 if RX empty. */
void uart_puts(const char *s);
/* I2 service TX: poll no later than absolute CNTVCT deadline. */
