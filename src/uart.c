#include <stdint.h>
#include "platform.h"

#define PL011_BASE  PLATFORM_UART_BASE
#define UART_DR     (*(volatile uint32_t*)(PL011_BASE + 0x00))
#define UART_FR     (*(volatile uint32_t*)(PL011_BASE + 0x18))
#define UART_IBRD   (*(volatile uint32_t*)(PL011_BASE + 0x24))
#define UART_FBRD   (*(volatile uint32_t*)(PL011_BASE + 0x28))
#define UART_LCRH   (*(volatile uint32_t*)(PL011_BASE + 0x2C))
#define UART_CR     (*(volatile uint32_t*)(PL011_BASE + 0x30))

static int g_test_tx_stuck;

static uint64_t uart_counter(void)
{
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

void uart_init(void) {
    UART_CR   = 0;
    UART_IBRD = 26;
    UART_FBRD = 3;
    UART_LCRH = (3 << 5);
    UART_CR   = (1<<0)|(1<<8)|(1<<9);
}

void uart_putc(char c) {
    while (UART_FR & (1 << 5));
    UART_DR = c;
}

char uart_getc(void) {
    while (UART_FR & (1 << 4));
    return UART_DR & 0xFF;
}

int uart_rx_ready(void) {
    /* FR bit 4 = RXFE (receive FIFO empty) */
    return (UART_FR & (1 << 4)) ? 0 : 1;
}

int uart_getc_nb(uint8_t *out) {
    if (UART_FR & (1 << 4))
        return 0;
    if (out)
        *out = (uint8_t)(UART_DR & 0xFF);
    return 1;
}

void uart_puts(const char *s) {
#ifdef I2_OPERATOR
    (void)s;
    return;
#else
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
#endif
}

int uart_putc_nb(uint8_t byte)
{
    if (g_test_tx_stuck || (UART_FR & (1 << 5)))
        return 0;
    UART_DR = byte;
    return 1;
}

void uart_read_bytes(uint8_t *buf, uint64_t n) {
    for (uint64_t i = 0; i < n; i++)
        buf[i] = (uint8_t)uart_getc();
}

void uart_write_bytes(const uint8_t *buf, uint64_t n) {
    for (uint64_t i = 0; i < n; i++)
        uart_putc((char)buf[i]);
}

int uart_putc_bounded(char c, uint64_t absolute_deadline)
{
    for (;;) {
        if (!g_test_tx_stuck && !(UART_FR & (1 << 5))) {
            UART_DR = c;
            return 1;
        }
        if (uart_counter() >= absolute_deadline)
            return 0;
    }
}

void uart_test_tx_stuck(int stuck)
{
    g_test_tx_stuck = stuck ? 1 : 0;
}

int uart_test_tx_is_stuck(void)
{
    return g_test_tx_stuck;
}
