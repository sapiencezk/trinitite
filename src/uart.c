#include <stdint.h>
#include "platform.h"

#define PL011_BASE  PLATFORM_UART_BASE
#define UART_DR     (*(volatile uint32_t*)(PL011_BASE + 0x00))
#define UART_FR     (*(volatile uint32_t*)(PL011_BASE + 0x18))
#define UART_IBRD   (*(volatile uint32_t*)(PL011_BASE + 0x24))
#define UART_FBRD   (*(volatile uint32_t*)(PL011_BASE + 0x28))
#define UART_LCRH   (*(volatile uint32_t*)(PL011_BASE + 0x2C))
#define UART_CR     (*(volatile uint32_t*)(PL011_BASE + 0x30))

#if defined(TRINITITE_PLATFORM_RPI4B)
/*
 * Route PL011 (UART0) onto GPIO 14/15 (ALT0). enable_uart=1 clocks the
 * block; on a wireless CM4 the firmware otherwise leaves UART0 on the
 * Bluetooth pins. Compiled only into I3_HOST rpi4b images.
 */
#define BCM2838_GPIO_BASE 0xFE200000ULL
#define BCM2838_GPFSEL1   0x04u
#define GPIO_ALT0         4u

static void mux_pl011_gpio(void)
{
    volatile uint32_t *gpfsel1 =
        (volatile uint32_t *)(uintptr_t)(BCM2838_GPIO_BASE + BCM2838_GPFSEL1);
    uint32_t v = *gpfsel1;
    v &= ~((7u << 12) | (7u << 15));
    v |= (GPIO_ALT0 << 12) | (GPIO_ALT0 << 15);
    *gpfsel1 = v;
    __asm__ volatile("dsb sy" ::: "memory");
}
#endif

void uart_init(void) {
#if defined(TRINITITE_PLATFORM_RPI4B)
    mux_pl011_gpio();
#endif
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

void uart_puts(const char *s) {
    while (*s) {
        if (*s == '\n') uart_putc('\r');
        uart_putc(*s++);
    }
}
