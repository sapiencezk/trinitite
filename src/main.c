#include <stdint.h>
#include "uart.h"
#include "memory.h"
#include "noun.h"
#include "cold.h"
#include "i2_ingress.h"

extern void forth_main(void);

void main(void) {
    uart_init();

    /* Write stack canary */
    *(volatile uint32_t*)DSTACK_GUARD = STACK_CANARY;

    noun_heap_init();
    i2_rx_init();
    cold_init();

    forth_main();   /* never returns */
}
