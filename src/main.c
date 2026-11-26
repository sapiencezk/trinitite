#include <stdint.h>
#include "uart.h"
#include "memory.h"
#include "noun.h"
#include "cold.h"
#include "digital_out.h"
#include "lite_host.h"

void main(void) {
#if defined(TRINITITE_PLATFORM_RPI4B)
    digital_out_boot_safe();
#endif
    uart_init();
    uart_puts("LITEH boot\r\n");

    noun_heap_init();
    cold_init();

    lite_host_boot();
}
