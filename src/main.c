#include <stdint.h>
#include "uart.h"
#include "memory.h"
#include "noun.h"
#include "cold.h"
#include "i2_admission_metrics.h"
#include "digital_out.h"
#include "i3_host.h"

void main(void) {
#if defined(TRINITITE_PLATFORM_RPI4B)
    digital_out_boot_safe();
#endif
    uart_init();
    uart_puts("I3H boot\r\n");

    noun_heap_init();
    i2_admission_metrics_init();
    cold_init();

    i3_host_boot();
}
