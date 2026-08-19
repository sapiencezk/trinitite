#include <stdint.h>
#include "uart.h"
#include "memory.h"
#include "noun.h"
#include "cold.h"
#include "i2_ingress.h"
#include "i2_admission_metrics.h"
#include "digital_out.h"
#ifdef I2_OPERATOR
#include "i2_operator.h"
#else
extern void forth_main(void);
#endif

void main(void) {
    /* M6 fixed bank is configured and cleared before ordinary app enable. */
    (void)digital_out_boot_safe();
    uart_init();

    /* Write stack canary */
    *(volatile uint32_t*)DSTACK_GUARD = STACK_CANARY;

    noun_heap_init();
    i2_admission_metrics_init();
    i2_rx_init();
    cold_init();

#ifdef I2_OPERATOR
    i2_operator_boot();
#else
    forth_main();   /* never returns */
#endif
}
