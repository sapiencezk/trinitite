#include <stdint.h>
#include "uart.h"
#include "memory.h"
#include "noun.h"
#include "cold.h"
#include "i2_ingress.h"
#include "i2_admission_metrics.h"
#include "digital_out.h"
#if defined(M38_D7_NATIVE)
#include "m38_resource_abi_target.h"
#elif defined(M38_D5_NATIVE)
#include "m38_resource_abi_target.h"
#elif defined(M38_C)
#include "m38_c_target.h"
#elif defined(I2_OPERATOR)
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

#if defined(M38_D7_NATIVE)
    m38_resource_core_boot();
#elif defined(M38_D5_NATIVE)
    m38_resource_abi_boot();
#elif defined(M38_C)
    m38_c_boot();
#elif defined(I2_OPERATOR)
    i2_operator_boot();
#else
    forth_main();   /* never returns */
#endif
}
