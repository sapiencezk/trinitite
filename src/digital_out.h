#pragma once

/* Pi 4 only: the fixed output bank (GPIO 17, 27 and 22) is set to output
 * and driven low before anything else runs. */
void digital_out_boot_safe(void);
