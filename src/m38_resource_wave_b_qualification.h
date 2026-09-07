#pragma once

/*
 * One private build seam for the Wave B qualification image.  Scenario
 * selection is compile-time only; none of these names is part of ResourceABI
 * and no symbol is emitted unless the selected scenario is enabled by the
 * nested Makefile.
 */
#if defined(M38_D8_WAVE_B_QUALIFICATION)
#define M38_D8_WAVE_B_ENABLED 1
#endif

