#pragma once

#include "noun.h"

/* The native boundary consumes and returns the frozen D0-R2 noun grammar. */
/* A returned result is borrowed from the module-owned publication arena and
 * remains valid until the next dispatch; callers must serialize or copy it
 * before making another boundary call. */
noun m38_resource_abi_dispatch(noun request);

/* M38-D5 native ResourceABI vertical slice. */
void m38_resource_abi_boot(void);
