#pragma once

#include "noun.h"

/* The native boundary consumes and returns the frozen D0-R2 noun grammar. */
/* A returned result is borrowed from the module-owned publication arena and
 * remains valid through caller serialization/copy until the next top-level
 * dispatch.  This is a single-core, single-consumer boundary contract; it is
 * not a general callback, reentrant, ownership-transfer, or multicore ABI. */
noun m38_resource_abi_dispatch(noun request);

/* M38-D5 native ResourceABI vertical slice. */
void m38_resource_abi_boot(void);

/* M38-D7 native ResourceCore boundary.  The boot witness admits only the
 * canonical serialized ResourceCore plus its minimal R5 descriptor. */
void m38_resource_core_boot(void);
