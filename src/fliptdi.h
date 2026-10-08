#pragma once

#include "setup.h"

#define TB2_FLIPTDI_ID    "tb2_fliptdi"
#define TB2_FLIPTDI_API   TB2_SETUP_API
#define TB2_FLIPTDI_ASSET "plugins/tb2_fliptdi.fal"

/** FlipTDI uses the existing synchronous setup-module contract. The module
 * owns every view, thread and hardware handle until run() returns. */
