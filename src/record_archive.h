#pragma once
#include "record_tasks.h"

/** Stream a complete record/package or a redacted diagnostic TAR. Import first
 * validates an isolated staging tree; no external references are accepted. */
Tb2RecordResult tb2_record_archive(Tb2WorkflowIO*, Tb2RecordTask*);
