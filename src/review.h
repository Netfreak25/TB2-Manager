#pragma once
#include "setup.h"
/** Formats the exact build approval into a caller-owned transient buffer. */
void tb2_review_approval(const Tb2SetupRequest*, char* text, size_t capacity);
bool tb2_review_run(Tb2SetupRequest*);
bool tb2_headers_ui(Tb2SetupRequest*);
