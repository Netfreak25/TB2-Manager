#pragma once
#include "workflow.h"

/** Paths and fingerprints are owned by the resident controller and bound to a
 * checked restoration descriptor. target is exclusively owned by that job.
 * Both input handles stay open until the independent image check completes. */
typedef struct {
    Tb2WorkflowIO* io;
    const char* donor;
    const char* source;
    const char* target;
    const char* directory;
    const Tb2InputKey* donor_key;
    const Tb2InputKey* target_key;
    const uint8_t* donor_hash;
    const uint8_t* source_hash;
    bool connection;
    bool build;
    bool check_only;
    Tb2ReadResult donor_read, source_read;
    Tb2ImageResult image;
    char error[224];
} Tb2RestoreRequest;

int tb2_restore_run(Tb2RestoreRequest*);
