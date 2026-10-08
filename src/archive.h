#pragma once
#include "workflow.h"

#define TB2_ARCHIVE_OWNED    1U
#define TB2_ARCHIVE_VERIFIED 2U
typedef struct {
    uint32_t flags;
    uint8_t digest[32];
} Tb2ArchiveReceipt;
typedef struct {
    Tb2WorkflowIO* io;
    const char* package_dir;
    const char* image_path;
    const uint8_t* package_hash;
    const uint8_t* ca_hash;
    Tb2ArchiveReceipt* receipt;
    void* context;
    bool (*checkpoint)(void* context, const Tb2ArchiveReceipt* receipt);
    char error[160];
} Tb2ArchiveRequest;

bool tb2_archive_path(const char* image, char output[TB2_JOB_PATH_MAX]);
/** Reuse only a continuously held, freshly verified image handle. After restart,
 * open and hash the complete file against the durable image proof before export. */
int tb2_archive_image_lease(
    Tb2WorkflowIO*,
    const char* image,
    const uint8_t hash[32],
    void** lease);
/** Seven fixed ustar members. Never overwrites a foreign file. Each input is
 * bound before export and rechecked while writing; output is synced, closed,
 * reopened and fully hashed. Retry needs no box key or image reprocessing. */
int tb2_archive_run(Tb2ArchiveRequest* request);
