#include "store.h"
#include "probe.h"
#include <furi.h>
#include <furi_hal.h>
#include <storage/storage.h>
#include <toolbox/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAIL_BYTES 512U
/** Only the resident callback opens/owns the handle. This transient parser
 * restores its append position/sequence before the store module is unloaded. */
static bool prepare_log(Tb2StoreRequest* r) {
    char path[TB2_JOB_PATH_MAX];
    snprintf(path, sizeof(path), "%s/debug.log", r->run_directory);
    File* file = r->open_log(r->log_context, path);
    if(!file) return false;
    uint64_t size = storage_file_size(file);
    if(size > UINT32_MAX) return false;
    char tail[LOG_TAIL_BYTES + 1] = {0};
    size_t count = size > LOG_TAIL_BYTES ? LOG_TAIL_BYTES : (size_t)size;
    if(!storage_file_seek(file, (uint32_t)(size - count), true) ||
       storage_file_read(file, tail, count) != count)
        return false;
    *r->log_sequence = 0;
    for(size_t i = 0; i < count; i++) {
        if((i && tail[i - 1] != '\n') || (!i && size > count)) continue;
        char* end;
        unsigned long sequence = strtoul(tail + i, &end, 10);
        if(*end == '|' && sequence > *r->log_sequence) *r->log_sequence = sequence;
    }
    return storage_file_seek(file, (uint32_t)size, true) &&
           (!count || tail[count - 1] == '\n' || storage_file_write(file, "\n", 1) == 1);
}
Tb2RecordResult tb2_store_preflight(Tb2StoreRequest* r) {
    if(!r->run_directory || !r->open_log || !r->log_sequence || !r->io) return Tb2RecordCorrupt;
    FS_Error rc = storage_common_mkdir(r->storage, TB2_JOBS_ROOT);
    if(rc != FSE_OK && rc != FSE_EXIST) return Tb2RecordIo;
    if(!r->run_directory[0]) {
        snprintf(
            r->run_directory,
            128,
            "%s/%08lx-%08lx",
            TB2_JOBS_ROOT,
            (unsigned long)furi_hal_rtc_get_timestamp(),
            (unsigned long)furi_hal_random_get());
        if(storage_common_mkdir(r->storage, r->run_directory) != FSE_OK) return Tb2RecordIo;
    }
    if(!prepare_log(r)) return Tb2RecordIo;
    const Version* version = furi_hal_version_get_firmware_version();
    char detail[256];
    snprintf(
        detail,
        sizeof(detail),
        "app=%s firmware=%s git=%s api=88.4 rtc=%lu action=%lu resume=%u",
        TB2_PROBE_VERSION,
        version_get_version(version),
        version_get_githash(version),
        (unsigned long)furi_hal_rtc_get_timestamp(),
        (unsigned long)r->workflow_action,
        r->resume);
    if(!r->io->event(r->io->context, "start", 0, detail)) return Tb2RecordIo;
    if(strncmp(version_get_githash(version), "3c9be0f", 7)) {
        snprintf(r->error, sizeof(r->error), "Requires Unleashed 0.92 / API 88.4.");
        return Tb2RecordConflict;
    }
    uint64_t total = 0, available = 0;
    rc = storage_common_fs_info(r->storage, EXT_PATH(""), &total, &available);
    if(rc != FSE_OK || available < r->required_bytes) {
        snprintf(
            detail,
            sizeof(detail),
            "fs=%d free=%llu required=%lu",
            rc,
            available,
            (unsigned long)r->required_bytes);
        r->io->event(r->io->context, "sd_space", TB2_PROBE_IO_ERROR, detail);
        snprintf(r->error, sizeof(r->error), "Not enough free SD space for files and log.");
        return Tb2RecordIo;
    }
    return Tb2RecordOk;
}
