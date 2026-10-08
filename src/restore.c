#include "restore.h"
#include "probe.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESTORE_FILES 3U
static const char* const names[RESTORE_FILES] = {"ca.der", "client.der", "private.der"};
typedef struct {
    Tb2RestoreRequest* request;
    void* donor;
    void* source;
    void* target;
    void* active;
    bool extracting, failed;
    uint32_t sizes[RESTORE_FILES];
    uint8_t hashes[RESTORE_FILES][32];
    Tb2ServerRecords connection;
} Restore;

static bool event(void* context, const char* operation, int code, const char* detail) {
    Restore* r = context;
    Tb2WorkflowIO* io = r->request->io;
    if(!io->event(io->context, operation, code, detail)) r->failed = true;
    return !r->failed;
}
static bool cancelled(void* context) {
    Restore* r = context;
    return r->failed || r->request->io->cancelled(r->request->io->context);
}
static void progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    Restore* r = context;
    r->request->io->progress(r->request->io->context, stage, done, total);
}
static int random_bytes(void* context, unsigned char* bytes, size_t size) {
    Restore* r = context;
    return r->request->io->random(r->request->io->context, bytes, size);
}
static bool source_read(void* context, uint32_t offset, void* bytes, size_t size) {
    Restore* r = context;
    Tb2WorkflowIO* io = r->request->io;
    return !cancelled(r) && offset <= TB2_IMAGE_SIZE && size <= TB2_IMAGE_SIZE - offset &&
           io->seek(io->context, r->active, offset) &&
           io->read(io->context, r->active, bytes, size) == size;
}
static bool plain_path(Restore* r, unsigned index, char path[TB2_JOB_PATH_MAX]) {
    int n = snprintf(
        path, TB2_JOB_PATH_MAX, "%s/restore-plain/%s", r->request->directory, names[index]);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static bool
    donor_read(void* context, unsigned index, uint8_t* bytes, size_t capacity, size_t* size) {
    Restore* r = context;
    Tb2WorkflowIO* io = r->request->io;
    char path[TB2_JOB_PATH_MAX];
    if(index >= RESTORE_FILES || !r->sizes[index] || r->sizes[index] > capacity || cancelled(r) ||
       !plain_path(r, index, path))
        return false;
    void* file = io->open(io->context, path, Tb2FileRead);
    uint8_t hash[32];
    bool ok = file && io->size(io->context, file) == r->sizes[index] &&
              io->read(io->context, file, bytes, r->sizes[index]) == r->sizes[index] &&
              !mbedtls_sha256(bytes, r->sizes[index], hash, 0) &&
              !memcmp(hash, r->hashes[index], sizeof(hash));
    if(file) ok = io->close(io->context, file) && ok;
    if(ok) *size = r->sizes[index];
    return ok;
}
static bool backup(void* context, const char* name, const void* bytes, size_t size) {
    Restore* r = context;
    if(!r->extracting) return true; /* Complete encrypted input is already archived. */
    unsigned index;
    for(index = 0; index < RESTORE_FILES; index++) {
        char relative[32];
        snprintf(relative, sizeof(relative), "client/%s", names[index]);
        if(!strcmp(relative, name)) break;
    }
    if(index == RESTORE_FILES) return true;
    Tb2WorkflowIO* io = r->request->io;
    char path[TB2_JOB_PATH_MAX];
    if(!size || size > TB2_PLAIN_MAX || !plain_path(r, index, path)) return false;
    int exists = io->exists(io->context, path);
    if(exists < 0) return false;
    void* file = io->open(io->context, path, exists ? Tb2FileUpdate : Tb2FileNew);
    bool ok = file && io->write(io->context, file, bytes, size) == size &&
              io->truncate(io->context, file) && io->sync(io->context, file);
    if(file) ok = io->close(io->context, file) && ok;
    r->sizes[index] = (uint32_t)size;
    if(mbedtls_sha256(bytes, size, r->hashes[index], 0)) ok = false;
    uint8_t* check = ok ? malloc(size) : NULL;
    size_t checked;
    ok = check && donor_read(r, index, check, size, &checked) && checked == size;
    if(check) {
        mbedtls_platform_zeroize(check, size);
        free(check);
    }
    return ok;
}
static bool target_reset(void* context) {
    Restore* r = context;
    Tb2WorkflowIO* io = r->request->io;
    if(cancelled(r) || !r->request->build) return false;
    return io->seek(io->context, r->target, 0) && io->truncate(io->context, r->target);
}
static bool target_transfer(Restore* r, bool write, uint32_t offset, void* bytes, size_t size) {
    Tb2WorkflowIO* io = r->request->io;
    if(cancelled(r) || offset > TB2_IMAGE_SIZE || size > TB2_IMAGE_SIZE - offset ||
       !io->seek(io->context, r->target, offset))
        return false;
    return (write ? io->write(io->context, r->target, bytes, size) :
                    io->read(io->context, r->target, bytes, size)) == size;
}
static bool target_read(void* context, uint32_t offset, void* bytes, size_t size) {
    return target_transfer(context, false, offset, bytes, size);
}
static bool target_write(void* context, uint32_t offset, const void* bytes, size_t size) {
    Restore* r = context;
    return r->request->build && target_transfer(r, true, offset, (void*)bytes, size);
}
static bool target_sync(void* context) {
    Restore* r = context;
    return r->request->io->sync(r->request->io->context, r->target);
}
static uint64_t target_size(void* context) {
    Restore* r = context;
    return r->request->io->size(r->request->io->context, r->target);
}
static bool close_file(Restore* r, void** file) {
    if(!*file) return true;
    bool ok = r->request->io->close(r->request->io->context, *file);
    *file = NULL;
    return ok;
}
int tb2_restore_run(Tb2RestoreRequest* request) {
    if(!request || !request->io || !request->donor || !request->source || !request->target ||
       !request->directory || !request->donor_key || !request->target_key ||
       !request->donor_hash || !request->source_hash ||
       !strcmp(request->target, request->source) || !strcmp(request->target, request->donor))
        return TB2_PROBE_CHECK_FAILED;
    request->error[0] = 0;
    memset(&request->donor_read, 0, sizeof(request->donor_read));
    memset(&request->source_read, 0, sizeof(request->source_read));
    memset(&request->image, 0, sizeof(request->image));
    Restore* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    r->request = request;
    Tb2WorkflowIO* io = request->io;
    char path[TB2_JOB_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/restore-plain", request->directory);
    int rc = n > 0 && n < (int)sizeof(path) && io->mkdir(io->context, path) ? 0 :
                                                                              TB2_PROBE_IO_ERROR;
    Tb2Reader reader = {
        .context = r,
        .image_size = TB2_IMAGE_SIZE,
        .read = source_read,
        .event = event,
        .cancelled = cancelled,
        .progress = progress,
        .backup = backup,
        .random = random_bytes};
    if(!rc) {
        r->donor = io->open(io->context, request->donor, Tb2FileRead);
        r->source = io->open(io->context, request->source, Tb2FileRead);
        if(!r->donor || !r->source || io->size(io->context, r->donor) != TB2_IMAGE_SIZE ||
           io->size(io->context, r->source) != TB2_IMAGE_SIZE)
            rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc) {
        r->active = r->donor;
        r->extracting = true;
        rc = tb2_reader_restore_source(
            &reader,
            request->donor_key,
            &request->donor_read,
            request->connection ? &r->connection : NULL);
        if(!rc && memcmp(request->donor_hash, request->donor_read.source_sha256, 32))
            rc = TB2_PROBE_CHECK_FAILED;
    }
    if(!rc) {
        r->active = r->source;
        r->extracting = false;
        rc = tb2_reader_run_key(&reader, request->target_key, &request->source_read);
        if(!rc && memcmp(request->source_hash, request->source_read.source_sha256, 32))
            rc = TB2_PROBE_CHECK_FAILED;
    }
    if(!rc && !request->check_only) {
        int exists = io->exists(io->context, request->target);
        r->target = exists < 0 ? NULL :
                                 io->open(
                                     io->context,
                                     request->target,
                                     !request->build ? Tb2FileRead :
                                     exists          ? Tb2FileUpdate :
                                                       Tb2FileNew);
        if(!r->target) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc && !request->check_only) {
        Tb2ImageTarget target = {
            .context = r,
            .reset = target_reset,
            .read = target_read,
            .write = target_write,
            .sync = target_sync,
            .size = target_size};
        Tb2CertificateRestore restore = {
            .context = r,
            .read = donor_read,
            .connection = request->connection ? &r->connection : NULL};
        rc = tb2_image_restore(
            &reader,
            &target,
            request->target_key,
            &request->source_read,
            &restore,
            &request->image,
            request->build);
    }
    if(!close_file(r, &r->donor)) rc = TB2_PROBE_IO_ERROR;
    if(!close_file(r, &r->source)) rc = TB2_PROBE_IO_ERROR;
    if(!rc && io->image_lease && !*io->image_lease) {
        *io->image_lease = r->target;
        r->target = NULL;
    }
    if(!close_file(r, &r->target)) rc = TB2_PROBE_IO_ERROR;
    if(r->failed) rc = TB2_PROBE_IO_ERROR;
    if(rc)
        snprintf(
            request->error,
            sizeof(request->error),
            "%s",
            request->image.error[0] ?
                request->image.error :
            request->source_read.error[0] ?
                request->source_read.error :
            request->donor_read.error[0] ?
                request->donor_read.error :
                "Restore binding or SD check failed. Inputs retained; retry.");
    mbedtls_platform_zeroize(r, sizeof(*r));
    free(r);
    return rc;
}
