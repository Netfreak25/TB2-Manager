#include "native_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    File* file;
} NativeFile;
static bool io_result(Tb2NativeIO* n, const char* operation, NativeFile* f, bool ok) {
    if(ok) return true;
    n->event(n->context, operation, -1, storage_file_get_error_desc(f->file));
    return false;
}
static void* file_open(void* context, const char* path, Tb2FileMode mode) {
    Tb2NativeIO* n = context;
    NativeFile* f = calloc(1, sizeof(*f));
    if(!f) return NULL;
    f->file = storage_file_alloc(n->storage);
    bool ok = storage_file_open(
        f->file,
        path,
        mode == Tb2FileRead ? FSAM_READ : FSAM_READ_WRITE,
        mode == Tb2FileNew ? FSOM_CREATE_NEW : FSOM_OPEN_EXISTING);
    if(!io_result(n, "sd_open", f, ok)) {
        if(ok) storage_file_close(f->file);
        storage_file_free(f->file);
        free(f);
        return NULL;
    }
    return f;
}
static bool file_close(void* context, void* handle) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    bool ok = storage_file_close(f->file);
    ok = io_result(n, "sd_close", f, ok);
    storage_file_free(f->file);
    free(f);
    return ok;
}
static size_t file_read(void* context, void* handle, void* data, size_t size) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    size_t actual = storage_file_read(f->file, data, size);
    return io_result(n, "sd_read", f, actual == size) ? actual : 0;
}
static size_t file_write(void* context, void* handle, const void* data, size_t size) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    size_t actual = storage_file_write(f->file, data, size);
    return io_result(n, "sd_write", f, actual == size) ? actual : 0;
}
static bool file_seek(void* context, void* handle, uint32_t offset) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    bool ok = storage_file_seek(f->file, offset, true);
    return io_result(n, "sd_seek", f, ok);
}
static uint64_t file_size(void* context, void* handle) {
    (void)context;
    return storage_file_size(((NativeFile*)handle)->file);
}
static bool file_sync(void* context, void* handle) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    return io_result(n, "sd_sync", f, storage_file_sync(f->file));
}
static bool file_truncate(void* context, void* handle) {
    Tb2NativeIO* n = context;
    NativeFile* f = handle;
    return io_result(n, "sd_truncate", f, storage_file_truncate(f->file));
}
static int file_exists(void* context, const char* path) {
    Tb2NativeIO* n = context;
    FileInfo info;
    FS_Error rc = storage_common_stat(n->storage, path, &info);
    if(rc == FSE_NOT_EXIST) return 0;
    if(rc != FSE_OK) {
        n->event(n->context, "sd_stat", rc, "metadata read failed");
        return -1;
    }
    return 1;
}
static bool directory(void* context, const char* path) {
    Tb2NativeIO* n = context;
    FS_Error rc = storage_common_mkdir(n->storage, path);
    return n->event(n->context, "sd_mkdir", rc, path) && (rc == FSE_OK || rc == FSE_EXIST);
}
static bool file_remove(void* context, const char* path) {
    Tb2NativeIO* n = context;
    FS_Error rc = storage_common_remove(n->storage, path);
    return n->event(n->context, "sd_remove_partial", rc, path) && rc == FSE_OK;
}
static void* directory_open(void* context, const char* path) {
    Tb2NativeIO* n = context;
    File* file = storage_file_alloc(n->storage);
    if(!storage_dir_open(file, path)) {
        storage_dir_close(file);
        storage_file_free(file);
        return NULL;
    }
    return file;
}
static int
    directory_read(void* context, void* directory, char* name, size_t capacity, bool* is_dir) {
    (void)context;
    if(!capacity || capacity > UINT16_MAX) return -1;
    FileInfo info;
    if(storage_dir_read(directory, &info, name, (uint16_t)capacity)) {
        *is_dir = file_info_is_dir(&info);
        return 1;
    }
    return storage_file_get_error(directory) == FSE_NOT_EXIST ? 0 : -1;
}
static bool directory_close(void* context, void* directory) {
    (void)context;
    bool ok = storage_dir_close(directory);
    storage_file_free(directory);
    return ok;
}
static bool move_new(void* context, const char* source, const char* target) {
    Tb2NativeIO* n = context;
    if(file_exists(context, target) != 0) return false;
    FS_Error rc = storage_common_rename(n->storage, source, target);
    return n->event(n->context, "sd_publish", rc, "path withheld") && rc == FSE_OK;
}
static bool event(void* context, const char* op, int rc, const char* detail) {
    Tb2NativeIO* n = context;
    return n->event(n->context, op, rc, detail);
}
static bool cancelled(void* context) {
    Tb2NativeIO* n = context;
    return n->cancelled(n->context);
}
static void progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    Tb2NativeIO* n = context;
    n->progress(n->context, stage, done, total);
}
static int random_bytes(void* context, unsigned char* bytes, size_t size) {
    Tb2NativeIO* n = context;
    return n->random(n->context, bytes, size);
}
Tb2WorkflowIO tb2_native_io(Tb2NativeIO* n) {
    Tb2WorkflowIO io = {
        .context = n,
        .open = file_open,
        .close = file_close,
        .read = file_read,
        .write = file_write,
        .seek = file_seek,
        .size = file_size,
        .sync = file_sync,
        .truncate = file_truncate,
        .exists = file_exists,
        .mkdir = directory,
        .remove = file_remove,
        .event = event,
        .cancelled = cancelled,
        .progress = progress,
        .random = random_bytes,
        .dir_open = directory_open,
        .dir_read = directory_read,
        .dir_close = directory_close,
        .move_new = move_new};
    return io;
}
