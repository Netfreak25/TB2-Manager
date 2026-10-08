#include "records.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static Tb2RecordResult
    transfer(Tb2WorkflowIO* io, void* source, void* target, uint32_t size, uint8_t digest[32]) {
    uint8_t* bytes = malloc(TB2_RECORD_CHUNK);
    if(!bytes) return Tb2RecordIo;
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    Tb2RecordResult rc = mbedtls_sha256_starts(&hash, 0) ? Tb2RecordIo : Tb2RecordOk;
    for(uint32_t offset = 0; !rc && offset < size;) {
        if(io->cancelled && io->cancelled(io->context)) {
            rc = Tb2RecordCancelled;
            break;
        }
        size_t count = size - offset;
        if(count > TB2_RECORD_CHUNK) count = TB2_RECORD_CHUNK;
        if(io->read(io->context, source, bytes, count) != count ||
           (target && io->write(io->context, target, bytes, count) != count) ||
           mbedtls_sha256_update(&hash, bytes, count)) {
            rc = Tb2RecordIo;
            break;
        }
        offset += (uint32_t)count;
        if(io->progress)
            io->progress(io->context, target ? "Archive image" : "Check archive", offset, size);
    }
    if(!rc && mbedtls_sha256_finish(&hash, digest)) rc = Tb2RecordIo;
    mbedtls_sha256_free(&hash);
    memset(bytes, 0, TB2_RECORD_CHUNK);
    free(bytes);
    return rc;
}
static Tb2RecordResult verify_path(Tb2WorkflowIO* io, const char* path, const Tb2ObjectRef* ref) {
    void* file = io->open(io->context, path, Tb2FileRead);
    if(!file) return Tb2RecordIo;
    uint8_t digest[32];
    Tb2RecordResult rc = io->size(io->context, file) == ref->size ?
                             transfer(io, file, NULL, ref->size, digest) :
                             Tb2RecordCorrupt;
    if(!io->close(io->context, file)) rc = Tb2RecordIo;
    if(!rc && memcmp(digest, ref->digest, sizeof(digest))) rc = Tb2RecordCorrupt;
    return rc;
}
Tb2RecordResult tb2_object_verify(Tb2WorkflowIO* io, const Tb2ObjectRef* ref) {
    char path[TB2_JOB_PATH_MAX];
    return tb2_object_path(path, ref) ? verify_path(io, path, ref) : Tb2RecordCorrupt;
}
Tb2RecordResult tb2_file_inspect(
    Tb2WorkflowIO* io,
    const char* path,
    uint32_t expected_size,
    Tb2ObjectRef* ref) {
    memset(ref, 0, sizeof(*ref));
    void* file = io->open(io->context, path, Tb2FileRead);
    if(!file) return Tb2RecordIo;
    Tb2RecordResult rc = io->size(io->context, file) == expected_size ?
                             transfer(io, file, NULL, expected_size, ref->digest) :
                             Tb2RecordCorrupt;
    if(!io->close(io->context, file)) rc = Tb2RecordIo;
    if(!rc) ref->size = expected_size;
    return rc;
}
Tb2RecordResult tb2_object_materialize(
    Tb2WorkflowIO* io,
    const Tb2ObjectRef* ref,
    const char* staging,
    const char* target) {
    int present = io->exists(io->context, target);
    if(present) return present < 0 ? Tb2RecordIo : verify_path(io, target, ref);
    char source[TB2_JOB_PATH_MAX], temp[TB2_JOB_PATH_MAX], id[TB2_RECORD_ID_SIZE];
    if(!tb2_object_path(source, ref) || !tb2_record_new_id(io, id)) return Tb2RecordIo;
    int n = snprintf(temp, sizeof(temp), "%s/copy-%s.part", staging, id);
    if(n <= 0 || n >= (int)sizeof(temp)) return Tb2RecordCorrupt;
    void* input = io->open(io->context, source, Tb2FileRead);
    Tb2RecordResult rc = input && io->size(io->context, input) == ref->size ? Tb2RecordOk :
                                                                              Tb2RecordIo;
    void* output = !rc ? io->open(io->context, temp, Tb2FileNew) : NULL;
    if(!output) rc = Tb2RecordIo;
    uint8_t digest[32];
    if(!rc) rc = transfer(io, input, output, ref->size, digest);
    if(input && !io->close(io->context, input)) rc = Tb2RecordIo;
    if(output) {
        bool sync = io->sync(io->context, output);
        bool closed = io->close(io->context, output);
        if(!sync || !closed) rc = Tb2RecordIo;
    }
    if(!rc && memcmp(digest, ref->digest, sizeof(digest))) rc = Tb2RecordConflict;
    if(!rc) rc = verify_path(io, temp, ref);
    if(!rc && !io->move_new(io->context, temp, target)) rc = Tb2RecordIo;
    if(!rc) rc = verify_path(io, target, ref);
    if(output && io->exists(io->context, temp) == 1 && !io->remove(io->context, temp) && !rc)
        rc = Tb2RecordIo;
    return rc;
}
Tb2RecordResult tb2_object_put(
    Tb2WorkflowIO* io,
    const char* source,
    const char* staging,
    const Tb2ObjectRef* expected,
    Tb2ObjectRef* result) {
    memset(result, 0, sizeof(*result));
    if(!io->move_new) return Tb2RecordIo;
    char temp[TB2_JOB_PATH_MAX], path[TB2_JOB_PATH_MAX], id[TB2_RECORD_ID_SIZE];
    if(!tb2_record_new_id(io, id)) return Tb2RecordIo;
    int n = snprintf(temp, sizeof(temp), "%s/object-%s.part", staging, id);
    if(n <= 0 || n >= (int)sizeof(temp)) return Tb2RecordCorrupt;
    void* input = io->open(io->context, source, Tb2FileRead);
    if(!input) return Tb2RecordIo;
    uint64_t size = io->size(io->context, input);
    if(!size || size > TB2_IMAGE_SIZE || (expected && expected->size != size)) {
        io->close(io->context, input);
        return Tb2RecordCorrupt;
    }
    void* output = io->open(io->context, temp, Tb2FileNew);
    Tb2ObjectRef ref = {.size = (uint32_t)size};
    Tb2RecordResult rc = output ? transfer(io, input, output, ref.size, ref.digest) : Tb2RecordIo;
    if(!io->close(io->context, input)) rc = Tb2RecordIo;
    if(output) {
        bool synced = io->sync(io->context, output);
        bool closed = io->close(io->context, output);
        if(!synced || !closed) rc = Tb2RecordIo;
    }
    if(!rc && expected && memcmp(expected->digest, ref.digest, 32)) rc = Tb2RecordConflict;
    if(!rc) rc = verify_path(io, temp, &ref);
    if(!rc && !tb2_object_path(path, &ref)) rc = Tb2RecordCorrupt;
    if(!rc) {
        char* slash = strrchr(path, '/');
        *slash = 0;
        bool made = io->mkdir(io->context, TB2_OBJECTS_ROOT) && io->mkdir(io->context, path);
        *slash = '/';
        if(!made) rc = Tb2RecordIo;
    }
    if(!rc) {
        int present = io->exists(io->context, path);
        if(present < 0)
            rc = Tb2RecordIo;
        else if(present)
            rc = verify_path(io, path, &ref);
        else if(!io->move_new(io->context, temp, path))
            rc = Tb2RecordIo;
        else
            rc = verify_path(io, path, &ref);
    }
    /* Only this call's exclusively created temporary file is eligible. */
    if(output && io->exists(io->context, temp) == 1 && !io->remove(io->context, temp) && !rc)
        rc = Tb2RecordIo;
    if(!rc) *result = ref;
    return rc;
}
