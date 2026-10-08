#include "archive.h"
#include "probe.h"
#include "tb2_config_select.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAR_BLOCK 512U
#define TAR_FILES (TB2_PACKAGE_FILES + 1U)
static const char* const names[TAR_FILES] = {
    "ca-root.pem",
    "ca-key.pem",
    "teddy-cert.pem",
    "teddy-key.pem",
    "ici.pem",
    "ici.key",
    "ca.der"};
typedef struct {
    Tb2ArchiveRequest* request;
    void* output;
    mbedtls_sha256_context hash;
    uint8_t bytes[TB2_PACKAGE_FILE_MAX];
    uint8_t input_hash[TAR_FILES][32];
    uint32_t size;
} Archive;

bool tb2_archive_path(const char* image, char output[TB2_JOB_PATH_MAX]) {
    size_t size = strlen(image);
    if(size < 5 || size >= TB2_JOB_PATH_MAX || strcmp(image + size - 4, ".bin")) return false;
    memcpy(output, image, size + 1);
    memcpy(output + size - 4, ".tar", 5);
    return true;
}
int tb2_archive_image_lease(
    Tb2WorkflowIO* io,
    const char* path,
    const uint8_t expected[32],
    void** lease) {
    if(!io || !path || !expected || !lease) return TB2_PROBE_CHECK_FAILED;
    bool held = *lease != NULL;
    if(!held) *lease = io->open(io->context, path, Tb2FileRead);
    int rc = *lease && io->size(io->context, *lease) == TB2_IMAGE_SIZE &&
                     io->seek(io->context, *lease, 0) ?
                 0 :
                 TB2_PROBE_IO_ERROR;
    if(!rc && !held) {
        uint8_t* bytes = malloc(TB2_LFS_BLOCK_SIZE);
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        rc = bytes ? mbedtls_sha256_starts(&sha, 0) : TB2_PROBE_IO_ERROR;
        for(uint32_t offset = 0; !rc && offset < TB2_IMAGE_SIZE; offset += TB2_LFS_BLOCK_SIZE) {
            io->progress(io->context, "Checking saved image", offset, TB2_IMAGE_SIZE);
            if(io->cancelled(io->context)) rc = TB2_PROBE_CANCELLED;
            if(!rc &&
               io->read(io->context, *lease, bytes, TB2_LFS_BLOCK_SIZE) != TB2_LFS_BLOCK_SIZE)
                rc = TB2_PROBE_IO_ERROR;
            if(!rc) rc = mbedtls_sha256_update(&sha, bytes, TB2_LFS_BLOCK_SIZE);
        }
        uint8_t actual[32];
        if(!rc) rc = mbedtls_sha256_finish(&sha, actual);
        if(!rc && memcmp(actual, expected, 32)) rc = TB2_PROBE_CHECK_FAILED;
        mbedtls_sha256_free(&sha);
        free(bytes);
        if(!rc && !io->seek(io->context, *lease, 0)) rc = TB2_PROBE_IO_ERROR;
    }
    if(rc && *lease) {
        io->close(io->context, *lease);
        *lease = NULL;
    }
    return rc;
}
static bool stopped(Archive* a) {
    return a->request->io->cancelled(a->request->io->context);
}
static int read_member(Archive* a, unsigned index, size_t* size, uint8_t digest[32]) {
    Tb2WorkflowIO* io = a->request->io;
    char path[TB2_JOB_PATH_MAX + 32];
    int length = snprintf(path, sizeof(path), "%s/%s", a->request->package_dir, names[index]);
    if(length < 0 || length >= (int)sizeof(path)) return TB2_PROBE_CHECK_FAILED;
    void* file = io->open(io->context, path, Tb2FileRead);
    uint64_t count = file ? io->size(io->context, file) : 0;
    bool ok = count && count <= sizeof(a->bytes) &&
              io->read(io->context, file, a->bytes, (size_t)count) == count;
    if(file) ok = io->close(io->context, file) && ok;
    if(!ok) return TB2_PROBE_IO_ERROR;
    *size = (size_t)count;
    return mbedtls_sha256(a->bytes, *size, digest, 0);
}
static int bind_inputs(Archive* a) {
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    for(unsigned i = 0; !rc && i < TAR_FILES; i++) {
        size_t size = 0;
        rc = stopped(a) ? TB2_PROBE_CANCELLED : read_member(a, i, &size, a->input_hash[i]);
        if(rc || i == TB2_PACKAGE_FILES) continue;
        uint8_t frame[5] = {
            (uint8_t)i,
            (uint8_t)size,
            (uint8_t)(size >> 8),
            (uint8_t)(size >> 16),
            (uint8_t)(size >> 24)};
        rc = mbedtls_sha256_update(&hash, frame, sizeof(frame));
        if(!rc) rc = mbedtls_sha256_update(&hash, a->bytes, size);
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&hash, digest);
    if(!rc && (memcmp(digest, a->request->package_hash, 32) ||
               memcmp(a->input_hash[TB2_PACKAGE_FILES], a->request->ca_hash, 32)))
        rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_sha256_free(&hash);
    return rc;
}
static bool write_bytes(Archive* a, const void* bytes, size_t count) {
    Tb2WorkflowIO* io = a->request->io;
    if(stopped(a) || io->write(io->context, a->output, bytes, count) != count ||
       mbedtls_sha256_update(&a->hash, bytes, count))
        return false;
    a->size += (uint32_t)count;
    return true;
}
static bool write_header(Archive* a, unsigned index, size_t size) {
    uint8_t header[TAR_BLOCK] = {0};
    memcpy(header, names[index], strlen(names[index]));
    memcpy(header + 100, "0000600", 7);
    memcpy(header + 108, "0000000", 7);
    memcpy(header + 116, "0000000", 7);
    snprintf((char*)header + 124, 12, "%011lo", (unsigned long)size);
    memcpy(header + 136, "00000000000", 11);
    memset(header + 148, ' ', 8);
    header[156] = '0';
    memcpy(header + 257, "ustar", 5);
    memcpy(header + 263, "00", 2);
    unsigned sum = 0;
    for(unsigned i = 0; i < sizeof(header); i++)
        sum += header[i];
    snprintf((char*)header + 148, 7, "%06o", sum);
    header[155] = ' ';
    return write_bytes(a, header, sizeof(header));
}
static int write_members(Archive* a) {
    const uint8_t padding[TAR_BLOCK] = {0};
    int rc = mbedtls_sha256_starts(&a->hash, 0);
    for(unsigned i = 0; !rc && i < TAR_FILES; i++) {
        size_t size = 0;
        uint8_t digest[32];
        rc = read_member(a, i, &size, digest);
        if(!rc && memcmp(digest, a->input_hash[i], 32)) rc = TB2_PROBE_CHECK_FAILED;
        if(!rc && (!write_header(a, i, size) || !write_bytes(a, a->bytes, size)))
            rc = TB2_PROBE_IO_ERROR;
        size_t pad = size % TAR_BLOCK ? TAR_BLOCK - size % TAR_BLOCK : 0;
        if(!rc && pad && !write_bytes(a, padding, pad)) rc = TB2_PROBE_IO_ERROR;
        a->request->io->progress(a->request->io->context, "Exporting TAR", i + 1, TAR_FILES);
    }
    if(!rc &&
       (!write_bytes(a, padding, sizeof(padding)) || !write_bytes(a, padding, sizeof(padding))))
        rc = TB2_PROBE_IO_ERROR;
    return rc;
}
static int verify(Archive* a, const char* path, const uint8_t expected[32]) {
    Tb2WorkflowIO* io = a->request->io;
    void* file = io->open(io->context, path, Tb2FileRead);
    int rc = file && io->size(io->context, file) == a->size ? 0 : TB2_PROBE_IO_ERROR;
    if(!rc) rc = mbedtls_sha256_starts(&a->hash, 0);
    for(uint32_t offset = 0; !rc && offset < a->size;) {
        size_t size = a->size - offset;
        if(size > sizeof(a->bytes)) size = sizeof(a->bytes);
        if(stopped(a)) rc = TB2_PROBE_CANCELLED;
        if(!rc && io->read(io->context, file, a->bytes, size) != size) rc = TB2_PROBE_IO_ERROR;
        if(!rc) rc = mbedtls_sha256_update(&a->hash, a->bytes, size);
        offset += (uint32_t)size;
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&a->hash, digest);
    if(!rc && memcmp(digest, expected, 32)) rc = TB2_PROBE_CHECK_FAILED;
    if(file && !io->close(io->context, file)) rc = TB2_PROBE_IO_ERROR;
    return rc;
}
int tb2_archive_run(Tb2ArchiveRequest* r) {
    char path[TB2_JOB_PATH_MAX];
    r->error[0] = 0;
    if(!r->io || !r->receipt || !r->package_hash || !r->ca_hash || !r->checkpoint ||
       !tb2_archive_path(r->image_path, path))
        return TB2_PROBE_CHECK_FAILED;
    Archive* a = calloc(1, sizeof(*a));
    if(!a) return TB2_PROBE_IO_ERROR;
    a->request = r;
    mbedtls_sha256_init(&a->hash);
    int rc = bind_inputs(a);
    int exists = rc ? -1 : r->io->exists(r->io->context, path);
    if(!rc && (exists < 0 || (exists && !(r->receipt->flags & TB2_ARCHIVE_OWNED)))) {
        snprintf(
            r->error,
            sizeof(r->error),
            "Archive exists or SD lookup failed. Select a new image name.");
        rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc) {
        a->output = r->io->open(r->io->context, path, exists ? Tb2FileUpdate : Tb2FileNew);
        if(!a->output) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc) {
        r->receipt->flags = TB2_ARCHIVE_OWNED;
        if(!r->checkpoint(r->context, r->receipt)) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc &&
       (!r->io->seek(r->io->context, a->output, 0) || !r->io->truncate(r->io->context, a->output)))
        rc = TB2_PROBE_IO_ERROR;
    if(!rc) rc = write_members(a);
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&a->hash, digest);
    if(a->output) {
        if(!r->io->sync(r->io->context, a->output)) rc = TB2_PROBE_IO_ERROR;
        if(!r->io->close(r->io->context, a->output)) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc) rc = verify(a, path, digest);
    if(!rc) {
        memcpy(r->receipt->digest, digest, 32);
        r->receipt->flags |= TB2_ARCHIVE_VERIFIED;
        if(!r->checkpoint(r->context, r->receipt)) rc = TB2_PROBE_IO_ERROR;
    }
    if(stopped(a)) rc = TB2_PROBE_CANCELLED;
    if(rc && !r->error[0])
        snprintf(
            r->error,
            sizeof(r->error),
            "Archive export incomplete. Image retained; retry export.");
    if(rc) r->receipt->flags &= ~TB2_ARCHIVE_VERIFIED;
    mbedtls_sha256_free(&a->hash);
    memset(a, 0, sizeof(*a));
    free(a);
    return rc;
}
