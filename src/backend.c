#include "backend.h"
#include "probe.h"
#include <flipper_application/flipper_application.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TB2_CERT_MODULE
typedef struct {
    Tb2WorkflowIO* io;
    void* file;
} InspectFile;

static bool inspect_read(void* context, uint32_t offset, void* bytes, size_t size) {
    InspectFile* file = context;
    return file->io->seek(file->io->context, file->file, offset) &&
           file->io->read(file->io->context, file->file, bytes, size) == size;
}
static bool inspect_event(void* context, const char* op, int rc, const char* detail) {
    InspectFile* file = context;
    return !file->io->event || file->io->event(file->io->context, op, rc, detail);
}
static bool inspect_cancelled(void* context) {
    InspectFile* file = context;
    return file->io->cancelled && file->io->cancelled(file->io->context);
}
static void inspect_progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    InspectFile* file = context;
    if(file->io->progress) file->io->progress(file->io->context, stage, done, total);
}

static int inspect_settings(Tb2BackendInspect* request) {
    if(!request->read || !request->settings) return TB2_PROBE_CHECK_FAILED;
    InspectFile file = {
        .io = request->io,
        .file = request->io->open(request->io->context, request->source, Tb2FileRead)};
    if(!file.file) return TB2_PROBE_IO_ERROR;
    Tb2Reader reader = {
        .context = &file,
        .image_size = request->io->size(request->io->context, file.file),
        .read = inspect_read,
        .event = inspect_event,
        .cancelled = inspect_cancelled,
        .progress = inspect_progress};
    int rc = tb2_reader_settings_identity(&reader, request->read, request->identity);
    if(!rc) rc = tb2_image_settings_snapshot(&reader, request->read, request->settings);
    if(!request->io->close(request->io->context, file.file)) rc = TB2_PROBE_IO_ERROR;
    return rc;
}

static int inspect(Tb2BackendInspect* request) {
    if(!request || !request->io || !request->source || !request->identity)
        return TB2_PROBE_CHECK_FAILED;
    if(request->action == Tb2BackendInspectIdentity)
        return tb2_identity_file(
            request->io,
            request->source,
            request->artifact_directory,
            request->identity,
            request->reuse_geometry);
    if(request->action == Tb2BackendInspectSettings) return inspect_settings(request);
    return TB2_PROBE_CHECK_FAILED;
}
#endif

#ifdef TB2_CERT_MODULE
typedef struct {
    Tb2WorkflowIO* io;
    const char* read_directory;
    const char* save_directory;
} PackageImportIO;

static bool
    package_import_path(char out[TB2_JOB_PATH_MAX], const char* directory, const char* name) {
    int n = snprintf(out, TB2_JOB_PATH_MAX, "%s/%s", directory, name);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static int package_import_read(
    void* context,
    const char* name,
    void* bytes,
    size_t capacity,
    size_t* size) {
    PackageImportIO* p = context;
    char path[TB2_JOB_PATH_MAX];
    if(!package_import_path(path, p->read_directory, name)) return TB2_PROBE_IO_ERROR;
    int present = p->io->exists(p->io->context, path);
    if(!present) return present < 0 ? TB2_PROBE_IO_ERROR : TB2_PACKAGE_MISSING;
    void* file = p->io->open(p->io->context, path, Tb2FileRead);
    uint64_t length = file ? p->io->size(p->io->context, file) : UINT64_MAX;
    bool ok = length && length <= TB2_PACKAGE_FILE_MAX &&
              (!bytes || (length <= capacity &&
                          p->io->read(p->io->context, file, bytes, (size_t)length) == length));
    if(file) ok = p->io->close(p->io->context, file) && ok;
    if(ok) *size = (size_t)length;
    return ok ? 0 : TB2_PROBE_IO_ERROR;
}
static bool package_import_save(void* context, const char* name, const void* bytes, size_t size) {
    PackageImportIO* p = context;
    char path[TB2_JOB_PATH_MAX];
    if(!package_import_path(path, p->save_directory, name) || !size || size > TB2_PACKAGE_FILE_MAX)
        return false;
    int present = p->io->exists(p->io->context, path);
    if(present < 0) return false;
    void* file = p->io->open(p->io->context, path, present ? Tb2FileUpdate : Tb2FileNew);
    bool ok = file && p->io->write(p->io->context, file, bytes, size) == size &&
              p->io->truncate(p->io->context, file) && p->io->sync(p->io->context, file);
    if(file) ok = p->io->close(p->io->context, file) && ok;
    return ok;
}
static bool package_import_event(void* context, const char* op, int rc, const char* detail) {
    PackageImportIO* p = context;
    return !p->io->event || p->io->event(p->io->context, op, rc, detail);
}
static bool package_import_cancelled(void* context) {
    PackageImportIO* p = context;
    return p->io->cancelled && p->io->cancelled(p->io->context);
}
static void package_import_time(uint32_t timestamp, char out[TB2_DATE_SIZE]) {
    uint32_t days = timestamp / 86400U, seconds = timestamp % 86400U;
    days += 719468U;
    uint32_t era = days / 146097U;
    unsigned doe = days - era * 146097U;
    unsigned yoe = (doe - doe / 1460U + doe / 36524U - doe / 146096U) / 365U;
    unsigned year = yoe + era * 400U;
    unsigned doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
    unsigned mp = (5U * doy + 2U) / 153U;
    unsigned month = mp < 10U ? mp + 3U : mp - 9U;
    year += month <= 2U;
    unsigned values[] = {
        year,
        month,
        doy - (153U * mp + 2U) / 5U + 1U,
        (unsigned)(seconds / 3600U),
        (unsigned)((seconds / 60U) % 60U),
        (unsigned)(seconds % 60U)};
    out[0] = (char)('0' + (values[0] / 1000U) % 10U);
    out[1] = (char)('0' + (values[0] / 100U) % 10U);
    out[2] = (char)('0' + (values[0] / 10U) % 10U);
    out[3] = (char)('0' + values[0] % 10U);
    for(unsigned i = 1; i < sizeof(values) / sizeof(values[0]); i++) {
        out[2U * i + 2U] = (char)('0' + (values[i] / 10U) % 10U);
        out[2U * i + 3U] = (char)('0' + values[i] % 10U);
    }
    out[TB2_DATE_SIZE - 1U] = 0;
}
static int
    package_import_hash(Tb2WorkflowIO* io, const char* path, uint32_t* size, uint8_t digest[32]) {
    void* file = io->open(io->context, path, Tb2FileRead);
    uint64_t length = file ? io->size(io->context, file) : UINT64_MAX;
    uint8_t* bytes = file && length && length <= TB2_PACKAGE_FILE_MAX ? malloc(512) : NULL;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    int rc = !bytes || mbedtls_sha256_starts(&sha, 0) ? TB2_PROBE_IO_ERROR : 0;
    for(uint32_t offset = 0; !rc && offset < length;) {
        size_t count = (size_t)(length - offset);
        if(count > 512U) count = 512U;
        if(io->read(io->context, file, bytes, count) != count ||
           mbedtls_sha256_update(&sha, bytes, count))
            rc = TB2_PROBE_IO_ERROR;
        offset += (uint32_t)count;
    }
    if(!rc && mbedtls_sha256_finish(&sha, digest)) rc = TB2_PROBE_IO_ERROR;
    if(file && !io->close(io->context, file)) rc = TB2_PROBE_IO_ERROR;
    mbedtls_sha256_free(&sha);
    if(bytes) {
        memset(bytes, 0, 512U);
        free(bytes);
    }
    if(!rc) *size = (uint32_t)length;
    return rc;
}
static int package_import(
    Tb2WorkflowIO* io,
    const char* read_directory,
    const char* save_directory,
    uint32_t timestamp,
    Tb2PackageImportResult* result) {
    if(!io || !read_directory || !save_directory || !result) return TB2_PROBE_CHECK_FAILED;
    memset(result, 0, sizeof(*result));
    PackageImportIO adapter = {
        .io = io, .read_directory = read_directory, .save_directory = save_directory};
    Tb2PackageIO package_io = {
        .context = &adapter,
        .read = package_import_read,
        .save = package_import_save,
        .event = package_import_event,
        .cancelled = package_import_cancelled};
    Tb2PackageOptions options = {
        .https_host = "historical.invalid", .ici_host = "historical.invalid"};
    package_import_time(timestamp, options.now);
    snprintf(options.expires, sizeof(options.expires), "20991231235959");
    int rc = tb2_package_inspect(&package_io, &options, true, &result->package);
    for(unsigned i = 0; !rc && i < TB2_PACKAGE_IMPORT_FILES; i++) {
        char path[TB2_JOB_PATH_MAX];
        const char* root = i < TB2_PACKAGE_FILES ? read_directory : save_directory;
        const char* name = i < TB2_PACKAGE_FILES ? tb2_package_names[i] : "ca.der";
        if(!package_import_path(path, root, name))
            rc = TB2_PROBE_CHECK_FAILED;
        else
            rc = package_import_hash(io, path, &result->size[i], result->sha256[i]);
    }
    return rc;
}
#endif

static const Tb2Backend backend = {
    .run = tb2_workflow_run,
    .combined = tb2_workflow_run_patch,
#ifndef TB2_CERT_MODULE
#endif
    .crypto_peak = tb2_probe_crypto_peak,
#ifndef TB2_CERT_MODULE
    .restore = tb2_restore_run,
    .inspect = inspect,
#else
    .package_import = package_import,
#endif
};
static const FlipperAppPluginDescriptor descriptor = {
#ifdef TB2_CERT_MODULE
    .appid = TB2_CERT_ID,
#else
    .appid = TB2_BACKEND_ID,
#endif
    .ep_api_version = TB2_BACKEND_API,
    .entry_point = &backend,
};

const FlipperAppPluginDescriptor* tb2_backend_entry(void) {
    return &descriptor;
}
