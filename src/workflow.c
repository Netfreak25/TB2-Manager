#include "workflow.h"
#include "probe.h"
#include "tb2_config_select.h"
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JOB_FILE        "job.tb2"
#define JOURNAL_FILE    "status.bin"
#define JOB_HEADER_SIZE 12U
#define JOB_MAX_RECORDS 4096U
#define FULL_PATH_MAX   (TB2_JOB_PATH_MAX + TB2_JOB_NAME_MAX)
#ifdef TB2_CERT_MODULE
#define WORKFLOW_SOURCE false
#define WORKFLOW_CERT   true
#define WORKFLOW_IMAGE  false
#elif defined(TB2_CORE_MODULE)
#define WORKFLOW_SOURCE true
#define WORKFLOW_CERT   false
#define WORKFLOW_IMAGE  true
#else
/* Host reference also runs the complete pipeline in one process. */
#define WORKFLOW_SOURCE true
#define WORKFLOW_CERT   true
#define WORKFLOW_IMAGE  true
#endif
typedef struct {
    Tb2WorkflowIO* io;
    const char* directory;
    const Tb2JobSpec* spec;
    const Tb2SettingsPatch* patch;
    Tb2WorkflowResult* result;
    void* journal;
    void* source;
    void* image;
    uint32_t sequence;
    bool io_failed, read_done, import_done, package_done, image_done, image_started, cancelled;
    char image_path[TB2_JOB_PATH_MAX];
    uint8_t package_hash[32], image_hash[32];
} Workflow;

static bool settings_patch_access(Workflow*, Tb2SettingsPatch*, bool create, bool remove);

static bool path(char out[FULL_PATH_MAX], const char* directory, const char* name) {
    if(!tb2_job_relative_path(name)) return false;
    int n = snprintf(out, FULL_PATH_MAX, "%s/%s", directory, name);
    return n > 0 && n < (int)FULL_PATH_MAX;
}
static bool event(void* context, const char* operation, int rc, const char* detail) {
    Workflow* w = context;
    if(!w->io->event(w->io->context, operation, rc, detail)) w->io_failed = true;
    return !w->io_failed;
}
static bool cancelled(void* context) {
    Workflow* w = context;
    return w->io_failed || w->io->cancelled(w->io->context);
}
static int random_bytes(void* context, unsigned char* data, size_t size) {
    Workflow* w = context;
    return w->io->random(w->io->context, data, size);
}
static void progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    Workflow* w = context;
    w->io->progress(w->io->context, stage, done, total);
}
static int failure(Workflow* w, int rc, const char* detail) {
    snprintf(w->result->error, sizeof(w->result->error), "%s", detail);
    event(w, "workflow_error", rc, detail);
    return rc;
}
static void* open_relative(Workflow* w, const char* name, Tb2FileMode mode) {
    char full[FULL_PATH_MAX];
    if(!path(full, w->directory, name)) return NULL;
    void* f = w->io->open(w->io->context, full, mode);
    event(w, "job_file_open", f ? 0 : TB2_PROBE_IO_ERROR, name);
    return f;
}
static bool close_file(Workflow* w, void** file) {
    if(!*file) return true;
    bool ok = w->io->close(w->io->context, *file);
    *file = NULL;
    return ok;
}
static bool append(Workflow* w, Tb2JobRecord* r) {
    if(w->io_failed || w->sequence >= JOB_MAX_RECORDS) return false;
    uint8_t bytes[TB2_JOB_RECORD_SIZE], check[TB2_JOB_RECORD_SIZE];
    r->sequence = w->sequence + 1;
    tb2_job_encode(r, bytes);
    uint32_t offset = w->sequence * TB2_JOB_RECORD_SIZE;
    bool ok = w->io->seek(w->io->context, w->journal, offset) &&
              w->io->write(w->io->context, w->journal, bytes, sizeof(bytes)) == sizeof(bytes) &&
              w->io->sync(w->io->context, w->journal) &&
              w->io->seek(w->io->context, w->journal, offset) &&
              w->io->read(w->io->context, w->journal, check, sizeof(check)) == sizeof(check) &&
              !memcmp(bytes, check, sizeof(bytes));
    char detail[96];
    snprintf(
        detail,
        sizeof(detail),
        "sequence=%lu kind=%u bytes=%u",
        (unsigned long)r->sequence,
        r->kind,
        TB2_JOB_RECORD_SIZE);
    if(!event(w, "journal_checkpoint", ok ? 0 : TB2_PROBE_IO_ERROR, detail)) ok = false;
    if(ok) w->sequence++;
    return ok;
}
static bool hash_handle(Workflow* w, void* f, uint8_t digest[32], const char* stage) {
    uint64_t size = w->io->size(w->io->context, f);
    if(size > UINT32_MAX || !w->io->seek(w->io->context, f, 0)) return false;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    int rc = mbedtls_sha256_starts(&sha, 0);
    uint8_t bytes[512];
    for(uint32_t offset = 0; !rc && offset < size;) {
        size_t n = size - offset;
        if(n > sizeof(bytes)) n = sizeof(bytes);
        if(cancelled(w) || w->io->read(w->io->context, f, bytes, n) != n) {
            rc = -1;
            break;
        }
        rc = mbedtls_sha256_update(&sha, bytes, n);
        offset += n;
        if(stage) progress(w, stage, offset, (uint32_t)size);
    }
    if(!rc) rc = mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    mbedtls_platform_zeroize(bytes, sizeof(bytes));
    return rc == 0;
}
static bool check_artifact(Workflow* w, const Tb2JobRecord* r) {
    void* f = open_relative(w, r->name, Tb2FileRead);
    uint8_t digest[32];
    bool ok = f && w->io->size(w->io->context, f) == r->size && hash_handle(w, f, digest, NULL) &&
              !memcmp(digest, r->digest, 32);
    ok = close_file(w, &f) && ok;
    return event(w, "artifact_fingerprint", ok ? 0 : TB2_PROBE_CHECK_FAILED, r->name) && ok;
}
/* Only an explicitly journalled incomplete write can be discarded. Full-size
 * mismatches and even truncated but parseable private keys stay untouched. */
static bool recover_pending(Workflow* w, Tb2JobRecord* r) {
    if(check_artifact(w, r)) {
        r->kind = Tb2JobFileDone;
        return append(w, r);
    }
    if(w->io_failed || cancelled(w)) return false;
    char full[FULL_PATH_MAX];
    if(!path(full, w->directory, r->name)) return false;
    int exists = w->io->exists(w->io->context, full);
    if(exists < 0) return false;
    if(exists) {
        void* f = open_relative(w, r->name, Tb2FileRead);
        uint64_t size = f ? w->io->size(w->io->context, f) : UINT64_MAX;
        bool safe = size < r->size && size <= TB2_PACKAGE_FILE_MAX;
        if(safe && (strstr(r->name, "key") || strstr(r->name, "private"))) {
            uint8_t* bytes = calloc(1, (size_t)size + 1);
            safe = bytes && w->io->read(w->io->context, f, bytes, (size_t)size) == size;
            if(safe) {
                mbedtls_pk_context key;
                mbedtls_pk_init(&key);
                bool pem = size > 10 && !memcmp(bytes, "-----BEGIN", 10);
                if(!mbedtls_pk_parse_key(&key, bytes, (size_t)size + pem, NULL, 0, random_bytes, w))
                    safe = false;
                mbedtls_pk_free(&key);
            }
            if(bytes) {
                mbedtls_platform_zeroize(bytes, (size_t)size + 1);
                free(bytes);
            }
        }
        safe = close_file(w, &f) && safe;
        if(!safe || !w->io->remove(w->io->context, full)) {
            failure(
                w,
                TB2_PROBE_CHECK_FAILED,
                "Conflicting partial file retained. Start a new job or restore the original.");
            return false;
        }
        if(!event(w, "unfinished_file_removed", 0, r->name)) return false;
    }
    r->kind = Tb2JobFileDiscarded;
    return append(w, r);
}
static bool replay(Workflow* w) {
    uint64_t size = w->io->size(w->io->context, w->journal);
    if(size > JOB_MAX_RECORDS * TB2_JOB_RECORD_SIZE) return false;
    Tb2JobRecord pending = {0};
    uint8_t bytes[TB2_JOB_RECORD_SIZE];
    while((uint64_t)w->sequence * sizeof(bytes) + sizeof(bytes) <= size) {
        if(cancelled(w)) return false;
        if(!w->io->seek(w->io->context, w->journal, w->sequence * sizeof(bytes)) ||
           w->io->read(w->io->context, w->journal, bytes, sizeof(bytes)) != sizeof(bytes))
            return false;
        Tb2JobRecord r;
        if(!tb2_job_decode(bytes, w->sequence + 1, &r)) {
            if((uint64_t)(w->sequence + 1) * sizeof(bytes) != size) return false;
            break;
        }
        w->sequence++;
        if(pending.kind && r.kind != Tb2JobFileDone && r.kind != Tb2JobFileDiscarded) return false;
        if(r.kind == Tb2JobFilePending)
            pending = r;
        else if(r.kind == Tb2JobFileDone || r.kind == Tb2JobFileDiscarded) {
            if(!pending.kind || strcmp(r.name, pending.name) || r.size != pending.size ||
               memcmp(r.digest, pending.digest, 32))
                return false;
            if(r.kind == Tb2JobFileDone && !check_artifact(w, &r)) return false;
            pending.kind = 0;
        } else if(r.kind == Tb2JobReadDone) {
            if(!tb2_job_get_read(&r, &w->result->read)) return false;
            w->read_done = true;
        } else if(r.kind == Tb2JobImportDone)
            w->import_done = true;
        else if(r.kind == Tb2JobPackageDone) {
            w->package_done = true;
            memcpy(w->package_hash, r.digest, 32);
        } else if(r.kind == Tb2JobImageDone) {
            if(w->spec->shared_image && !w->image_started) return false;
            w->image_done = true;
            memcpy(w->image_hash, r.digest, 32);
        } else if(r.kind == Tb2JobImageStarted) {
            if(w->image_started || w->image_done) return false;
            w->image_started = true;
        } else if(r.kind == Tb2JobCancelled)
            w->cancelled = true;
    }
    uint32_t good = w->sequence * TB2_JOB_RECORD_SIZE;
    if(size != good) {
        if(!event(w, "journal_torn_tail", 0, "discard last incomplete entry only") ||
           !w->io->seek(w->io->context, w->journal, good) ||
           !w->io->truncate(w->io->context, w->journal) ||
           !w->io->sync(w->io->context, w->journal))
            return false;
    }
    return !pending.kind || recover_pending(w, &pending);
}
static bool save_artifact(void* context, const char* name, const void* data, size_t size) {
    Workflow* w = context;
    char full[FULL_PATH_MAX];
    if(cancelled(w) || size > TB2_PACKAGE_FILE_MAX || !path(full, w->directory, name))
        return false;
    Tb2JobRecord r = {.kind = Tb2JobFilePending, .size = (uint32_t)size};
    snprintf(r.name, sizeof(r.name), "%s", name);
    if(mbedtls_sha256(data, size, r.digest, 0)) return false;
    int exists = w->io->exists(w->io->context, full);
    if(exists < 0) return false;
    if(exists) {
        if(!check_artifact(w, &r) || !append(w, &r)) return false;
        r.kind = Tb2JobFileDone;
        return append(w, &r);
    }
    if(!append(w, &r)) return false;
    void* f = open_relative(w, name, Tb2FileNew);
    bool ok = f && w->io->write(w->io->context, f, data, size) == size &&
              w->io->sync(w->io->context, f);
    ok = close_file(w, &f) && ok;
    if(!ok || !check_artifact(w, &r)) return false;
    r.kind = Tb2JobFileDone;
    return append(w, &r);
}
static bool source_read(void* context, uint32_t offset, void* bytes, size_t size) {
    Workflow* w = context;
    bool ok = !w->io_failed && offset <= TB2_IMAGE_SIZE && size <= TB2_IMAGE_SIZE - offset &&
              w->io->seek(w->io->context, w->source, offset);
    size_t actual = ok ? w->io->read(w->io->context, w->source, bytes, size) : 0;
    char detail[112];
    snprintf(
        detail,
        sizeof(detail),
        "offset=0x%08lx requested=%lu actual=%lu",
        (unsigned long)offset,
        (unsigned long)size,
        (unsigned long)actual);
    return event(w, "source_read", ok && actual == size ? 0 : TB2_PROBE_IO_ERROR, detail) && ok &&
           actual == size;
}
static int
    package_read(void* context, const char* name, void* bytes, size_t capacity, size_t* size) {
    Workflow* w = context;
    char relative[TB2_JOB_NAME_MAX], full[FULL_PATH_MAX];
    snprintf(relative, sizeof(relative), "package/%s", name);
    if(!path(full, w->directory, relative)) return TB2_PROBE_IO_ERROR;
    int exists = w->io->exists(w->io->context, full);
    if(!exists &&
       ((w->spec->server.fields & TB2_SERVER_HOST) ||
        (w->patch && (w->patch->server_fields & (Tb2ServerOtaHost | Tb2ServerIciHost)))) &&
       w->spec->imported_package[0]) {
        snprintf(relative, sizeof(relative), "imported-package/%s", name);
        if(!path(full, w->directory, relative)) return TB2_PROBE_IO_ERROR;
        exists = w->io->exists(w->io->context, full);
    }
    if(!exists) return TB2_PACKAGE_MISSING;
    if(exists < 0) return TB2_PROBE_IO_ERROR;
    void* f = open_relative(w, relative, Tb2FileRead);
    uint64_t length = f ? w->io->size(w->io->context, f) : UINT64_MAX;
    bool ok = length <= TB2_PACKAGE_FILE_MAX &&
              (!bytes || (length <= capacity &&
                          w->io->read(w->io->context, f, bytes, (size_t)length) == length));
    ok = close_file(w, &f) && ok;
    if(ok) *size = (size_t)length;
    return ok ? 0 : TB2_PROBE_IO_ERROR;
}
static bool package_save(void* context, const char* name, const void* bytes, size_t size) {
    char relative[TB2_JOB_NAME_MAX];
    snprintf(relative, sizeof(relative), "package/%s", name);
    return save_artifact(context, relative, bytes, size);
}
static bool import_package(Workflow* w) {
    uint8_t* bytes = malloc(TB2_PACKAGE_FILE_MAX);
    if(!bytes) return false;
    bool ok = true;
    for(unsigned i = 0; ok && w->spec->imported_package[0] && i <= TB2_PACKAGE_FILES; i++) {
        if(cancelled(w)) {
            ok = false;
            break;
        }
        const char* name = i == TB2_PACKAGE_FILES ? "ca.der" : tb2_package_names[i];
        char full[FULL_PATH_MAX];
        if(!path(full, w->spec->imported_package, name)) {
            ok = false;
            break;
        }
        int exists = w->io->exists(w->io->context, full);
        if(!exists) {
            if(i == TB2_PACKAGE_FILES) continue; /* ca.der is optional input. */
            char detail[96];
            snprintf(detail, sizeof(detail), "Certificate import incomplete: %s missing.", name);
            failure(w, TB2_PROBE_CHECK_FAILED, detail);
            ok = false;
            break;
        }
        if(exists < 0) {
            ok = false;
            break;
        }
        void* f = w->io->open(w->io->context, full, Tb2FileRead);
        uint64_t size = f ? w->io->size(w->io->context, f) : UINT64_MAX;
        ok = size > 0 && size <= TB2_PACKAGE_FILE_MAX &&
             w->io->read(w->io->context, f, bytes, (size_t)size) == size;
        ok = close_file(w, &f) && ok;
        if(ok &&
           ((w->spec->server.fields & TB2_SERVER_HOST) ||
            (w->patch && (w->patch->server_fields & (Tb2ServerOtaHost | Tb2ServerIciHost))))) {
            char relative[TB2_JOB_NAME_MAX];
            snprintf(relative, sizeof(relative), "imported-package/%s", name);
            ok = save_artifact(w, relative, bytes, (size_t)size);
        } else if(ok)
            ok = package_save(w, name, bytes, (size_t)size);
    }
    mbedtls_platform_zeroize(bytes, TB2_PACKAGE_FILE_MAX);
    free(bytes);
    if(ok) {
        Tb2JobRecord r = {.kind = Tb2JobImportDone};
        ok = append(w, &r);
    }
    return ok;
}
static bool target_reset(void* context) {
    Workflow* w = context;
    if(w->image_done || cancelled(w)) return false;
    if(!w->image) {
        int exists = w->io->exists(w->io->context, w->image_path);
        if(exists < 0) return false;
        if(w->spec->shared_image && !w->image_started) {
            if(exists) {
                failure(w, TB2_PROBE_CHECK_FAILED, "Target image exists; will not overwrite.");
                return false;
            }
            /* Durable ownership before the first image write; only this exact
             * job's partial output may subsequently be restarted or removed. */
            Tb2JobRecord r = {.kind = Tb2JobImageStarted};
            if(!append(w, &r)) return false;
            w->image_started = true;
        }
        w->image = w->io->open(w->io->context, w->image_path, exists ? Tb2FileUpdate : Tb2FileNew);
    }
    return w->image && w->io->seek(w->io->context, w->image, 0) &&
           w->io->truncate(w->io->context, w->image) &&
           event(w, "image_restart", 0, "job-owned incomplete image; fresh copy from original");
}
static bool target_transfer(Workflow* w, bool write, uint32_t offset, void* bytes, size_t size) {
    bool ok = !w->io_failed && (!write || !w->image_done) && offset <= TB2_IMAGE_SIZE &&
              size <= TB2_IMAGE_SIZE - offset && w->image &&
              w->io->seek(w->io->context, w->image, offset);
    size_t actual = ok ? (write ? w->io->write(w->io->context, w->image, bytes, size) :
                                  w->io->read(w->io->context, w->image, bytes, size)) :
                         0;
    char detail[112];
    snprintf(
        detail,
        sizeof(detail),
        "offset=0x%08lx requested=%lu actual=%lu",
        (unsigned long)offset,
        (unsigned long)size,
        (unsigned long)actual);
    return event(
               w,
               write ? "image_write" : "image_read",
               ok && actual == size ? 0 : TB2_PROBE_IO_ERROR,
               detail) &&
           ok && actual == size;
}
static bool target_read(void* c, uint32_t o, void* b, size_t n) {
    return target_transfer(c, false, o, b, n);
}
static bool target_write(void* c, uint32_t o, const void* b, size_t n) {
    return target_transfer(c, true, o, (void*)b, n);
}
static bool target_sync(void* context) {
    Workflow* w = context;
    bool ok = w->image && w->io->sync(w->io->context, w->image);
    return event(w, "image_sync", ok ? 0 : TB2_PROBE_IO_ERROR, w->image_path) && ok;
}
static uint64_t target_size(void* context) {
    Workflow* w = context;
    return w->image ? w->io->size(w->io->context, w->image) : 0;
}

static void spec_header(uint8_t header[JOB_HEADER_SIZE], const uint8_t* bytes, size_t size) {
    const uint32_t words[] = {0x31534254U, (uint32_t)size, tb2_job_crc(bytes, size)};
    for(unsigned i = 0; i < 3; i++)
        for(unsigned j = 0; j < 4; j++)
            header[i * 4 + j] = (uint8_t)(words[i] >> (8 * j));
}
bool tb2_workflow_create(Tb2WorkflowIO* io, const char* directory, const Tb2JobSpec* spec) {
    char full[FULL_PATH_MAX];
    if(spec->shared_image > 2 || !tb2_package_options_valid(&spec->options) ||
       !path(full, directory, JOB_FILE))
        return false;
    uint8_t* bytes = malloc(TB2_JOB_SPEC_SIZE);
    if(!bytes || !tb2_job_spec_encode(spec, bytes)) {
        free(bytes);
        return false;
    }
    void* f = io->open(io->context, full, Tb2FileNew);
    uint8_t header[JOB_HEADER_SIZE];
    spec_header(header, bytes, TB2_JOB_SPEC_SIZE);
    bool ok = f && io->write(io->context, f, header, sizeof(header)) == sizeof(header) &&
              io->write(io->context, f, bytes, TB2_JOB_SPEC_SIZE) == TB2_JOB_SPEC_SIZE &&
              io->sync(io->context, f);
    if(f) ok = io->close(io->context, f) && ok;
    free(bytes);
    Tb2JobSpec* check = malloc(sizeof(*check));
    ok = check && ok && tb2_workflow_load(io, directory, check) && tb2_job_spec_equal(spec, check);
    free(check);
    return ok;
}
bool tb2_workflow_load(Tb2WorkflowIO* io, const char* directory, Tb2JobSpec* spec) {
    char full[FULL_PATH_MAX];
    if(!path(full, directory, JOB_FILE)) return false;
    void* f = io->open(io->context, full, Tb2FileRead);
    uint8_t header[JOB_HEADER_SIZE], expected[JOB_HEADER_SIZE];
    uint64_t file_size = f ? io->size(io->context, f) : 0;
    size_t size = file_size >= JOB_HEADER_SIZE &&
                          file_size <= JOB_HEADER_SIZE + TB2_JOB_SPEC_SIZE ?
                      (size_t)file_size - JOB_HEADER_SIZE :
                      0;
    uint8_t* bytes = malloc(TB2_JOB_SPEC_SIZE);
    memset(spec, 0, sizeof(*spec));
    bool ok = bytes && f && tb2_job_spec_size(size) &&
              io->read(io->context, f, header, sizeof(header)) == sizeof(header) &&
              io->read(io->context, f, bytes, size) == size;
    if(f) ok = io->close(io->context, f) && ok;
    if(ok) {
        spec_header(expected, bytes, size);
        ok = !memcmp(header, expected, sizeof(header)) && tb2_job_spec_decode(bytes, size, spec) &&
             tb2_job_image_path(spec, directory, full);
    }
    free(bytes);
    return ok;
}
/** No journal, backup, certificate import or job directory is touched here. */
static int preview_server(Workflow* w, const Tb2InputKey* key) {
    Tb2WorkflowIO* io = w->io;
    w->source = io->open(io->context, w->spec->source, Tb2FileRead);
    int rc = TB2_PROBE_IO_ERROR;
    if(w->source && io->size(io->context, w->source) == TB2_IMAGE_SIZE) {
        Tb2Reader reader = {
            .context = w,
            .image_size = TB2_IMAGE_SIZE,
            .read = source_read,
            .event = event,
            .cancelled = cancelled,
            .progress = progress,
            .random = random_bytes};
        rc = tb2_reader_server_preview(&reader, key, &w->result->read, &w->result->server_values);
        if(rc) failure(w, rc, w->result->read.error);
    } else
        failure(w, rc, "Original dump missing or not exactly 16 MiB.");
    if(!close_file(w, &w->source)) rc = TB2_PROBE_IO_ERROR;
    if(w->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(rc) memset(&w->result->server_values, 0, sizeof(w->result->server_values));
    return rc;
}
int tb2_workflow_run_patch(
    Tb2WorkflowIO* io,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2InputKey* key,
    const Tb2SettingsPatch* patch,
    Tb2WorkflowAction action,
    uint32_t approved_missing,
    Tb2WorkflowResult* result) {
    memset(result, 0, sizeof(*result));
    Workflow* w = calloc(1, sizeof(*w));
    if(!w) return TB2_PROBE_IO_ERROR;
    w->io = io;
    w->directory = directory;
    w->spec = spec;
    w->patch = patch;
    w->result = result;
    const bool settings_only = !WORKFLOW_CERT && patch && key && key->kind == Tb2InputKeyInvalid;
    int rc = tb2_probe_crypto_begin();
    if(action == Tb2WorkflowPreviewServer) {
        if(!rc && WORKFLOW_SOURCE)
            rc = preview_server(w, key);
        else if(!rc)
            rc = TB2_PROBE_CHECK_FAILED;
        free(w);
        return rc;
    }
    if(!patch && (spec->server.fields & TB2_SERVER_HOST) &&
       (strcmp(spec->server.host, spec->options.https_host) ||
        strcmp(spec->server.host, spec->options.ici_host)))
        rc = failure(
            w, TB2_PROBE_CHECK_FAILED, "Server override and certificate hostnames differ.");
    if(!tb2_job_image_path(spec, directory, w->image_path))
        rc = failure(w, TB2_PROBE_CHECK_FAILED, "Invalid image target or source equals target.");
    Tb2JobSpec* bound = malloc(sizeof(*bound));
    if(!bound || !tb2_workflow_load(io, directory, bound)) rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) {
        /* Current, explicitly displayed RTC is refreshed on resume; source,
         * hosts, expiration and imported directory remain immutable. */
        memcpy(bound->options.now, spec->options.now, TB2_DATE_SIZE);
        if(!tb2_job_spec_equal(bound, spec)) rc = TB2_PROBE_CHECK_FAILED;
    }
    free(bound);
    Tb2SettingsPatch approved_patch = {0};
    if(!rc && patch) {
        bool supplied = tb2_settings_patch_valid(patch);
        if(supplied) approved_patch = *patch;
        if(!settings_patch_access(
               w,
               &approved_patch,
               supplied && (action == Tb2WorkflowInspect || action == Tb2WorkflowBuild),
               false))
            rc = failure(
                w,
                TB2_PROBE_CHECK_FAILED,
                "Approved settings changes are missing, damaged or differ from this job.");
        else
            w->patch = &approved_patch;
    }
    if(rc && !result->error[0])
        failure(w, rc, "Job configuration differs from job.tb2 or RTC is invalid.");
    char full[FULL_PATH_MAX];
    const char* folders[] = {"original", "credentials", "client", "package", "imported-package"};
    for(unsigned i = 0; !rc && i < sizeof(folders) / sizeof(*folders); i++)
        if(!path(full, directory, folders[i]) || !io->mkdir(io->context, full))
            rc = TB2_PROBE_IO_ERROR;
    if(!rc && !path(full, directory, JOURNAL_FILE)) rc = TB2_PROBE_IO_ERROR;
    int exists = rc ? -1 : io->exists(io->context, full);
    if(!rc && exists < 0) rc = TB2_PROBE_IO_ERROR;
    if(!rc) w->journal = open_relative(w, JOURNAL_FILE, exists ? Tb2FileUpdate : Tb2FileNew);
    if(!rc && (!w->journal || !replay(w)))
        rc = failure(
            w,
            TB2_PROBE_CHECK_FAILED,
            "Invalid status or backup fingerprint, or SD error; not released.");
    result->resumed = w->sequence > 0;
    if(!rc && !event(w, "image_destination", 0, w->image_path)) rc = TB2_PROBE_IO_ERROR;
    if(!rc && spec->shared_image == 1 && action == Tb2WorkflowBuild &&
       !io->mkdir(io->context, TB2_SPI_MEM_ROOT))
        rc = TB2_PROBE_IO_ERROR;
    if(!rc && (w->cancelled || action == Tb2WorkflowCancel)) {
        if(!w->cancelled) {
            Tb2JobRecord r = {.kind = Tb2JobCancelled};
            if(!append(w, &r)) rc = TB2_PROBE_IO_ERROR;
        }
        if(!rc && !w->image_done && (!spec->shared_image || w->image_started)) {
            int present = io->exists(io->context, w->image_path);
            if(present < 0 || (present && !io->remove(io->context, w->image_path)))
                rc = TB2_PROBE_IO_ERROR;
            else if(present)
                event(w, "unfinished_image_removed", 0, w->image_path);
        }
        if(!rc)
            rc = failure(
                w, TB2_PROBE_CANCELLED, "Job aborted. Originals, backups and keys retained.");
    }
    if(!rc && WORKFLOW_SOURCE) {
        w->source = io->open(io->context, spec->source, Tb2FileRead);
        if(!w->source || io->size(io->context, w->source) != TB2_IMAGE_SIZE)
            rc = failure(w, TB2_PROBE_IO_ERROR, "Original dump missing or not exactly 16 MiB.");
    }
    Tb2Reader reader = {
        .context = w,
        .image_size = TB2_IMAGE_SIZE,
        .read = source_read,
        .event = event,
        .cancelled = cancelled,
        .progress = progress,
        .backup = save_artifact,
        .random = random_bytes};
    if(!rc && WORKFLOW_SOURCE && w->read_done) {
        uint8_t hash[32];
        if(!hash_handle(w, w->source, hash, "Checking source") ||
           memcmp(hash, result->read.source_sha256, 32))
            rc = failure(
                w,
                TB2_PROBE_CHECK_FAILED,
                "Original dump fingerprint differs from job; do not replace source.");
        else
            event(
                w,
                "backup_reused",
                0,
                "source and all saved artifacts rehashed; extraction not repeated");
    }
    if(!rc && WORKFLOW_SOURCE && !w->read_done) {
        rc = settings_only ? tb2_reader_settings(&reader, &result->read) :
                             tb2_reader_run_key(&reader, key, &result->read);
        if(rc)
            failure(w, rc, result->read.error);
        else {
            Tb2JobRecord r = {0};
            tb2_job_set_read(&r, &result->read);
            if(!append(w, &r)) rc = TB2_PROBE_IO_ERROR;
        }
    }
    if(!rc && WORKFLOW_SOURCE && WORKFLOW_CERT && !settings_only && !w->import_done &&
       !import_package(w)) {
        rc = TB2_PROBE_CHECK_FAILED;
        if(!result->error[0])
            rc = failure(
                w, TB2_PROBE_IO_ERROR, "Certificate import incomplete; source files unchanged.");
    }
    Tb2PackageIO package = {
        .context = w,
        .read = package_read,
        .save = package_save,
        .event = event,
        .cancelled = cancelled,
        .random = random_bytes};
    if(!rc && WORKFLOW_CERT && !WORKFLOW_SOURCE && w->read_done && !w->import_done &&
       !import_package(w)) {
        rc = TB2_PROBE_CHECK_FAILED;
        if(!result->error[0])
            rc = failure(
                w, TB2_PROBE_IO_ERROR, "Certificate import incomplete; source files unchanged.");
    }
    if(!rc && WORKFLOW_CERT && (!w->read_done || !w->import_done) && !WORKFLOW_SOURCE)
        rc = failure(
            w, TB2_PROBE_CHECK_FAILED, "Inspect the source before certificate processing.");
    if(!rc && WORKFLOW_CERT && action == Tb2WorkflowBuild) {
        Tb2JobRecord r = {.kind = Tb2JobApproved, .flags = approved_missing};
        if(!append(w, &r)) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc && WORKFLOW_CERT) {
        progress(w, "Checking certificates", 0, 1);
        int (*run_package)(Tb2PackageIO*, const Tb2PackageOptions*, uint32_t, Tb2PackageResult*) =
            (spec->server.fields & TB2_SERVER_HOST) ||
                    (w->patch &&
                     (w->patch->server_fields & (Tb2ServerOtaHost | Tb2ServerIciHost))) ?
                tb2_package_update :
                tb2_package_run;
        rc = run_package(
            &package,
            &spec->options,
            action == Tb2WorkflowBuild ?
                (spec->imported_package[0] ?
                     (approved_missing & (0x3fU << TB2_PACKAGE_REISSUE_SHIFT)) :
                     approved_missing) |
                    TB2_PACKAGE_EXPORT_DER :
                0,
            &result->package);
        if(rc == TB2_PACKAGE_MISSING && result->package.missing && spec->imported_package[0]) {
            snprintf(
                result->package.error,
                sizeof(result->package.error),
                "Import incomplete; missing:\n");
            for(unsigned i = 0; i < TB2_PACKAGE_FILES; i++) {
                if(!(result->package.missing & (1U << i))) continue;
                size_t used = strlen(result->package.error);
                snprintf(
                    result->package.error + used,
                    sizeof(result->package.error) - used,
                    "%s\n",
                    tb2_package_names[i]);
            }
            rc = TB2_PROBE_CHECK_FAILED;
        }
        if(rc) failure(w, rc, result->package.error);
    }
    if(!rc && WORKFLOW_CERT && w->package_done &&
       memcmp(w->package_hash, result->package.package_sha256, 32))
        rc = failure(w, TB2_PROBE_CHECK_FAILED, "Certificate package changed since approval.");
    if(!rc && WORKFLOW_CERT && action == Tb2WorkflowBuild && !w->package_done) {
        Tb2JobRecord r = {.kind = Tb2JobPackageDone};
        memcpy(r.digest, result->package.package_sha256, 32);
        if(!append(w, &r)) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc && WORKFLOW_IMAGE && !WORKFLOW_CERT && !settings_only && action == Tb2WorkflowBuild &&
       !w->package_done)
        rc =
            failure(w, TB2_PROBE_CHECK_FAILED, "Certificate phase incomplete; image not started.");
    if(!rc && WORKFLOW_IMAGE && (action == Tb2WorkflowBuild || w->image_done)) {
        void* ca_file = NULL;
        uint64_t size = 0;
        uint8_t* ca = NULL;
        if(!settings_only) {
            ca_file = open_relative(w, "package/ca.der", Tb2FileRead);
            size = ca_file ? io->size(io->context, ca_file) : 0;
            ca = size && size <= TB2_PLAIN_MAX ? malloc((size_t)size) : NULL;
            if(!ca || io->read(io->context, ca_file, ca, (size_t)size) != size)
                rc = TB2_PROBE_IO_ERROR;
            if(!close_file(w, &ca_file)) rc = TB2_PROBE_IO_ERROR;
        }
        Tb2ImageTarget target = {
            .context = w,
            .reset = target_reset,
            .read = target_read,
            .write = target_write,
            .sync = target_sync,
            .size = target_size};
        if(!rc && w->image_done) {
            w->image = io->open(io->context, w->image_path, Tb2FileRead);
            if(!w->image) rc = TB2_PROBE_IO_ERROR;
            if(!rc)
                rc = settings_only ?
                         tb2_image_settings_process(
                             &reader, &target, &result->read, w->patch, &result->image, false) :
                     w->patch ? tb2_image_settings_cert_process(
                                    &reader,
                                    &target,
                                    key,
                                    &result->read,
                                    ca,
                                    size,
                                    w->patch,
                                    &result->image,
                                    false) :
                                tb2_image_process(
                                    &reader,
                                    &target,
                                    key,
                                    &result->read,
                                    ca,
                                    size,
                                    &spec->server,
                                    &result->image,
                                    false);
            if(!rc && memcmp(w->image_hash, result->image.sha256, 32))
                rc = failure(
                    w,
                    TB2_PROBE_CHECK_FAILED,
                    "Completed image fingerprint mismatch; not released.");
        } else if(!rc)
            rc = settings_only ?
                     tb2_image_settings_process(
                         &reader, &target, &result->read, w->patch, &result->image, true) :
                 w->patch ? tb2_image_settings_cert_process(
                                &reader,
                                &target,
                                key,
                                &result->read,
                                ca,
                                size,
                                w->patch,
                                &result->image,
                                true) :
                            tb2_image_process(
                                &reader,
                                &target,
                                key,
                                &result->read,
                                ca,
                                size,
                                &spec->server,
                                &result->image,
                                true);
        free(ca);
        if(rc && !result->error[0]) failure(w, rc, result->image.error);
        if(!io->image_lease && !close_file(w, &w->image)) rc = TB2_PROBE_IO_ERROR;
        if(!rc && !w->image_done) {
            Tb2JobRecord r = {.kind = Tb2JobImageDone};
            memcpy(r.digest, result->image.sha256, 32);
            if(!append(w, &r)) rc = TB2_PROBE_IO_ERROR;
        }
        if(!rc) result->complete = true;
    }
    bool retain_image = !rc && result->complete && io->image_lease && !*io->image_lease;
    bool closed_image = retain_image || close_file(w, &w->image);
    bool closed_source = close_file(w, &w->source);
    bool closed_journal = close_file(w, &w->journal);
    if(!closed_image || !closed_source || !closed_journal) rc = TB2_PROBE_IO_ERROR;
    if(cancelled(w) && !w->io_failed) rc = TB2_PROBE_CANCELLED;
    if(w->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(rc) result->complete = false;
    if(rc && !result->error[0])
        failure(
            w,
            rc,
            rc == TB2_PROBE_CANCELLED ? "Stopped; saved files retained." :
                                        "SD or status error; result not released.");
    if(!event(
           w,
           "workflow_finished",
           rc,
           result->complete ? "image locally verified; chip verification is separate" :
                              "no image released")) {
        rc = TB2_PROBE_IO_ERROR;
        result->complete = false;
    }
    if(!rc && retain_image) {
        *io->image_lease = w->image;
        w->image = NULL;
    }
    if(!close_file(w, &w->image)) {
        rc = TB2_PROBE_IO_ERROR;
        result->complete = false;
    }
    if((!rc && result->complete) || action == Tb2WorkflowCancel)
        if(patch && !settings_patch_access(w, &approved_patch, false, true))
            rc = TB2_PROBE_IO_ERROR;
    mbedtls_platform_zeroize(&approved_patch, sizeof(approved_patch));
    free(w);
    return rc;
}

int tb2_workflow_run(
    Tb2WorkflowIO* io,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2InputKey* key,
    Tb2WorkflowAction action,
    uint32_t approved_missing,
    Tb2WorkflowResult* result) {
    return tb2_workflow_run_patch(
        io, directory, spec, key, NULL, action, approved_missing, result);
}

#define SETTINGS_PATCH_FILE "settings.patch"
static bool settings_patch_access(Workflow* w, Tb2SettingsPatch* patch, bool create, bool remove) {
    char full[FULL_PATH_MAX];
    if(!path(full, w->directory, SETTINGS_PATCH_FILE)) return false;
    if(remove) {
        int exists = w->io->exists(w->io->context, full);
        return exists == 0 || (exists == 1 && w->io->remove(w->io->context, full));
    }
    uint8_t* bytes = malloc(TB2_SETTINGS_PATCH_BYTES);
    if(!bytes) return false;
    int exists = w->io->exists(w->io->context, full);
    bool ok = exists >= 0;
    if(ok && create && !exists) {
        ok = tb2_settings_patch_encode(patch, bytes);
        void* file = ok ? w->io->open(w->io->context, full, Tb2FileNew) : NULL;
        ok = file &&
             w->io->write(w->io->context, file, bytes, TB2_SETTINGS_PATCH_BYTES) ==
                 TB2_SETTINGS_PATCH_BYTES &&
             w->io->sync(w->io->context, file);
        if(file) ok = w->io->close(w->io->context, file) && ok;
        exists = ok ? 1 : exists;
    }
    void* file = ok && exists ? w->io->open(w->io->context, full, Tb2FileRead) : NULL;
    Tb2SettingsPatch saved;
    ok = file && w->io->size(w->io->context, file) == TB2_SETTINGS_PATCH_BYTES &&
         w->io->read(w->io->context, file, bytes, TB2_SETTINGS_PATCH_BYTES) ==
             TB2_SETTINGS_PATCH_BYTES &&
         tb2_settings_patch_decode(bytes, &saved);
    if(file) ok = w->io->close(w->io->context, file) && ok;
    if(ok && tb2_settings_patch_valid(patch)) {
        uint8_t* expected = malloc(TB2_SETTINGS_PATCH_BYTES);
        ok = expected && tb2_settings_patch_encode(patch, expected) &&
             !memcmp(bytes, expected, TB2_SETTINGS_PATCH_BYTES);
        if(expected) {
            mbedtls_platform_zeroize(expected, TB2_SETTINGS_PATCH_BYTES);
            free(expected);
        }
    }
    if(ok) *patch = saved;
    mbedtls_platform_zeroize(&saved, sizeof(saved));
    mbedtls_platform_zeroize(bytes, TB2_SETTINGS_PATCH_BYTES);
    free(bytes);
    return ok;
}
