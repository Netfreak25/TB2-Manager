#include "ui_store.h"
#include "workflow.h"
#include <storage/storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UI_VERSION         1U
#define UI_PREFS_MAGIC     0x31504254U
#define UI_STATUS_MAGIC    0x31554254U
#define UI_JOB_MAGIC       0x31534254U
#define UI_JOB_HEADER_SIZE 12U
#define UI_PREFS_VERSION   4U
#define UI_PREFS_V1_SIZE   (12U + 2U * TB2_JOB_PATH_MAX)
#define UI_PREFS_V2_SIZE   (UI_PREFS_V1_SIZE + TB2_SERVER_HOST_SIZE + 5U)
#define UI_PREFS_V3_SIZE   (UI_PREFS_V2_SIZE + 1U)
#define UI_PREFS_SIZE      (12U + 2U * TB2_JOB_PATH_MAX + 2U * TB2_SERVER_HOST_SIZE + 4U + 2U)
#define UI_STATUS_SIZE     36U
#define UI_JOURNAL_LIMIT   4096U
#define UI_READBACK_CHUNK  64U

static uint32_t ui_get32(const uint8_t* bytes) {
    uint32_t value = 0;
    for(unsigned i = 0; i < 4; i++)
        value |= (uint32_t)bytes[i] << (8U * i);
    return value;
}

static void ui_put32(uint8_t* bytes, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        bytes[i] = (uint8_t)(value >> (8U * i));
}

/** Absolute SD paths with no aliases, control characters or traversal components. */
static bool ui_path_valid(const char* path, bool empty) {
    if(!path) return false;
    size_t length = 0;
    while(length < TB2_JOB_PATH_MAX && path[length])
        length++;
    if(length == TB2_JOB_PATH_MAX) return false;
    if(!path[0]) return empty;
    if(!strcmp(path, "/ext")) return true;
    if(strncmp(path, "/ext/", 5)) return false;
    const char* segment = path + 5;
    for(const char* p = segment;; p++) {
        unsigned char c = (unsigned char)*p;
        if(!c || c == '/') {
            size_t segment_length = (size_t)(p - segment);
            if(!segment_length || (segment_length == 1 && segment[0] == '.') ||
               (segment_length == 2 && segment[0] == '.' && segment[1] == '.'))
                return false;
            if(!c) return true;
            segment = p + 1;
        } else if(c < 32 || c == 127 || strchr("\\:*?\"<>|", c)) {
            return false;
        }
    }
}

static bool ui_server_values_valid(const Tb2ServerValues* values, uint8_t fields) {
    return !(fields &
             ~(Tb2ServerOtaHost | Tb2ServerOtaPort | Tb2ServerIciHost | Tb2ServerIciPort)) &&
           (!(fields & Tb2ServerOtaHost) || tb2_server_host_valid(values->https_host)) &&
           (!(fields & Tb2ServerIciHost) || tb2_server_host_valid(values->mqtt_host)) &&
           (!(fields & Tb2ServerOtaPort) || values->https_port) &&
           (!(fields & Tb2ServerIciPort) || values->mqtt_port);
}

static bool ui_child(char path[TB2_JOB_PATH_MAX], const char* directory, const char* name) {
    if(!ui_path_valid(directory, false)) return false;
    int size = snprintf(path, TB2_JOB_PATH_MAX, "%s/%s", directory, name);
    return size > 0 && size < (int)TB2_JOB_PATH_MAX;
}

/** -1: error/corrupt, 0: absent, 1: exactly size bytes read and successfully closed. */
static int ui_read(void* storage, const char* path, void* bytes, size_t size) {
    File* file = storage_file_alloc(storage);
    if(!file) return -1;
    bool opened = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING);
    bool missing = !opened && storage_file_get_error(file) == FSE_NOT_EXIST;
    bool ok = opened && storage_file_size(file) == size &&
              storage_file_read(file, bytes, size) == size;
    bool closed = storage_file_close(file);
    storage_file_free(file);
    /* Unleashed requires close after a failed open, but FatFS then reports an
     * invalid object. Preserve the captured missing-file result after cleanup. */
    if(missing) return 0;
    if(!closed) return -1;
    return ok ? 1 : -1;
}

/** Never claim persistence until a separately reopened handle confirms the exact bytes. */
static bool ui_write(void* storage, const char* path, const uint8_t* bytes, size_t size) {
    File* file = storage_file_alloc(storage);
    if(!file) return false;
    bool ok = storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS) &&
              storage_file_write(file, bytes, size) == size && storage_file_sync(file);
    ok = storage_file_close(file) && ok;
    if(ok) {
        ok = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING) &&
             storage_file_size(file) == size;
        uint8_t check[UI_READBACK_CHUNK];
        for(size_t offset = 0; ok && offset < size;) {
            size_t count = size - offset;
            if(count > sizeof(check)) count = sizeof(check);
            ok = storage_file_read(file, check, count) == count &&
                 !memcmp(check, bytes + offset, count);
            offset += count;
        }
        ok = storage_file_close(file) && ok;
    }
    storage_file_free(file);
    return ok;
}

bool tb2_ui_preferences_load(void* storage, Tb2UiPreferences* out) {
    if(!out) return false;
    memset(out, 0, sizeof(*out));
    uint8_t bytes[UI_PREFS_SIZE] = {0};
    FileInfo info;
    if(storage_common_stat(storage, TB2_UI_PREFERENCES_PATH, &info) != FSE_OK ||
       file_info_is_dir(&info) ||
       (info.size != UI_PREFS_V1_SIZE && info.size != UI_PREFS_V2_SIZE &&
        info.size != UI_PREFS_V3_SIZE && info.size != UI_PREFS_SIZE))
        return false;
    size_t size = (size_t)info.size;
    if(ui_read(storage, TB2_UI_PREFERENCES_PATH, bytes, size) != 1 ||
       ui_get32(bytes) != UI_PREFS_MAGIC ||
       ui_get32(bytes + 4) != (size == UI_PREFS_V1_SIZE ? UI_VERSION :
                               size == UI_PREFS_V2_SIZE ? 2U :
                               size == UI_PREFS_V3_SIZE ? 3U :
                                                          UI_PREFS_VERSION) ||
       ui_get32(bytes + size - 4) != tb2_job_crc(bytes, size - 4) ||
       !ui_path_valid((const char*)bytes + 8, true) ||
       !ui_path_valid((const char*)bytes + 8 + TB2_JOB_PATH_MAX, true))
        return false;
    Tb2ServerChange server = {0};
    if(size == UI_PREFS_V2_SIZE || size == UI_PREFS_V3_SIZE) {
        const uint8_t* saved = bytes + UI_PREFS_V1_SIZE - 4;
        memcpy(server.host, saved, sizeof(server.host));
        memcpy(server.ports, saved + sizeof(server.host), sizeof(server.ports));
        server.fields = saved[sizeof(server.host) + sizeof(server.ports)];
        if(!tb2_server_change_valid(&server)) return false;
        if(server.fields & TB2_SERVER_HOST) {
            memcpy(out->server_values.https_host, server.host, sizeof(server.host));
            memcpy(out->server_values.mqtt_host, server.host, sizeof(server.host));
            out->server_fields |= Tb2ServerOtaHost | Tb2ServerIciHost;
        }
        if(server.fields & TB2_SERVER_HTTPS) {
            out->server_values.https_port = tb2_server_port(&server, false);
            out->server_fields |= Tb2ServerOtaPort;
        }
        if(server.fields & TB2_SERVER_MQTT) {
            out->server_values.mqtt_port = tb2_server_port(&server, true);
            out->server_fields |= Tb2ServerIciPort;
        }
    } else if(size == UI_PREFS_SIZE) {
        const uint8_t* saved = bytes + 8 + 2U * TB2_JOB_PATH_MAX;
        memcpy(out->server_values.https_host, saved, TB2_SERVER_HOST_SIZE);
        memcpy(out->server_values.mqtt_host, saved + TB2_SERVER_HOST_SIZE, TB2_SERVER_HOST_SIZE);
        out->server_values.https_port =
            (uint16_t)saved[2U * TB2_SERVER_HOST_SIZE] |
            (uint16_t)((uint16_t)saved[2U * TB2_SERVER_HOST_SIZE + 1U] << 8U);
        out->server_values.mqtt_port =
            (uint16_t)saved[2U * TB2_SERVER_HOST_SIZE + 2U] |
            (uint16_t)((uint16_t)saved[2U * TB2_SERVER_HOST_SIZE + 3U] << 8U);
        out->server_fields = saved[2U * TB2_SERVER_HOST_SIZE + 4U];
        out->hardware_options = saved[2U * TB2_SERVER_HOST_SIZE + 5U];
        if(!ui_server_values_valid(&out->server_values, out->server_fields) ||
           out->hardware_options > (Tb2HardwareManualUid | Tb2HardwareSpiMask)) {
            memset(out, 0, sizeof(*out));
            return false;
        }
        if((out->server_fields & (Tb2ServerOtaHost | Tb2ServerIciHost)) ==
               (Tb2ServerOtaHost | Tb2ServerIciHost) &&
           !strcmp(out->server_values.https_host, out->server_values.mqtt_host)) {
            memcpy(server.host, out->server_values.https_host, sizeof(server.host));
            server.fields |= TB2_SERVER_HOST;
        }
        if(out->server_fields & Tb2ServerOtaPort) {
            tb2_server_set_port(&server, false, out->server_values.https_port);
            server.fields |= TB2_SERVER_HTTPS;
        }
        if(out->server_fields & Tb2ServerIciPort) {
            tb2_server_set_port(&server, true, out->server_values.mqtt_port);
            server.fields |= TB2_SERVER_MQTT;
        }
    }
    const char* package = (const char*)bytes + 8;
    const char* output = package + TB2_JOB_PATH_MAX;
    /* Both terminators were checked within their fixed-size fields above. */
    memcpy(out->package_dir, package, strlen(package) + 1);
    memcpy(out->output_dir, output, strlen(output) + 1);
    out->server = server;
    if(size == UI_PREFS_V3_SIZE) {
        if(bytes[UI_PREFS_V2_SIZE - 4] > 1) {
            memset(out, 0, sizeof(*out));
            return false;
        }
        out->hardware_options = bytes[UI_PREFS_V2_SIZE - 4] ? Tb2HardwareManualUid : 0;
    }
    return true;
}

bool tb2_ui_preferences_save(void* storage, const Tb2UiPreferences* preferences) {
    if(!preferences || !ui_path_valid(preferences->package_dir, true) ||
       !ui_path_valid(preferences->output_dir, true) ||
       !tb2_server_change_valid(&preferences->server))
        return false;
    Tb2ServerValues values = preferences->server_values;
    uint8_t fields = preferences->server_fields;
    if(!fields && preferences->server.fields) {
        if(preferences->server.fields & TB2_SERVER_HOST) {
            memcpy(values.https_host, preferences->server.host, sizeof(preferences->server.host));
            memcpy(values.mqtt_host, preferences->server.host, sizeof(preferences->server.host));
            fields |= Tb2ServerOtaHost | Tb2ServerIciHost;
        }
        if(preferences->server.fields & TB2_SERVER_HTTPS) {
            values.https_port = tb2_server_port(&preferences->server, false);
            fields |= Tb2ServerOtaPort;
        }
        if(preferences->server.fields & TB2_SERVER_MQTT) {
            values.mqtt_port = tb2_server_port(&preferences->server, true);
            fields |= Tb2ServerIciPort;
        }
    }
    if(!ui_server_values_valid(&values, fields)) return false;
    uint8_t bytes[UI_PREFS_SIZE] = {0};
    ui_put32(bytes, UI_PREFS_MAGIC);
    ui_put32(bytes + 4, UI_PREFS_VERSION);
    /* Copy strings only: stale bytes after their terminators must never reach the SD. */
    memcpy(bytes + 8, preferences->package_dir, strlen(preferences->package_dir));
    memcpy(bytes + 8 + TB2_JOB_PATH_MAX, preferences->output_dir, strlen(preferences->output_dir));
    uint8_t* saved = bytes + 8 + 2U * TB2_JOB_PATH_MAX;
    memcpy(saved, values.https_host, strlen(values.https_host));
    memcpy(saved + TB2_SERVER_HOST_SIZE, values.mqtt_host, strlen(values.mqtt_host));
    saved[2U * TB2_SERVER_HOST_SIZE] = (uint8_t)values.https_port;
    saved[2U * TB2_SERVER_HOST_SIZE + 1U] = (uint8_t)(values.https_port >> 8U);
    saved[2U * TB2_SERVER_HOST_SIZE + 2U] = (uint8_t)values.mqtt_port;
    saved[2U * TB2_SERVER_HOST_SIZE + 3U] = (uint8_t)(values.mqtt_port >> 8U);
    saved[2U * TB2_SERVER_HOST_SIZE + 4U] = fields;
    saved[2U * TB2_SERVER_HOST_SIZE + 5U] = preferences->hardware_options;
    ui_put32(bytes + sizeof(bytes) - 4, tb2_job_crc(bytes, sizeof(bytes) - 4));
    return ui_write(storage, TB2_UI_PREFERENCES_PATH, bytes, sizeof(bytes));
}

bool tb2_ui_preferences_reset(void* storage) {
    FileInfo info;
    FS_Error existing = storage_common_stat(storage, TB2_UI_PREFERENCES_PATH, &info);
    if(existing == FSE_NOT_EXIST) return true;
    if(existing != FSE_OK || file_info_is_dir(&info)) return false;
    FS_Error error = storage_common_remove(storage, TB2_UI_PREFERENCES_PATH);
    if(error != FSE_OK && error != FSE_NOT_EXIST) return false;
    return storage_common_stat(storage, TB2_UI_PREFERENCES_PATH, &info) == FSE_NOT_EXIST;
}

static bool ui_job_load(
    void* storage,
    const char* directory,
    Tb2JobSpec* spec,
    uint32_t* metadata_crc,
    uint32_t* metadata_size) {
    memset(spec, 0, sizeof(*spec));
    char path[TB2_JOB_PATH_MAX];
    if(!ui_child(path, directory, "job.tb2")) return false;
    File* file = storage_file_alloc(storage);
    if(!file) return false;
    uint8_t header[UI_JOB_HEADER_SIZE];
    bool ok = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING) &&
              storage_file_read(file, header, sizeof(header)) == sizeof(header);
    uint32_t size = ok ? ui_get32(header + 4) : 0;
    uint8_t* bytes = malloc(TB2_JOB_SPEC_SIZE);
    ok = ok && ui_get32(header) == UI_JOB_MAGIC && bytes && tb2_job_spec_size(size) &&
         storage_file_size(file) == UI_JOB_HEADER_SIZE + size &&
         storage_file_read(file, bytes, size) == size &&
         ui_get32(header + 8) == tb2_job_crc(bytes, size) &&
         tb2_job_spec_decode(bytes, size, spec);
    free(bytes);
    ok = storage_file_close(file) && ok;
    storage_file_free(file);
    ok = ok && ui_path_valid(spec->source, false) && strcmp(spec->source, "/ext") &&
         ui_path_valid(spec->imported_package, true) &&
         memchr(spec->output_path, 0, sizeof(spec->output_path)) && spec->shared_image <= 2 &&
         (spec->shared_image != 2 || ui_path_valid(spec->output_path, false)) &&
         tb2_package_options_valid(&spec->options) && tb2_job_image_path(spec, directory, path);
    if(ok) {
        if(metadata_crc) *metadata_crc = ui_get32(header + 8);
        if(metadata_size) *metadata_size = size;
    } else {
        memset(spec, 0, sizeof(*spec));
    }
    return ok;
}

bool tb2_ui_job_load(void* storage, const char* directory, Tb2JobSpec* spec) {
    return spec && ui_job_load(storage, directory, spec, NULL, NULL);
}

/** Validate the actual on-card job before binding or trusting its UI status. */
static bool ui_binding(
    void* storage,
    const char* directory,
    const Tb2JobSpec* spec,
    uint32_t* crc,
    uint32_t* size) {
    if(!spec) return false;
    Tb2JobSpec* check = malloc(sizeof(*check));
    bool ok = check && ui_job_load(storage, directory, check, crc, size);
    if(ok) {
        /* Workflow permits only the displayed RTC to change on resume. Keep the
         * binding CRC from the original bytes, never from the refreshed spec. */
        memcpy(check->options.now, spec->options.now, TB2_DATE_SIZE);
        ok = tb2_job_spec_equal(spec, check);
    }
    free(check);
    return ok;
}

/** Read-only bounded journal validation. Never repair a torn tail or inspect artifacts. */
static Tb2UiState ui_legacy_state(void* storage, const char* directory, const Tb2JobSpec* spec) {
    char path[TB2_JOB_PATH_MAX];
    if(!ui_child(path, directory, "status.bin")) return Tb2UiUnknown;
    File* file = storage_file_alloc(storage);
    if(!file) return Tb2UiUnknown;
    bool opened = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING);
    bool missing = !opened && storage_file_get_error(file) == FSE_NOT_EXIST;
    uint64_t size = opened ? storage_file_size(file) : 0;
    bool ok = opened && size <= UI_JOURNAL_LIMIT * TB2_JOB_RECORD_SIZE;
    bool image_done = false, image_started = false, cancelled = false;
    Tb2JobRecord* records = calloc(2, sizeof(*records));
    uint8_t bytes[TB2_JOB_RECORD_SIZE];
    ok = ok && records;
    for(uint32_t sequence = 1; ok && sequence <= size / sizeof(bytes); sequence++) {
        Tb2JobRecord* current = records + 1;
        ok = storage_file_read(file, bytes, sizeof(bytes)) == sizeof(bytes) &&
             tb2_job_decode(bytes, sequence, current) && !cancelled;
        if(!ok) break;
        if(records->kind && current->kind != Tb2JobFileDone &&
           current->kind != Tb2JobFileDiscarded) {
            ok = false;
        } else if(current->kind == Tb2JobFilePending) {
            *records = *current;
        } else if(current->kind == Tb2JobFileDone || current->kind == Tb2JobFileDiscarded) {
            ok = records->kind && !strcmp(current->name, records->name) &&
                 current->size == records->size && !memcmp(current->digest, records->digest, 32);
            records->kind = 0;
        } else if(current->kind == Tb2JobReadDone) {
            Tb2ReadResult* read = malloc(sizeof(*read));
            ok = read && tb2_job_get_read(current, read);
            free(read);
        } else if(current->kind == Tb2JobImageStarted) {
            ok = !image_started && !image_done;
            image_started = true;
        } else if(current->kind == Tb2JobImageDone) {
            ok = !spec->shared_image || image_started;
            image_done = true;
        } else if(current->kind == Tb2JobCancelled) {
            cancelled = true;
        }
    }
    /* A damaged tail cannot prove successful completion or final cancellation. */
    bool whole = size % TB2_JOB_RECORD_SIZE == 0 && records && !records->kind;
    free(records);
    bool closed = storage_file_close(file);
    storage_file_free(file);
    if(missing) return Tb2UiIncomplete;
    if(!closed || !ok) return Tb2UiUnknown;
    if(!whole) return Tb2UiIncomplete;
    return cancelled ? Tb2UiAborted : image_done ? Tb2UiLegacyComplete : Tb2UiIncomplete;
}

Tb2UiStatus tb2_ui_status_read(void* storage, const char* directory, const Tb2JobSpec* spec) {
    Tb2UiStatus status = {0};
    uint32_t crc, size;
    char path[TB2_JOB_PATH_MAX];
    if(!ui_binding(storage, directory, spec, &crc, &size) ||
       !ui_child(path, directory, TB2_UI_STATUS_NAME))
        return status;
    uint8_t bytes[UI_STATUS_SIZE];
    int read = ui_read(storage, path, bytes, sizeof(bytes));
    if(!read) {
        status.state = ui_legacy_state(storage, directory, spec);
        return status;
    }
    if(read != 1 || ui_get32(bytes) != UI_STATUS_MAGIC || ui_get32(bytes + 4) != UI_VERSION ||
       ui_get32(bytes + 8) != crc || ui_get32(bytes + 12) != size ||
       ui_get32(bytes + 16) != tb2_job_crc(directory, strlen(directory)) ||
       ui_get32(bytes + 20) < Tb2UiPrepared || ui_get32(bytes + 20) > Tb2UiAborted ||
       ui_get32(bytes + 24) > Tb2WorkflowCancel ||
       ui_get32(bytes + sizeof(bytes) - 4) != tb2_job_crc(bytes, sizeof(bytes) - 4))
        return status;
    status.state = (Tb2UiState)ui_get32(bytes + 20);
    status.action = ui_get32(bytes + 24);
    status.result = (int32_t)ui_get32(bytes + 28);
    if(status.state == Tb2UiAborted && ui_legacy_state(storage, directory, spec) != Tb2UiAborted)
        memset(&status, 0, sizeof(status));
    return status;
}

bool tb2_ui_status_write(
    void* storage,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2UiStatus* status) {
    if(!status || status->state < Tb2UiPrepared || status->state > Tb2UiAborted ||
       status->action > Tb2WorkflowCancel)
        return false;
    uint32_t crc, size;
    char path[TB2_JOB_PATH_MAX];
    if(!ui_binding(storage, directory, spec, &crc, &size) ||
       !ui_child(path, directory, TB2_UI_STATUS_NAME) ||
       (status->state == Tb2UiAborted &&
        ui_legacy_state(storage, directory, spec) != Tb2UiAborted))
        return false;
    uint8_t bytes[UI_STATUS_SIZE] = {0};
    ui_put32(bytes, UI_STATUS_MAGIC);
    ui_put32(bytes + 4, UI_VERSION);
    ui_put32(bytes + 8, crc);
    ui_put32(bytes + 12, size);
    ui_put32(bytes + 16, tb2_job_crc(directory, strlen(directory)));
    ui_put32(bytes + 20, status->state);
    ui_put32(bytes + 24, status->action);
    ui_put32(bytes + 28, (uint32_t)status->result);
    ui_put32(bytes + sizeof(bytes) - 4, tb2_job_crc(bytes, sizeof(bytes) - 4));
    return ui_write(storage, path, bytes, sizeof(bytes));
}
