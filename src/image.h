#pragma once

#include "reader.h"
#include "server.h"
#include "settings.h"

/** Target is a distinct file owned by the job. Source has no write callback.
 * reset() truncates ONLY that work file; never the dump or completed result.
 * All transfers must be exact; sync must reach the SD storage API. */
typedef struct {
    void* context;
    bool (*reset)(void* context);
    bool (*read)(void* context, uint32_t offset, void* data, size_t size);
    bool (*write)(void* context, uint32_t offset, const void* data, size_t size);
    bool (*sync)(void* context);
    uint64_t (*size)(void* context);
} Tb2ImageTarget;

typedef struct {
    uint8_t sha256[32];
    bool ca_changed;
    bool settings_changed;
    bool endpoints_known; /* Only explicit settings change/restore interprets endpoints. */
    Tb2ServerValues endpoints;
    Tb2SettingsSnapshot settings;
    char error[224];
} Tb2ImageResult;

/** Donor plaintext must come from a validated CA/client/private set. read() is
 * bounded to one file and must reject a changed donor binding on every call. */
typedef struct {
    void* context;
    bool (*read)(void*, unsigned index, uint8_t* bytes, size_t capacity, size_t* size);
    const Tb2ServerRecords* connection;
} Tb2CertificateRestore;

/** Copy, CA-only modification, then full validation. RAM is independent of
 * image size. Restart after interruption begins with reset + original copy.
 * ca_der must be the validated CA from the approved certificate package. */
int tb2_image_build(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca_der,
    size_t ca_size,
    Tb2ImageResult* result);

/** Revalidate an existing output without changing a byte. Also used on resume;
 * a DONE journal entry alone must never authorize a result for flashing. */
int tb2_image_verify(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca_der,
    size_t ca_size,
    Tb2ImageResult* result);

/** Explicit server override. Keep (NULL/zero fields) never parses /settings.
 * Verification compares the complete expected transformed file, including all
 * unknown bytes, after discarding filesystem caches. */
int tb2_image_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca_der,
    size_t ca_size,
    const Tb2ServerChange* change,
    Tb2ImageResult* result,
    bool build);

/** Keyless settings-only processing. The complete source is copied and only
 * the logical /settings file may change. Certificate files and every other
 * byte are independently included in the unchanged-data checks. */
int tb2_image_settings_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2ReadResult* inspected,
    const Tb2SettingsPatch* patch,
    Tb2ImageResult* result,
    bool build);
/** Combined certificate and settings modification used by Guided modify. */
int tb2_image_settings_cert_process(
    Tb2Reader*,
    Tb2ImageTarget*,
    const Tb2InputKey*,
    const Tb2ReadResult*,
    const uint8_t* ca_der,
    size_t ca_size,
    const Tb2SettingsPatch*,
    Tb2ImageResult*,
    bool build);
int tb2_image_settings_snapshot(
    Tb2Reader* source,
    const Tb2ReadResult* inspected,
    Tb2SettingsSnapshot* snapshot);
/** Exactly three encrypted certificate files may change. Authentication files,
 * unrelated settings/files and bytes outside LittleFS are independently compared. */
int tb2_image_restore(
    Tb2Reader*,
    Tb2ImageTarget*,
    const Tb2InputKey*,
    const Tb2ReadResult*,
    const Tb2CertificateRestore*,
    Tb2ImageResult*,
    bool build);
