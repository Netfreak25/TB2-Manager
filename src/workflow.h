#pragma once
#include "image.h"
#include "job.h"

typedef enum {
    Tb2FileRead,
    Tb2FileNew,
    Tb2FileUpdate
} Tb2FileMode;
typedef struct {
    void* context;
    void* (*open)(void* context, const char* path, Tb2FileMode mode);
    bool (*close)(void* context, void* file);
    size_t (*read)(void* context, void* file, void* data, size_t size);
    size_t (*write)(void* context, void* file, const void* data, size_t size);
    bool (*seek)(void* context, void* file, uint32_t offset);
    uint64_t (*size)(void* context, void* file);
    bool (*sync)(void* context, void* file);
    bool (*truncate)(void* context, void* file); /* At current position. */
    int (*exists)(void* context, const char* path); /* 1 present, 0 absent, -1 error. */
    bool (*mkdir)(void* context, const char* path); /* Existing directory is OK. */
    bool (*remove)(void* context, const char* path); /* Exact job-owned partial file only. */
    bool (*event)(void* context, const char* operation, int rc, const char* detail);
    bool (*cancelled)(void* context);
    void (*progress)(void* context, const char* stage, uint32_t done, uint32_t total);
    int (*random)(void* context, unsigned char* data, size_t size);
    void** image_lease; /* Optional resident owner receives the freshly verified handle. */
    /* Resident-owned directory handles; read returns 1 entry, 0 end, -1 error.
     * Enumeration is driven by workers/ticks, never drawing/input callbacks. */
    void* (*dir_open)(void* context, const char* path);
    int (*dir_read)(void* context, void* directory, char* name, size_t capacity, bool* is_dir);
    bool (*dir_close)(void* context, void* directory);
    bool (*move_new)(void* context, const char* source, const char* target);
} Tb2WorkflowIO;

typedef enum {
    Tb2WorkflowInspect,
    Tb2WorkflowBuild,
    Tb2WorkflowCancel,
    Tb2WorkflowPreviewServer
} Tb2WorkflowAction;
typedef struct {
    Tb2ReadResult read;
    Tb2PackageResult package;
    Tb2ImageResult image;
    Tb2ServerValues server_values; /* Explicit, read-only pre-job preview. */
    bool complete; /* Only true after fresh validation, never solely from journal. */
    bool resumed;
    char error[224];
} Tb2WorkflowResult;

/** CREATE_NEW metadata in a fresh caller-owned directory. Never stores keys. */
bool tb2_workflow_create(Tb2WorkflowIO* io, const char* directory, const Tb2JobSpec* spec);
bool tb2_workflow_load(Tb2WorkflowIO* io, const char* directory, Tb2JobSpec* spec);
/** Inspect only extracts/validates. Build requires the exact missing-file mask
 * confirmed by the user. Retry rechecks every completed artifact; interrupted
 * image writes start from the original. Completed images are verified read-only. */
int tb2_workflow_run(
    Tb2WorkflowIO* io,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2InputKey* key,
    Tb2WorkflowAction action,
    uint32_t approved_missing,
    Tb2WorkflowResult* result);
int tb2_workflow_run_patch(
    Tb2WorkflowIO*,
    const char* directory,
    const Tb2JobSpec*,
    const Tb2InputKey*,
    const Tb2SettingsPatch*,
    Tb2WorkflowAction,
    uint32_t approved_missing,
    Tb2WorkflowResult*);

/** Settings-only build/verify path. No key, certificate package or plaintext
 * certificate backup is opened. The approved patch is supplied by the
 * resident controller (or its CRC-checked private resume sidecar). */
