#include "probe.h"
#include "workflow.h"
#include "native_io.h"
#include "backend.h"
#include "setup.h"
#include "store.h"
#include "fliptdi.h"
#include <flipper_application/flipper_application.h>
#include <loader/firmware_api/firmware_api.h>
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/submenu.h>
#include <gui/view_dispatcher.h>
#include <storage/storage.h>
#include <toolbox/version.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __GNUC__
/* Keep -Os inlining decisions, but do not clone controller phases. */
#pragma GCC optimize("no-ipa-cp-clone")
#endif

#define TAG                 "TB2Builder"
#define APP_ROOT            TB2_JOBS_ROOT
#define WORKER_STACK        8192U
#define UI_TICK_MS          100U
#define LOG_SYNC_INTERVAL   32U
#define REQUIRED_FREE_BYTES (TB2_IMAGE_SIZE + 32U * 1024U * 1024U)
#define SD_RETRY            "SD error. Check card."
#define PROCESSOR_RETRY     "Processing failed."

typedef enum {
    ModuleCore,
    ModuleSetup,
    ModuleAux,
    ModuleSpi,
    ModuleExport,
    ModuleCertificates,
    ModuleBoxes,
    ModuleStore,
    ModuleImports,
    ModuleFlipTdi
} ModuleKind;
typedef enum {
    ScreenRunning,
    ScreenCancel,
    ScreenAbort,
    ScreenError
} Screen;
typedef enum {
    ControlContinue = 10,
    ControlPause,
    ControlAbort
} Control;
typedef struct {
    Storage* storage;
    File* log;
    Gui* gui;
    ViewDispatcher* dispatcher;
    DialogEx* dialog;
    Submenu* controls;
    FuriString* key_path;
    FuriThread* worker;
    const Tb2Backend* backend;
    const Tb2Setup* setup;
    const Tb2Spi* spi;
    const Tb2Store* store;
    FuriMutex* mutex;
    atomic_bool cancel, finished, abort_job, exit_after_stop;
    atomic_bool waiting_for_chip;
    bool log_failed, running, key_from_file;
    bool resume_job, metadata_ready;
    bool hardware_worker, historical, progress_indeterminate;
    Tb2SpiAction spi_action;
    void* file_lease;
    bool controls_open; /* Guarded by mutex; worker claims completion once. */
    Tb2ModifyMode modify_mode;
    bool settings_worker, settings_only;
    bool restore_connection;
    bool record_task_worker, package_worker;
    Tb2RecordTask* record_task;
    Tb2WorkflowAction action;
    Tb2UiStatus status;
    uint32_t approved_missing, progress_percent, sequence, started;
    char progress_stage[32];
    Screen screen;
    int result;
    bool known_uid, identification_worker;
    uint8_t hardware_options;
    Tb2InputKey input_key;
    Tb2InputKey donor_key;
    char run_dir[128], error[256], display[192], warning[224];
    char selected_path[TB2_JOB_PATH_MAX];
    char box_id[TB2_RECORD_ID_SIZE], version_id[TB2_RECORD_ID_SIZE];
    char selected_version[TB2_RECORD_ID_SIZE];
    char original_version[TB2_RECORD_ID_SIZE];
    char box_alias[TB2_RECORD_ALIAS_SIZE];
    uint8_t expected_uid[8];
    char artifact_directory[TB2_JOB_PATH_MAX];
    Tb2Operation operation;
    Tb2SpiResult spi_result;
    Tb2ImageIdentity identity;
    Tb2SpiReceipt chip;
    /* Keep the large Modify payloads after the frequently accessed controller
     * state. This private layout avoids long-offset ARM accesses in every phase. */
    Tb2JobSpec spec;
    Tb2WorkflowResult flow;
    Tb2SettingsSnapshot settings_snapshot;
    Tb2SettingsPatch settings_patch;
} ProbeApp;

static bool save_status(ProbeApp* app, Tb2UiState state);
static bool invoke_setup(ProbeApp* app, Tb2SetupRequest* request);
static void draw_screen(ProbeApp* app);
static bool operation_access(ProbeApp* app, Tb2WorkflowIO* fs, Tb2OperationAccess access);
static Tb2RecordResult store_access(ProbeApp*, Tb2WorkflowIO*, Tb2StoreRequest*);

static bool modules_idle(const ProbeApp* app) {
    return !app->backend && !app->setup && !app->spi && !app->store;
}

static void ui_status(ProbeApp* app, const char* text, bool error) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(error && !app->error[0]) strlcpy(app->error, text, sizeof(app->error));
    furi_mutex_release(app->mutex);
}

static bool log_event(void* context, const char* operation, int code, const char* detail) {
    ProbeApp* app = context;
    char line[512];
    int n = snprintf(
        line,
        sizeof(line),
        "%lu|%s|%d|%s\n",
        (unsigned long)++app->sequence,
        operation,
        code,
        detail);
    if(n < 0 || (size_t)n >= sizeof(line)) {
        app->log_failed = true;
        return false;
    }
    FURI_LOG_D(TAG, "%s", line);
    if(!strcmp(operation, "package_step")) ui_status(app, detail, false);
    if(!app->log) return true; /* Pre-job browsing also reaches Furi debug. */
    if(app->log_failed || storage_file_write(app->log, line, (size_t)n) != (size_t)n ||
       (app->sequence % LOG_SYNC_INTERVAL == 0 && !storage_file_sync(app->log))) {
        app->log_failed = true;
        ui_status(app, SD_RETRY, true);
        FURI_LOG_E(TAG, "log write/sync failed: %s", storage_file_get_error_desc(app->log));
        return false;
    }
    return true;
}

static bool cancel_requested(void* context) {
    return atomic_load(&((ProbeApp*)context)->cancel);
}

static int random_data(void* context, unsigned char* data, size_t size) {
    UNUSED(context);
    if(size > UINT32_MAX) return -1;
    if(size) furi_hal_random_fill_buf(data, (uint32_t)size);
    return 0;
}

static void reader_progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    ProbeApp* app = context;
    uint32_t percent = total ? (uint32_t)((uint64_t)done * 100 / total) : 0;
    if(!strcmp(app->progress_stage, stage) && app->progress_percent == percent) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    strlcpy(app->progress_stage, stage, sizeof(app->progress_stage));
    app->progress_percent = percent;
    app->progress_indeterminate = total == 0;
    furi_mutex_release(app->mutex);
}

static Tb2WorkflowIO filesystem(ProbeApp* app, Tb2NativeIO* native) {
    *native = (Tb2NativeIO){
        .storage = app->storage,
        .context = app,
        .event = log_event,
        .cancelled = cancel_requested,
        .progress = reader_progress,
        .random = random_data};
    Tb2WorkflowIO io = tb2_native_io(native);
    io.image_lease = &app->file_lease;
    return io;
}

static void* open_log(void* context, const char* path) {
    ProbeApp* app = context;
    app->log = storage_file_alloc(app->storage);
    return storage_file_open(app->log, path, FSAM_READ_WRITE, FSOM_OPEN_ALWAYS) ? app->log : NULL;
}

static bool prepare_run(ProbeApp* app, Tb2WorkflowIO* fs) {
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return false;
    r->action = Tb2StorePreflight;
    r->run_directory = app->run_dir;
    r->log_context = app;
    r->open_log = open_log;
    r->log_sequence = &app->sequence;
    r->workflow_action = app->action;
    r->resume = app->resume_job;
    r->required_bytes = app->action == Tb2WorkflowCancel ? 0 :
                        app->hardware_worker ? (tb2_operation_flash(app->operation.kind) ?
                                                    1024U * 1024U :
                                                    TB2_IMAGE_SIZE + 1024U * 1024U) :
                                               REQUIRED_FREE_BYTES;
    bool ready = !store_access(app, fs, r);
    free(r);
    if(!ready) return false;
    if(app->hardware_worker || app->operation.kind == Tb2OperationRestore) return true;
    if(!app->operation.kind) {
        app->operation.kind = Tb2OperationModify;
        app->operation.state = Tb2UiPrepared;
    }
    if(!app->metadata_ready || !app->operation.modify_bound) {
        if(!operation_access(app, fs, Tb2OperationBind)) return false;
        app->metadata_ready = true;
    }
    if(app->operation.kind && !app->operation.sequence &&
       !operation_access(app, fs, Tb2OperationCreate))
        return false;
    return true;
}

static bool module_error(ProbeApp* app, const char* stage, int code, const char* detail) {
    if(!code) return false;
    log_event(app, stage, code, detail);
    bool preload = !strcmp(stage, "module_preload");
    ui_status(
        app,
        preload && code == FlipperApplicationPreloadStatusNotEnoughMemory ?
            "Not enough memory to load component" :
        preload && code == FlipperApplicationPreloadStatusInvalidFile ?
            "App component missing or unreadable" :
            "App component incompatible",
        true);
    return true;
}

static bool load_module(ProbeApp* app, FlipperApplication* module, ModuleKind kind) {
    static const struct {
        const char* id;
        uint8_t api, interface;
    } modules[] = {
        {TB2_BACKEND_ID, TB2_BACKEND_API, 0},
        {TB2_SETUP_ID, TB2_SETUP_API, 1},
        {TB2_AUX_ID, TB2_SETUP_API, 1},
        {TB2_SPI_ID, TB2_SPI_API, 2},
        {TB2_EXPORT_ID, TB2_SETUP_API, 1},
        {TB2_CERT_ID, TB2_BACKEND_API, 0},
        {TB2_BOXES_ID, TB2_SETUP_API, 1},
        {TB2_STORE_ID, TB2_STORE_API, 3},
        {TB2_IMPORTS_ID, TB2_EDITOR_API, 1},
        {TB2_FLIPTDI_ID, TB2_FLIPTDI_API, 1}};
    if((unsigned)kind >= sizeof(modules) / sizeof(modules[0])) return false;
    const char* id = modules[kind].id;
    uint32_t api = modules[kind].api;
    if(app->log && !storage_file_sync(app->log)) {
        app->log_failed = true;
        ui_status(app, SD_RETRY, true);
        return false;
    }
    char detail[96];
    int path_size = snprintf(
        detail,
        sizeof(detail),
        APP_ASSETS_PATH("plugins/%s.fal"),
        kind == ModuleCore ? TB2_BACKEND_FILE : id);
    if(path_size < 0 || path_size >= (int)sizeof(detail)) return false;
    log_event(app, "module_select", 0, id);
    FlipperApplicationPreloadStatus preloaded = flipper_application_preload(module, detail);
    if(module_error(
           app,
           "module_preload",
           preloaded,
           flipper_application_preload_status_to_string(preloaded)))
        return false;
    FlipperApplicationLoadStatus mapped = flipper_application_map_to_memory(module);
    if(module_error(app, "module_map", mapped, flipper_application_load_status_to_string(mapped)))
        return false;
    const FlipperAppPluginDescriptor* descriptor =
        flipper_application_plugin_get_descriptor(module);
    if(module_error(
           app,
           "module_descriptor",
           !flipper_application_is_plugin(module) || !descriptor || !descriptor->appid ||
               strcmp(descriptor->appid, id) || descriptor->ep_api_version != api ||
               !descriptor->entry_point,
           id))
        return false;
    bool invalid;
    if(kind == ModuleSpi) {
        const Tb2Spi* spi = descriptor->entry_point;
        invalid = !spi->run || !spi->operation;
        if(!invalid) app->spi = spi;
    } else if(modules[kind].interface == 3) {
        const Tb2Store* store = descriptor->entry_point;
        invalid = !store->run;
        if(!invalid) app->store = store;
    } else if(modules[kind].interface == 1) {
        const Tb2Setup* setup = descriptor->entry_point;
        invalid = !setup->run;
        if(!invalid) app->setup = setup;
    } else {
        const Tb2Backend* backend = descriptor->entry_point;
        invalid = kind == ModuleCore ?
                      !backend->run || !backend->crypto_peak || !backend->inspect :
                      !backend->run || !backend->crypto_peak || !backend->package_import;
        if(!invalid) app->backend = backend;
    }
    return !module_error(app, "module_entry", invalid, id);
}

/* Keep the shared unload sequence once in the resident frontend. */
static __attribute__((noinline)) void close_module(ProbeApp* app, FlipperApplication* module) {
    app->backend = NULL;
    app->setup = NULL;
    app->spi = NULL;
    app->store = NULL;
    flipper_application_free(module);
}

/** No module-owned pointer crosses a phase boundary. Only value results and the
 * resident IO adapter survive; each module closes all of its own file handles. */
static int32_t backend_phase(ProbeApp* app, Tb2WorkflowIO* fs, ModuleKind kind) {
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    bool loaded = load_module(app, module, kind);
    int rc = TB2_PROBE_IO_ERROR;
    if(loaded) {
        if((app->settings_patch.categories || app->operation.settings_only) &&
           app->backend->combined)
            rc = app->backend->combined(
                fs,
                app->run_dir,
                &app->spec,
                &app->input_key,
                &app->settings_patch,
                app->action,
                app->approved_missing,
                &app->flow);
        else
            rc = app->backend->run(
                fs,
                app->run_dir,
                &app->spec,
                &app->input_key,
                app->action,
                app->approved_missing,
                &app->flow);
    }
    close_module(app, module);
    return rc;
}

/** Serialize the last accepted user request with the worker's closing phase. */
static bool close_controls(ProbeApp* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->controls_open = false;
    bool abort = atomic_load(&app->abort_job);
    furi_mutex_release(app->mutex);
    return abort;
}

static int32_t run_spi(ProbeApp* app, Tb2SpiRequest* request);
#include "app_records.c"
#include "app_hardware.c"
#include "app_restore.c"
#include "app_record_tasks.c"

static int32_t worker(void* context) {
    ProbeApp* app = context;
    if(app->operation.kind == Tb2OperationRestore) return restore_worker(app);
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    app->result = TB2_PROBE_IO_ERROR;
    memset(&app->flow, 0, sizeof(app->flow));
    if(app->settings_worker) {
        ui_status(app, "Reading settings", false);
        Tb2BackendInspect* request = calloc(1, sizeof(*request));
        if(request) {
            request->action = Tb2BackendInspectSettings;
            request->io = &fs;
            request->source = app->spec.source;
            request->read = &app->flow.read;
            request->settings = &app->settings_snapshot;
            request->identity = &app->identity;
            app->result = core_inspect(app, request);
            free(request);
        }
        if(app->result) ui_status(app, "Settings read failed.", true);
        close_controls(app);
        atomic_store(&app->finished, true);
        return 0;
    }
    bool preview = app->action == Tb2WorkflowPreviewServer;
    if(preview || (prepare_run(app, &fs) && begin_modify_operation(app, &fs) &&
                   save_status(app, Tb2UiRunning))) {
        ui_status(app, "Loading", false);
        if(!app->settings_only)
            log_event(
                app,
                "key_input",
                0,
                app->key_from_file ? "Key file; redacted" : "Serial; redacted");
        bool key_ok = app->settings_only || app->action == Tb2WorkflowCancel ||
                      !app->key_from_file || load_key_file(app);
        if(key_ok) {
            bool build = app->action == Tb2WorkflowBuild;
            app->result = backend_phase(
                app,
                &fs,
                app->settings_only ? ModuleCore :
                build              ? ModuleCertificates :
                                     ModuleCore);
            if(!app->result && !build && !preview && app->operation.kind == Tb2OperationAio &&
               memcmp(app->operation.dump.digest, app->flow.read.source_sha256, 32)) {
                app->result = TB2_PROBE_CHECK_FAILED;
                snprintf(app->flow.error, sizeof(app->flow.error), "Dump changed.");
            }
            if(!app->result && !build && !preview && app->action != Tb2WorkflowCancel)
                app->result = record_source(app, &fs);
            if(!app->settings_only && !preview && !app->result &&
               app->action != Tb2WorkflowCancel && !atomic_load(&app->cancel) &&
               !atomic_load(&app->abort_job)) {
                Tb2WorkflowResult previous = app->flow;
                app->result = backend_phase(app, &fs, build ? ModuleCore : ModuleCertificates);
                if(build)
                    app->flow.package = previous.package;
                else {
                    app->flow.image = previous.image;
                    app->flow.complete = previous.complete && !app->result;
                }
            }
            if(app->result && app->result != TB2_PACKAGE_MISSING)
                ui_status(app, app->flow.error, true);
        }
        if(!app->result && app->flow.complete && app->operation.kind &&
           !atomic_load(&app->cancel) && !atomic_load(&app->abort_job)) {
            memcpy(app->operation.image_hash, app->flow.image.sha256, 32);
            memcpy(app->operation.package_hash, app->flow.package.package_sha256, 32);
            memcpy(app->operation.ca_hash, app->flow.package.ca_sha256, 32);
            if(app->settings_only) {
                app->result = record_publish(
                    app,
                    &fs,
                    app->operation.image,
                    app->operation.image_hash,
                    Tb2WorkshopTarget,
                    true);
                if(!app->result) {
                    Tb2StoreRequest* preferences = calloc(1, sizeof(*preferences));
                    if(preferences) {
                        preferences->action = Tb2StoreSettingsPreferences;
                        preferences->settings_patch = &app->settings_patch;
                        if(store_access(app, &fs, preferences))
                            snprintf(app->warning, sizeof(app->warning), "Presets not saved.");
                        free(preferences);
                    }
                }
                if(!app->result) app->result = continue_aio_flash(app, &fs);
            } else if(app->spec.export_archive) {
                app->operation.phase = Tb2PhaseExport;
                app->result = export_and_flash(app, &fs);
            } else {
                app->result = record_publish(
                    app,
                    &fs,
                    app->operation.image,
                    app->operation.image_hash,
                    Tb2WorkshopTarget,
                    true);
            }
        }
        bool abort = close_controls(app);
        if(key_ok && abort && !app->log_failed && !preview) {
            log_event(app, "user_abort_confirmed", 0, "keep inputs");
            atomic_store(&app->cancel, false);
            app->action = Tb2WorkflowCancel;
            app->result = backend_phase(app, &fs, ModuleCore);
        }
        if(app->exit_after_stop) log_event(app, "user_pause", 0, "paused");
    } else
        ui_status(app, app->warning[0] ? app->warning : SD_RETRY, true);
    /* Nothing from the backend is referenced after this point. UI selection
     * is only enabled after tick() has also joined/freed the worker thread. */
    if(app->log_failed) app->result = TB2_PROBE_IO_ERROR;
    log_event(
        app,
        "run_closed",
        app->result,
        app->flow.complete && !app->result ? "image verified" : "inputs kept");
    close_worker_log(app);
    atomic_store(&app->finished, true);
    return 0;
}

/** The only setup operation permitted during a worker is the headless status
 * write. GUI setup runs with the processing dispatcher stopped and no worker. */
static bool invoke_setup(ProbeApp* app, Tb2SetupRequest* request) {
    bool headless = request->kind == Tb2SetupCreate || request->kind == Tb2SetupOperation ||
                    request->kind == Tb2SetupExport;
    if(!modules_idle(app) || (!headless && (app->worker || app->running))) return false;
    request->storage = app->storage;
    request->gui = app->gui;
    request->context = app;
    request->event = log_event;
    request->spec = &app->spec;
    request->input_key = &app->input_key;
    request->donor_key = &app->donor_key;
    request->settings_snapshot = &app->settings_snapshot;
    request->settings_patch = &app->settings_patch;
    request->image_identity = &app->identity;
    request->modify_mode = app->modify_mode;
    request->restore_connection = app->restore_connection;
    request->settings_only = app->settings_only;
    enum {
        SetupNeedsTask = 128U
    };
    static const uint8_t setup_modules[Tb2SetupAioImport + 1] = {
        ModuleAux,
        ModuleAux,
        ModuleAux,
        ModuleExport,
        ModuleAux,
        ModuleAux,
        ModuleSetup,
        ModuleExport,
        ModuleExport,
        ModuleSetup,
        ModuleSetup,
        ModuleAux,
        ModuleSetup,
        ModuleSetup,
        ModuleAux,
        ModuleSetup,
        ModuleAux,
        ModuleSetup,
        ModuleSetup,
        ModuleSetup,
        ModuleExport,
        ModuleAux,
        ModuleAux,
        ModuleAux,
        ModuleSetup,
        ModuleExport,
        ModuleBoxes | SetupNeedsTask,
        ModuleBoxes | SetupNeedsTask,
        ModuleExport,
        ModuleImports,
        ModuleBoxes,
        ModuleSetup,
        ModuleExport,
        ModuleSetup,
        ModuleBoxes | SetupNeedsTask,
        ModuleExport,
        ModuleBoxes,
        ModuleImports | SetupNeedsTask,
        ModuleImports | SetupNeedsTask,
        ModuleImports | SetupNeedsTask,
        ModuleImports | SetupNeedsTask,
        ModuleFlipTdi,
        ModuleAux,
        ModuleAux,
        ModuleAux,
        ModuleImports,
        ModuleImports | SetupNeedsTask};
    uint8_t module_kind = setup_modules[request->kind];
    if((module_kind & SetupNeedsTask) && !app->record_task)
        app->record_task = calloc(1, sizeof(*app->record_task));
    request->record_task = app->record_task;
    request->flow = &app->flow;
    request->server_values = app->flow.server_values;
    request->result = app->result;
    request->status = app->status;
    request->operation = &app->operation;
    request->historical = app->historical;
    memcpy(request->box_id, app->box_id, sizeof(request->box_id));
    memcpy(request->box_alias, app->box_alias, sizeof(request->box_alias));
    memcpy(request->version_id, app->version_id, sizeof(request->version_id));
    strlcpy(request->directory, app->run_dir, sizeof(request->directory));
    if(request->kind == Tb2SetupOriginalPrompt) strcpy(request->version_id, app->original_version);
    if(request->kind == Tb2SetupRestoreDonor) strcpy(request->version_id, app->selected_version);
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    request->key_from_file = app->key_from_file;
    snprintf(
        request->key_path, sizeof(request->key_path), "%s", furi_string_get_cstr(app->key_path));
    bool defaults = request->kind == Tb2SetupNew || request->kind == Tb2SetupCertificates ||
                    request->kind == Tb2SetupTarget || request->kind == Tb2SetupServerChoice ||
                    request->kind == Tb2SetupRecordKey;
    if(defaults || request->kind == Tb2SetupLoadConfig) {
        if(defaults) request->defaults = calloc(1, sizeof(*request->defaults));
        Tb2StoreRequest* config = calloc(1, sizeof(*config));
        if(config) {
            config->action = Tb2StoreDefaults;
            config->selection = request;
        }
        bool ready = config && (!defaults || request->defaults) && !store_access(app, &fs, config);
        free(config);
        if(!ready) {
            free(request->defaults);
            request->defaults = NULL;
            return false;
        }
        if(!defaults) return true;
    }
    /* Stop belongs to the joined worker, not the next record selection. */
    if(!app->worker && !app->running) atomic_store(&app->cancel, false);
    if(!request->filesystem) request->filesystem = &fs;
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    bool ok = load_module(app, module, module_kind & ~SetupNeedsTask) && app->setup->run(request);
    if(!ok && request->error[0]) strlcpy(app->error, request->error, sizeof(app->error));
    close_module(app, module);
    if(request->filesystem == &fs) request->filesystem = NULL;
    if(defaults) {
        free(request->defaults);
        request->defaults = NULL;
    }
    return ok;
}

static bool save_status(ProbeApp* app, Tb2UiState state) {
    if(!app->metadata_ready) return false;
    app->status = (Tb2UiStatus){.state = state, .action = app->action, .result = app->result};
    Tb2StoreRequest* request = calloc(1, sizeof(*request));
    if(!request) {
        strlcpy(app->warning, "Status save failed.", sizeof(app->warning));
        return false;
    }
    request->action = Tb2StoreStatus;
    request->spec = &app->spec;
    request->status = app->status;
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    bool ok = !store_access(app, &fs, request);
    if(!ok)
        strlcpy(
            app->warning,
            request->error[0] ? request->error : "Status save failed.",
            sizeof(app->warning));
    free(request);
    return ok;
}

/** A finished image is historical only after all worker-owned handles closed.
 * Persistence warnings never replace the actual workflow outcome. */
static void finish_worker(ProbeApp* app) {
    if(!app->worker) return;
    furi_thread_join(app->worker);
    furi_thread_free(app->worker);
    app->worker = NULL;
    app->running = false;
    if(app->identification_worker || app->record_task_worker || app->package_worker) return;
    if(app->hardware_worker) {
        finish_hardware(app);
        record_event(app);
        return;
    }
    if(app->action == Tb2WorkflowPreviewServer) return;
    Tb2UiState state = Tb2UiFailed;
    if(!app->result && app->flow.complete)
        state = Tb2UiComplete;
    else if(app->result == TB2_PROBE_CANCELLED)
        state = app->action == Tb2WorkflowCancel ? Tb2UiAborted : Tb2UiPaused;
    else if(app->action == Tb2WorkflowInspect && (!app->result || app->result == TB2_PACKAGE_MISSING))
        state = Tb2UiPrepared;
    app->status = (Tb2UiStatus){.state = state, .action = app->action, .result = app->result};
    if(app->metadata_ready) save_status(app, state);
    if(app->operation.kind && app->operation.sequence) {
        Tb2Operation* op = &app->operation;
        op->state = state;
        op->result = app->result;
        if(atomic_load(&app->abort_job)) op->state = Tb2UiAborted;
        if(state == Tb2UiComplete) op->phase = Tb2PhaseComplete;
        Tb2NativeIO native;
        Tb2WorkflowIO fs = filesystem(app, &native);
        operation_access(app, &fs, Tb2OperationSave);
    }
    record_event(app);
    if(app->result || app->operation.kind != Tb2OperationAio) release_lease(app);
}

static void dialog_result(DialogExResult result, void* context) {
    ProbeApp* app = context;
    view_dispatcher_send_custom_event(app->dispatcher, (uint32_t)result);
}
static void control_result(void* context, uint32_t result) {
    ProbeApp* app = context;
    view_dispatcher_send_custom_event(app->dispatcher, result);
}
/* Shared by the startup screen and the existing processing/error dialog. */
static void show_dialog(ProbeApp* app, const char* header, const char* text) {
    dialog_ex_set_header(app->dialog, header, 64, 0, AlignCenter, AlignTop);
    dialog_ex_set_text(app->dialog, text, 64, 16, AlignCenter, AlignTop);
    view_dispatcher_switch_to_view(app->dispatcher, 0);
}

static void draw_screen(ProbeApp* app) {
    if(app->screen == ScreenCancel) {
        submenu_reset(app->controls);
        submenu_set_header(app->controls, "Processing");
        submenu_add_item(app->controls, "Continue", ControlContinue, control_result, app);
        submenu_add_item(app->controls, "Stop", ControlPause, control_result, app);
        submenu_add_item(app->controls, "Abort job", ControlAbort, control_result, app);
        view_dispatcher_switch_to_view(app->dispatcher, 1);
        return;
    }
    dialog_ex_reset(app->dialog);
    dialog_ex_set_context(app->dialog, app);
    dialog_ex_set_result_callback(app->dialog, dialog_result);
    const char* header = "TB2 Manager " TB2_PROBE_VERSION;
    if(app->screen == ScreenAbort) {
        header = "Abort this job?";
        strlcpy(app->display, "Remove partial image?\nBackups kept.", sizeof(app->display));
        dialog_ex_set_left_button_text(app->dialog, "No");
        dialog_ex_set_right_button_text(app->dialog, "Yes");
    } else if(app->screen == ScreenError) {
        header = "Selection failed";
        strlcpy(
            app->display,
            app->error[0] ? app->error : "Failed.\nSee Details.",
            sizeof(app->display));
        dialog_ex_set_center_button_text(app->dialog, "Close");
    } else {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        char progress[24];
        if(atomic_load(&app->waiting_for_chip))
            strlcpy(progress, "Back: cancel", sizeof(progress));
        else if(app->progress_indeterminate)
            strlcpy(progress, "Waiting", sizeof(progress));
        else
            snprintf(progress, sizeof(progress), "%lu %%", (unsigned long)app->progress_percent);
        snprintf(
            app->display,
            sizeof(app->display),
            "%s\n%s\n%lu s elapsed",
            atomic_load(&app->cancel) ? "Stop requested" :
            app->progress_stage[0]    ? app->progress_stage :
                                        "Preparing SD",
            progress,
            (unsigned long)((furi_get_tick() - app->started) / furi_kernel_get_tick_frequency()));
        furi_mutex_release(app->mutex);
    }
    show_dialog(app, header, app->display);
}
static bool navigation(void* context) {
    ProbeApp* app = context;
    if(app->screen == ScreenError) {
        view_dispatcher_stop(app->dispatcher);
        return true;
    }
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    bool waiting = app->screen == ScreenRunning && app->controls_open &&
                   atomic_load(&app->waiting_for_chip);
    if(waiting) atomic_store(&app->cancel, true);
    furi_mutex_release(app->mutex);
    if(!waiting) app->screen = app->screen == ScreenRunning ? ScreenCancel : ScreenRunning;
    draw_screen(app);
    return true;
}
static bool custom_event(void* context, uint32_t event) {
    ProbeApp* app = context;
    if(app->screen == ScreenError) {
        view_dispatcher_stop(app->dispatcher);
        return true;
    }
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(!app->controls_open) {
        furi_mutex_release(app->mutex);
        app->screen = ScreenRunning;
        draw_screen(app);
        return true;
    }
    if(app->screen == ScreenCancel) {
        if(event == ControlPause) {
            app->exit_after_stop = true;
            atomic_store(&app->cancel, true);
        }
        app->screen = event == ControlAbort ? ScreenAbort : ScreenRunning;
    } else if(app->screen == ScreenAbort) {
        if(event == DialogExResultRight) {
            atomic_store(&app->abort_job, true);
            atomic_store(&app->cancel, true);
        }
        app->screen = ScreenRunning;
    }
    furi_mutex_release(app->mutex);
    draw_screen(app);
    return true;
}
static void tick(void* context) {
    ProbeApp* app = context;
    if(atomic_load(&app->finished))
        view_dispatcher_stop(app->dispatcher);
    else if(app->running && app->screen == ScreenRunning)
        draw_screen(app);
}
static void start_worker(ProbeApp* app, Tb2WorkflowAction action) {
    furi_check(!app->worker && !app->backend && !app->setup && !app->running);
    app->action = action;
    app->error[0] = app->warning[0] = 0;
    app->log_failed = app->exit_after_stop = false;
    app->historical = false;
    app->progress_stage[0] = 0;
    app->progress_percent = 0;
    app->progress_indeterminate = true;
    atomic_store(&app->cancel, false);
    atomic_store(&app->waiting_for_chip, false);
    atomic_store(&app->abort_job, false);
    atomic_store(&app->finished, false);
    app->running = true;
    app->controls_open = true;
    app->screen = ScreenRunning;
    app->started = furi_get_tick();
    draw_screen(app);
    app->worker = furi_thread_alloc_ex(
        "TB2Builder",
        WORKER_STACK,
        app->identification_worker ? identify_worker :
        app->package_worker        ? package_import_worker :
        app->record_task_worker    ? record_task_worker :
        app->hardware_worker       ? hardware_worker :
                                     worker,
        app);
    furi_thread_set_priority(app->worker, FuriThreadPriorityLow);
    furi_thread_start(app->worker);
}
static void run_worker_ui(ProbeApp* app, Tb2WorkflowAction action) {
    start_worker(app, action);
    view_dispatcher_run(app->dispatcher);
    if(!atomic_load(&app->finished)) atomic_store(&app->cancel, true);
    finish_worker(app);
}
static void run_record_task(ProbeApp* app) {
    Tb2WorkflowAction previous = app->action;
    app->record_task_worker = true;
    app->identification_worker = app->record_task->kind == Tb2RecordTaskIdentify;
    run_worker_ui(app, Tb2WorkflowInspect);
    app->record_task_worker = false;
    app->identification_worker = false;
    app->action = previous;
}

/* Every dispatcher lifetime is finished before loading the next module. */
static bool choose_record(ProbeApp* app, bool hardware, bool resume) {
    if(tb2_operation_pure(app->operation.kind)) {
        /* Hardware receipts bind retries directly; never consult a box record. */
        app->box_id[0] = app->version_id[0] = app->box_alias[0] = app->selected_version[0] = 0;
        app->original_version[0] = 0;
        app->known_uid = false;
        memset(app->expected_uid, 0, sizeof(app->expected_uid));
        memset(&app->input_key, 0, sizeof(app->input_key));
        memset(&app->donor_key, 0, sizeof(app->donor_key));
        furi_string_reset(app->key_path);
        app->key_from_file = false;
        return true;
    }
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    Tb2StoreRequest* store = calloc(1, sizeof(*store));
    Tb2SetupRequest* choice = calloc(1, sizeof(*choice));
    if(!store || !choice) {
        free(store);
        free(choice);
        app->result = TB2_PROBE_IO_ERROR;
        ui_status(app, "Box selection failed.", true);
        return false;
    }
    bool ok = true;
    if(resume) {
        app->chip = app->operation.kind == Tb2OperationFlash ? app->operation.flash :
                                                               app->operation.dump;
        store->action = Tb2StoreLoadBinding;
        Tb2RecordResult rc = store_access(app, &fs, store);
        if(!rc)
            strcpy(app->box_id, store->record_id);
        else if(rc != Tb2RecordMissing)
            ok = false;
        if(ok && app->operation.kind == Tb2OperationRestore)
            ok = !record_restore_plan(app, &fs, false);
    } else {
        if(hardware) {
            app->identification_worker = true;
            run_worker_ui(app, Tb2WorkflowInspect);
            app->identification_worker = false;
            ok = !app->result;
        }
    }
select_record:
    if(ok && !app->box_id[0]) {
        choice->kind = Tb2SetupSelectBox;
        ok = invoke_setup(app, choice);
        if(ok && choice->action == Tb2SetupActionRecordTask && app->record_task &&
           app->record_task->kind == Tb2RecordTaskSaveBox) {
            run_record_task(app);
            ok = !app->result;
            if(ok) strcpy(app->box_id, app->record_task->box);
        } else {
            ok = ok && choice->action == Tb2SetupActionBoxSelected;
            if(ok) strcpy(app->box_id, choice->box_id);
        }
        clear_record_task(app);
    }
    if(ok) {
        store->record_id[0] = 0;
        store->action = Tb2StoreDescribe;
        Tb2RecordResult described = store_access(app, &fs, store);
        ok = !described;
        if(!ok) {
            app->result = record_result(described);
            if(!strstr(app->error, "Module load failed"))
                strlcpy(
                    app->error,
                    described == Tb2RecordIo ? "SD access failed." : "Box lookup failed.",
                    sizeof(app->error));
        }
        if(ok) strcpy(app->box_alias, store->alias);
        app->known_uid = store->uid_available;
        memcpy(app->expected_uid, store->uid, sizeof(app->expected_uid));
        if(ok && !resume && (app->chip.flags & Tb2SpiBound) && app->known_uid &&
           memcmp(app->chip.uid, app->expected_uid, sizeof(app->expected_uid))) {
            snprintf(choice->error, sizeof(choice->error), "Wrong chip. Select box.");
            app->box_id[0] = app->box_alias[0] = 0;
            goto select_record;
        }
    }
    free(store);
    free(choice);
    return ok;
}

static Tb2OperationKind operation_kind(Tb2SetupAction action) {
    if(action == Tb2SetupActionPureDump) return Tb2OperationPureDump;
    if(action == Tb2SetupActionPureFlash) return Tb2OperationPureFlash;
    static const uint8_t kinds[] = {
        Tb2OperationModify, Tb2OperationDump, Tb2OperationFlash, Tb2OperationAio};
    if(action >= Tb2SetupActionModify && action <= Tb2SetupActionAio)
        return kinds[action - Tb2SetupActionModify];
    return action == Tb2SetupActionRestore ? Tb2OperationRestore : 0;
}

static Tb2SpiAction spi_action(const ProbeApp* app, Tb2SetupAction action) {
    static const uint8_t direct[] = {Tb2SpiRead, Tb2SpiVerifyRead, Tb2SpiFlash, Tb2SpiVerifyFlash};
    static const uint8_t retry[] = {
        Tb2SpiRead,
        Tb2SpiVerifyRead,
        Tb2SpiPreflight,
        Tb2SpiPreflight,
        Tb2SpiPreflight,
        Tb2SpiPreflight,
        Tb2SpiPreflight,
        Tb2SpiFlash,
        Tb2SpiVerifyFlash,
        Tb2SpiPreflight,
        Tb2SpiRead,
        Tb2SpiFlash,
        Tb2SpiFlash};
    if(action >= Tb2SetupActionRead && action <= Tb2SetupActionVerifyFlash)
        return direct[action - Tb2SetupActionRead];
    if(action == Tb2SetupActionFlash || action == Tb2SetupActionPureFlash) return Tb2SpiPreflight;
    if(app->operation.kind == Tb2OperationRestore && app->operation.phase == Tb2PhaseModifySetup)
        return Tb2SpiVerifyRead;
    return app->operation.phase <= Tb2PhaseArchiveTarget ? retry[app->operation.phase] :
                                                           Tb2SpiPreflight;
}

/** Only the progress/cancel UI remains resident while processing. Each idle
 * interaction is a complete, non-nested setup-module lifetime. */
static void run_ui(ProbeApp* app) {
    Tb2SetupKind kind = Tb2SetupRoot;
    Tb2SetupKind parent_kind = Tb2SetupRoot;
    for(;;) {
        Tb2SetupRequest* request = calloc(1, sizeof(*request));
        if(!request) break;
        bool original_prompt = app->original_version[0] != 0;
        request->kind = original_prompt ? Tb2SetupOriginalPrompt : kind;
        request->editor_kind = parent_kind;
        request->wizard = kind < Tb2SetupMenu;
        strlcpy(request->path, app->selected_path, sizeof(request->path));
        strlcpy(request->error, app->error, sizeof(request->error));
        strlcpy(request->warning, app->warning, sizeof(request->warning));
        bool ok = invoke_setup(app, request);
        Tb2SetupAction action = request->action;
        Tb2SetupKind editor = request->editor_kind;
        if((action >= Tb2SetupActionModify && action <= Tb2SetupActionJobs) ||
           action == Tb2SetupActionFlashVersion || action == Tb2SetupActionFlipTdi ||
           action == Tb2SetupActionPureDump || action == Tb2SetupActionPureFlash)
            parent_kind = editor;
        if(ok && action != Tb2SetupActionExit && !original_prompt) {
            if(kind == Tb2SetupRoot) app->hardware_options = request->hardware_options;
            app->modify_mode = request->modify_mode;
            app->settings_only = request->settings_only;
            memcpy(app->box_id, request->box_id, sizeof(app->box_id));
            if(!app->box_id[0]) app->box_alias[0] = 0;
            memcpy(app->version_id, request->version_id, sizeof(app->version_id));
            app->restore_connection = request->restore_connection;
            if(action == Tb2SetupActionSavedOperation) {
                app->settings_only = app->operation.settings_only;
                app->result = request->result;
                app->historical = true;
                app->metadata_ready = app->operation.modify_bound;
                strlcpy(app->error, request->error, sizeof(app->error));
                strlcpy(app->warning, request->warning, sizeof(app->warning));
            }
            app->key_from_file = request->key_from_file;
            furi_string_set(app->key_path, request->key_path);
            /* A preflight failure may have created only the directory. Preserve
             * that distinction on Retry; catalog selections were parsed by setup. */
            if(!request->directory[0])
                app->metadata_ready = false;
            else if(action != Tb2SetupActionSavedOperation && strcmp(app->run_dir, request->directory))
                app->metadata_ready = true;
            strlcpy(app->run_dir, request->directory, sizeof(app->run_dir));
            app->resume_job = app->metadata_ready;
            strlcpy(app->selected_path, request->path, sizeof(app->selected_path));
        }
        if(original_prompt) {
            app->original_version[0] = 0;
            if(ok && action == Tb2SetupActionRecordTask) {
                int processing_result = app->result;
                run_record_task(app);
                memcpy(app->error, request->error, sizeof(app->error));
                memcpy(app->warning, request->warning, sizeof(app->warning));
                app->historical = request->historical;
                if(app->result && !app->warning[0])
                    strlcpy(app->warning, "Original not saved.", sizeof(app->warning));
                app->result = processing_result;
            }
            free(request);
            clear_record_task(app);
            continue;
        }
        free(request);
        if(!ok) {
            app->screen = ScreenError;
            atomic_store(&app->finished, false);
            draw_screen(app);
            view_dispatcher_run(app->dispatcher);
            break;
        }
        if(action == Tb2SetupActionExit) break;
        if(action == Tb2SetupActionAioImport) {
            release_lease(app); /* Normal import opens the selected file itself. */
            kind = Tb2SetupAioImport;
            continue;
        }
        if(action == Tb2SetupActionFlipTdi) {
            kind = Tb2SetupFlipTdi;
            continue;
        }
        if(action == Tb2SetupActionUseKey || action == Tb2SetupActionUseCandidate ||
           action == Tb2SetupActionRestoreSavedKeys) {
            load_record_key(app, action);
            kind = action == Tb2SetupActionRestoreSavedKeys ? Tb2SetupRestoreKeys :
                                                              Tb2SetupRecordKey;
            continue;
        }
        if(action == Tb2SetupActionRecordTask) {
            if(!app->record_task) {
                kind = Tb2SetupRoot;
                continue;
            }
            Tb2RecordTaskKind task_kind = app->record_task->kind;
            run_record_task(app);
            if(task_kind == Tb2RecordTaskTargetReserve) {
                if(!app->result) {
                    strlcpy(
                        app->selected_path,
                        app->record_task->import.output,
                        sizeof(app->selected_path));
                    strlcpy(
                        app->spec.output_path,
                        app->record_task->import.output,
                        sizeof(app->spec.output_path));
                    strlcpy(
                        app->operation.image,
                        app->record_task->import.output,
                        sizeof(app->operation.image));
                    strlcpy(app->version_id, app->record_task->version, sizeof(app->version_id));
                }
                kind = app->result ? Tb2SetupRecordResult : editor;
                continue;
            }
            if(task_kind == Tb2RecordTaskImportPackage && !app->result &&
               !app->record_task->import.package_checked) {
                app->package_worker = true;
                run_worker_ui(app, Tb2WorkflowInspect);
                app->package_worker = false;
                kind = Tb2SetupImports;
                continue;
            }
            if(task_kind == Tb2RecordTaskFilePublish) {
                bool published = !app->result && finish_dump_publication(app);
                bool aio = app->operation.kind == Tb2OperationAio;
                clear_record_task(app);
                kind = published ? (aio ? Tb2SetupModifyMenu : Tb2SetupHardwareResult) :
                                   Tb2SetupHardwareResult;
                continue;
            }
            kind = task_kind == Tb2RecordTaskFirmwareHeaders        ? Tb2SetupFirmwareHeaders :
                   task_kind >= Tb2RecordTaskRenamePrepare          ? Tb2SetupImports :
                   app->result                                      ? Tb2SetupRecordResult :
                   app->record_task->flags & TB2_RECORD_MOVE_SOURCE ? Tb2SetupVersionLabel :
                   task_kind >= Tb2RecordTaskImportInspect          ? Tb2SetupImports :
                                                                      Tb2SetupRecordResult;
            continue;
        }
        static const uint8_t action_screen[Tb2SetupActionSettingsBuild + 1] = {
            [Tb2SetupActionApplyServer] = Tb2SetupCertificates + 1,
            [Tb2SetupActionKeepServer] = Tb2SetupServerChoice + 1,
            [Tb2SetupActionCertificates] = Tb2SetupCertificates + 1,
            [Tb2SetupActionTarget] = Tb2SetupTarget + 1,
            [Tb2SetupActionOperationLog] = Tb2SetupOperationLog + 1,
            [Tb2SetupActionOperationResult] = Tb2SetupHardwareResult + 1,
            [Tb2SetupActionBoxes] = Tb2SetupBoxes + 1,
            [Tb2SetupActionJobDetails] = Tb2SetupJobDetails + 1,
            [Tb2SetupActionResult] = Tb2SetupResult + 1,
            [Tb2SetupActionOperationDetails] = Tb2SetupOperationDetails + 1,
            [Tb2SetupActionImports] = Tb2SetupImports + 1,
        };
        uint8_t screen = action <= Tb2SetupActionSettingsBuild ? action_screen[action] : 0;
        if(screen) {
            kind = (Tb2SetupKind)(screen - 1);
            continue;
        }
        if(action == Tb2SetupActionSettingsInspect) {
            app->settings_only = true;
            app->settings_worker = true;
            run_worker_ui(app, Tb2WorkflowInspect);
            app->settings_worker = false;
            kind = app->result ? Tb2SetupModifyMenu : Tb2SetupSettingsEditor;
            continue;
        }
        if(action == Tb2SetupActionRestoreSelected) {
            strcpy(app->selected_version, app->version_id);
            Tb2NativeIO native;
            Tb2WorkflowIO fs = filesystem(app, &native);
            kind = record_restore_plan(app, &fs, true) ? Tb2SetupRestoreDonor :
                                                         Tb2SetupRestoreKeys;
            continue;
        }
        if(action == Tb2SetupActionRestore || action == Tb2SetupActionFlashVersion ||
           (action == Tb2SetupActionModify && app->version_id[0])) {
            strcpy(app->selected_version, app->version_id);
        } else if(
            action == Tb2SetupActionFlash || action == Tb2SetupActionModify ||
            action == Tb2SetupActionDump || action == Tb2SetupActionAio) {
            app->selected_version[0] = 0;
        }
        if(action == Tb2SetupActionFlashVersion) action = Tb2SetupActionFlash;
        if(action == Tb2SetupActionSavedOperation) {
            release_lease(app);
            app->selected_version[0] = 0;
            kind = Tb2SetupHardwareResult;
            continue;
        }
        if(action == Tb2SetupActionHome || action == Tb2SetupActionJobs) {
            clear_record_task(app);
            release_lease(app);
            if(action == Tb2SetupActionJobs)
                kind = Tb2SetupJobs;
            else {
                kind = Tb2SetupRoot;
                parent_kind = Tb2SetupRoot;
            }
            continue;
        }
        Tb2OperationKind new_operation = operation_kind(action);
        if(new_operation) {
            clear_record_task(app);
            release_lease(app);
            memset(&app->operation, 0, sizeof(app->operation));
            app->operation.state = Tb2UiPrepared;
            app->operation.kind = new_operation;
            app->metadata_ready = app->resume_job = app->historical = false;
            app->run_dir[0] = 0;
            memset(&app->chip, 0, sizeof(app->chip));
            memset(&app->identity, 0, sizeof(app->identity));
            memset(&app->input_key, 0, sizeof(app->input_key));
            memset(&app->donor_key, 0, sizeof(app->donor_key));
            furi_string_reset(app->key_path);
            app->key_from_file = false;
            memset(&app->settings_snapshot, 0, sizeof(app->settings_snapshot));
            memset(&app->settings_patch, 0, sizeof(app->settings_patch));
            app->settings_only = false;
            app->modify_mode = Tb2ModifyGuided;
            app->result = 0;
            app->error[0] = app->warning[0] = 0;
            if(!choose_record(app, action != Tb2SetupActionModify, false)) {
                kind = app->result || app->error[0] ? Tb2SetupHardwareResult : parent_kind;
                continue;
            }
            app->operation.dump = app->operation.flash = app->chip;
            if(!tb2_operation_flash(new_operation)) {
                kind = action == Tb2SetupActionModify ? Tb2SetupModifyMenu : Tb2SetupDumpTarget;
                continue;
            }
            strlcpy(app->operation.source, app->selected_path, sizeof(app->operation.source));
            strlcpy(app->operation.image, app->selected_path, sizeof(app->operation.image));
            app->operation.phase = Tb2PhaseFlashPrepare;
        }
        if(action == Tb2SetupActionEdit) {
            if(editor == parent_kind) release_lease(app);
            kind = editor;
            continue;
        }
        app->hardware_worker =
            action == Tb2SetupActionFlash || action == Tb2SetupActionPureFlash ||
            (action >= Tb2SetupActionRead && action <= Tb2SetupActionRetryOperation);
        if(action == Tb2SetupActionRetryOperation && !app->result &&
           app->operation.phase == Tb2PhaseArchiveSource) {
            app->hardware_worker = false;
            kind = Tb2SetupVersionLabel;
            continue;
        }
        if(action == Tb2SetupActionRetryOperation &&
           !(app->operation.kind == Tb2OperationRestore &&
             app->operation.phase == Tb2PhaseModifySetup) &&
           (app->operation.phase == Tb2PhaseModifySetup ||
            app->operation.phase == Tb2PhaseModifyCheck ||
            app->operation.phase == Tb2PhaseModifyBuild ||
            (app->operation.kind == Tb2OperationModify &&
             app->operation.phase == Tb2PhaseComplete))) {
            app->hardware_worker = false;
            if(!choose_record(app, false, true)) {
                kind = Tb2SetupRoot;
                continue;
            }
            if(app->operation.settings_only) {
                app->settings_only = true;
                action = Tb2SetupActionSettingsBuild;
            } else {
                kind = app->operation.kind == Tb2OperationRestore ?
                           (app->operation.phase == Tb2PhaseModifySetup ? Tb2SetupRestoreDonor :
                                                                          Tb2SetupRestoreKeys) :
                       app->operation.phase == Tb2PhaseModifySetup ? Tb2SetupNew :
                                                                     Tb2SetupResume;
                if(kind == Tb2SetupNew)
                    strlcpy(
                        app->selected_path,
                        app->operation.phase == Tb2PhaseModifySetup && app->operation.image[0] ?
                            app->operation.image :
                            app->operation.source,
                        sizeof(app->selected_path));
                continue;
            }
        }
        if(app->hardware_worker) {
            if(app->operation.sequence && !choose_record(app, true, true)) {
                kind = Tb2SetupHardwareResult;
                continue;
            }
            if(action == Tb2SetupActionRead && !app->operation.sequence)
                strlcpy(app->operation.source, app->selected_path, sizeof(app->operation.source));
            if(action == Tb2SetupActionProgram) app->operation.approved = true;
            app->spi_action = spi_action(app, action);
        }
        if(!app->hardware_worker && action != Tb2SetupActionPreviewServer &&
           (app->run_dir[0] || !app->box_id[0]) &&
           !choose_record(app, false, app->run_dir[0] != 0)) {
            kind = Tb2SetupRoot;
            continue;
        }
        app->approved_missing = action == Tb2SetupActionBuild ?
                                    app->flow.package.missing |
                                        (app->flow.package.reissue << TB2_PACKAGE_REISSUE_SHIFT) :
                                    0;
        if(action == Tb2SetupActionBuild || action == Tb2SetupActionRestoreBuild ||
           action == Tb2SetupActionSettingsBuild)
            app->operation.approved = true;
        if(action == Tb2SetupActionSettingsBuild) app->operation.settings_only = true;
        run_worker_ui(
            app,
            action == Tb2SetupActionBuild || action == Tb2SetupActionRestoreBuild ||
                    action == Tb2SetupActionSettingsBuild ?
                Tb2WorkflowBuild :
            action == Tb2SetupActionPreviewServer ? Tb2WorkflowPreviewServer :
                                                    Tb2WorkflowInspect);
        if(app->hardware_worker) {
            app->historical = false;
            kind = !app->result && app->operation.phase == Tb2PhaseArchiveSource ?
                       Tb2SetupVersionLabel :
                   !app->result && app->operation.kind == Tb2OperationRestore &&
                           app->operation.phase == Tb2PhaseModifySetup ?
                       Tb2SetupRestoreDonor :
                   !app->result && app->spi_action == Tb2SpiPreflight ? Tb2SetupOperationDetails :
                   !app->result && app->operation.phase == Tb2PhaseModifySetup ?
                                                                        Tb2SetupModifyMenu :
                                                                        Tb2SetupHardwareResult;
            if(kind == Tb2SetupNew || kind == Tb2SetupModifyMenu)
                strlcpy(
                    app->selected_path,
                    app->operation.phase == Tb2PhaseModifySetup && app->operation.image[0] ?
                        app->operation.image :
                        app->operation.source,
                    sizeof(app->selected_path));
            continue;
        }
        if(app->action == Tb2WorkflowPreviewServer) {
            kind = app->result ? Tb2SetupServerChoice : Tb2SetupServerEditor;
            continue;
        }
        if(app->operation.kind == Tb2OperationRestore) {
            kind = app->action == Tb2WorkflowInspect ?
                       (app->result ? Tb2SetupRestoreKeys : Tb2SetupRestoreApprove) :
                       Tb2SetupHardwareResult;
            continue;
        }
        /* A requested stop still reports a failed final status write. */
        if(app->exit_after_stop && !app->warning[0]) break;
        kind = app->action == Tb2WorkflowInspect && !app->flow.complete &&
                       (!app->result || app->result == TB2_PACKAGE_MISSING) ?
                   Tb2SetupApprove :
                   Tb2SetupResult;
        if(app->operation.kind && (app->operation.phase == Tb2PhaseExport ||
                                   (app->operation.kind == Tb2OperationAio &&
                                    app->operation.phase >= Tb2PhaseFlashPrepare)))
            kind = Tb2SetupHardwareResult;
    }
    release_lease(app);
}
int32_t tb2_probe_app(void* argument) {
    UNUSED(argument);
    ProbeApp* app = calloc(1, sizeof(*app));
    if(!app) return -1;
    atomic_init(&app->cancel, false);
    atomic_init(&app->finished, false);
    atomic_init(&app->abort_job, false);
    atomic_init(&app->exit_after_stop, false);
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->gui = furi_record_open(RECORD_GUI);
    app->dialog = dialog_ex_alloc();
    app->controls = submenu_alloc();
    app->key_path = furi_string_alloc();
    app->dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->dispatcher, custom_event);
    view_dispatcher_set_navigation_event_callback(app->dispatcher, navigation);
    view_dispatcher_set_tick_event_callback(app->dispatcher, tick, UI_TICK_MS);
    view_dispatcher_add_view(app->dispatcher, 0, dialog_ex_get_view(app->dialog));
    view_dispatcher_add_view(app->dispatcher, 1, submenu_get_view(app->controls));
    view_dispatcher_attach_to_gui(app->dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    show_dialog(app, "TB2 Manager", "Starting...\nStorage setup");
    FS_Error root_error = storage_common_mkdir(app->storage, TB2_APP_ROOT);
    bool folders_ready = root_error == FSE_OK || root_error == FSE_EXIST;
    if(folders_ready) {
        root_error = storage_common_mkdir(app->storage, TB2_JOBS_ROOT);
        folders_ready = root_error == FSE_OK || root_error == FSE_EXIST;
    }
    show_dialog(app, "TB2 Manager", "Starting...\nLoading menu");
    if(folders_ready) {
        run_ui(app);
    } else {
        strlcpy(app->error, SD_RETRY, sizeof(app->error));
        app->screen = ScreenError;
        draw_screen(app);
        view_dispatcher_run(app->dispatcher);
    }
    if(app->worker) {
        atomic_store(&app->cancel, true);
        finish_worker(app);
    }
    view_dispatcher_remove_view(app->dispatcher, 0);
    view_dispatcher_remove_view(app->dispatcher, 1);
    dialog_ex_free(app->dialog);
    submenu_free(app->controls);
    furi_string_free(app->key_path);
    view_dispatcher_free(app->dispatcher);
    furi_mutex_free(app->mutex);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_STORAGE);
    clear_record_task(app);
    volatile unsigned char* wipe = (volatile unsigned char*)app;
    for(size_t i = 0; i < sizeof(*app); i++)
        wipe[i] = 0;
    free(app);
    return 0;
}
