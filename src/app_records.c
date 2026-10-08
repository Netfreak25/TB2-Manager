/* Resident orchestration only: no filesystem parser or archive buffers here. */
static Tb2RecordResult store_access(ProbeApp* app, Tb2WorkflowIO* fs, Tb2StoreRequest* r) {
    if(!modules_idle(app)) return Tb2RecordIo;
    r->io = fs;
    r->storage = app->storage;
    r->staging = app->run_dir;
    r->descriptor_crc = app->operation.descriptor_crc;
    if(!r->record_id[0]) strcpy(r->record_id, app->box_id);
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    Tb2RecordResult rc = load_module(app, module, ModuleStore) ? app->store->run(r) : Tb2RecordIo;
    close_module(app, module);
    if(rc != Tb2RecordMissing && rc && !app->error[0])
        ui_status(app, r->error[0] ? r->error : "Box record failed.", true);
    return rc;
}
static int record_result(Tb2RecordResult rc) {
    return !rc                      ? 0 :
           rc == Tb2RecordCancelled ? TB2_PROBE_CANCELLED :
           rc == Tb2RecordIo        ? TB2_PROBE_IO_ERROR :
                                      TB2_PROBE_CHECK_FAILED;
}
static int core_inspect(ProbeApp* app, Tb2BackendInspect* request) {
    if(!modules_idle(app)) return TB2_PROBE_IO_ERROR;
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    int rc = load_module(app, module, ModuleCore) ? app->backend->inspect(request) :
                                                    TB2_PROBE_IO_ERROR;
    close_module(app, module);
    return rc;
}
static void record_event(ProbeApp* app) {
    /* Preflight has no flash result to add and must not load Store while the
     * SPI worker is being retired. Other entries require a concrete version. */
    if(tb2_operation_pure(app->operation.kind) || app->spi_action == Tb2SpiPreflight ||
       !app->version_id[0] || !app->operation.sequence)
        return;
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(r) {
        Tb2NativeIO native;
        Tb2WorkflowIO fs = filesystem(app, &native);
        strcpy(r->version_id, app->version_id);
        r->timestamp = furi_hal_rtc_get_timestamp();
        r->operation = &app->operation;
        r->result_code = app->result;
        r->action = Tb2StoreSaveEntry;
        store_access(app, &fs, r);
    } else
        strlcpy(app->warning, "History unsaved.", sizeof(app->warning));
    free(r);
}
static bool load_key_file(ProbeApp* app) {
    memset(&app->input_key, 0, sizeof(app->input_key));
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) {
        app->result = TB2_PROBE_IO_ERROR;
        return false;
    }
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    r->action = Tb2StoreKeyFile;
    r->source = furi_string_get_cstr(app->key_path);
    r->key = &app->input_key;
    app->result = record_result(store_access(app, &fs, r));
    free(r);
    return !app->result;
}
static bool load_record_key(ProbeApp* app, Tb2SetupAction action) {
    bool candidate = action == Tb2SetupActionUseCandidate;
    bool restore = action == Tb2SetupActionRestoreSavedKeys;
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return false;
    Tb2InputKey key = {0};
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    r->action = restore ? Tb2StoreRestoreKeys : Tb2StoreLoadKey;
    r->key = &key;
    r->candidate_key = candidate;
    if(restore) {
        r->donor_key = &app->donor_key;
        strcpy(r->version_id, app->selected_version);
    }
    app->result = record_result(store_access(app, &fs, r));
    if(!app->result) {
        app->input_key = key;
        app->key_from_file = false;
        furi_string_reset(app->key_path);
        app->error[0] = 0;
    } else {
        strlcpy(app->error, "Saved key missing.", sizeof(app->error));
    }
    volatile uint8_t* bytes = (volatile uint8_t*)&key;
    for(size_t i = 0; i < sizeof(key); i++)
        bytes[i] = 0;
    free(r);
    return !app->result;
}
static int inspect_identity_file(
    ProbeApp* app,
    Tb2WorkflowIO* fs,
    const char* path,
    const char* artifact_name) {
    memset(&app->identity, 0, sizeof(app->identity));
    snprintf(
        app->artifact_directory,
        sizeof(app->artifact_directory),
        "%s/%s-artifacts",
        app->run_dir,
        artifact_name);
    /* The SPI module already contains the read-only identity/artifact reader.
     * Loading the much larger modifying Core here needlessly raises the peak. */
    Tb2SpiRequest request = {
        .action = Tb2SpiInspectFile,
        .io = fs,
        .path = path,
        .directory = app->artifact_directory,
        .identity = &app->identity};
    return run_spi(app, &request);
}
static int identity_file(ProbeApp* app, Tb2WorkflowIO* fs, const char* path) {
    const char* artifact_name = !strcmp(path, app->operation.source) ? "source" :
                                !strcmp(path, app->operation.image)  ? "target" :
                                                                       "backup";
    return inspect_identity_file(app, fs, path, artifact_name);
}
static int record_bind(ProbeApp* app, Tb2WorkflowIO* fs) {
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    r->action = Tb2StoreBind;
    r->uid_available = (app->chip.flags & Tb2SpiBound) != 0;
    memcpy(r->uid, app->chip.uid, sizeof(r->uid));
    int rc = record_result(store_access(app, fs, r));
    free(r);
    return rc;
}
static int record_restore_plan(ProbeApp* app, Tb2WorkflowIO* fs, bool create) {
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    r->action = create ? Tb2StoreRestorePlan : Tb2StoreLoadRestorePlan;
    strcpy(r->version_id, app->selected_version);
    r->restore_connection = app->restore_connection;
    Tb2RecordResult saved = store_access(app, fs, r);
    int rc = record_result(saved);
    if(saved == Tb2RecordMissing && !create &&
       (app->operation.phase == Tb2PhaseSource || app->operation.phase == Tb2PhaseSourceVerify ||
        app->operation.phase == Tb2PhaseArchiveSource ||
        app->operation.phase == Tb2PhaseModifySetup))
        rc = 0; /* Donor selection follows the verified current dump. */
    if(!saved) {
        strcpy(app->selected_version, r->version_id);
        app->restore_connection = r->restore_connection;
    }
    free(r);
    return rc;
}
static int record_publish(
    ProbeApp* app,
    Tb2WorkflowIO* fs,
    const char* path,
    const uint8_t digest[32],
    Tb2WorkshopSlot slot,
    bool checked) {
    const char* artifact_name = slot == Tb2WorkshopTarget ? "target" :
                                slot == Tb2WorkshopSource ? "source" :
                                                            "backup";
    int inspected = inspect_identity_file(app, fs, path, artifact_name);
    if(inspected) return inspected;
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    Tb2ObjectRef expected = {.size = TB2_IMAGE_SIZE};
    memcpy(expected.digest, digest, sizeof(expected.digest));
    r->action = Tb2StorePublish;
    r->source = path;
    r->expected = &expected;
    r->slot = slot;
    if(slot == Tb2WorkshopTarget && app->operation.kind == Tb2OperationFlash)
        r->existing_version = app->selected_version;
    else if(
        slot == Tb2WorkshopTarget && app->record_task &&
        app->record_task->kind == Tb2RecordTaskTargetReserve && app->record_task->version[0]) {
        r->existing_version = app->record_task->version;
        r->readable_target = true;
    }
    r->operation = &app->operation;
    r->flow = &app->flow;
    r->identity = &app->identity;
    r->checked = checked;
    r->settings_only = app->settings_only;
    r->hardware = app->hardware_worker;
    r->settings_patch = &app->settings_patch;
    r->key = &app->input_key;
    r->uid_available = (app->chip.flags & Tb2SpiBound) != 0;
    memcpy(r->uid, app->chip.uid, sizeof(r->uid));
    int rc = record_result(store_access(app, fs, r));
    if(!rc) {
        strcpy(app->version_id, r->version_id);
        if(slot != Tb2WorkshopTarget) strcpy(app->original_version, r->version_id);
    }
    free(r);
    return rc;
}
static int record_source(ProbeApp* app, Tb2WorkflowIO* fs) {
    const char* path = app->operation.source;
    const uint8_t* digest = app->hardware_worker ? app->operation.dump.digest :
                                                   app->flow.read.source_sha256;
    return record_publish(app, fs, path, digest, Tb2WorkshopSource, !app->hardware_worker);
}

/** Keep the immutable descriptor source unchanged. Until Modify binds its
 * output, the journal image field carries the checked readable dump path. */
static bool finish_dump_publication(ProbeApp* app) {
    Tb2RecordTask* task = app->record_task;
    if(!task || task->result || !task->version[0] || !task->import.output[0]) return false;
    strlcpy(app->version_id, task->version, sizeof(app->version_id));
    strlcpy(app->selected_path, task->import.output, sizeof(app->selected_path));
    strlcpy(app->operation.image, task->import.output, sizeof(app->operation.image));
    app->operation.result = 0;
    app->operation.state = app->operation.kind == Tb2OperationDump ? Tb2UiComplete : Tb2UiPrepared;
    app->operation.phase = app->operation.kind == Tb2OperationDump ? Tb2PhaseComplete :
                                                                     Tb2PhaseModifySetup;
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    if(!operation_access(app, &fs, Tb2OperationSave)) {
        app->result = TB2_PROBE_IO_ERROR;
        strlcpy(app->error, "Dump saved; status unsaved.", sizeof(app->error));
        return false;
    }
    if(!task->import.duplicate)
        strlcpy(app->original_version, task->version, sizeof(app->original_version));
    app->result = 0;
    return true;
}
