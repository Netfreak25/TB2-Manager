/* Included by app.c: resident coordination only. Processing remains in FALs. */
static bool operation_access(ProbeApp* app, Tb2WorkflowIO* fs, Tb2OperationAccess access) {
    if(!modules_idle(app)) return false;
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    bool ok = load_module(app, module, ModuleSpi) &&
              app->spi->operation(fs, app->run_dir, &app->operation, access, &app->spec);
    close_module(app, module);
    if(!ok) strlcpy(app->warning, SD_RETRY, sizeof(app->warning));
    return ok;
}

static void release_lease(ProbeApp* app) {
    if(!app->file_lease) return;
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    if(!fs.close(fs.context, app->file_lease))
        strlcpy(app->warning, SD_RETRY, sizeof(app->warning));
    app->file_lease = NULL;
}

static void spi_waiting(void* context, bool waiting) {
    atomic_store(&((ProbeApp*)context)->waiting_for_chip, waiting);
}

static int32_t run_spi(ProbeApp* app, Tb2SpiRequest* request) {
    request->speed = (app->hardware_options & Tb2HardwareSpiMask) >> Tb2HardwareSpiShift;
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    int32_t rc = load_module(app, module, ModuleSpi) ? app->spi->run(request) : TB2_PROBE_IO_ERROR;
    close_module(app, module);
    return rc;
}

static int32_t spi_phase(ProbeApp* app, Tb2WorkflowIO* fs, Tb2SpiAction action) {
    memset(&app->spi_result, 0, sizeof(app->spi_result));
    bool dump = action == Tb2SpiRead || action == Tb2SpiVerifyRead;
    Tb2SpiRequest request = {
        .io = fs,
        .path = dump && !(app->operation.phase == Tb2PhaseComplete && app->operation.image[0]) ?
                    app->operation.source :
                    app->operation.image,
        .action = action,
        .receipt = dump ? &app->operation.dump : &app->operation.flash,
        .result = &app->spi_result,
        .lease = &app->file_lease,
        .operation = &app->operation,
        .directory = app->run_dir,
        .expected_uid = app->known_uid ? app->expected_uid : NULL,
        .wait_context = app,
        .waiting = spi_waiting};
    int rc = run_spi(app, &request);
    if(app->spi_result.phase == Tb2SpiPhaseVerify && action != Tb2SpiPreflight)
        app->operation.phase = dump ? Tb2PhaseSourceVerify : Tb2PhaseFlashVerify;
    if(rc)
        ui_status(app, app->spi_result.error[0] ? app->spi_result.error : PROCESSOR_RETRY, true);
    return rc;
}

static int32_t identify_worker(void* context) {
    ProbeApp* app = context;
    Tb2RecordTask* task = app->record_task_worker ? app->record_task : NULL;
    if(task) {
        Tb2RecordTaskKind kind = task->kind;
        memset(task, 0, sizeof(*task));
        task->kind = kind;
        task->flags = Tb2IdentifyResult;
    }
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    memset(&app->chip, 0, sizeof(app->chip));
    Tb2SpiRequest request = {
        .io = &fs,
        .path = "",
        .action = Tb2SpiDetect,
        .receipt = &app->chip,
        .result = &app->spi_result,
        .probe_uid = true,
        .wait_context = app,
        .waiting = spi_waiting};
    app->result = run_spi(app, &request);
    if(!app->result && !(app->chip.flags & Tb2SpiBound)) app->chip.flags = Tb2SpiManual;
    if(task && !app->result) {
        task->uid_available = (app->chip.flags & Tb2SpiBound) != 0;
        memcpy(task->uid, app->chip.uid, sizeof(task->uid));
    }
    if(!app->result &&
       (task || (!(app->hardware_options & Tb2HardwareManualUid) && !app->box_id[0])) &&
       (app->chip.flags & Tb2SpiBound)) {
        Tb2StoreRequest* r = calloc(1, sizeof(*r));
        if(r) {
            r->action = Tb2StoreFindUid;
            memcpy(r->uid, app->chip.uid, sizeof(r->uid));
            app->result = record_result(store_access(app, &fs, r));
            if(!app->result && r->found) strcpy(task ? task->box : app->box_id, r->record_id);
            if(task && !app->result && r->found) strcpy(task->note, r->alias);
            free(r);
        } else
            app->result = TB2_PROBE_IO_ERROR;
    }
    close_controls(app);
    atomic_store(&app->finished, true);
    return 0;
}

/** Probe the current firmware and require a retained input backup before erase.
 * A backup is an independent child operation; the parent Flash source is immutable. */
static int archive_before_flash(ProbeApp* app, Tb2WorkflowIO* fs) {
    /* Archive checks may reopen the selected BIN (also when it is the backup).
     * Drop the preflight handle first. Flash then reopens and checks its digest
     * against the existing receipt before erase; pure Flash keeps its lease. */
    release_lease(app);
    Tb2StoreRequest* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    if(app->operation.flash.flags & Tb2SpiEraseStarted) {
        /* A partly written chip is never promoted to a new input backup. */
        r->action = Tb2StoreFlashReady;
        int rc = record_result(store_access(app, fs, r));
        free(r);
        return rc;
    }
    Tb2SpiRequest probe = {
        .io = fs,
        .path = "",
        .action = Tb2SpiFirmware,
        .receipt = &app->operation.flash,
        .result = &app->spi_result,
        .expected_uid = app->known_uid ? app->expected_uid : NULL,
        .wait_context = app,
        .waiting = spi_waiting};
    int rc = run_spi(app, &probe);
    if(!rc) {
        Tb2ImageIdentity identity = {
            .firmware = app->spi_result.firmware, .secondary = app->spi_result.secondary};
        r->action = Tb2StoreBackup;
        r->firmware = &app->spi_result.firmware;
        r->identity = &identity;
        rc = record_result(store_access(app, fs, r));
    }
    bool needed = !r->found;
    free(r);
    if(!rc && needed) {
        Tb2SpiReceipt receipt = {0};
        char path[TB2_JOB_PATH_MAX];
        snprintf(path, sizeof(path), "%s/backup.bin", app->run_dir);
        probe.path = path;
        probe.receipt = &receipt;
        probe.operation = &app->operation;
        probe.directory = app->run_dir;
        probe.backup = true;
        rc = run_spi(app, &probe);
        if(!rc) rc = record_publish(app, fs, path, receipt.digest, Tb2WorkshopBackup, false);
    }
    if(!rc)
        rc = record_publish(
            app, fs, app->operation.image, app->operation.flash.digest, Tb2WorkshopTarget, false);
    return rc;
}

static void close_worker_log(ProbeApp* app) {
    close_controls(app);
    if(app->log) {
        /* storage_file_close() flushes the file. An explicit sync immediately
         * before close duplicated the same SD flush and could leave the worker
         * waiting after its operation checkpoint was already durable. */
        bool closed = storage_file_close(app->log);
        storage_file_free(app->log);
        app->log = NULL;
        if(!closed || app->log_failed) {
            app->result = TB2_PROBE_IO_ERROR;
            app->flow.complete = false;
            ui_status(app, SD_RETRY, true);
        }
    }
}

static bool begin_modify_operation(ProbeApp* app, Tb2WorkflowIO* fs) {
    if(record_bind(app, fs)) return false;
    if(!app->operation.kind) return true;
    app->operation.state = Tb2UiRunning;
    app->operation.phase = app->action == Tb2WorkflowBuild ? Tb2PhaseModifyBuild :
                                                             Tb2PhaseModifyCheck;
    return operation_access(app, fs, Tb2OperationSave);
}

static __attribute__((noinline)) int32_t continue_aio_flash(ProbeApp* app, Tb2WorkflowIO* fs) {
    Tb2Operation* op = &app->operation;
    if(op->kind != Tb2OperationAio) return 0;
    if(!op->approved || !(op->dump.flags & Tb2SpiDumpVerified)) return TB2_PROBE_CHECK_FAILED;
    op->flash.flags |= (op->dump.flags & (Tb2SpiBound | Tb2SpiManual)) | Tb2SpiFileChecked |
                       Tb2SpiDigestBound;
    memcpy(op->flash.uid, op->dump.uid, TB2_SPI_UID_SIZE);
    memcpy(op->flash.digest, op->image_hash, 32);
    op->phase = Tb2PhaseFlashProgram;
    return operation_access(app, fs, Tb2OperationSave) ? spi_phase(app, fs, Tb2SpiFlash) :
                                                         TB2_PROBE_IO_ERROR;
}

/** Export has its own retry boundary; it does not re-enter image or certificate processing. */
static int32_t export_and_flash(ProbeApp* app, Tb2WorkflowIO* fs) {
    if(!operation_access(app, fs, Tb2OperationSave)) return TB2_PROBE_IO_ERROR;
    Tb2SetupRequest* r = calloc(1, sizeof(*r));
    if(!r) return TB2_PROBE_IO_ERROR;
    r->kind = Tb2SetupExport;
    r->filesystem = fs;
    bool ok = invoke_setup(app, r);
    int rc = ok ? r->result : TB2_PROBE_IO_ERROR;
    if(rc) ui_status(app, r->error[0] ? r->error : "Archive failed. Retry.", true);
    free(r);
    if(!rc)
        rc = record_publish(
            app, fs, app->operation.image, app->operation.image_hash, Tb2WorkshopTarget, true);
    if(!rc) rc = continue_aio_flash(app, fs);
    return rc;
}

/** Retry the SD-only source archive boundary without touching the chip again.
 * Dump keeps the verified source ready for naming; Restore also republishes the
 * source and resumes donor selection after the original lookup. */
static int32_t archive_verified_source(ProbeApp* app, Tb2WorkflowIO* fs) {
    if(!(app->operation.dump.flags & Tb2SpiDumpVerified)) return TB2_PROBE_CHECK_FAILED;
    int32_t rc = app->operation.kind == Tb2OperationRestore ?
                     record_source(app, fs) :
                     identity_file(app, fs, app->operation.source);
    if(!rc && app->operation.kind == Tb2OperationRestore && !app->selected_version[0]) {
        Tb2StoreRequest* original = calloc(1, sizeof(*original));
        if(!original) return TB2_PROBE_IO_ERROR;
        original->action = Tb2StoreOriginal;
        original->firmware = &app->identity.firmware;
        rc = record_result(store_access(app, fs, original));
        if(!rc && original->found) strcpy(app->selected_version, original->version_id);
        free(original);
    }
    return rc;
}

static int32_t hardware_worker(void* context) {
    ProbeApp* app = context;
    /* Only this live AIO result owns the continuously held, verified output.
     * Persisted flags alone never exempt a resumed job from archive checks. */
    bool aio_lease = app->operation.kind == Tb2OperationAio && app->file_lease &&
                     app->operation.state == Tb2UiComplete &&
                     (app->operation.flash.flags & (Tb2SpiBound | Tb2SpiFlashVerified)) ==
                         (Tb2SpiBound | Tb2SpiFlashVerified);
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    app->result = TB2_PROBE_IO_ERROR;
    bool fresh_directory = false;
    if(prepare_run(app, &fs)) {
        if(!app->operation.sequence) app->operation.state = Tb2UiPrepared;
        bool ready = app->operation.sequence || operation_access(app, &fs, Tb2OperationCreate);
        /* Failed descriptor creation has not started hardware or claimed a BIN.
         * Preserve its diagnostic directory; retry in a new owned directory. */
        fresh_directory = !ready && !app->operation.sequence;
        app->operation.state = Tb2UiRunning;
        app->operation.result = 0;
        if(ready && operation_access(app, &fs, Tb2OperationSave) &&
           (tb2_operation_pure(app->operation.kind) || !record_bind(app, &fs))) {
            bool retry_source_archive = app->operation.phase == Tb2PhaseArchiveSource;
            if(app->operation.phase == Tb2PhaseExport) {
                app->spi_action = app->operation.kind == Tb2OperationAio ? Tb2SpiFlash :
                                                                           Tb2SpiDetect;
                app->result = export_and_flash(app, &fs);
            } else {
                app->result = 0;
                if(app->spi_action == Tb2SpiFlash && app->operation.kind == Tb2OperationFlash) {
                    app->operation.phase = app->operation.format == 1 ? Tb2PhaseFlashProgram :
                                                                        Tb2PhaseBackupCheck;
                    app->result = operation_access(app, &fs, Tb2OperationSave) ?
                                      archive_before_flash(app, &fs) :
                                      TB2_PROBE_IO_ERROR;
                }
                if(!app->result &&
                   (app->spi_action == Tb2SpiFlash || app->spi_action == Tb2SpiVerifyFlash) &&
                   !tb2_operation_flash(app->operation.kind) && !aio_lease) {
                    Tb2StoreRequest* saved = calloc(1, sizeof(*saved));
                    if(saved) {
                        Tb2ObjectRef expected = {.size = TB2_IMAGE_SIZE};
                        memcpy(expected.digest, app->operation.flash.digest, 32);
                        saved->action = Tb2StoreFlashReady;
                        saved->expected = &expected;
                        app->result = record_result(store_access(app, &fs, saved));
                        free(saved);
                    } else
                        app->result = TB2_PROBE_IO_ERROR;
                }
                if(!app->result && app->spi_action == Tb2SpiVerifyFlash &&
                   app->operation.kind == Tb2OperationFlash) {
                    app->result = record_publish(
                        app,
                        &fs,
                        app->operation.image,
                        app->operation.flash.digest,
                        Tb2WorkshopTarget,
                        false);
                }
                if(!app->result && !retry_source_archive)
                    app->result = spi_phase(app, &fs, app->spi_action);
                if(!app->result && retry_source_archive) {
                    app->result = archive_verified_source(app, &fs);
                } else if(
                    !app->result &&
                    (app->spi_action == Tb2SpiRead || app->spi_action == Tb2SpiVerifyRead)) {
                    app->chip = app->operation.dump;
                    if(app->spi_action == Tb2SpiRead) {
                        app->operation.phase = Tb2PhaseSourceVerify;
                        if(!operation_access(app, &fs, Tb2OperationSave))
                            app->result = TB2_PROBE_IO_ERROR;
                    } else if(!tb2_operation_pure(app->operation.kind)) {
                        app->operation.phase = app->operation.format == 1 ? Tb2PhaseSourceVerify :
                                                                            Tb2PhaseArchiveSource;
                        if(operation_access(app, &fs, Tb2OperationSave))
                            app->result = archive_verified_source(app, &fs);
                        else
                            app->result = TB2_PROBE_IO_ERROR;
                    }
                }
            }
        }
    }
    if(close_controls(app)) {
        app->operation.state = Tb2UiAborted;
        app->result = TB2_PROBE_CANCELLED;
    }
    close_worker_log(app);
    if(fresh_directory) app->run_dir[0] = 0;
    if(app->result) release_lease(app);
    atomic_store(&app->finished, true);
    return 0;
}

/** Called only after join and log close; a failed final write does not replace the result. */
static void finish_hardware(ProbeApp* app) {
    Tb2Operation* op = &app->operation;
    op->result = app->result;
    if(op->state != Tb2UiAborted) {
        op->state = app->result == TB2_PROBE_CANCELLED ? Tb2UiPaused :
                    app->result                        ? Tb2UiFailed :
                                                         Tb2UiPrepared;
        if(!app->result) {
            if(app->spi_action == Tb2SpiPreflight)
                op->phase = Tb2PhaseFlashPrepare;
            else if(
                op->kind == Tb2OperationRestore && (op->dump.flags & Tb2SpiDumpVerified) &&
                (app->spi_action == Tb2SpiVerifyRead || op->phase == Tb2PhaseArchiveSource))
                op->phase = Tb2PhaseModifySetup;
            else if(op->phase == Tb2PhaseSourceVerify && !(op->dump.flags & Tb2SpiDumpVerified))
                op->state = Tb2UiPrepared;
            else if(op->phase == Tb2PhaseArchiveSource)
                op->state = Tb2UiPrepared;
            else {
                op->phase = Tb2PhaseComplete;
                op->state = Tb2UiComplete;
            }
        }
    }
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    if(op->sequence) operation_access(app, &fs, Tb2OperationSave);
    if(op->state == Tb2UiComplete && op->modify_bound && app->metadata_ready)
        save_status(app, Tb2UiComplete);
}
