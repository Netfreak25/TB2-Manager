/* Resident sequencing only; all file parsing and crypto stay in the loaded module. */
static int32_t restore_worker(ProbeApp* app) {
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    Tb2Operation* op = &app->operation;
    Tb2RestoreRequest* r = calloc(1, sizeof(*r));
    Tb2StoreRequest* saved = calloc(1, sizeof(*saved));
    Tb2BoxVersion* donor = calloc(1, sizeof(*donor));
    app->flow.complete = false;
    app->result = TB2_PROBE_IO_ERROR;
    if(!r || !saved || !donor || !prepare_run(app, &fs)) goto done;
    if(record_restore_plan(app, &fs, true)) goto done;
    op->state = Tb2UiRunning;
    op->phase = app->action == Tb2WorkflowBuild ? Tb2PhaseModifyBuild : Tb2PhaseModifyCheck;
    if(!(op->dump.flags & Tb2SpiDumpVerified) ||
       (app->action == Tb2WorkflowBuild && !op->approved) ||
       !operation_access(app, &fs, Tb2OperationSave) || record_restore_plan(app, &fs, false))
        goto done;
    saved->action = Tb2StoreCheckout;
    saved->version = donor;
    strcpy(saved->version_id, app->selected_version);
    app->result = record_result(store_access(app, &fs, saved));
    if(app->result) goto done;
    snprintf(op->image, sizeof(op->image), "%s/restored.bin", app->run_dir);
    if(!operation_access(app, &fs, Tb2OperationSave)) {
        app->result = TB2_PROBE_IO_ERROR;
        goto done;
    }
    r->io = &fs;
    r->directory = app->run_dir;
    r->donor = saved->path;
    r->source = op->source;
    r->target = op->image;
    r->donor_key = &app->donor_key;
    r->target_key = &app->input_key;
    r->donor_hash = donor->image.digest;
    r->source_hash = op->dump.digest;
    r->connection = app->restore_connection;
    r->check_only = app->action != Tb2WorkflowBuild;
    const uint8_t empty[32] = {0};
    r->build = !memcmp(op->image_hash, empty, sizeof(empty));
    FlipperApplication* module = flipper_application_alloc(app->storage, firmware_api_interface);
    app->result = load_module(app, module, ModuleCore) && app->backend->restore ?
                      app->backend->restore(r) :
                      TB2_PROBE_IO_ERROR;
    close_module(app, module);
    if(app->result) {
        ui_status(app, r->error[0] ? r->error : PROCESSOR_RETRY, true);
        goto done;
    }
    app->flow.read = r->source_read;
    app->flow.image = r->image;
    /* A retry may verify the existing output but cannot replace its fingerprint. */
    if(!r->check_only && !r->build && memcmp(op->image_hash, r->image.sha256, 32)) {
        app->result = TB2_PROBE_CHECK_FAILED;
        goto done;
    }
    if(r->check_only) {
        if(donor->firmware.known) {
            /* Both keys passed independent image validation. Keep the donor's
             * association on its own version, then prefer the current profile. */
            saved->action = Tb2StoreSaveKey;
            saved->key = &app->donor_key;
            saved->profile = r->donor_read.profile;
            Tb2FirmwareIdentity firmware = donor->firmware;
            saved->firmware = &firmware;
            app->result = record_result(store_access(app, &fs, saved));
            saved->firmware = NULL;
            if(app->result) goto done;
        }
        app->result = record_source(app, &fs);
        goto done;
    }
    memcpy(app->flow.package.ca_sha256, r->donor_read.ca_sha256, 32);
    memcpy(app->flow.read.client_sha256, r->donor_read.client_sha256, 32);
    memcpy(op->image_hash, r->image.sha256, 32);
    if(!operation_access(app, &fs, Tb2OperationSave)) {
        app->result = TB2_PROBE_IO_ERROR;
        goto done;
    }
    app->result = record_publish(app, &fs, op->image, op->image_hash, Tb2WorkshopTarget, true);
    if(!app->result) {
        op->flash.flags |= (op->dump.flags & (Tb2SpiBound | Tb2SpiManual)) | Tb2SpiFileChecked |
                           Tb2SpiDigestBound;
        memcpy(op->flash.uid, op->dump.uid, sizeof(op->flash.uid));
        memcpy(op->flash.digest, op->image_hash, 32);
        op->phase = Tb2PhaseFlashProgram;
        if(!operation_access(app, &fs, Tb2OperationSave))
            app->result = TB2_PROBE_IO_ERROR;
        else
            app->result = spi_phase(app, &fs, Tb2SpiFlash);
    }
    app->flow.complete = !app->result;
done:
    if(close_controls(app)) {
        op->state = Tb2UiAborted;
        app->result = TB2_PROBE_CANCELLED;
    }
    close_worker_log(app);
    if(app->result) release_lease(app);
    free(donor);
    free(saved);
    free(r);
    atomic_store(&app->finished, true);
    return 0;
}
