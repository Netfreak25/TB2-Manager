/* Management uses the same responsive resident progress/Back controller. */
static void clear_record_task(ProbeApp* app) {
    if(app->record_task) {
        volatile unsigned char* bytes = (volatile unsigned char*)app->record_task;
        for(size_t i = 0; i < sizeof(*app->record_task); i++)
            bytes[i] = 0;
        free(app->record_task);
        app->record_task = NULL;
    }
}
static int32_t record_task_worker(void* context) {
    ProbeApp* app = context;
    Tb2NativeIO native;
    Tb2WorkflowIO fs = filesystem(app, &native);
    app->result = 0;
    Tb2SpiRequest request = {.io = &fs, .wait_context = app, .waiting = spi_waiting};
    if(app->record_task->kind == Tb2RecordTaskFirmwareHeaders) {
        memset(&app->record_task->headers, 0, sizeof(app->record_task->headers));
        request.action = Tb2SpiHeaders;
        request.headers = &app->record_task->headers;
        app->result = run_spi(app, &request);
        goto complete;
    }
    if(app->record_task->kind == Tb2RecordTaskImportInspect &&
       !app->record_task->import.identity_checked) {
        Tb2ImportDraft* draft = &app->record_task->import;
        memset(&draft->identity, 0, sizeof(draft->identity));
        request.path = app->record_task->path;
        request.action = Tb2SpiInspectFile;
        request.identity = &draft->identity;
        app->result = run_spi(app, &request);
        if(!app->result) draft->identity_checked = true;
    }
    if(!app->result) {
        Tb2StoreRequest* r = calloc(1, sizeof(*r));
        if(!r)
            app->result = TB2_PROBE_IO_ERROR;
        else {
            r->action = Tb2StoreTask;
            r->task = app->record_task;
            if(!r->task->timestamp) r->task->timestamp = furi_hal_rtc_get_timestamp();
            app->result = record_result(store_access(app, &fs, r));
            free(r);
        }
    }
    if(!app->result && app->record_task->kind == Tb2RecordTaskCompareChip) {
        Tb2SpiReceipt receipt = {0};
        request.action = Tb2SpiCompare;
        request.path = app->record_task->path;
        request.receipt = &receipt;
        request.result = &app->record_task->comparison;
        app->result = run_spi(app, &request);
    }
complete:
    close_controls(app);
    atomic_store(&app->finished, true);
    return 0;
}

static int32_t package_import_worker(void* context) {
    ProbeApp* app = context;
    Tb2RecordTask* task = app->record_task;
    app->result = TB2_PROBE_IO_ERROR;
    if(task) {
        Tb2NativeIO native;
        Tb2WorkflowIO fs = filesystem(app, &native);
        const char* directory = task->import.package_folder ? task->path : task->staging;
        FlipperApplication* module =
            flipper_application_alloc(app->storage, firmware_api_interface);
        bool loaded = load_module(app, module, ModuleCertificates);
        if(loaded)
            app->result = app->backend->package_import(
                &fs, directory, task->staging, task->timestamp, &task->import.package_result);
        close_module(app, module);
        if(!app->result) {
            task->import.package_checked = true;
            task->import.stage = Tb2ImportPackagePreview;
            task->result = Tb2RecordOk;
        } else {
            task->import.stage = Tb2ImportPackageSource;
            task->result = app->result == TB2_PROBE_CANCELLED ? Tb2RecordCancelled :
                                                                Tb2RecordCorrupt;
        }
    }
    close_controls(app);
    atomic_store(&app->finished, true);
    return 0;
}
