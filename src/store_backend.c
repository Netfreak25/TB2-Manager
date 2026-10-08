#include "store.h"
#include <flipper_application/flipper_application.h>
#include <stdio.h>

#ifdef _MSC_VER
#define STORE_BACKEND_NOINLINE __declspec(noinline)
#else
#define STORE_BACKEND_NOINLINE __attribute__((noinline))
#endif

/** Publish an image from values produced by a preceding Core phase. Store owns
 * metadata and object publication, but never mounts or interprets the image. */
static Tb2RecordResult publish(Tb2StoreRequest* request) {
    if(!request->io || !request->source || !request->expected || !request->operation ||
       !request->flow || !request->identity)
        return Tb2RecordCorrupt;
    char artifacts[TB2_JOB_PATH_MAX];
    const char* name = request->slot == Tb2WorkshopTarget ? "target" :
                       request->slot == Tb2WorkshopSource ? "source" :
                                                            "backup";
    int length = snprintf(artifacts, sizeof(artifacts), "%s/%s-artifacts", request->staging, name);
    if(length <= 0 || length >= (int)sizeof(artifacts)) return Tb2RecordCorrupt;
    char package[TB2_JOB_PATH_MAX];
    request->action = Tb2StoreCapture;
    request->artifact_directory = artifacts;
    request->created = request->operation->created;
    request->version_flags = request->checked ?
                                 (request->settings_only ?
                                      Tb2VersionSettingsChecked :
                                      Tb2VersionImageChecked | Tb2VersionCertificatesChecked) :
                                 0;
    if(request->checked) {
        request->ca_fingerprint = request->slot == Tb2WorkshopTarget ?
                                      request->flow->package.ca_sha256 :
                                      request->flow->read.ca_sha256;
        request->client_fingerprint = request->flow->read.client_sha256;
    }
    if(request->slot == Tb2WorkshopTarget && request->checked &&
       request->operation->kind != Tb2OperationRestore) {
        length = snprintf(package, sizeof(package), "%s/package", request->staging);
        if(length <= 0 || length >= (int)sizeof(package)) return Tb2RecordCorrupt;
        request->package_directory = package;
        request->package_hash = request->operation->package_hash;
        request->package_ca_hash = request->operation->ca_hash;
        if(request->flow->image.endpoints_known)
            request->endpoints = &request->flow->image.endpoints;
    }
    Tb2RecordResult rc = tb2_store_run(request);
    if(!rc && request->slot == Tb2WorkshopSource && request->checked && !request->hardware &&
       request->identity->firmware.known) {
        request->action = Tb2StoreSaveKey;
        request->firmware = &request->identity->firmware;
        request->profile = request->flow->read.profile;
        rc = tb2_store_run(request);
    }
    return rc;
}

static STORE_BACKEND_NOINLINE Tb2RecordResult settings_preferences(Tb2StoreRequest* request) {
    Tb2UiPreferences preferences = {0};
    tb2_ui_preferences_load(request->storage, &preferences);
    const Tb2SettingsPatch* patch = request->settings_patch;
    if(patch->categories & Tb2SettingsHosts) {
        if(patch->server_fields & Tb2ServerOtaHost)
            memcpy(preferences.server_values.https_host, patch->ota_host, TB2_SERVER_HOST_SIZE);
        if(patch->server_fields & Tb2ServerIciHost)
            memcpy(preferences.server_values.mqtt_host, patch->ici_host, TB2_SERVER_HOST_SIZE);
        if(patch->server_fields & Tb2ServerOtaPort)
            preferences.server_values.https_port = patch->ota_port;
        if(patch->server_fields & Tb2ServerIciPort)
            preferences.server_values.mqtt_port = patch->ici_port;
        preferences.server_fields |= patch->server_fields;
        memset(&preferences.server, 0, sizeof(preferences.server));
    }
    return tb2_ui_preferences_save(request->storage, &preferences) ? Tb2RecordOk : Tb2RecordIo;
}

static Tb2RecordResult run(Tb2StoreRequest* request) {
    if(request->action == Tb2StorePublish) return publish(request);
    if(request->action == Tb2StoreTask) {
        Tb2RecordResult rc = tb2_store_task_key_file(request);
        if(rc) return rc;
    }
    if(request->action == Tb2StorePreflight) return tb2_store_preflight(request);
    if(request->action == Tb2StoreDefaults)
        return request->selection && (request->selection->kind == Tb2SetupLoadConfig ?
                                          tb2_setup_config(request->selection) :
                                          tb2_setup_defaults(request->selection)) ?
                   Tb2RecordOk :
                   Tb2RecordIo;
    if(request->action == Tb2StoreStatus) {
        if(request->spec && tb2_setup_status_values(
                                request->storage,
                                request->staging,
                                request->spec,
                                &request->status,
                                request->error,
                                sizeof(request->error)))
            return Tb2RecordOk;
        if(!request->error[0])
            snprintf(request->error, sizeof(request->error), "Job status not saved. Check SD.");
        return Tb2RecordIo;
    }
    if(request->action == Tb2StoreSettingsPreferences && request->settings_patch)
        return settings_preferences(request);
    return request->action == Tb2StoreKeyFile ? tb2_store_key_file(request) :
                                                tb2_store_run(request);
}
static const Tb2Store store = {.run = run};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_STORE_ID,
    .ep_api_version = TB2_STORE_API,
    .entry_point = &store};
const FlipperAppPluginDescriptor* tb2_store_entry(void) {
    return &descriptor;
}
