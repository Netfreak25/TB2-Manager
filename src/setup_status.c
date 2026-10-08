#include "setup.h"
#include <stdio.h>
#include <string.h>
bool tb2_setup_status_values(
    void* storage,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2UiStatus* status,
    char* warning,
    size_t warning_size) {
    if(!tb2_ui_status_write(storage, directory, spec, status)) {
        snprintf(warning, warning_size, "Job status not saved. Check SD.");
        return false;
    }
    if(status->state != Tb2UiComplete) return true;
    Tb2UiPreferences preferences = {0};
    tb2_ui_preferences_load(storage, &preferences);
    if(spec->server.fields) preferences.server = spec->server;
    if(spec->imported_package[0] && !(spec->server.fields & TB2_SERVER_HOST))
        snprintf(
            preferences.package_dir, sizeof(preferences.package_dir), "%s", spec->imported_package);
    else
        snprintf(
            preferences.package_dir, sizeof(preferences.package_dir), "%s/package", directory);
    char output[TB2_JOB_PATH_MAX];
    if(!tb2_job_image_path(spec, directory, output)) return false;
    const char* slash = strrchr(output, '/');
    if(!slash) return false;
    snprintf(
        preferences.output_dir,
        sizeof(preferences.output_dir),
        "%.*s",
        (int)(slash - output),
        output);
    if(!tb2_ui_preferences_save(storage, &preferences)) {
        snprintf(warning, warning_size, "Image verified; last folders not saved.");
        return false;
    }
    return true;
}

/** Headless persistence runs while no backend or GUI objects are allocated. */
bool tb2_setup_status(Tb2SetupRequest* r) {
    return tb2_setup_status_values(
        r->storage, r->directory, r->spec, &r->status, r->warning, sizeof(r->warning));
}
