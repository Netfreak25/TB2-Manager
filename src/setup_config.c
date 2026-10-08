#include "setup.h"
#ifndef TB2_SETUP_HOST_TEST
#include <storage/storage.h>
#include <furi_hal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SETUP_CONFIG_SIZE 1024U
bool tb2_setup_defaults(Tb2SetupRequest* r) {
    if(!r->defaults) return false;
    tb2_ui_preferences_load(r->storage, &r->preferences);
    Tb2JobSpec* selected = r->spec;
    r->spec = r->defaults;
    memset(r->spec, 0, sizeof(*r->spec));
    DateTime date;
    furi_hal_rtc_get_datetime(&date);
    char text[32];
    for(unsigned i = 0; i < 2; i++) {
        int n = snprintf(
            text,
            sizeof(text),
            "%04u%02u%02u%02u%02u%02u",
            date.year + (i ? 10 : 0),
            date.month,
            date.day,
            date.hour,
            date.minute,
            date.second);
        if(n == TB2_DATE_SIZE - 1)
            memcpy(i ? r->spec->options.expires : r->spec->options.now, text, TB2_DATE_SIZE);
    }
    bool ok = tb2_setup_config(r);
    r->spec = selected;
    return ok;
}
bool tb2_setup_config(Tb2SetupRequest* r) {
    snprintf(r->spec->options.https_host, TB2_HOST_MAX, "tbs2.tonie.cloud");
    snprintf(r->spec->options.ici_host, TB2_HOST_MAX, "ici.tonie.cloud");
    File* file = storage_file_alloc(r->storage);
    bool opened = storage_file_open(file, TB2_CONFIG_PATH, FSAM_READ, FSOM_OPEN_EXISTING);
    int rc = storage_file_get_error(file);
    bool ok = r->event(r->context, "config_open", rc, TB2_CONFIG_PATH) &&
              (opened || rc == FSE_NOT_EXIST);
    if(opened) {
        uint64_t size = storage_file_size(file);
        char* text = size <= SETUP_CONFIG_SIZE ? malloc(SETUP_CONFIG_SIZE) : NULL;
        if(ok && text) {
            size_t actual = storage_file_read(file, text, size);
            ok = r->event(
                     r->context,
                     "config_read",
                     storage_file_get_error(file),
                     "bounded read; contents withheld") &&
                 actual == size && tb2_job_parse_config(text, size, r->spec, r->error);
        } else
            ok = false;
        bool closed = storage_file_close(file);
        ok = r->event(
                 r->context,
                 "config_close",
                 storage_file_get_error(file),
                 closed ? "closed" : "failed") &&
             closed && ok;
        free(text);
    }
    storage_file_free(file);
    if(!ok || !tb2_package_options_valid(&r->spec->options)) {
        if(!r->error[0])
            snprintf(
                r->error,
                sizeof(r->error),
                "Invalid config, SD or log. Check Flipper UTC clock and builder.conf.");
        return false;
    }
    return true;
}
