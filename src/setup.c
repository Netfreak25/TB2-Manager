#include "setup.h"
#include "probe.h"
#include <flipper_application/flipper_application.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/byte_input.h>
#include <dialogs/dialogs.h>
#include <furi_hal.h>
#include <storage/storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef TB2_AUX_MODULE
#include <gui/modules/number_input.h>
#include <gui/modules/widget.h>
#include "tb2_aux_icons.h"
#endif

#define SETUP_PAGE_SIZE   6U
#define SETUP_NAME_SIZE   96U
#define SETUP_ERROR_SIZE  768U
#define SETUP_CONFIG_SIZE 1024U
#include "menu_label.h"
typedef enum {
    SetupMenu,
    SetupDetails,
    SetupKeyboard
} SetupView;
#if defined(TB2_AUX_MODULE) || defined(TB2_SETUP_HOST_TEST)
typedef enum {
    SetupSummary,
    SetupFolder,
    SetupName,
    SetupError,
    SetupExit
} SetupScreen;
typedef enum {
    SetupUse,
    SetupParent,
    SetupPrevious,
    SetupNext,
    SetupSelectFolder,
    SetupEditName,
    SetupSave,
    SetupNameSaved,
    SetupChild
} SetupAction;
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* details;
    TextInput* keyboard;
    SetupScreen screen, error_return;
    bool accepted;
    uint32_t page, count;
    char directory[TB2_JOB_PATH_MAX], filename[SETUP_NAME_SIZE], edit[SETUP_NAME_SIZE];
    char previous_directory[TB2_JOB_PATH_MAX];
    char names[SETUP_PAGE_SIZE][TB2_JOB_PATH_MAX];
    char error[SETUP_ERROR_SIZE];
} Setup;

static bool setup_event(Setup* s, const char* operation, int rc, const char* detail) {
    return s->request->event(s->request->context, operation, rc, detail);
}
static void setup_item(void* context, uint32_t action) {
    Setup* s = context;
    view_dispatcher_send_custom_event(s->dispatcher, action);
}
static void setup_add(Setup* s, const char* label, uint32_t action) {
    submenu_add_item(s->menu, label, action, setup_item, s);
}
static void setup_error(Setup* s, SetupScreen back) {
    s->error_return = back;
    s->screen = SetupError;
    text_box_set_text(s->details, s->error);
    view_dispatcher_switch_to_view(s->dispatcher, SetupDetails);
}
static void setup_summary(Setup* s) {
    submenu_reset(s->menu);
    submenu_set_header(
        s->menu,
        s->request->dump_target ? "Dump target" :
        s->request->wizard      ? "4/4 Image target" :
                                  "Image target");
    char label[TB2_JOB_PATH_MAX + 16U];
    snprintf(label, sizeof(label), "Folder: %s", s->directory);
    setup_add(s, label, SetupSelectFolder);
    snprintf(label, sizeof(label), "Name: %s", s->filename);
    setup_add(s, label, SetupEditName);
    setup_add(
        s,
        s->request->dump_target ? "Read chip" :
        s->request->wizard      ? "Check" :
                                  "Use target",
        SetupSave);
    s->screen = SetupSummary;
    view_dispatcher_switch_to_view(s->dispatcher, SetupMenu);
}
/** A removed remembered directory must not trap the picker. Only its browsing
 * cursor moves to a readable ancestor; Back keeps the previous selection. */
static void setup_existing_parent(Setup* s) {
    FileInfo info;
    while(strcmp(s->directory, "/ext") &&
          (storage_common_stat(s->request->storage, s->directory, &info) != FSE_OK ||
           !file_info_is_dir(&info))) {
        char* slash = strrchr(s->directory, '/');
        if(!slash || slash < s->directory + 4) break;
        *slash = 0;
    }
}
static void setup_folder(Setup* s) {
    submenu_reset(s->menu);
    tb2_menu_header(s->menu, s->request->gui, strrchr(s->directory, '/') + 1);
    setup_add(s, "Use this folder", SetupUse);
    if(strcmp(s->directory, "/ext")) setup_add(s, ".. (parent folder)", SetupParent);
    if(s->page) setup_add(s, "< Previous folders", SetupPrevious);
    s->count = 0;
    File* dir = storage_file_alloc(s->request->storage);
    bool opened = storage_dir_open(dir, s->directory), more = false;
    bool logged = setup_event(s, "folder_open", storage_file_get_error(dir), "path withheld");
    FileInfo info;
    char name[TB2_JOB_PATH_MAX];
    unsigned seen = 0;
    while(opened && logged && storage_dir_read(dir, &info, name, sizeof(name))) {
        logged = setup_event(s, "folder_read", 0, "entry; name withheld");
        if(!file_info_is_dir(&info) || !strcmp(name, ".") || !strcmp(name, "..")) continue;
        if(seen++ < s->page) continue;
        if(s->count == SETUP_PAGE_SIZE) {
            more = true;
            break;
        }
        snprintf(s->names[s->count], sizeof(s->names[0]), "%s", name);
        setup_add(s, name, SetupChild + s->count++);
    }
    int rc = storage_file_get_error(dir);
    bool ok = opened && logged && (more || rc == FSE_NOT_EXIST);
    ok = setup_event(s, "folder_read_end", rc, more ? "page full" : "end or error") && ok;
    if(opened && !storage_dir_close(dir)) {
        rc = storage_file_get_error(dir);
        ok = false;
    }
    logged = setup_event(s, "folder_close", storage_file_get_error(dir), "directory handle");
    storage_file_free(dir);
    if(!ok || !logged) {
        snprintf(s->error, sizeof(s->error), "Cannot read folder.\nCheck SD.");
        setup_error(s, SetupExit);
        return;
    }
    if(more) setup_add(s, "More folders >", SetupNext);
    s->screen = SetupFolder;
    view_dispatcher_switch_to_view(s->dispatcher, SetupMenu);
}
static bool setup_package_check(Setup* s) {
    snprintf(s->error, sizeof(s->error), "Invalid certificate folder:\n%s\n\n", s->directory);
    bool ok = true;
    for(unsigned i = 0; i < TB2_PACKAGE_FILES; i++) {
        char path[TB2_JOB_PATH_MAX + TB2_JOB_NAME_MAX], message[96];
        snprintf(path, sizeof(path), "%s/%s", s->directory, tb2_package_names[i]);
        FileInfo info;
        int rc = storage_common_stat(s->request->storage, path, &info);
        bool valid = rc == FSE_OK && !file_info_is_dir(&info) && info.size > 0;
        snprintf(
            message,
            sizeof(message),
            "%s: %s (fs=%d)",
            tb2_package_names[i],
            valid               ? "found" :
            rc == FSE_NOT_EXIST ? "missing" :
                                  "empty, not a file or SD error",
            rc);
        if(!setup_event(s, "package_file_check", valid ? 0 : TB2_PROBE_CHECK_FAILED, message)) {
            snprintf(s->error, sizeof(s->error), "Cannot write SD log. Selection cancelled.");
            setup_error(s, SetupExit);
            return false;
        }
        if(!valid) {
            size_t used = strlen(s->error);
            snprintf(s->error + used, sizeof(s->error) - used, "%s\n", message);
            ok = false;
        }
    }
    if(!ok) setup_error(s, s->request->kind == Tb2SetupCheckPackage ? SetupExit : SetupFolder);
    return ok;
}
/** Filename only: separators, FAT metacharacters and ambiguous dot/space names
 * are rejected. The on-screen keyboard supplies ASCII; .bin is added if absent. */
static bool setup_bin_suffix(const char* name) {
    size_t n = strlen(name);
    return n > 4 && name[n - 4] == '.' && (name[n - 3] | 32) == 'b' && (name[n - 2] | 32) == 'i' &&
           (name[n - 1] | 32) == 'n';
}
static bool setup_name_valid(const char* name) {
    size_t length = strlen(name);
    if(!length || length >= SETUP_NAME_SIZE ||
       (!setup_bin_suffix(name) && length > SETUP_NAME_SIZE - sizeof(".bin")) || name[0] == '.' ||
       name[0] == ' ' || name[length - 1] == '.' || name[length - 1] == ' ')
        return false;
    for(size_t i = 0; i < length; i++)
        if((unsigned char)name[i] < 32 || (unsigned char)name[i] >= 127 ||
           strchr("/\\:*?\"<>|", name[i]))
            return false;
    return true;
}
static void setup_name_done(void* context) {
    setup_item(context, SetupNameSaved);
}
static void setup_name(Setup* s) {
    snprintf(s->edit, sizeof(s->edit), "%s", s->filename);
    text_input_set_header_text(s->keyboard, "Image filename (.bin)");
    text_input_set_result_callback(
        s->keyboard, setup_name_done, s, s->edit, sizeof(s->edit), false);
    s->screen = SetupName;
    view_dispatcher_switch_to_view(s->dispatcher, SetupKeyboard);
}
static bool setup_target(Setup* s, char path[TB2_JOB_PATH_MAX]) {
    int length = snprintf(path, TB2_JOB_PATH_MAX, "%s/%s", s->directory, s->filename);
    if(length < 0 || length >= (int)TB2_JOB_PATH_MAX) {
        snprintf(s->error, sizeof(s->error), "Target path too long.");
        return false;
    }
    FileInfo info;
    int rc = storage_common_stat(s->request->storage, s->directory, &info);
    bool ok = rc == FSE_OK && file_info_is_dir(&info);
    if(!setup_event(s, "target_directory", rc, "path withheld") || !ok) {
        snprintf(s->error, sizeof(s->error), "Target folder is missing or cannot be read.");
        return false;
    }
    rc = storage_common_stat(s->request->storage, path, &info);
    if(!setup_event(s, "target_exists", rc, "path withheld") || rc != FSE_NOT_EXIST) {
        snprintf(
            s->error,
            sizeof(s->error),
            "Target exists or SD is unavailable.\nNothing overwritten.");
        return false;
    }
    return true;
}
static void setup_accept(Setup* s, const char* path) {
    if(!setup_event(s, "setup_accept", 0, "selection validated; no file writes")) {
        snprintf(s->error, sizeof(s->error), "Cannot write SD log. Selection cancelled.");
        setup_error(s, SetupExit);
        return;
    }
    snprintf(s->request->path, sizeof(s->request->path), "%s", path);
    s->accepted = true;
    view_dispatcher_stop(s->dispatcher);
}
static bool setup_back(void* context) {
    Setup* s = context;
    if(s->screen == SetupError) {
        s->screen = s->error_return;
        if(s->screen == SetupFolder)
            view_dispatcher_switch_to_view(s->dispatcher, SetupMenu);
        else if(s->screen == SetupSummary)
            setup_summary(s);
        else if(s->screen == SetupName)
            setup_name(s);
        else
            view_dispatcher_stop(s->dispatcher);
    } else if(s->request->kind == Tb2SetupOutput && s->screen != SetupSummary) {
        if(s->screen == SetupFolder)
            snprintf(s->directory, sizeof(s->directory), "%s", s->previous_directory);
        setup_summary(s);
    } else {
        setup_event(s, "setup_cancel", 0, "previous selection unchanged");
        view_dispatcher_stop(s->dispatcher);
    }
    return true;
}
static bool setup_action(void* context, uint32_t action) {
    Setup* s = context;
    if(s->screen == SetupName && action == SetupNameSaved) {
        if(!setup_name_valid(s->edit)) {
            snprintf(
                s->error,
                sizeof(s->error),
                "Invalid name.\nNo /, special chars, leading dots/spaces.");
            setup_error(s, SetupName);
        } else {
            size_t length = strlen(s->edit);
            snprintf(
                s->filename,
                sizeof(s->filename),
                "%.*s.bin",
                (int)(setup_bin_suffix(s->edit) ? length - 4 : length),
                s->edit);
            setup_summary(s);
        }
    } else if(s->screen == SetupSummary) {
        if(action == SetupSelectFolder) {
            snprintf(s->previous_directory, sizeof(s->previous_directory), "%s", s->directory);
            setup_existing_parent(s);
            s->page = 0;
            setup_folder(s);
        } else if(action == SetupEditName)
            setup_name(s);
        else if(action == SetupSave) {
            char path[TB2_JOB_PATH_MAX];
            if(setup_target(s, path))
                setup_accept(s, path);
            else
                setup_error(s, SetupSummary);
        }
    } else if(s->screen == SetupFolder) {
        if(action == SetupUse) {
            if(s->request->kind == Tb2SetupOutput)
                setup_summary(s);
            else if(s->request->kind == Tb2SetupFolderOnly || setup_package_check(s))
                setup_accept(s, s->directory);
        } else {
            char path[TB2_JOB_PATH_MAX];
            if(action == SetupParent) {
                if(!strcmp(s->directory, "/ext")) return true;
                snprintf(
                    path,
                    sizeof(path),
                    "%.*s",
                    (int)(strrchr(s->directory, '/') - s->directory),
                    s->directory);
            } else if(action == SetupNext || action == SetupPrevious) {
                if(action == SetupPrevious && !s->page) return true;
                s->page = action == SetupNext ? s->page + SETUP_PAGE_SIZE :
                                                s->page - SETUP_PAGE_SIZE;
                setup_folder(s);
                return true;
            } else if(action >= SetupChild && action - SetupChild < s->count) {
                int length = snprintf(
                    path, sizeof(path), "%s/%s", s->directory, s->names[action - SetupChild]);
                if(length < 0 || length >= (int)sizeof(path)) {
                    snprintf(s->error, sizeof(s->error), "Folder path too long.");
                    setup_error(s, SetupFolder);
                    return true;
                }
            } else
                return true;
            snprintf(s->directory, sizeof(s->directory), "%s", path);
            s->page = 0;
            setup_folder(s);
        }
    }
    return true;
}
#endif
/** Configuration parsing is setup-only code, unloaded before crypto. */
#ifdef TB2_SETUP_HOST_TEST
#include "setup_config.c"
#define setup_config tb2_setup_config
#else
static bool setup_config(Tb2SetupRequest* r) {
    if(!r->defaults) return false;
    r->spec->options = r->defaults->options;
    snprintf(
        r->spec->imported_package,
        sizeof(r->spec->imported_package),
        "%s",
        r->defaults->imported_package);
    return true;
}
#endif
#if defined(TB2_AUX_MODULE) || defined(TB2_SETUP_HOST_TEST)
static bool setup_legacy_run(Tb2SetupRequest* request) {
    if(request->kind == Tb2SetupLoadConfig) return setup_config(request);
    Setup* s = calloc(1, sizeof(*s));
    if(!s) {
        snprintf(request->error, sizeof(request->error), "Not enough RAM for selection.");
        return false;
    }
    s->request = request;
    const char* slash = strrchr(request->path, '/');
    bool output = request->kind == Tb2SetupOutput;
    bool help = request->kind == Tb2SetupHelp || request->kind == Tb2SetupConfigHelp;
    if(!help &&
       (strncmp(request->path, "/ext", 4) || (request->path[4] && request->path[4] != '/') ||
        (output && (!slash || slash < request->path + 4 || !setup_name_valid(slash + 1))))) {
        snprintf(request->error, sizeof(request->error), "Invalid selection path.");
        free(s);
        return false;
    }
    snprintf(
        s->directory,
        sizeof(s->directory),
        "%.*s",
        output ? (int)(slash - request->path) : (int)strlen(request->path),
        request->path);
    if(output)
        snprintf(s->filename, sizeof(s->filename), "%s", slash + 1);
    else if(!help && (request->kind == Tb2SetupPackage || request->kind == Tb2SetupFolderOnly))
        setup_existing_parent(s);
    s->dispatcher = view_dispatcher_alloc();
    s->menu = submenu_alloc();
    s->details = text_box_alloc();
    s->keyboard = text_input_alloc();
    view_dispatcher_set_event_callback_context(s->dispatcher, s);
    view_dispatcher_set_custom_event_callback(s->dispatcher, setup_action);
    view_dispatcher_set_navigation_event_callback(s->dispatcher, setup_back);
    view_dispatcher_add_view(s->dispatcher, SetupMenu, submenu_get_view(s->menu));
    view_dispatcher_add_view(s->dispatcher, SetupDetails, text_box_get_view(s->details));
    view_dispatcher_add_view(s->dispatcher, SetupKeyboard, text_input_get_view(s->keyboard));
    view_dispatcher_attach_to_gui(s->dispatcher, request->gui, ViewDispatcherTypeFullscreen);
    if(help) {
        snprintf(
            s->error,
            sizeof(s->error),
            "%s",
            request->kind == Tb2SetupConfigHelp ?
                "Config (optional):\n" TB2_CONFIG_PATH
                "\nhttps_host=tbs2.tonie.cloud\nici_host=ici.tonie.cloud\nexpires_utc=YYYYMMDDhhmmss\npackage_dir=/ext/certs\nRTC: UTC\nSecret: mcu-sn.txt/manual\nAES: aes_key.txt\nKeys not logged." :
                "16-MiB dump + key + package/new CA.\nTarget, UTC, approve.\nImage verified = fresh check.\nBack: stop; keep backups. No upload.");
        setup_error(s, SetupExit);
    } else if(output)
        setup_summary(s);
    else if(request->kind == Tb2SetupCheckPackage) {
        if(setup_package_check(s)) setup_accept(s, s->directory);
    } else
        setup_folder(s);
    if(!s->accepted) view_dispatcher_run(s->dispatcher);
    view_dispatcher_remove_view(s->dispatcher, SetupMenu);
    view_dispatcher_remove_view(s->dispatcher, SetupDetails);
    view_dispatcher_remove_view(s->dispatcher, SetupKeyboard);
    submenu_free(s->menu);
    text_box_free(s->details);
    text_input_free(s->keyboard);
    view_dispatcher_free(s->dispatcher);
    bool accepted = s->accepted;
    if(request->wizard && output && !accepted) {
        int length =
            snprintf(request->path, sizeof(request->path), "%s/%s", s->directory, s->filename);
        if(length < 0 || length >= (int)sizeof(request->path)) request->path[0] = 0;
    }
    free(s);
    return accepted;
}
/** Editors return to the resident dispatcher bridge after releasing all views. */
static bool setup_edit_run(Tb2SetupRequest* request) {
    bool accepted = setup_legacy_run(request);
    if(request->kind == Tb2SetupOutput) {
        if(request->path[0])
            snprintf(request->spec->output_path, TB2_JOB_PATH_MAX, "%s", request->path);
        request->action = accepted ? (request->settings_only ? Tb2SetupActionSettingsBuild :
                                                               Tb2SetupActionInspect) :
                                     Tb2SetupActionCertificates;
    } else {
        if(accepted)
            snprintf(request->spec->imported_package, TB2_JOB_PATH_MAX, "%s", request->path);
        request->action = accepted ? Tb2SetupActionTarget : Tb2SetupActionCertificates;
    }
    return true;
}
#endif
#ifdef TB2_AUX_MODULE
#include "setup_aux.c"
#else
#include "setup_manager.c"
#endif
static bool setup_run(Tb2SetupRequest* request) {
#ifdef TB2_AUX_MODULE
    if(request->kind == Tb2SetupLoadConfig) return setup_config(request);
    if(request->kind == Tb2SetupDumpTarget) {
        if(!request->path[0]) {
            Tb2UiPreferences preferences = {0};
            tb2_ui_preferences_load(request->storage, &preferences);
            int n = snprintf(
                request->path,
                sizeof(request->path),
                "%s/dump-%08lx-%08lx.bin",
                preferences.output_dir[0] ? preferences.output_dir : TB2_APP_ROOT,
                (unsigned long)furi_hal_rtc_get_timestamp(),
                (unsigned long)furi_hal_random_get());
            if(n < 0 || n >= (int)sizeof(request->path)) return false;
        }
        request->kind = Tb2SetupOutput;
        request->dump_target = true;
        request->action = setup_legacy_run(request) ? Tb2SetupActionRead : Tb2SetupActionEdit;
        return true;
    }
    if(request->kind < Tb2SetupMenu || request->kind == Tb2SetupFolderOnly)
        return setup_edit_run(request);
    return aux_run(request);
#else
    if(request->kind == Tb2SetupLoadConfig) return setup_config(request);
    if(request->kind >= Tb2SetupMenu) return manager_run(request);
#ifdef TB2_SETUP_HOST_TEST
    return setup_legacy_run(request);
#else
    return false;
#endif
#endif
}
static const Tb2Setup setup = {.run = setup_run};
static const FlipperAppPluginDescriptor descriptor = {
#ifdef TB2_AUX_MODULE
    .appid = TB2_AUX_ID,
#else
    .appid = TB2_SETUP_ID,
#endif
    .ep_api_version = TB2_SETUP_API,
    .entry_point = &setup};
const FlipperAppPluginDescriptor* tb2_setup_entry(void) {
    return &descriptor;
}
