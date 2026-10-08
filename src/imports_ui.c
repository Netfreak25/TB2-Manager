#include "setup.h"
#include "review.h"
#include "record_tasks.h"
#include "probe.h"
#include <dialogs/dialogs.h>
#include <flipper_application/flipper_application.h>
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/view_dispatcher.h>
#include <storage/storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMPORT_MENU    0U
#define IMPORT_TEXT    1U
#define IMPORT_KEY     2U
#define IMPORT_VERSION 3U

typedef enum {
    ImportSecrets = 100,
    ImportImages,
    ImportPackages,
    ImportKeyFile,
    ImportKeyManual,
    ImportKeyDone,
    ImportApply,
    ImportOriginal,
    ImportModified,
    ImportFirmwareA,
    ImportFirmwareB,
    ImportEditVersion,
    ImportVersionDone,
    ImportPackageFolder,
    ImportPackageTar,
    ImportDetails,
    ImportUp,
    ImportDown,
    ImportLeft,
    ImportRight,
    ImportDonorKey,
    ImportCurrentKey,
    ImportSavedKeys,
    ImportRestoreCheck,
    ImportDonorFile,
    ImportCurrentFile,
    VersionRenameDone,
    VersionRetry,
    ModifyGuided = 300,
    ModifyHosts,
    ModifyWifi,
    ModifyDevice,
    ModifyCertificates,
    EditFirmwareA,
    EditFirmwareB,
    EditFirmwareManual,
    EditHosts,
    EditWifi,
    EditDevice,
    EditReview,
    EditOtaHost,
    EditOtaPort,
    EditIciHost,
    EditIciPort,
    EditBothHosts,
    EditRegion,
    EditAddProfile,
    EditSsid,
    EditSecurity,
    EditPassword,
    EditPasswordRemove,
    EditPriority,
    EditDeleteProfile,
    EditLifecycle,
    EditOffline,
    EditLogLevel,
    EditValueDone,
    EditDone,
    EditApply,
    EditProfileBase = 400
} ImportEvent;
typedef enum {
    EditFieldNone,
    EditFieldOtaHost,
    EditFieldOtaPort,
    EditFieldIciHost,
    EditFieldIciPort,
    EditFieldBothHosts,
    EditFieldSsid,
    EditFieldPsk,
    EditFieldPriority,
} EditField;
typedef struct {
    uint8_t digits[TB2_FILE_VERSION_DIGITS], selected;
} VersionModel;
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* text;
    TextInput* keyboard;
    View* version;
    uint32_t view;
    bool donor;
    uint8_t profile;
    EditField edit_field;
    char key[TB2_WIFI_PSK_SIZE + 1];
    char selected_path[TB2_JOB_PATH_MAX];
} ImportUI;

static void import_show(ImportUI*);
static void import_key_done(void*);
static void editor_value_done(void*);
static void import_event(void* ctx, uint32_t event) {
    ImportUI* u = ctx;
    view_dispatcher_send_custom_event(u->dispatcher, event);
}
static void version_name_done(void* context) {
    import_event(context, VersionRenameDone);
}
static void import_add(ImportUI* u, const char* label, ImportEvent event) {
    submenu_add_item(u->menu, label, event, import_event, u);
}
static void import_text(ImportUI* u, const char* message) {
    text_box_set_text(u->text, message);
    u->view = IMPORT_TEXT;
    view_dispatcher_switch_to_view(u->dispatcher, IMPORT_TEXT);
}
static void import_work(ImportUI* u, Tb2RecordTaskKind kind) {
    u->request->record_task->kind = kind;
    u->request->action = Tb2SetupActionRecordTask;
    view_dispatcher_stop(u->dispatcher);
}
static void version_draw(Canvas* c, void* model) {
    VersionModel* m = model;
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 1, 9, "Firmware version");
    canvas_set_font(c, FontSecondary);
    const uint8_t positions[] = {17, 43, 55, 81, 93};
    for(unsigned i = 0; i < TB2_FILE_VERSION_DIGITS; i++) {
        char digit[] = {(char)('0' + m->digits[i]), 0};
        canvas_draw_str(c, positions[i], 29, digit);
        if(i == m->selected) canvas_draw_line(c, positions[i], 32, positions[i] + 7, 32);
    }
    canvas_draw_str(c, 31, 29, ".");
    canvas_draw_str(c, 69, 29, ".");
    Tb2FileVersion v;
    char value[TB2_FILE_VERSION_TEXT], line[32];
    tb2_file_version_from_digits(&v, m->digits);
    tb2_file_version_format(&v, value, sizeof(value));
    snprintf(line, sizeof(line), "Filename: %s", value);
    canvas_draw_str(c, 1, 47, line);
    canvas_draw_str(c, 1, 63, "Back: cancel   OK: Apply");
}
static bool version_input(InputEvent* input, void* ctx) {
    if(input->type != InputTypeShort && input->type != InputTypeRepeat) return false;
    ImportEvent ev;
    switch(input->key) {
    case InputKeyUp:
        ev = ImportUp;
        break;
    case InputKeyDown:
        ev = ImportDown;
        break;
    case InputKeyLeft:
        ev = ImportLeft;
        break;
    case InputKeyRight:
        ev = ImportRight;
        break;
    case InputKeyOk:
        ev = ImportVersionDone;
        break;
    default:
        return false;
    }
    import_event(ctx, ev);
    return true;
}
static void import_edit_version(ImportUI* u) {
    with_view_model(
        u->version,
        VersionModel * m,
        {
            tb2_file_version_digits(&u->request->record_task->import.label, m->digits);
            m->selected = 0;
        },
        true);
    u->view = IMPORT_VERSION;
    view_dispatcher_switch_to_view(u->dispatcher, IMPORT_VERSION);
}

static bool firmware_1622(const Tb2ImageIdentity* identity) {
    return (identity->firmware.known && !strcmp(identity->firmware.version, "1.6.22")) ||
           (identity->secondary.known && !strcmp(identity->secondary.version, "1.6.22"));
}

static void modify_select(ImportUI* u, Tb2ModifyMode mode) {
    u->request->modify_mode = mode;
    /* Every mode starts with the keyless settings/firmware inspection. The
     * certificate path requests a key only after the image label is known. */
    u->request->settings_only = true;
    u->request->editor_kind = Tb2SetupNew;
    u->request->action = Tb2SetupActionEdit;
    view_dispatcher_stop(u->dispatcher);
}

static void editor_text(ImportUI* u, EditField field, const char* header, const char* value) {
    u->edit_field = field;
    memset(u->key, 0, sizeof(u->key));
    snprintf(u->key, sizeof(u->key), "%s", value ? value : "");
    u->view = IMPORT_KEY;
    text_input_set_header_text(u->keyboard, header);
    text_input_set_result_callback(
        u->keyboard, editor_value_done, u, u->key, sizeof(u->key), true);
    view_dispatcher_switch_to_view(u->dispatcher, IMPORT_KEY);
}

static void editor_firmware(ImportUI* u) {
    Tb2ImageIdentity* identity = u->request->image_identity;
    submenu_set_header(u->menu, "Firmware label");
    char label[48];
    snprintf(
        label,
        sizeof(label),
        "Slot A: %s",
        identity->firmware.known ? identity->firmware.version : "Unknown");
    import_add(u, label, EditFirmwareA);
    snprintf(
        label,
        sizeof(label),
        "Slot B: %s",
        identity->secondary.known ? identity->secondary.version : "Unknown");
    import_add(u, label, EditFirmwareB);
    import_add(u, "Enter manually", EditFirmwareManual);
}

static void editor_hosts(ImportUI* u) {
    Tb2SettingsSnapshot* s = u->request->settings_snapshot;
    Tb2SettingsPatch* p = u->request->settings_patch;
    char label[80];
    submenu_set_header(u->menu, "Hosts & ports");
    snprintf(
        label,
        sizeof(label),
        "OTA: %s",
        p->server_fields & Tb2ServerOtaHost ? p->ota_host : s->servers.https_host);
    import_add(u, label, EditOtaHost);
    snprintf(
        label,
        sizeof(label),
        "OTA port: %u",
        p->server_fields & Tb2ServerOtaPort ? p->ota_port : s->servers.https_port);
    import_add(u, label, EditOtaPort);
    snprintf(
        label,
        sizeof(label),
        "ICI: %s",
        p->server_fields & Tb2ServerIciHost ? p->ici_host : s->servers.mqtt_host);
    import_add(u, label, EditIciHost);
    snprintf(
        label,
        sizeof(label),
        "ICI port: %u",
        p->server_fields & Tb2ServerIciPort ? p->ici_port : s->servers.mqtt_port);
    import_add(u, label, EditIciPort);
    import_add(u, "Set both hosts", EditBothHosts);
    import_add(u, "Done", EditDone);
}

static const char* security_name(uint8_t value) {
    return value == 0 ? "Open" : value == 1 ? "WPA2" : value == 3 ? "WPA3" : "WPA";
}

static void editor_wifi(ImportUI* u) {
    Tb2SettingsSnapshot* s = u->request->settings_snapshot;
    Tb2SettingsPatch* p = u->request->settings_patch;
    submenu_set_header(u->menu, "Wi-Fi profiles");
    char label[64];
    uint8_t region = p->region_set ? p->region : s->region;
    snprintf(label, sizeof(label), "Region: %s", region ? "US" : "EU");
    import_add(u, label, EditRegion);
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++) {
        Tb2WifiChange* change = &p->wifi[i];
        if(!s->wifi[i].any && change->operation != Tb2WifiAdd) continue;
        const char* name = change->fields & Tb2WifiSsid ? change->ssid : s->wifi[i].ssid;
        bool complete = (s->wifi[i].present & (Tb2WifiSsid | Tb2WifiSecurity | Tb2WifiPriority)) ==
                        (Tb2WifiSsid | Tb2WifiSecurity | Tb2WifiPriority);
        if(change->operation == Tb2WifiAdd) complete = change->fields & Tb2WifiSsid;
        snprintf(
            label,
            sizeof(label),
            "Profile %u: %s",
            i,
            name[0] ? name : (complete ? "Open" : "Incomplete"));
        import_add(u, label, EditProfileBase + i);
    }
    import_add(u, "Add profile", EditAddProfile);
    import_add(u, "Done", EditDone);
}

static void editor_wifi_profile(ImportUI* u) {
    Tb2WifiSnapshot* old = &u->request->settings_snapshot->wifi[u->profile];
    Tb2WifiChange* change = &u->request->settings_patch->wifi[u->profile];
    char label[72];
    snprintf(label, sizeof(label), "Wi-Fi profile %u", u->profile);
    submenu_set_header(u->menu, label);
    snprintf(
        label, sizeof(label), "SSID: %s", change->fields & Tb2WifiSsid ? change->ssid : old->ssid);
    import_add(u, label, EditSsid);
    uint8_t security = change->fields & Tb2WifiSecurity ? change->security : old->security;
    snprintf(label, sizeof(label), "Security: %s", security_name(security));
    import_add(u, label, EditSecurity);
    const char* password = !(change->fields & Tb2WifiPsk) ? "Keep" :
                           change->psk[0]                 ? "Replace" :
                                                            "Remove";
    snprintf(label, sizeof(label), "Password: %s", password);
    import_add(u, label, EditPassword);
    import_add(u, "Remove password", EditPasswordRemove);
    uint8_t priority = change->fields & Tb2WifiPriority ? change->priority : old->priority;
    snprintf(label, sizeof(label), "Priority: %u", priority);
    import_add(u, label, EditPriority);
    if(u->profile) import_add(u, "Delete profile", EditDeleteProfile);
    import_add(u, "Done", EditDone);
}

static void editor_device(ImportUI* u) {
    Tb2SettingsSnapshot* s = u->request->settings_snapshot;
    Tb2SettingsPatch* p = u->request->settings_patch;
    submenu_set_header(u->menu, "Service settings");
    char label[48];
    uint8_t lifecycle = p->device_fields & Tb2DeviceLifecycle ? p->lifecycle : s->lifecycle;
    snprintf(label, sizeof(label), "Lifecycle: %u", lifecycle);
    import_add(u, label, EditLifecycle);
    uint8_t offline = p->device_fields & Tb2DeviceOffline ? p->offline : s->offline;
    snprintf(label, sizeof(label), "Offline mode: %s", offline ? "On" : "Off");
    import_add(u, label, EditOffline);
    uint8_t level = p->device_fields & Tb2DeviceLogLevel ? p->log_level : s->log_level;
    snprintf(label, sizeof(label), "ICI log level: %u", level);
    import_add(u, label, EditLogLevel);
    import_add(u, "Done", EditDone);
}

static void editor_home(ImportUI* u) {
    Tb2SettingsPatch* p = u->request->settings_patch;
    submenu_set_header(
        u->menu, u->request->modify_mode == Tb2ModifyGuided ? "Modify wizard" : "Modify settings");
    if(u->request->modify_mode == Tb2ModifyGuided) {
        import_add(u, p->categories & Tb2SettingsHosts ? "Hosts: Edit" : "Hosts: Keep", EditHosts);
        import_add(u, p->categories & Tb2SettingsWifi ? "Wi-Fi: Edit" : "Wi-Fi: Keep", EditWifi);
        import_add(
            u, p->categories & Tb2SettingsDevice ? "Device: Edit" : "Device: Keep", EditDevice);
        import_add(u, "Certificates: Keep", ModifyCertificates);
    } else {
        import_add(
            u,
            u->request->modify_mode == Tb2ModifyHosts  ? "Edit hosts & ports" :
            u->request->modify_mode == Tb2ModifyWifi   ? "Edit Wi-Fi profiles" :
            u->request->modify_mode == Tb2ModifyDevice ? "Edit service settings" :
                                                         "Continue to certificates",
            u->request->modify_mode == Tb2ModifyHosts  ? EditHosts :
            u->request->modify_mode == Tb2ModifyWifi   ? EditWifi :
            u->request->modify_mode == Tb2ModifyDevice ? EditDevice :
                                                         ModifyCertificates);
    }
    import_add(u, "Review & build", EditReview);
}

static void editor_review(ImportUI* u) {
    Tb2SettingsPatch* patch = u->request->settings_patch;
    submenu_set_header(u->menu, "Review changes");
    if(patch->categories & Tb2SettingsHosts) import_add(u, "Hosts & ports: Edit", EditHosts);
    if(patch->categories & Tb2SettingsWifi) import_add(u, "Wi-Fi profiles: Edit", EditWifi);
    if(patch->categories & Tb2SettingsDevice) import_add(u, "Service settings: Edit", EditDevice);
    import_add(
        u,
        u->request->operation && u->request->operation->kind == Tb2OperationAio ?
            "Modify & Flash" :
            "Build modified image",
        EditApply);
}

static void editor_show(ImportUI* u) {
    Tb2ImportDraft* draft = &u->request->record_task->import;
    submenu_reset(u->menu);
    u->view = IMPORT_MENU;
    if(!draft->label_confirmed) {
        draft->stage = Tb2EditFirmware;
        editor_firmware(u);
    } else if(draft->stage == Tb2EditHosts)
        editor_hosts(u);
    else if(draft->stage == Tb2EditWifi)
        editor_wifi(u);
    else if(draft->stage == Tb2EditWifiProfile)
        editor_wifi_profile(u);
    else if(draft->stage == Tb2EditDevice)
        editor_device(u);
    else if(draft->stage == Tb2ImportDone)
        editor_review(u);
    else
        editor_home(u);
    view_dispatcher_switch_to_view(u->dispatcher, IMPORT_MENU);
}
static void import_show(ImportUI* u) {
    Tb2RecordTask* t = u->request->record_task;
    submenu_reset(u->menu);
    u->view = IMPORT_MENU;
    if(u->request->kind == Tb2SetupModifyMenu) {
        submenu_set_header(u->menu, "Modify");
        import_add(u, "Guided modify", ModifyGuided);
        import_add(u, "Hosts & ports", ModifyHosts);
        import_add(u, "Wi-Fi profiles", ModifyWifi);
        import_add(u, "Device settings", ModifyDevice);
        import_add(u, "Certificates", ModifyCertificates);
        view_dispatcher_switch_to_view(u->dispatcher, IMPORT_MENU);
        return;
    }
    if(u->request->kind == Tb2SetupSettingsEditor) {
        editor_show(u);
        return;
    }
    if(t && t->kind >= Tb2RecordTaskRenamePrepare) {
        if(t->kind == Tb2RecordTaskRenamePrepare && !u->request->result) {
            u->view = IMPORT_KEY;
            text_input_set_header_text(u->keyboard, "Version display name");
            text_input_set_result_callback(
                u->keyboard, version_name_done, u, t->path, sizeof(t->path), true);
            view_dispatcher_switch_to_view(u->dispatcher, IMPORT_KEY);
            return;
        }
        bool compare = t->kind == Tb2RecordTaskCompareChip;
        submenu_set_header(
            u->menu,
            u->request->result ? "Operation failed" :
            compare            ? (t->comparison.different ? "Different" : "Identical") :
                                 "Name saved");
        if(compare || u->request->result) import_add(u, "Retry", VersionRetry);
        if(u->request->result) {
            const char* error = compare && t->comparison.error[0] ? t->comparison.error :
                                t->report[0]                      ? t->report :
                                                                    u->request->error;
            if(!t->report[0]) snprintf(t->report, sizeof(t->report), "%s", error);
            import_add(u, "Details", ImportDetails);
        }
        view_dispatcher_switch_to_view(u->dispatcher, IMPORT_MENU);
        return;
    }
    if(u->request->kind == Tb2SetupVersionLabel) {
        t->import.stage = t->import.stage == Tb2ImportImagePreview ? Tb2ImportImagePreview :
                                                                     Tb2ImportImageVersion;
    }
    if(u->request->kind == Tb2SetupRestoreKeys) {
        submenu_set_header(u->menu, "Restore keys");
        import_add(u, "Use saved keys", ImportSavedKeys);
        import_add(
            u,
            u->request->donor_key->kind ? "Original key: selected" : "Original key file",
            ImportDonorFile);
        import_add(
            u,
            u->request->input_key->kind ? "Current key: selected" : "Current key file",
            ImportCurrentFile);
        import_add(u, "Check restore", ImportRestoreCheck);
        view_dispatcher_switch_to_view(u->dispatcher, IMPORT_MENU);
        return;
    }
    switch(t->import.stage) {
    case Tb2ImportHome:
        submenu_set_header(u->menu, "Import into box");
        import_add(u, "Secrets", ImportSecrets);
        import_add(u, "Server certificates", ImportPackages);
        import_add(u, "Images", ImportImages);
        break;
    case Tb2ImportSecrets:
        submenu_set_header(u->menu, "Import secret");
        import_add(u, "Select file", ImportKeyFile);
        break;
    case Tb2ImportKeyPreview:
        submenu_set_header(u->menu, "Unverified proposal");
        import_add(
            u,
            t->key.kind == Tb2InputKeySecret ? "8-byte box secret" : "16-byte AES key",
            ImportDetails);
        import_add(u, "Save key proposal", ImportApply);
        break;
    case Tb2ImportImageType:
        submenu_set_header(u->menu, "Image provenance");
        import_add(u, "Original", ImportOriginal);
        import_add(u, "Modified", ImportModified);
        import_add(u, "Image details", ImportDetails);
        break;
    case Tb2ImportImageVersion:
        submenu_set_header(u->menu, "Firmware label");
        snprintf(
            u->request->record_task->report,
            TB2_RECORD_REPORT_SIZE,
            "Slot A: %s\nSlot B: %s\nActive slot unknown.",
            t->import.identity.firmware.known ? t->import.identity.firmware.version : "Unknown",
            t->import.identity.secondary.known ? t->import.identity.secondary.version : "Unknown");
        char slot[48];
        snprintf(
            slot,
            sizeof(slot),
            "Slot A: %s",
            t->import.identity.firmware.known ? t->import.identity.firmware.version : "Unknown");
        import_add(u, slot, ImportFirmwareA);
        snprintf(
            slot,
            sizeof(slot),
            "Slot B: %s",
            t->import.identity.secondary.known ? t->import.identity.secondary.version : "Unknown");
        import_add(u, slot, ImportFirmwareB);
        import_add(u, "Enter manually", ImportEditVersion);
        if(t->import.label_confirmed) import_add(u, "Preview import", ImportApply);
        import_add(u, "Image details", ImportDetails);
        break;
    case Tb2ImportImagePreview:
        submenu_set_header(u->menu, t->import.duplicate ? "Already imported" : "Import image");
        import_add(u, "Details / target", ImportDetails);
        import_add(u, t->import.duplicate ? "Open version" : "Import image", ImportApply);
        break;
    case Tb2ImportPackageSource:
        submenu_set_header(u->menu, "Server certificates");
        if(t->import.package_result.package.error[0]) {
            snprintf(
                t->report,
                sizeof(t->report),
                "Server package rejected.\n%s",
                t->import.package_result.package.error);
            import_add(u, "Error details", ImportDetails);
        }
        import_add(u, "Folder: select ca-root.pem", ImportPackageFolder);
        import_add(u, "Select package TAR", ImportPackageTar);
        break;
    case Tb2ImportPackagePreview:
        submenu_set_header(u->menu, "Package checked");
        import_add(u, "Certificate details", ImportDetails);
        import_add(u, "Save package", ImportApply);
        break;
    default:
        submenu_set_header(u->menu, "Import into box");
        import_add(u, "Details", ImportDetails);
        break;
    }
    view_dispatcher_switch_to_view(u->dispatcher, IMPORT_MENU);
}
static bool import_browser(ImportUI* u, const char* extension) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, extension, NULL);
    options.base_path = TB2_APP_ROOT;
    options.hide_ext = false;
    FuriString* selected = furi_string_alloc_set(TB2_APP_ROOT);
    FuriString* start = furi_string_alloc_set(TB2_APP_ROOT);
    bool ok = dialog_file_browser_show(dialogs, selected, start, &options);
    char* target = u->request->record_task ? u->request->record_task->path : u->selected_path;
    if(ok && strlen(furi_string_get_cstr(selected)) < TB2_JOB_PATH_MAX)
        strcpy(target, furi_string_get_cstr(selected));
    else
        ok = false;
    furi_string_free(selected);
    furi_string_free(start);
    furi_record_close(RECORD_DIALOGS);
    return ok;
}
static bool import_read_key_file(ImportUI* u, Tb2InputKey* key) {
    if(!import_browser(u, ".txt")) return false;
    File* file = storage_file_alloc(u->request->storage);
    const char* path = u->request->record_task ? u->request->record_task->path : u->selected_path;
    bool opened = storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING);
    uint64_t size = opened ? storage_file_size(file) : 0;
    char bytes[TB2_KEY_TEXT_MAX + 4] = {0};
    bool ok = opened && size > 0 && size <= TB2_KEY_TEXT_MAX + 3 &&
              storage_file_read(file, bytes, (size_t)size) == size;
    if(opened) ok = storage_file_close(file) && ok;
    storage_file_free(file);
    if(ok) {
        const char* text = bytes;
        size_t length = (size_t)size;
        if(length >= 3 && (uint8_t)bytes[0] == 0xef && (uint8_t)bytes[1] == 0xbb &&
           (uint8_t)bytes[2] == 0xbf) {
            text += 3;
            length -= 3;
        }
        ok = tb2_reader_parse_key(text, length, key);
    }
    memset(bytes, 0, sizeof(bytes));
    if(!ok) memset(key, 0, sizeof(*key));
    return ok;
}
static void import_key_done(void* ctx) {
    import_event(ctx, ImportKeyDone);
}
static void editor_value_done(void* ctx) {
    import_event(ctx, EditValueDone);
}
static bool import_back(void* ctx) {
    ImportUI* u = ctx;
    if(u->request->record_task && u->request->record_task->kind >= Tb2RecordTaskRenamePrepare) {
        if(u->view == IMPORT_TEXT)
            import_show(u);
        else {
            u->request->action = Tb2SetupActionBoxes;
            view_dispatcher_stop(u->dispatcher);
        }
        return true;
    }
    if(u->request->kind == Tb2SetupVersionLabel) {
        if(u->view == IMPORT_TEXT || u->view == IMPORT_VERSION) {
            import_show(u);
        } else if(u->request->record_task->import.stage == Tb2ImportImagePreview) {
            u->request->record_task->import.stage = Tb2ImportImageVersion;
            import_show(u);
        } else {
            u->request->action = Tb2SetupActionOperationResult;
            view_dispatcher_stop(u->dispatcher);
        }
        return true;
    }
    if(u->request->kind == Tb2SetupModifyMenu) {
        u->request->action = Tb2SetupActionEdit;
        view_dispatcher_stop(u->dispatcher);
        return true;
    }
    if(u->request->kind == Tb2SetupSettingsEditor) {
        Tb2ImportDraft* draft = &u->request->record_task->import;
        if(u->view == IMPORT_KEY || u->view == IMPORT_VERSION) {
            memset(u->key, 0, sizeof(u->key));
            editor_show(u);
        } else if(draft->stage == Tb2EditWifiProfile) {
            draft->stage = Tb2EditWifi;
            editor_show(u);
        } else if(
            draft->stage == Tb2EditHosts || draft->stage == Tb2EditWifi ||
            draft->stage == Tb2EditDevice) {
            draft->stage = Tb2EditReview;
            editor_show(u);
        } else {
            u->request->editor_kind = Tb2SetupModifyMenu;
            u->request->action = Tb2SetupActionEdit;
            view_dispatcher_stop(u->dispatcher);
        }
        return true;
    }
    if(u->request->kind == Tb2SetupRestoreKeys) {
        memset(u->key, 0, sizeof(u->key));
        if(u->view == IMPORT_MENU) {
            u->request->action = Tb2SetupActionHome;
            view_dispatcher_stop(u->dispatcher);
        } else
            import_show(u);
        return true;
    }
    Tb2ImportDraft* d = &u->request->record_task->import;
    if(u->view == IMPORT_TEXT || u->view == IMPORT_VERSION)
        import_show(u);
    else if(u->view == IMPORT_KEY) {
        memset(u->key, 0, sizeof(u->key));
        d->stage = Tb2ImportSecrets;
        import_show(u);
    } else if(d->stage == Tb2ImportHome) {
        u->request->action = Tb2SetupActionBoxes;
        view_dispatcher_stop(u->dispatcher);
    } else {
        d->stage = d->stage == Tb2ImportImagePreview ? Tb2ImportImageVersion :
                   d->stage == Tb2ImportImageVersion ? Tb2ImportImageType :
                                                       Tb2ImportHome;
        import_show(u);
    }
    return true;
}
static bool import_restore_event(ImportUI* u, uint32_t ev) {
    if(ev == ImportDonorFile || ev == ImportCurrentFile) {
        Tb2InputKey* key = ev == ImportDonorFile ? u->request->donor_key : u->request->input_key;
        if(import_read_key_file(u, key))
            import_show(u);
        else
            import_text(u, "Key: 16 hex (secret) or 32 (AES).");
        return true;
    }
    if(ev == ImportDonorKey || ev == ImportCurrentKey) {
        u->donor = ev == ImportDonorKey;
        u->view = IMPORT_KEY;
        memset(u->key, 0, sizeof(u->key));
        text_input_set_header_text(
            u->keyboard, u->donor ? "Original key (hex)" : "Current key (hex)");
        text_input_set_result_callback(
            u->keyboard, import_key_done, u, u->key, sizeof(u->key), true);
        view_dispatcher_switch_to_view(u->dispatcher, IMPORT_KEY);
    } else if(ev == ImportKeyDone) {
        Tb2InputKey key;
        if(tb2_reader_parse_key(u->key, strlen(u->key), &key)) {
            *(u->donor ? u->request->donor_key : u->request->input_key) = key;
            import_show(u);
        } else
            import_text(u, "Key: 16 hex (secret) or 32 (AES).");
        memset(&key, 0, sizeof(key));
        memset(u->key, 0, sizeof(u->key));
    } else if(ev == ImportSavedKeys || ev == ImportRestoreCheck) {
        if(ev == ImportRestoreCheck &&
           (!u->request->donor_key->kind || !u->request->input_key->kind)) {
            import_text(u, "Both image keys required.");
            return true;
        }
        u->request->action = ev == ImportSavedKeys ? Tb2SetupActionRestoreSavedKeys :
                                                     Tb2SetupActionRestoreCheck;
        view_dispatcher_stop(u->dispatcher);
    } else
        return false;
    return true;
}

static bool ascii_text(const char* text, size_t maximum, bool empty) {
    size_t size = strlen(text);
    if((!empty && !size) || size > maximum) return false;
    for(size_t i = 0; i < size; i++)
        if((unsigned char)text[i] < 32 || (unsigned char)text[i] > 126) return false;
    return true;
}

static bool parse_u8(const char* text, uint8_t* value) {
    if(!*text) return false;
    char* end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if(*end || parsed > 255) return false;
    *value = (uint8_t)parsed;
    return true;
}

static bool parse_port_text(const char* text, uint16_t* value) {
    if(!*text) return false;
    char* end = NULL;
    unsigned long parsed = strtoul(text, &end, 10);
    if(*end || !parsed || parsed > 65535) return false;
    *value = (uint16_t)parsed;
    return true;
}

static Tb2WifiChange* editor_wifi_change(ImportUI* u) {
    Tb2WifiChange* change = &u->request->settings_patch->wifi[u->profile];
    if(change->operation == Tb2WifiKeep)
        change->operation = u->request->settings_snapshot->wifi[u->profile].any ? Tb2WifiUpdate :
                                                                                  Tb2WifiAdd;
    u->request->settings_patch->categories |= Tb2SettingsWifi;
    return change;
}

static void editor_error(ImportUI* u, const char* text) {
    snprintf(u->request->record_task->report, TB2_RECORD_REPORT_SIZE, "%s", text);
    import_text(u, u->request->record_task->report);
}

static void editor_certificate_flow(ImportUI* u) {
    Tb2SettingsPatch* patch = u->request->settings_patch;
    Tb2SettingsSnapshot* snapshot = u->request->settings_snapshot;
    snprintf(
        u->request->spec->options.https_host,
        TB2_HOST_MAX,
        "%s",
        patch->server_fields & Tb2ServerOtaHost ? patch->ota_host : snapshot->servers.https_host);
    snprintf(
        u->request->spec->options.ici_host,
        TB2_HOST_MAX,
        "%s",
        patch->server_fields & Tb2ServerIciHost ? patch->ici_host : snapshot->servers.mqtt_host);
    memset(&u->request->spec->server, 0, sizeof(u->request->spec->server));
    u->request->spec->export_archive = 1;
    u->request->settings_only = false;
    u->request->editor_kind = Tb2SetupResume;
    u->request->record_task->import.identity = *u->request->image_identity;
    import_work(u, Tb2RecordTaskTargetReserve);
}

static bool editor_custom(ImportUI* u, uint32_t ev) {
    Tb2ImportDraft* draft = &u->request->record_task->import;
    Tb2SettingsSnapshot* snapshot = u->request->settings_snapshot;
    Tb2SettingsPatch* patch = u->request->settings_patch;
    if(u->request->kind == Tb2SetupModifyMenu) {
        if(ev >= ModifyGuided && ev <= ModifyCertificates) {
            modify_select(u, (Tb2ModifyMode)(ev - ModifyGuided));
            return true;
        }
        return false;
    }
    if(u->request->kind != Tb2SetupSettingsEditor) return false;
    if(ev >= EditProfileBase && ev < EditProfileBase + TB2_WIFI_PROFILE_COUNT) {
        u->profile = (uint8_t)(ev - EditProfileBase);
        draft->stage = Tb2EditWifiProfile;
        editor_show(u);
        return true;
    }
    if(ev == ImportVersionDone && u->view == IMPORT_VERSION) {
        with_view_model(
            u->version,
            VersionModel * m,
            { tb2_file_version_from_digits(&draft->label, m->digits); },
            false);
        draft->label_confirmed = true;
        draft->label_manual = true;
        draft->stage = Tb2EditReview;
        editor_show(u);
        return true;
    }
    switch(ev) {
    case EditFirmwareA:
    case EditFirmwareB: {
        const Tb2FirmwareIdentity* firmware = ev == EditFirmwareA ?
                                                  &u->request->image_identity->firmware :
                                                  &u->request->image_identity->secondary;
        if(!firmware->known || !tb2_file_version_parse(firmware->version, &draft->label)) {
            editor_error(u, "Choose another slot or enter a version.");
            break;
        }
        draft->label_confirmed = true;
        draft->label_manual = false;
        draft->stage = Tb2EditReview;
        editor_show(u);
        break;
    }
    case EditFirmwareManual:
        import_edit_version(u);
        break;
    case EditHosts:
        draft->stage = Tb2EditHosts;
        editor_show(u);
        break;
    case EditWifi:
        draft->stage = Tb2EditWifi;
        editor_show(u);
        break;
    case EditDevice:
        draft->stage = Tb2EditDevice;
        editor_show(u);
        break;
    case EditReview:
        draft->stage = Tb2ImportDone;
        editor_show(u);
        break;
    case EditOtaHost:
        editor_text(
            u,
            EditFieldOtaHost,
            "OTA hostname",
            patch->server_fields & Tb2ServerOtaHost ? patch->ota_host :
                                                      snapshot->servers.https_host);
        break;
    case EditIciHost:
        editor_text(
            u,
            EditFieldIciHost,
            "ICI hostname",
            patch->server_fields & Tb2ServerIciHost ? patch->ici_host :
                                                      snapshot->servers.mqtt_host);
        break;
    case EditBothHosts:
        editor_text(u, EditFieldBothHosts, "Both hostnames", snapshot->servers.https_host);
        break;
    case EditOtaPort:
    case EditIciPort: {
        char text[8];
        uint16_t value =
            ev == EditOtaPort ?
                (patch->server_fields & Tb2ServerOtaPort ? patch->ota_port :
                                                           snapshot->servers.https_port) :
                (patch->server_fields & Tb2ServerIciPort ? patch->ici_port :
                                                           snapshot->servers.mqtt_port);
        snprintf(text, sizeof(text), "%u", value);
        editor_text(
            u,
            ev == EditOtaPort ? EditFieldOtaPort : EditFieldIciPort,
            ev == EditOtaPort ? "OTA port" : "ICI port",
            text);
        break;
    }
    case EditRegion:
        patch->categories |= Tb2SettingsWifi;
        patch->region = (patch->region_set ? patch->region : snapshot->region) ^ 1U;
        patch->region_set = true;
        editor_show(u);
        break;
    case EditAddProfile:
        for(unsigned i = 1; i < TB2_WIFI_PROFILE_COUNT; i++) {
            if(snapshot->wifi[i].any || patch->wifi[i].operation != Tb2WifiKeep) continue;
            u->profile = (uint8_t)i;
            Tb2WifiChange* change = editor_wifi_change(u);
            change->fields = Tb2WifiSsid | Tb2WifiSecurity | Tb2WifiPriority;
            change->security = 0;
            change->priority = 0;
            draft->stage = Tb2EditWifiProfile;
            editor_show(u);
            return true;
        }
        editor_error(u, "Profiles 1-9 occupied (including incomplete).");
        break;
    case EditSsid: {
        Tb2WifiChange* change = &patch->wifi[u->profile];
        editor_text(
            u,
            EditFieldSsid,
            "Wi-Fi SSID",
            change->fields & Tb2WifiSsid ? change->ssid : snapshot->wifi[u->profile].ssid);
        break;
    }
    case EditSecurity: {
        static const uint8_t values[] = {0, 1, 3, 9};
        Tb2WifiChange* change = editor_wifi_change(u);
        uint8_t current = change->fields & Tb2WifiSecurity ? change->security :
                                                             snapshot->wifi[u->profile].security;
        unsigned selected = 0;
        while(selected < 4 && values[selected] != current)
            selected++;
        change->security = values[(selected + 1) % 4];
        change->fields |= Tb2WifiSecurity;
        if(!change->security) {
            change->fields |= Tb2WifiPsk;
            change->psk[0] = 0;
        }
        editor_show(u);
        break;
    }
    case EditPassword:
        editor_text(u, EditFieldPsk, "Wi-Fi password", "");
        break;
    case EditPasswordRemove: {
        Tb2WifiChange* change = editor_wifi_change(u);
        change->fields |= Tb2WifiPsk;
        change->psk[0] = 0;
        editor_show(u);
        break;
    }
    case EditPriority: {
        Tb2WifiChange* change = &patch->wifi[u->profile];
        char text[4];
        snprintf(
            text,
            sizeof(text),
            "%u",
            change->fields & Tb2WifiPriority ? change->priority :
                                               snapshot->wifi[u->profile].priority);
        editor_text(u, EditFieldPriority, "Priority 0-255", text);
        break;
    }
    case EditDeleteProfile:
        if(u->profile) {
            memset(&patch->wifi[u->profile], 0, sizeof(patch->wifi[u->profile]));
            patch->wifi[u->profile].operation = Tb2WifiDelete;
            patch->categories |= Tb2SettingsWifi;
            draft->stage = Tb2EditWifi;
            editor_show(u);
        }
        break;
    case EditLifecycle:
    case EditOffline:
    case EditLogLevel: {
        bool supported = firmware_1622(u->request->image_identity);
        bool present = ev == EditLifecycle ? snapshot->lifecycle_present :
                       ev == EditOffline   ? snapshot->offline_present :
                                             snapshot->log_level_present;
        if(!present && !supported) {
            editor_error(u, "Field missing; creation needs 1.6.22.");
            break;
        }
        patch->categories |= Tb2SettingsDevice;
        if(ev == EditLifecycle) {
            uint8_t current = patch->device_fields & Tb2DeviceLifecycle ? patch->lifecycle :
                                                                          snapshot->lifecycle;
            patch->device_fields |= Tb2DeviceLifecycle;
            patch->lifecycle = current >= 8 || current < 1 ? 1 : current + 1;
        } else if(ev == EditOffline) {
            uint8_t current = patch->device_fields & Tb2DeviceOffline ? patch->offline :
                                                                        snapshot->offline;
            patch->device_fields |= Tb2DeviceOffline;
            patch->offline = current ^ 1U;
        } else {
            uint8_t current = patch->device_fields & Tb2DeviceLogLevel ? patch->log_level :
                                                                         snapshot->log_level;
            patch->device_fields |= Tb2DeviceLogLevel;
            patch->log_level = (uint8_t)((current + 1U) % 5U);
        }
        editor_show(u);
        break;
    }
    case EditDone:
        draft->stage = Tb2EditReview;
        editor_show(u);
        break;
    case EditValueDone: {
        bool valid = true;
        if(u->edit_field == EditFieldOtaHost || u->edit_field == EditFieldIciHost ||
           u->edit_field == EditFieldBothHosts) {
            valid = tb2_server_host_valid(u->key);
            if(valid) {
                patch->categories |= Tb2SettingsHosts;
                if(u->edit_field != EditFieldIciHost) {
                    patch->server_fields |= Tb2ServerOtaHost;
                    strcpy(patch->ota_host, u->key);
                }
                if(u->edit_field != EditFieldOtaHost) {
                    patch->server_fields |= Tb2ServerIciHost;
                    strcpy(patch->ici_host, u->key);
                }
            }
        } else if(u->edit_field == EditFieldOtaPort || u->edit_field == EditFieldIciPort) {
            uint16_t value = 0;
            valid = parse_port_text(u->key, &value);
            if(valid) {
                patch->categories |= Tb2SettingsHosts;
                if(u->edit_field == EditFieldOtaPort) {
                    patch->server_fields |= Tb2ServerOtaPort;
                    patch->ota_port = value;
                } else {
                    patch->server_fields |= Tb2ServerIciPort;
                    patch->ici_port = value;
                }
            }
        } else if(u->edit_field == EditFieldSsid) {
            valid = ascii_text(u->key, TB2_WIFI_SSID_SIZE - 1, false);
            if(valid) {
                Tb2WifiChange* change = editor_wifi_change(u);
                change->fields |= Tb2WifiSsid;
                strcpy(change->ssid, u->key);
            }
        } else if(u->edit_field == EditFieldPsk) {
            valid = ascii_text(u->key, TB2_WIFI_PSK_SIZE - 1, false);
            if(valid) {
                Tb2WifiChange* change = editor_wifi_change(u);
                change->fields |= Tb2WifiPsk;
                strcpy(change->psk, u->key);
            }
        } else if(u->edit_field == EditFieldPriority) {
            uint8_t value = 0;
            valid = parse_u8(u->key, &value);
            if(valid) {
                Tb2WifiChange* change = editor_wifi_change(u);
                change->fields |= Tb2WifiPriority;
                change->priority = value;
            }
        }
        memset(u->key, 0, sizeof(u->key));
        if(!valid)
            editor_error(u, "Invalid format, length or ASCII.");
        else
            editor_show(u);
        break;
    }
    case EditApply:
        if(!patch->categories || !tb2_settings_patch_valid(patch)) {
            editor_error(u, "Complete SSID, security and password.");
            break;
        }
        bool host_changed = ((patch->server_fields & Tb2ServerOtaHost) &&
                             strcmp(patch->ota_host, snapshot->servers.https_host)) ||
                            ((patch->server_fields & Tb2ServerIciHost) &&
                             strcmp(patch->ici_host, snapshot->servers.mqtt_host));
        if(host_changed) {
            editor_certificate_flow(u);
            break;
        }
        u->request->settings_only = true;
        u->request->editor_kind = Tb2SetupTarget;
        u->request->record_task->import.identity = *u->request->image_identity;
        import_work(u, Tb2RecordTaskTargetReserve);
        break;
    case ModifyCertificates:
        editor_certificate_flow(u);
        break;
    default:
        return false;
    }
    return true;
}

static bool import_custom(void* ctx, uint32_t ev) {
    ImportUI* u = ctx;
    if(editor_custom(u, ev)) return true;
    if(u->request->kind == Tb2SetupRestoreKeys) return import_restore_event(u, ev);
    Tb2RecordTask* t = u->request->record_task;
    Tb2ImportDraft* d = &t->import;
    if(ev >= ImportUp && ev <= ImportRight) {
        with_view_model(
            u->version,
            VersionModel * m,
            {
                if(ev == ImportLeft)
                    m->selected =
                        (m->selected + TB2_FILE_VERSION_DIGITS - 1) % TB2_FILE_VERSION_DIGITS;
                else if(ev == ImportRight)
                    m->selected = (m->selected + 1) % TB2_FILE_VERSION_DIGITS;
                else
                    m->digits[m->selected] =
                        (m->digits[m->selected] + (ev == ImportUp ? 1 : 9)) % 10;
            },
            true);
        return true;
    }
    switch(ev) {
    case VersionRenameDone:
        import_work(u, Tb2RecordTaskRename);
        break;
    case VersionRetry:
        import_work(u, t->kind);
        break;
    case ImportSecrets:
        d->stage = Tb2ImportSecrets;
        import_show(u);
        break;
    case ImportPackages:
        d->stage = Tb2ImportPackageSource;
        import_show(u);
        break;
    case ImportImages:
        if(import_browser(u, ".bin")) {
            memset(d, 0, sizeof(*d));
            t->version[0] = 0;
            t->flags = 0;
            import_work(u, Tb2RecordTaskImportInspect);
        }
        break;
    case ImportKeyFile:
        if(import_browser(u, ".txt")) import_work(u, Tb2RecordTaskImportKey);
        break;
    case ImportKeyManual:
        memset(u->key, 0, sizeof(u->key));
        u->view = IMPORT_KEY;
        text_input_set_header_text(u->keyboard, "Secret / AES key (hex)");
        text_input_set_result_callback(
            u->keyboard, import_key_done, u, u->key, sizeof(u->key), true);
        view_dispatcher_switch_to_view(u->dispatcher, IMPORT_KEY);
        break;
    case ImportKeyDone:
        if(tb2_reader_parse_key(u->key, strlen(u->key), &t->key)) {
            d->stage = Tb2ImportKeyPreview;
            strcpy(t->report, "Unverified key; verified key retained.");
            import_show(u);
        } else
            import_text(u, "Key: 16 hex (secret) or 32 (AES).");
        memset(u->key, 0, sizeof(u->key));
        break;
    case ImportOriginal:
    case ImportModified:
        d->image_kind = ev == ImportOriginal ? Tb2ImageOriginal : Tb2ImageModified;
        d->stage = Tb2ImportImageVersion;
        import_show(u);
        break;
    case ImportFirmwareA:
    case ImportFirmwareB: {
        const Tb2FirmwareIdentity* firmware = ev == ImportFirmwareA ? &d->identity.firmware :
                                                                      &d->identity.secondary;
        if(!firmware->known || !tb2_file_version_parse(firmware->version, &d->label)) {
            import_text(u, "Choose another slot or enter a version.");
            break;
        }
        d->label_confirmed = true;
        d->label_manual = false;
        import_show(u);
        break;
    }
    case ImportEditVersion:
        d->label_manual = true;
        import_edit_version(u);
        break;
    case ImportVersionDone:
        with_view_model(
            u->version,
            VersionModel * m,
            { tb2_file_version_from_digits(&d->label, m->digits); },
            false);
        d->label_confirmed = true;
        d->label_manual = true;
        import_show(u);
        break;
    case ImportPackageFolder:
    case ImportPackageTar:
        if(import_browser(u, ev == ImportPackageFolder ? ".pem" : ".tar")) {
            d->package_checked = false;
            memset(&d->package_result, 0, sizeof(d->package_result));
            d->package_folder = ev == ImportPackageFolder;
            if(d->package_folder) {
                char* slash = strrchr(t->path, '/');
                if(!slash || strcmp(slash + 1, "ca-root.pem")) {
                    import_text(u, "Select ca-root.pem in the package folder.");
                    break;
                }
                *slash = 0;
            }
            import_work(u, Tb2RecordTaskImportPackage);
        }
        break;
    case ImportDetails:
        if(d->stage == Tb2ImportPackagePreview) {
            const Tb2PackageResult* result = &d->package_result.package;
            snprintf(
                t->report,
                sizeof(t->report),
                "Pairs, chain, signatures, key usage: OK.\nValidity: %s\nAssignment: %s",
                result->validity & Tb2PackageExpired     ? "Expired" :
                result->validity & Tb2PackageNotYetValid ? "Not yet valid" :
                                                           "Valid at import",
                t->version[0] ? "Selected Modified version" : "Unassigned");
        }
        import_text(u, t->report);
        break;
    case ImportApply:
        if(d->stage == Tb2ImportKeyPreview)
            import_work(u, Tb2RecordTaskKeyCandidate);
        else if(d->stage == Tb2ImportImageVersion)
            import_work(u, Tb2RecordTaskFilePreview);
        else if(d->stage == Tb2ImportImagePreview) {
            if(d->duplicate && !(t->flags & TB2_RECORD_MOVE_SOURCE)) {
                strcpy(u->request->version_id, t->version);
                u->request->action = Tb2SetupActionBoxes;
                view_dispatcher_stop(u->dispatcher);
            } else
                import_work(
                    u,
                    t->flags & TB2_RECORD_MOVE_SOURCE ? Tb2RecordTaskFilePublish :
                                                        Tb2RecordTaskImportImage);
        } else if(d->stage == Tb2ImportPackagePreview)
            import_work(u, Tb2RecordTaskPackageAssign);
        break;
    default:
        return false;
    }
    return true;
}
static bool run(Tb2SetupRequest* r) {
    if(r->kind == Tb2SetupFirmwareHeaders && r->record_task) return tb2_headers_ui(r);
    if((!r->record_task && r->kind != Tb2SetupRestoreKeys) || !r->box_id[0]) return false;
    if(r->kind == Tb2SetupAioImport) {
        if(!r->operation || r->operation->kind != Tb2OperationAio ||
           r->operation->state != Tb2UiComplete || !r->operation->image[0])
            return false;
        Tb2RecordTask* task = r->record_task;
        memset(task, 0, sizeof(*task));
        task->kind = Tb2RecordTaskImportInspect;
        strcpy(task->box, r->box_id);
        strcpy(task->path, r->operation->image);
        task->import.image_kind = Tb2ImageModified;
        r->action = Tb2SetupActionRecordTask;
        return true;
    }
    if(r->kind == Tb2SetupVersionLabel && !(r->record_task->flags & TB2_RECORD_MOVE_SOURCE)) {
        if(!r->operation || !r->image_identity || !r->operation->source[0]) return false;
        Tb2RecordTask* task = r->record_task;
        memset(task, 0, sizeof(*task));
        task->kind = Tb2RecordTaskFilePublish;
        task->flags = TB2_RECORD_MOVE_SOURCE;
        snprintf(task->path, sizeof(task->path), "%s", r->operation->source);
        task->import.stage = Tb2ImportImageVersion;
        task->import.image_kind = Tb2ImageOriginal;
        task->import.identity = *r->image_identity;
        task->import.identity_checked = true;
        task->import.image.size = TB2_IMAGE_SIZE;
        memcpy(task->import.image.digest, r->operation->dump.digest, 32);
    }
    ImportUI* u = calloc(1, sizeof(*u));
    if(!u) return false;
    u->request = r;
    if(r->record_task) strcpy(r->record_task->box, r->box_id);
    u->dispatcher = view_dispatcher_alloc();
    u->menu = submenu_alloc();
    u->text = text_box_alloc();
    u->keyboard = text_input_alloc();
    u->version = view_alloc();
    view_allocate_model(u->version, ViewModelTypeLocking, sizeof(VersionModel));
    view_set_context(u->version, u);
    view_set_draw_callback(u->version, version_draw);
    view_set_input_callback(u->version, version_input);
    view_dispatcher_set_event_callback_context(u->dispatcher, u);
    view_dispatcher_set_custom_event_callback(u->dispatcher, import_custom);
    view_dispatcher_set_navigation_event_callback(u->dispatcher, import_back);
    view_dispatcher_add_view(u->dispatcher, IMPORT_MENU, submenu_get_view(u->menu));
    view_dispatcher_add_view(u->dispatcher, IMPORT_TEXT, text_box_get_view(u->text));
    view_dispatcher_add_view(u->dispatcher, IMPORT_KEY, text_input_get_view(u->keyboard));
    view_dispatcher_add_view(u->dispatcher, IMPORT_VERSION, u->version);
    view_dispatcher_attach_to_gui(u->dispatcher, r->gui, ViewDispatcherTypeFullscreen);
    import_show(u);
    if(r->kind == Tb2SetupRestoreKeys && r->error[0])
        import_text(u, r->error);
    else if(
        r->record_task && r->record_task->kind < Tb2RecordTaskRenamePrepare &&
        r->record_task->result)
        import_text(u, r->record_task->report);
    view_dispatcher_run(u->dispatcher);
    for(unsigned i = 0; i <= IMPORT_VERSION; i++)
        view_dispatcher_remove_view(u->dispatcher, i);
    view_free(u->version);
    text_input_free(u->keyboard);
    text_box_free(u->text);
    submenu_free(u->menu);
    view_dispatcher_free(u->dispatcher);
    memset(u, 0, sizeof(*u));
    free(u);
    return true;
}
static const Tb2Setup imports = {.run = run};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_IMPORTS_ID,
    .ep_api_version = TB2_EDITOR_API,
    .entry_point = &imports};
const FlipperAppPluginDescriptor* tb2_imports_entry(void) {
    return &descriptor;
}
