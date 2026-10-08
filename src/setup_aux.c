/* Included by setup.c. Native views are transient; no worker is resident here. */
typedef enum {
    AuxHome,
    AuxActions,
    AuxHelp,
    AuxSettings,
    AuxServer,
    AuxFolders,
    AuxManage,
    AuxManageRoot,
    AuxIdentity,
    AuxDelete,
    AuxText,
    AuxHost,
    AuxPort,
    AuxWiring,
    AuxApproval,
    AuxHardware
} AuxScreen;
typedef enum {
    AuxBoxesOpen,
    AuxImagesOpen,
    AuxActionsOpen,
    AuxManageOpen,
    AuxHelpOpen,
    AuxExit,
    AuxDump,
    AuxFlash,
    AuxModify,
    AuxAio,
    AuxFlipTdi,
    AuxJobs,
    AuxSettingsOpen,
    AuxInstructions,
    AuxWire,
    AuxVersion,
    AuxServerOpen,
    AuxFoldersOpen,
    AuxIdentityOpen,
    AuxUidToggle,
    AuxSpiToggle,
    AuxIdentitySave,
    AuxHostEdit,
    AuxOtaHostEdit,
    AuxIciHostEdit,
    AuxBothHostsEdit,
    AuxHttpsEdit,
    AuxMqttEdit,
    AuxPreset,
    AuxPackageFolder,
    AuxOutputFolder,
    AuxCurrent,
    AuxReset,
    AuxSave,
    AuxImageFlash,
    AuxImageModify,
    AuxDeleteOpen,
    AuxFullPath,
    AuxDeleteConfirm,
    AuxHostDone,
    AuxPortDone,
    AuxProgram,
    AuxOperationDetails,
    AuxRetry,
    AuxReadAgain,
    AuxVerifyRead,
    AuxVerifyFlash,
    AuxAioImport,
    AuxHomeReturn,
    AuxNextBox,
    AuxOperationLog,
    AuxParent
} AuxAction;
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* text;
    TextInput* keyboard;
    NumberInput* number;
    Widget* wiring;
    AuxScreen screen, back;
    bool job_editor, mqtt;
    uint8_t host_target;
    int folder;
    int32_t number_value;
    Tb2UiPreferences draft;
    Tb2ServerChange server;
    char host[TB2_SERVER_HOST_SIZE];
    char text_buffer[2048];
} Aux;
static void aux_show(Aux* a, AuxScreen screen);
static void aux_event(void* context, uint32_t event) {
    Aux* a = context;
    view_dispatcher_send_custom_event(a->dispatcher, event);
}
static void aux_add(Aux* a, const char* text, AuxAction action) {
    submenu_add_item(a->menu, text, action, aux_event, a);
}
static void
    aux_items(Aux* a, const char* header, const char* labels, uint8_t count, AuxAction first) {
    submenu_set_header(a->menu, header);
    for(uint8_t i = 0; i < count; i++) {
        aux_add(a, labels, (AuxAction)(first + i));
        labels += strlen(labels) + 1;
    }
}
static void aux_done(Aux* a, Tb2SetupAction action) {
    a->request->action = action;
    view_dispatcher_stop(a->dispatcher);
}
static void aux_text(Aux* a, AuxScreen back, const char* text) {
    if(text != a->text_buffer) strlcpy(a->text_buffer, text, sizeof(a->text_buffer));
    a->screen = AuxText;
    a->back = back;
    text_box_set_text(a->text, a->text_buffer);
    view_dispatcher_switch_to_view(a->dispatcher, SetupDetails);
}
static bool aux_browser(Aux* a) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, ".bin", NULL);
    options.base_path = TB2_APP_ROOT;
    options.hide_ext = false;
    FuriString* selected =
        furi_string_alloc_set(a->request->path[0] ? a->request->path : TB2_APP_ROOT);
    FuriString* start = furi_string_alloc_set(TB2_APP_ROOT);
    bool ok = dialog_file_browser_show(dialogs, selected, start, &options);
    if(ok && strlen(furi_string_get_cstr(selected)) < sizeof(a->request->path))
        snprintf(a->request->path, sizeof(a->request->path), "%s", furi_string_get_cstr(selected));
    else
        ok = false;
    furi_string_free(start);
    furi_string_free(selected);
    furi_record_close(RECORD_DIALOGS);
    return ok;
}
static uint16_t aux_port(Aux* a, bool mqtt) {
    if(!a->job_editor) {
        uint16_t value = mqtt ? a->draft.server_values.mqtt_port :
                                a->draft.server_values.https_port;
        return value ? value : (mqtt ? 8883 : 443);
    }
    uint16_t value = tb2_server_port(&a->server, mqtt);
    if(value) return value;
    return mqtt ? a->request->server_values.mqtt_port : a->request->server_values.https_port;
}
static void aux_show(Aux* a, AuxScreen screen) {
    typedef struct {
        char uid[12];
        char speed[11];
        char save[5];
    } HardwareLabels;
    static const char root[] = "Boxes\0Images\0Actions\0Manage\0Help\0Exit";
    static const char actions[] = "Dump\0Flash\0Modify\0AIO\0Core Flasher";
    static const char manage[] = "Jobs\0Settings";
    static const char help[] = "Instructions\0Wiring\0Version";
    static const char settings[] = "Server presets\0Folders\0Hardware";
    static const char folders[] = "Cert folder\0Output folder\0Show paths\0Reset folders\0Save";
    static const char image[] = "Flash\0Modify\0Delete\0Full path";
    static const char delete_image[] = "View name\0Delete BIN";
    static HardwareLabels hardware[] = {
        {"UID: Auto  ", "SPI:  2MHz", "Save"},
        {"UID: Manual", "SPI:  2MHz", "Save"},
    };
    a->screen = screen;
    submenu_reset(a->menu);
    char label[96];
    switch(screen) {
    case AuxHome:
        aux_items(a, "TB2 Manager " TB2_PROBE_VERSION, root, 6, AuxBoxesOpen);
        break;
    case AuxActions:
        aux_items(a, "Actions", actions, 5, AuxDump);
        break;
    case AuxApproval:
        tb2_menu_header(
            a->menu,
            a->request->gui,
            a->request->box_alias[0] ? a->request->box_alias : "Flash image?");
        aux_add(a, "Flash image", AuxProgram);
        aux_add(a, "Details", AuxOperationDetails);
        break;
    case AuxHardware: {
        Tb2SetupRequest* r = a->request;
        Tb2Operation* op = r->operation;
        bool done = !r->historical && !r->result && op->state == Tb2UiComplete;
        submenu_set_header(
            a->menu,
            r->historical                    ? "Saved state" :
            done                             ? (tb2_operation_dump(op->kind) ?
                                                    "Dump verified" :
                                                op->kind == Tb2OperationModify ?
                                                    (r->settings_only ? "Settings image verified" : "Image verified") :
                                                    "Flash verified") :
            op->state == Tb2UiAborted        ? "Job aborted" :
            r->result == TB2_PROBE_CANCELLED ? "Stopped" :
            !r->result && op->phase == Tb2PhaseSourceVerify && (op->dump.flags & Tb2SpiDumpSaved) ?
                                               "Dump saved" :
                                               "Incomplete");
        aux_add(a, "Details", AuxOperationDetails);
        aux_add(a, "View log", AuxOperationLog);
        if(done && op->kind == Tb2OperationAio) {
            if(op->flash.flags & Tb2SpiBound) aux_add(a, "Flash dump", AuxProgram);
            aux_add(a, "Import", AuxAioImport);
        }
        if(op->state != Tb2UiAborted && op->state != Tb2UiUnknown) {
            if(op->phase == Tb2PhaseSourceVerify ||
               (op->state == Tb2UiComplete && tb2_operation_dump(op->kind)))
                aux_add(
                    a,
                    (op->dump.flags & Tb2SpiDumpVerified) || r->result ? "Verify again" :
                                                                         "Verify dump",
                    AuxVerifyRead);
            else if(
                op->phase == Tb2PhaseFlashVerify ||
                (op->state == Tb2UiComplete && op->kind != Tb2OperationModify))
                aux_add(a, "Verify again", AuxVerifyFlash);
            else if(!done)
                aux_add(
                    a,
                    op->phase == Tb2PhaseArchiveSource ? "Name dump" : "Retry / resume",
                    AuxRetry);
            if(!done && op->phase == Tb2PhaseSourceVerify && !(op->dump.flags & Tb2SpiDigestBound))
                aux_add(a, "Read again", AuxReadAgain);
            if(op->phase == Tb2PhaseFlashVerify) aux_add(a, "Retry flash", AuxProgram);
        }
        if(tb2_operation_pure(op->kind))
            aux_add(a, "Back", AuxParent);
        else
            aux_add(a, "Next box", AuxNextBox);
        aux_add(a, "Main menu", AuxHomeReturn);
        break;
    }
    case AuxHelp:
        aux_items(a, "Help", help, 3, AuxInstructions);
        break;
    case AuxSettings:
        aux_items(a, "Settings", settings, 3, AuxServerOpen);
        break;
    case AuxIdentity:
        HardwareLabels* labels = &hardware[!!(a->draft.hardware_options & Tb2HardwareManualUid)];
        unsigned speed = (a->draft.hardware_options & Tb2HardwareSpiMask) >> Tb2HardwareSpiShift;
        labels->speed[5] = "   1"[speed];
        labels->speed[6] = "2486"[speed];
        aux_items(a, "Hardware", labels->uid, 3, AuxUidToggle);
        break;
    case AuxManageRoot:
        aux_items(a, "Manage", manage, 2, AuxJobs);
        break;
    case AuxServer:
        submenu_set_header(a->menu, a->job_editor ? "Edit servers" : "Server presets");
        if(a->job_editor) {
            snprintf(
                label,
                sizeof(label),
                "Host: %s",
                a->server.fields & TB2_SERVER_HOST ? a->server.host : "keep");
            aux_add(a, label, AuxHostEdit);
        } else {
            snprintf(
                label,
                sizeof(label),
                "OTA: %s",
                a->draft.server_fields & Tb2ServerOtaHost ? a->draft.server_values.https_host :
                                                            "not set");
            aux_add(a, label, AuxOtaHostEdit);
            snprintf(
                label,
                sizeof(label),
                "ICI: %s",
                a->draft.server_fields & Tb2ServerIciHost ? a->draft.server_values.mqtt_host :
                                                            "not set");
            aux_add(a, label, AuxIciHostEdit);
            aux_add(a, "Set both", AuxBothHostsEdit);
        }
        snprintf(
            label,
            sizeof(label),
            "HTTPS: %u%s",
            aux_port(a, false),
            a->job_editor && !(a->server.fields & TB2_SERVER_HTTPS) ? " (keep)" : "");
        aux_add(a, label, AuxHttpsEdit);
        snprintf(
            label,
            sizeof(label),
            "MQTT: %u%s",
            aux_port(a, true),
            a->job_editor && !(a->server.fields & TB2_SERVER_MQTT) ? " (keep)" : "");
        aux_add(a, label, AuxMqttEdit);
        if(a->job_editor) {
            if(a->draft.server_fields) aux_add(a, "Use presets", AuxPreset);
            aux_add(a, "Image values", AuxCurrent);
        }
        aux_add(a, "Reset servers", AuxReset);
        aux_add(a, a->job_editor ? "Apply" : "Save", AuxSave);
        break;
    case AuxFolders:
        aux_items(a, "Folders", folders, 5, AuxPackageFolder);
        break;
    case AuxManage:
        if(!a->request->path[0] && !aux_browser(a)) {
            aux_done(a, Tb2SetupActionHome);
            return;
        }
        aux_items(a, "Image", image, 4, AuxImageFlash);
        break;
    case AuxDelete:
        aux_items(a, "Delete BIN?", delete_image, 2, AuxFullPath);
        break;
    default:
        return;
    }
    view_dispatcher_switch_to_view(a->dispatcher, SetupMenu);
}
static bool aux_host_valid(const char* text, FuriString* error, void* context) {
    UNUSED(context);
    if(!text[0] || tb2_server_host_valid(text)) return true;
    furi_string_set(error, "DNS: 63 ASCII max; no URL, IP or port.");
    return false;
}
static void aux_host_done(void* context) {
    aux_event(context, AuxHostDone);
}
static void aux_number_done(void* context, int32_t value) {
    Aux* a = context;
    a->number_value = value;
    aux_event(a, AuxPortDone);
}
static bool aux_back(void* context) {
    Aux* a = context;
    switch(a->screen) {
    case AuxHome:
        aux_done(a, Tb2SetupActionExit);
        break;
    case AuxText:
        aux_show(a, a->back);
        break;
    case AuxHost:
    case AuxPort:
        aux_show(a, AuxServer);
        break;
    case AuxServer:
        if(a->job_editor)
            aux_done(a, Tb2SetupActionKeepServer);
        else
            aux_show(a, AuxSettings);
        break;
    case AuxIdentity:
    case AuxFolders:
        aux_show(a, AuxSettings);
        break;
    case AuxSettings:
        aux_show(a, AuxManageRoot);
        break;
    case AuxWiring:
        aux_show(a, AuxHelp);
        break;
    case AuxDelete:
        aux_show(a, AuxManage);
        break;
    case AuxManage:
        a->request->path[0] = 0;
        aux_show(a, AuxManage);
        break;
    case AuxApproval:
    case AuxHardware:
        if(a->request->editor_kind == Tb2SetupImages) a->request->path[0] = 0;
        aux_done(a, Tb2SetupActionEdit);
        break;
    default:
        aux_show(a, AuxHome);
        break;
    }
    return true;
}
static bool aux_save(Aux* a) {
    if(a->screen == AuxServer && a->job_editor && !tb2_server_change_valid(&a->server))
        return false;
    if(a->job_editor) {
        a->request->spec->server = a->server;
        if(a->server.fields) {
            snprintf(
                a->request->spec->options.https_host,
                TB2_HOST_MAX,
                "%s",
                a->server.fields & TB2_SERVER_HOST ? a->server.host :
                                                     a->request->server_values.https_host);
            snprintf(
                a->request->spec->options.ici_host,
                TB2_HOST_MAX,
                "%s",
                a->server.fields & TB2_SERVER_HOST ? a->server.host :
                                                     a->request->server_values.mqtt_host);
        }
        aux_done(a, Tb2SetupActionApplyServer);
        return true;
    }
    Tb2UiPreferences saved = {0};
    tb2_ui_preferences_load(a->request->storage, &saved);
    if(a->screen == AuxServer) {
        saved.server_values = a->draft.server_values;
        saved.server_fields = a->draft.server_fields;
        memset(&saved.server, 0, sizeof(saved.server));
    } else if(a->screen == AuxIdentity) {
        saved.hardware_options = a->draft.hardware_options;
    } else {
        memcpy(saved.package_dir, a->draft.package_dir, sizeof(saved.package_dir));
        memcpy(saved.output_dir, a->draft.output_dir, sizeof(saved.output_dir));
    }
    if(!tb2_ui_preferences_save(a->request->storage, &saved)) return false;
    a->draft = saved;
    aux_text(a, AuxSettings, "Settings saved.");
    return true;
}
static bool aux_action(void* context, uint32_t action) {
    Aux* a = context;
    if(action >= AuxProgram && action <= AuxHomeReturn) {
        static const uint8_t actions[] = {
            Tb2SetupActionProgram,
            Tb2SetupActionOperationDetails,
            Tb2SetupActionRetryOperation,
            Tb2SetupActionRead,
            Tb2SetupActionVerifyRead,
            Tb2SetupActionVerifyFlash,
            Tb2SetupActionAioImport,
            Tb2SetupActionHome};
        aux_done(a, actions[action - AuxProgram]);
        return true;
    }
    Tb2SetupRequest* r = a->request;
    switch(action) {
    case AuxParent:
        aux_back(a);
        break;
    case AuxOperationLog:
        aux_done(a, Tb2SetupActionOperationLog);
        break;
    case AuxNextBox:
        r->box_id[0] = r->version_id[0] = r->path[0] = r->directory[0] = r->key_path[0] = 0;
        if(r->input_key) memset(r->input_key, 0, sizeof(*r->input_key));
        if(r->donor_key) memset(r->donor_key, 0, sizeof(*r->donor_key));
        if(r->operation) r->operation->approved = false;
        r->key_from_file = r->restore_connection = false;
        aux_done(a, Tb2SetupActionHome);
        break;
    case AuxDump:
        r->path[0] = 0;
        aux_done(a, Tb2SetupActionPureDump);
        break;
    case AuxAio:
        r->path[0] = 0;
        aux_done(a, Tb2SetupActionAio);
        break;
    case AuxFlipTdi:
        aux_done(a, Tb2SetupActionFlipTdi);
        break;
    case AuxJobs:
        aux_done(a, Tb2SetupActionJobs);
        break;
    case AuxExit:
        aux_done(a, Tb2SetupActionExit);
        break;
    case AuxImageModify:
    case AuxModify:
        if(a->screen != AuxManage) r->path[0] = 0;
        r->version_id[0] = 0;
        aux_done(a, Tb2SetupActionModify);
        break;
    case AuxImageFlash:
    case AuxFlash:
        if(a->screen == AuxManage || aux_browser(a)) {
            aux_done(a, Tb2SetupActionPureFlash);
        }
        break;
    case AuxActionsOpen:
        r->editor_kind = Tb2SetupActions;
        aux_show(a, AuxActions);
        break;
    case AuxManageOpen:
        r->editor_kind = Tb2SetupManage;
        aux_show(a, AuxManageRoot);
        break;
    case AuxBoxesOpen:
        r->version_id[0] = 0;
        aux_done(a, Tb2SetupActionBoxes);
        break;
    case AuxImagesOpen:
        r->version_id[0] = 0;
        r->editor_kind = Tb2SetupImages;
        r->path[0] = 0;
        aux_show(a, AuxManage);
        break;
    case AuxIdentityOpen:
        tb2_ui_preferences_load(r->storage, &a->draft);
        aux_show(a, AuxIdentity);
        break;
    case AuxUidToggle:
        a->draft.hardware_options ^= Tb2HardwareManualUid;
        aux_show(a, AuxIdentity);
        break;
    case AuxSpiToggle:
        a->draft.hardware_options = (a->draft.hardware_options + (1U << Tb2HardwareSpiShift)) &
                                    (Tb2HardwareManualUid | Tb2HardwareSpiMask);
        aux_show(a, AuxIdentity);
        break;
    case AuxHelpOpen:
        aux_show(a, AuxHelp);
        break;
    case AuxSettingsOpen:
        aux_show(a, AuxSettings);
        break;
    case AuxServerOpen:
        tb2_ui_preferences_load(r->storage, &a->draft);
        aux_show(a, AuxServer);
        break;
    case AuxFoldersOpen:
        tb2_ui_preferences_load(r->storage, &a->draft);
        aux_show(a, AuxFolders);
        break;
    case AuxInstructions:
        aux_text(a, AuxHelp, "Dump: read/verify\nFlash: erase/write/verify\nKeys/TAR private");
        break;
    case AuxVersion:
        aux_text(a, AuxHelp, TB2_PROBE_VERSION "\nAPI88.4\nW25Q128FV\nSPI 2/4MHz");
        break;
    case AuxWire:
        a->screen = AuxWiring;
        widget_reset(a->wiring);
        widget_add_icon_element(a->wiring, 0, 0, &I_Wiring_SPI_128x64);
        view_dispatcher_switch_to_view(a->dispatcher, 4);
        break;
    case AuxHostEdit:
    case AuxOtaHostEdit:
    case AuxIciHostEdit:
    case AuxBothHostsEdit:
        a->host_target = action == AuxOtaHostEdit   ? 1 :
                         action == AuxIciHostEdit   ? 2 :
                         action == AuxBothHostsEdit ? 3 :
                                                      0;
        strlcpy(
            a->host,
            a->job_editor       ? a->server.host :
            a->host_target == 2 ? a->draft.server_values.mqtt_host :
                                  a->draft.server_values.https_host,
            sizeof(a->host));
        text_input_reset(a->keyboard);
        text_input_set_header_text(
            a->keyboard,
            a->job_editor || a->host_target == 3 ? "Both hosts" :
            a->host_target == 1                  ? "OTA hostname" :
                                                   "ICI hostname");
        text_input_set_minimum_length(a->keyboard, 0);
        text_input_set_validator(a->keyboard, aux_host_valid, a);
        text_input_set_result_callback(
            a->keyboard, aux_host_done, a, a->host, sizeof(a->host), false);
        a->screen = AuxHost;
        view_dispatcher_switch_to_view(a->dispatcher, SetupKeyboard);
        break;
    case AuxHostDone:
        if(a->host[0] && !tb2_server_host_valid(a->host)) break;
        if(a->job_editor) {
            memcpy(a->server.host, a->host, sizeof(a->host));
            if(a->host[0])
                a->server.fields |= TB2_SERVER_HOST;
            else
                a->server.fields &= ~TB2_SERVER_HOST;
        } else {
            if(a->host_target != 2) {
                snprintf(a->draft.server_values.https_host, TB2_SERVER_HOST_SIZE, "%s", a->host);
                if(a->host[0])
                    a->draft.server_fields |= Tb2ServerOtaHost;
                else
                    a->draft.server_fields &= ~Tb2ServerOtaHost;
            }
            if(a->host_target != 1) {
                snprintf(a->draft.server_values.mqtt_host, TB2_SERVER_HOST_SIZE, "%s", a->host);
                if(a->host[0])
                    a->draft.server_fields |= Tb2ServerIciHost;
                else
                    a->draft.server_fields &= ~Tb2ServerIciHost;
            }
        }
        aux_show(a, AuxServer);
        break;
    case AuxHttpsEdit:
    case AuxMqttEdit:
        a->mqtt = action == AuxMqttEdit;
        number_input_set_header_text(a->number, a->mqtt ? "MQTT port" : "HTTPS port");
        number_input_set_result_callback(
            a->number, aux_number_done, a, aux_port(a, a->mqtt), 1, UINT16_MAX);
        a->screen = AuxPort;
        view_dispatcher_switch_to_view(a->dispatcher, 3);
        break;
    case AuxPortDone:
        if(a->number_value < 1 || a->number_value > UINT16_MAX) break;
        if(a->job_editor) {
            tb2_server_set_port(&a->server, a->mqtt, (uint16_t)a->number_value);
            a->server.fields |= a->mqtt ? TB2_SERVER_MQTT : TB2_SERVER_HTTPS;
        } else if(a->mqtt) {
            a->draft.server_values.mqtt_port = (uint16_t)a->number_value;
            a->draft.server_fields |= Tb2ServerIciPort;
        } else {
            a->draft.server_values.https_port = (uint16_t)a->number_value;
            a->draft.server_fields |= Tb2ServerOtaPort;
        }
        aux_show(a, AuxServer);
        break;
    case AuxPreset:
        if((a->draft.server_fields & (Tb2ServerOtaHost | Tb2ServerIciHost)) ==
               (Tb2ServerOtaHost | Tb2ServerIciHost) &&
           !strcmp(a->draft.server_values.https_host, a->draft.server_values.mqtt_host)) {
            strlcpy(a->server.host, a->draft.server_values.https_host, sizeof(a->server.host));
            a->server.fields |= TB2_SERVER_HOST;
        }
        if(a->draft.server_fields & Tb2ServerOtaPort) {
            tb2_server_set_port(&a->server, false, a->draft.server_values.https_port);
            a->server.fields |= TB2_SERVER_HTTPS;
        }
        if(a->draft.server_fields & Tb2ServerIciPort) {
            tb2_server_set_port(&a->server, true, a->draft.server_values.mqtt_port);
            a->server.fields |= TB2_SERVER_MQTT;
        }
        aux_show(a, AuxServer);
        break;
    case AuxReset:
        if(a->screen == AuxServer) {
            if(a->job_editor)
                memset(&a->server, 0, sizeof(a->server));
            else {
                memset(&a->draft.server_values, 0, sizeof(a->draft.server_values));
                a->draft.server_fields = 0;
            }
        } else {
            a->draft.package_dir[0] = 0;
            a->draft.output_dir[0] = 0;
        }
        aux_show(a, a->screen);
        break;
    case AuxIdentitySave:
    case AuxSave:
        if(!aux_save(a)) aux_text(a, a->screen, "Save failed. Check values/SD.");
        break;
    case AuxCurrent:
        if(a->screen == AuxFolders)
            snprintf(
                a->text_buffer,
                sizeof(a->text_buffer),
                "Certificates:\n%s\nOutput:\n%s",
                a->draft.package_dir,
                a->draft.output_dir);
        else
            snprintf(
                a->text_buffer,
                sizeof(a->text_buffer),
                "Image:\nOTA %s:%u\nICI %s:%u",
                r->server_values.https_host,
                r->server_values.https_port,
                r->server_values.mqtt_host,
                r->server_values.mqtt_port);
        aux_text(a, a->screen, a->text_buffer);
        break;
    case AuxPackageFolder:
    case AuxOutputFolder:
        a->folder = action == AuxPackageFolder ? 1 : 2;
        view_dispatcher_stop(a->dispatcher);
        break;
    case AuxFullPath:
        aux_text(a, a->screen, r->path);
        break;
    case AuxDeleteOpen:
        /* Native scrollable text shows the entire filename before confirmation. */
        aux_text(a, AuxDelete, r->path);
        break;
    case AuxDeleteConfirm: {
        FileInfo info;
        size_t size = strlen(r->path);
        if(size > 4 && setup_bin_suffix(r->path) &&
           storage_common_stat(r->storage, r->path, &info) == FSE_OK && !file_info_is_dir(&info) &&
           storage_common_remove(r->storage, r->path) == FSE_OK) {
            r->path[0] = 0;
            aux_text(a, AuxManage, "BIN deleted. Jobs kept.");
        } else
            aux_text(a, AuxManage, "Delete failed. Check SD.");
        break;
    }
    default:
        return false;
    }
    return true;
}
static bool aux_run(Tb2SetupRequest* r) {
    Aux* a = calloc(1, sizeof(*a));
    if(!a) return false;
    a->request = r;
    a->job_editor = r->kind == Tb2SetupServerEditor;
    r->action = Tb2SetupActionExit;
    tb2_ui_preferences_load(r->storage, &a->draft);
    if(a->job_editor) a->server = r->spec->server;
    a->dispatcher = view_dispatcher_alloc();
    a->menu = submenu_alloc();
    a->text = text_box_alloc();
    a->keyboard = text_input_alloc();
    a->number = number_input_alloc();
    a->wiring = widget_alloc();
    view_dispatcher_set_event_callback_context(a->dispatcher, a);
    view_dispatcher_set_custom_event_callback(a->dispatcher, aux_action);
    view_dispatcher_set_navigation_event_callback(a->dispatcher, aux_back);
    view_dispatcher_add_view(a->dispatcher, SetupMenu, submenu_get_view(a->menu));
    view_dispatcher_add_view(a->dispatcher, SetupDetails, text_box_get_view(a->text));
    view_dispatcher_add_view(a->dispatcher, SetupKeyboard, text_input_get_view(a->keyboard));
    view_dispatcher_add_view(a->dispatcher, 3, number_input_get_view(a->number));
    view_dispatcher_add_view(a->dispatcher, 4, widget_get_view(a->wiring));
    view_dispatcher_attach_to_gui(a->dispatcher, r->gui, ViewDispatcherTypeFullscreen);
    aux_show(
        a,
        a->job_editor                     ? AuxServer :
        r->kind == Tb2SetupFlashApprove   ? AuxApproval :
        r->kind == Tb2SetupHardwareResult ? AuxHardware :
        r->kind == Tb2SetupActions        ? AuxActions :
        r->kind == Tb2SetupManage         ? AuxManageRoot :
        r->kind == Tb2SetupImages         ? AuxManage :
                                            AuxHome);
    if(r->kind == Tb2SetupHardwareResult && r->result && r->error[0])
        aux_text(a, AuxHardware, r->error);
    for(;;) {
        view_dispatcher_run(a->dispatcher);
        if(!a->folder) break;
        Tb2SetupRequest* edit = malloc(sizeof(*edit));
        if(!edit) {
            a->folder = 0;
            aux_text(a, AuxFolders, "Low RAM. Retry.");
            continue;
        }
        *edit = *r;
        edit->kind = Tb2SetupFolderOnly;
        char* path = a->folder == 1 ? a->draft.package_dir : a->draft.output_dir;
        strlcpy(edit->path, path[0] ? path : TB2_APP_ROOT, sizeof(edit->path));
        if(setup_legacy_run(edit)) snprintf(path, TB2_JOB_PATH_MAX, "%s", edit->path);
        free(edit);
        a->folder = 0;
        aux_show(a, AuxFolders);
    }
    for(unsigned i = 0; i < 5; i++)
        view_dispatcher_remove_view(a->dispatcher, i);
    submenu_free(a->menu);
    text_box_free(a->text);
    text_input_free(a->keyboard);
    number_input_free(a->number);
    widget_free(a->wiring);
    view_dispatcher_free(a->dispatcher);
    /* Reload committed preferences: Back may have discarded a draft. */
    tb2_ui_preferences_load(r->storage, &a->draft);
    r->hardware_options = a->draft.hardware_options;
    free(a);
    return true;
}
