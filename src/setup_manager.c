/* Included by setup.c: one transient module owns every non-processing view. */
#include "record_tasks.h"
#define MANAGER_ROOT        TB2_JOBS_ROOT
#define MANAGER_TEXT_SIZE   1800U
#define MANAGER_SCAN_BUDGET 4U
#define MANAGER_TICK_MS     50U
typedef enum {
    ManagerHome,
    ManagerDump,
    ManagerKey,
    ManagerServer,
    ManagerCertificates,
    ManagerTarget,
    ManagerHelp,
    ManagerSettings,
    ManagerText,
    ManagerApprove,
    ManagerResult,
    ManagerCatalog,
    ManagerJob,
    ManagerManual,
    ManagerLog
} ManagerScreen;
typedef enum {
    ManagerNew = 100,
    ManagerJobs,
    ManagerHelpOpen,
    ManagerDumpChoose,
    ManagerContinue,
    ManagerKeyFile,
    ManagerKeyManual,
    ManagerKeySaved,
    ManagerRecordKey,
    ManagerCandidateKey,
    ManagerKeepServer,
    ManagerChangeServer,
    ManagerUseRemembered,
    ManagerUseConfigured,
    ManagerPackageChoose,
    ManagerPackageNew,
    ManagerOutputChoose,
    ManagerInspect,
    ManagerBuild,
    ManagerDetails,
    ManagerNextBox,
    ManagerRetry,
    ManagerSettingsOpen,
    ManagerReset,
    ManagerConfigHelp,
    ManagerInstructions,
    ManagerLogOpen,
    ManagerLogPrevious,
    ManagerLogNext,
    ManagerCatalogUp,
    ManagerCatalogDown,
    ManagerCatalogOpen,
    ManagerJobResume,
    ManagerJobResult
} ManagerAction;
typedef struct {
    char directory[128];
    char name[SETUP_NAME_SIZE];
    char date[TB2_DATE_SIZE];
    Tb2UiStatus status;
    bool valid, operation;
} ManagerEntry;
/** Only these two visible rows cross into the GUI thread. No storage access. */
typedef struct {
    char names[2][SETUP_NAME_SIZE];
    char details[2][40];
    uint8_t rows, selected;
    bool loading;
} ManagerCatalogModel;
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* text;
    ByteInput* bytes;
    View* catalog;
    ManagerScreen screen, text_return;
    File* scan;
    uint8_t count, selected, states_read;
    bool scanning, scan_reverse, scan_more, first_page, historical, resume;
    int pending;
    uint32_t log_offset, log_size;
    Tb2UiPreferences preferences;
    char configured[TB2_JOB_PATH_MAX];
    char display[160];
    char text_buffer[MANAGER_TEXT_SIZE];
    uint8_t secret[TB2_SN_SIZE];
    ManagerEntry entries[SETUP_PAGE_SIZE], anchor;
    union {
        Tb2JobSpec scratch;
        Tb2Operation operation_scratch;
    };
} Manager;

static void manager_show(Manager* m, ManagerScreen screen);
static void manager_preferences(Manager* m) {
#ifdef TB2_SETUP_HOST_TEST
    tb2_ui_preferences_load(m->request->storage, &m->preferences);
#else
    m->preferences = m->request->preferences;
#endif
}
static void manager_menu(Manager* m, const char* title) {
    submenu_reset(m->menu);
    snprintf(
        m->display,
        sizeof(m->display),
        "%s%s%s",
        title,
        m->request->box_alias[0] ? ": " : "",
        m->request->box_alias);
    tb2_menu_header(m->menu, m->request->gui, m->display);
}
static void manager_event(void* context, uint32_t action) {
    Manager* m = context;
    view_dispatcher_send_custom_event(m->dispatcher, action);
}
static void manager_add(Manager* m, const char* label, ManagerAction action) {
    submenu_add_item(m->menu, label, action, manager_event, m);
}
static const char* manager_basename(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}
static void manager_text(Manager* m, ManagerScreen back) {
    m->text_return = back;
    m->screen = ManagerText;
    text_box_set_text(m->text, m->text_buffer);
    view_dispatcher_switch_to_view(m->dispatcher, SetupDetails);
}
static void manager_error(Manager* m, ManagerScreen back, const char* error) {
    snprintf(m->text_buffer, sizeof(m->text_buffer), "%s", error);
    manager_text(m, back);
}
static void manager_date(char out[TB2_DATE_SIZE], unsigned extra_years) {
    DateTime date;
    furi_hal_rtc_get_datetime(&date);
    char buffer[32];
    int size = snprintf(
        buffer,
        sizeof(buffer),
        "%04u%02u%02u%02u%02u%02u",
        date.year + extra_years,
        date.month,
        date.day,
        date.hour,
        date.minute,
        date.second);
    if(size == TB2_DATE_SIZE - 1)
        memcpy(out, buffer, TB2_DATE_SIZE);
    else
        out[0] = 0;
}
static const char* manager_state(Tb2UiState state) {
    switch(state) {
    case Tb2UiPrepared:
        return "Prepared";
    case Tb2UiRunning:
    case Tb2UiPaused:
        return "Interrupted";
    case Tb2UiComplete:
    case Tb2UiLegacyComplete:
        return "Complete";
    case Tb2UiFailed:
        return "Failed";
    case Tb2UiAborted:
        return "Aborted";
    case Tb2UiIncomplete:
        return "Incomplete";
    default:
        return "Status unknown";
    }
}
/** Pixel-based shortening is shared by the catalog and result dialog. */
static void
    manager_fit(Canvas* canvas, char* out, size_t capacity, const char* input, unsigned width) {
    snprintf(out, capacity, "%s", input);
    if(canvas_string_width(canvas, out) <= width) return;
    size_t count = strlen(out);
    if(count > capacity - 4) count = capacity - 4;
    do {
        out[count] = '.';
        out[count + 1] = '.';
        out[count + 2] = '.';
        out[count + 3] = 0;
        if(canvas_string_width(canvas, out) <= width) return;
    } while(count--);
    out[0] = 0;
}
static void manager_catalog_draw(Canvas* canvas, void* context) {
    ManagerCatalogModel* model = context;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, model->loading ? "Jobs ..." : "Jobs");
    canvas_set_font(canvas, FontSecondary);
    for(unsigned i = 0; i < model->rows; i++) {
        char line[SETUP_NAME_SIZE];
        unsigned y = 25 + i * 23;
        manager_fit(canvas, line, sizeof(line), model->names[i], 114);
        canvas_draw_str(canvas, 10, y, line);
        manager_fit(canvas, line, sizeof(line), model->details[i], 114);
        canvas_draw_str(canvas, 10, y + 11, line);
        if(model->selected == i) canvas_draw_str(canvas, 1, y, ">");
    }
    if(!model->rows) canvas_draw_str(canvas, 10, 32, model->loading ? "Reading SD" : "No jobs");
}
static bool manager_catalog_input(InputEvent* event, void* context) {
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;
    Manager* m = context;
    if(event->key == InputKeyUp)
        manager_event(m, ManagerCatalogUp);
    else if(event->key == InputKeyDown)
        manager_event(m, ManagerCatalogDown);
    else if(event->key == InputKeyOk)
        manager_event(m, ManagerCatalogOpen);
    else
        return false;
    return true;
}
static void manager_catalog_model(Manager* m) {
    with_view_model(
        m->catalog,
        ManagerCatalogModel * model,
        {
            memset(model, 0, sizeof(*model));
            model->loading = m->scanning;
            unsigned start = m->selected & ~1U;
            model->selected = m->selected - start;
            for(unsigned i = start; i < m->count && i < start + 2; i++) {
                unsigned row = model->rows++;
                ManagerEntry* entry = &m->entries[i];
                snprintf(model->names[row], sizeof(model->names[row]), "%s", entry->name);
                snprintf(
                    model->details[row],
                    sizeof(model->details[row]),
                    "%.*s.%.*s.%.*s  %s",
                    2,
                    entry->date[0] ? entry->date + 6 : "--",
                    2,
                    entry->date[0] ? entry->date + 4 : "--",
                    2,
                    entry->date[0] ? entry->date + 2 : "--",
                    entry->valid ? manager_state(entry->status.state) : "Damaged data");
            }
        },
        true);
}
static void manager_scan_close(Manager* m) {
    if(m->scan) {
        storage_dir_close(m->scan);
        storage_file_free(m->scan);
        m->scan = NULL;
    }
    m->scanning = false;
}
/** Descending datetime, then descending directory; same comparator on every page. */
static int manager_compare(const ManagerEntry* a, const ManagerEntry* b) {
    int order = strcmp(b->date, a->date);
    return order ? order : strcmp(b->directory, a->directory);
}
static void manager_scan_start(Manager* m, bool first, bool reverse) {
    manager_scan_close(m);
    if(!first && m->count)
        m->anchor = m->entries[reverse ? 0 : m->count - 1];
    else
        memset(&m->anchor, 0, sizeof(m->anchor));
    m->count = m->selected = m->states_read = 0;
    m->first_page = first;
    m->scan_reverse = reverse;
    m->scan_more = false;
    m->screen = ManagerCatalog;
    m->scan = storage_file_alloc(m->request->storage);
    if(!storage_dir_open(m->scan, MANAGER_ROOT)) {
        int rc = storage_file_get_error(m->scan);
        storage_file_free(m->scan);
        m->scan = NULL;
        if(rc != FSE_NOT_EXIST) {
            manager_error(m, ManagerHome, "Cannot read jobs folder. Check SD.");
            return;
        }
    } else
        m->scanning = true;
    manager_catalog_model(m);
    view_dispatcher_switch_to_view(m->dispatcher, 5);
}
static void manager_insert(Manager* m, const ManagerEntry* candidate) {
    if(m->anchor.directory[0]) {
        int order = manager_compare(candidate, &m->anchor);
        if(m->scan_reverse ? order >= 0 : order <= 0) return;
    }
    unsigned index = 0;
    while(index < m->count && manager_compare(&m->entries[index], candidate) < 0)
        index++;
    if(m->count == SETUP_PAGE_SIZE) {
        m->scan_more = true;
        if(m->scan_reverse) {
            if(index == 0) return;
            memmove(m->entries, m->entries + 1, (--index) * sizeof(*m->entries));
        } else {
            if(index == SETUP_PAGE_SIZE) return;
            memmove(
                m->entries + index + 1,
                m->entries + index,
                (SETUP_PAGE_SIZE - index - 1) * sizeof(*m->entries));
        }
    } else {
        memmove(
            m->entries + index + 1, m->entries + index, (m->count - index) * sizeof(*m->entries));
        m->count++;
    }
    m->entries[index] = *candidate;
}
/** Four directory reads/metadata probes per tick; only six selected statuses read. */
static void manager_tick(void* context) {
    Manager* m = context;
    if(!m->scanning || m->screen != ManagerCatalog) return;
    if(m->scan) {
        for(unsigned i = 0; i < MANAGER_SCAN_BUDGET; i++) {
            FileInfo info;
            char name[TB2_JOB_PATH_MAX];
            if(!storage_dir_read(m->scan, &info, name, sizeof(name))) {
                int rc = storage_file_get_error(m->scan);
                bool closed = storage_dir_close(m->scan);
                storage_file_free(m->scan);
                m->scan = NULL;
                if(rc != FSE_NOT_EXIST || !closed) {
                    m->scanning = false;
                    manager_error(m, ManagerHome, "Cannot read jobs from SD.");
                }
                break;
            }
            if(!file_info_is_dir(&info) || !strcmp(name, ".") || !strcmp(name, "..")) continue;
            ManagerEntry entry = {0};
            int length =
                snprintf(entry.directory, sizeof(entry.directory), MANAGER_ROOT "/%s", name);
            if(length < 0 || length >= (int)sizeof(entry.directory)) continue;
            char metadata[TB2_JOB_PATH_MAX];
            snprintf(metadata, sizeof(metadata), "%s/" TB2_OPERATION_NAME, entry.directory);
            entry.operation = storage_common_stat(m->request->storage, metadata, &info) !=
                              FSE_NOT_EXIST;
            if(entry.operation)
                entry.valid = m->request->filesystem &&
                              tb2_operation_info(
                                  m->request->filesystem, entry.directory, &m->operation_scratch);
            else {
                snprintf(metadata, sizeof(metadata), "%s/job.tb2", entry.directory);
                if(storage_common_stat(m->request->storage, metadata, &info) == FSE_NOT_EXIST)
                    continue;
                entry.valid = tb2_ui_job_load(m->request->storage, entry.directory, &m->scratch);
            }
            snprintf(
                entry.name,
                sizeof(entry.name),
                "%.*s",
                (int)sizeof(entry.name) - 1,
                entry.valid ?
                    manager_basename(
                        entry.operation ? m->operation_scratch.source : m->scratch.source) :
                    name);
            if(entry.valid)
                memcpy(
                    entry.date,
                    entry.operation ? m->operation_scratch.created : m->scratch.options.now,
                    sizeof(entry.date));
            manager_insert(m, &entry);
        }
        return;
    }
    if(m->states_read < m->count) {
        ManagerEntry* entry = &m->entries[m->states_read++];
        if(entry->operation) {
            entry->status.state =
                entry->valid &&
                        tb2_operation_load(
                            m->request->filesystem, entry->directory, &m->operation_scratch) ?
                    m->operation_scratch.state :
                    Tb2UiUnknown;
            if(entry->valid && m->operation_scratch.torn) entry->status.state = Tb2UiUnknown;
            return;
        }
        if(entry->valid && tb2_ui_job_load(m->request->storage, entry->directory, &m->scratch))
            entry->status = tb2_ui_status_read(m->request->storage, entry->directory, &m->scratch);
        else
            entry->valid = false;
        return;
    }
    m->scanning = false;
    if(m->scan_reverse) m->first_page = !m->scan_more;
    m->selected = m->scan_reverse && m->count ? m->count - 1 : 0;
    manager_catalog_model(m);
}
static bool manager_browse(Manager* m, const char* extension, char out[TB2_JOB_PATH_MAX]) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, extension, NULL);
    options.base_path = TB2_SPI_MEM_ROOT;
    options.hide_ext = false;
    FuriString* path = furi_string_alloc_set(out[0] ? out : TB2_SPI_MEM_ROOT);
    FuriString* start = furi_string_alloc_set(TB2_SPI_MEM_ROOT);
    bool selected = dialog_file_browser_show(dialogs, path, start, &options);
    if(selected && strlen(furi_string_get_cstr(path)) < TB2_JOB_PATH_MAX)
        snprintf(out, TB2_JOB_PATH_MAX, "%s", furi_string_get_cstr(path));
    else
        selected = false;
    furi_string_free(path);
    furi_string_free(start);
    furi_record_close(RECORD_DIALOGS);
    (void)m;
    return selected;
}
static void manager_clear_key(Manager* m) {
    memset(m->request->input_key, 0, sizeof(*m->request->input_key));
    memset(m->request->key_path, 0, sizeof(m->request->key_path));
    memset(m->secret, 0, sizeof(m->secret));
    m->request->key_from_file = false;
}
static bool manager_keep_server(Manager* m) {
#ifndef TB2_SETUP_HOST_TEST
    if(!m->request->defaults) return false;
    memcpy(
        m->request->spec->options.https_host,
        m->request->defaults->options.https_host,
        TB2_HOST_MAX);
    memcpy(
        m->request->spec->options.ici_host, m->request->defaults->options.ici_host, TB2_HOST_MAX);
    memset(&m->request->spec->server, 0, sizeof(m->request->spec->server));
    return true;
#else
    Tb2SetupRequest* defaults = malloc(sizeof(*defaults));
    if(!defaults) return false;
    *defaults = *m->request;
    defaults->spec = &m->scratch;
    m->scratch = *m->request->spec;
    bool ok = setup_config(defaults);
    if(ok) {
        memcpy(m->request->spec->options.https_host, m->scratch.options.https_host, TB2_HOST_MAX);
        memcpy(m->request->spec->options.ici_host, m->scratch.options.ici_host, TB2_HOST_MAX);
        memset(&m->request->spec->server, 0, sizeof(m->request->spec->server));
    } else
        manager_error(m, ManagerServer, defaults->error);
    free(defaults);
    return ok;
#endif
}
static void manager_new(Manager* m) {
    Tb2SetupRequest* r = m->request;
    memset(r->spec, 0, sizeof(*r->spec));
    manager_clear_key(m);
    if(!r->operation || r->operation->kind != Tb2OperationAio ||
       r->operation->phase != Tb2PhaseModifySetup)
        r->directory[0] = 0;
    r->error[0] = r->warning[0] = 0;
    m->resume = m->historical = false;
    manager_date(r->spec->options.now, 0);
    manager_date(r->spec->options.expires, 10);
    if(!setup_config(r)) {
        manager_error(m, ManagerHome, r->error);
        return;
    }
    snprintf(m->configured, sizeof(m->configured), "%s", r->spec->imported_package);
    manager_preferences(m);
    const char* directory = m->preferences.output_dir[0] ? m->preferences.output_dir :
                                                           TB2_SPI_MEM_ROOT;
    if(strlen(directory) + sizeof("/tb2-00000000-00000000.bin") > sizeof(r->spec->output_path))
        directory = TB2_SPI_MEM_ROOT;
    r->spec->shared_image = 2;
    r->spec->export_archive = r->settings_only ? 0 : 1;
    snprintf(
        r->spec->output_path,
        sizeof(r->spec->output_path),
        "%.*s/tb2-%08lx-%08lx.bin",
        (int)(sizeof(r->spec->output_path) - sizeof("/tb2-00000000-00000000.bin")),
        directory,
        (unsigned long)furi_hal_rtc_get_timestamp(),
        (unsigned long)furi_hal_random_get());
    if(m->preferences.package_dir[0])
        snprintf(
            r->spec->imported_package,
            sizeof(r->spec->imported_package),
            "%s",
            m->preferences.package_dir);
    manager_show(m, ManagerDump);
}
static void manager_done(Manager* m, Tb2SetupAction action) {
    m->request->action = action;
    view_dispatcher_stop(m->dispatcher);
}
static void manager_key_done(void* context) {
    manager_event(context, ManagerKeySaved);
}
static void manager_manual(Manager* m) {
    memset(m->secret, 0, sizeof(m->secret));
    if(m->request->input_key->kind == Tb2InputKeySecret)
        memcpy(m->secret, m->request->input_key->bytes, sizeof(m->secret));
    else {
        File* file = storage_file_alloc(m->request->storage);
        if(storage_file_open(file, TB2_APP_ROOT "/mcu-sn.txt", FSAM_READ, FSOM_OPEN_EXISTING)) {
            char text[TB2_KEY_TEXT_MAX] = {0};
            uint64_t size = storage_file_size(file);
            if(size <= sizeof(text) && storage_file_read(file, text, size) == size)
                tb2_reader_parse_serial(text, size, m->secret);
            memset(text, 0, sizeof(text));
            storage_file_close(file);
        }
        storage_file_free(file);
    }
    byte_input_set_header_text(m->bytes, "MCU-SN: 8 Bytes / 16 Hex");
    byte_input_set_result_callback(
        m->bytes, manager_key_done, NULL, m, m->secret, sizeof(m->secret));
    m->screen = ManagerManual;
    view_dispatcher_switch_to_view(m->dispatcher, 4);
}
static void manager_finish_key(Manager* m) {
    if(m->resume) {
        manager_date(m->request->spec->options.now, 0);
        manager_done(m, Tb2SetupActionResume);
    } else
        manager_show(m, ManagerServer);
}
static void manager_schedule(Manager* m, Tb2SetupKind kind, const char* path) {
    snprintf(m->request->path, sizeof(m->request->path), "%s", path);
    m->pending = (int)kind;
    view_dispatcher_stop(m->dispatcher);
}
static void manager_show(Manager* m, ManagerScreen screen) {
    Tb2SetupRequest* r = m->request;
    m->screen = screen;
    switch(screen) {
    case ManagerHome:
        manager_done(m, Tb2SetupActionHome);
        return;
    case ManagerDump:
        manager_menu(m, "1/4 Dump");
        manager_add(
            m,
            r->spec->source[0] ? manager_basename(r->spec->source) : "Select original dump",
            ManagerDumpChoose);
        if(r->spec->source[0]) manager_add(m, "Continue", ManagerContinue);
        break;
    case ManagerKey:
        manager_menu(m, m->resume ? "Key for job" : "2/4 Key");
        manager_add(m, "Key file", ManagerKeyFile);
        manager_add(m, "Enter manually", ManagerKeyManual);
        if(r->box_id[0]) {
            manager_add(m, "Use record key", ManagerRecordKey);
            manager_add(m, "Use key proposal", ManagerCandidateKey);
        }
        if(r->key_from_file || r->input_key->kind != Tb2InputKeyInvalid)
            manager_add(m, "Continue", ManagerContinue);
        break;
    case ManagerCertificates:
        manager_menu(m, "3/4 Certificates");
        if(m->preferences.package_dir[0]) manager_add(m, "Use last package", ManagerUseRemembered);
        if(m->configured[0] && strcmp(m->configured, m->preferences.package_dir))
            manager_add(m, "Configured package", ManagerUseConfigured);
        manager_add(m, "Choose folder", ManagerPackageChoose);
        manager_add(m, "Create new package", ManagerPackageNew);
        break;
    case ManagerTarget:
        if(r->record_task && r->record_task->kind == Tb2RecordTaskTargetReserve &&
           r->record_task->import.output[0] &&
           !strcmp(r->record_task->import.output, r->spec->output_path)) {
            manager_done(
                m, r->settings_only ? Tb2SetupActionSettingsBuild : Tb2SetupActionInspect);
            return;
        }
        manager_schedule(m, Tb2SetupOutput, r->spec->output_path);
        return;
    case ManagerServer:
        manager_menu(m, "Server settings");
        manager_add(m, "Keep", ManagerKeepServer);
        manager_add(m, "Change", ManagerChangeServer);
        break;
    case ManagerResult:
        manager_done(m, Tb2SetupActionResult);
        return;
    case ManagerJob:
        if(!m->historical) {
            manager_menu(m, "Result details");
            manager_add(m, "Paths / check results", ManagerJobResult);
            manager_add(m, "View log", ManagerLogOpen);
            break;
        }
        manager_menu(m, "Saved state");
        if(r->status.state == Tb2UiComplete || r->status.state == Tb2UiLegacyComplete) {
            manager_add(m, "View result", ManagerJobResult);
            manager_add(m, "Verify again", ManagerJobResume);
        } else if(r->status.state != Tb2UiAborted)
            manager_add(m, "Resume", ManagerJobResume);
        manager_add(m, "Details", ManagerDetails);
        manager_add(m, "View log", ManagerLogOpen);
        break;
    case ManagerCatalog:
        manager_catalog_model(m);
        view_dispatcher_switch_to_view(m->dispatcher, 5);
        return;
    default:
        return;
    }
    view_dispatcher_switch_to_view(m->dispatcher, SetupMenu);
}
static bool manager_back(void* context) {
    Manager* m = context;
    switch(m->screen) {
    case ManagerHome:
        manager_done(m, Tb2SetupActionExit);
        break;
    case ManagerText:
        manager_show(m, m->text_return);
        break;
    case ManagerDump:
    case ManagerHelp:
    case ManagerApprove:
    case ManagerResult:
        manager_done(m, Tb2SetupActionHome);
        break;
    case ManagerKey:
        manager_show(m, m->resume ? ManagerJob : ManagerDump);
        break;
    case ManagerCertificates:
        manager_show(m, ManagerServer);
        break;
    case ManagerServer:
        manager_show(m, ManagerKey);
        break;
    case ManagerManual:
        memset(m->secret, 0, sizeof(m->secret));
        manager_show(m, ManagerKey);
        break;
    case ManagerSettings:
        manager_show(m, ManagerHelp);
        break;
    case ManagerCatalog:
        manager_scan_close(m);
        manager_done(m, Tb2SetupActionEdit);
        break;
    case ManagerJob:
        if(m->historical) {
            m->screen = ManagerCatalog;
            view_dispatcher_switch_to_view(m->dispatcher, 5);
        } else
            manager_show(m, ManagerResult);
        break;
    case ManagerLog:
        if(m->request->kind == Tb2SetupOperationLog)
            manager_done(m, Tb2SetupActionOperationResult);
        else
            manager_show(m, m->historical ? ManagerJob : ManagerResult);
        break;
    default:
        manager_show(m, ManagerHome);
        break;
    }
    return true;
}
static bool manager_action(void* context, uint32_t action) {
    Manager* m = context;
    Tb2SetupRequest* r = m->request;
    switch(action) {
    case ManagerNew:
        manager_new(m);
        break;
    case ManagerNextBox:
        r->box_id[0] = r->version_id[0] = 0;
        r->path[0] = 0;
        manager_done(m, Tb2SetupActionModify);
        break;
    case ManagerJobs:
        manager_scan_start(m, true, false);
        break;
    case ManagerHelpOpen:
        manager_show(m, ManagerHelp);
        break;
    case ManagerDumpChoose: {
        if(r->operation && r->operation->kind == Tb2OperationAio &&
           (r->operation->dump.flags & Tb2SpiDumpVerified)) {
            manager_error(m, ManagerDump, "AIO dump is bound. Use a new job to change it.");
            break;
        }
        char source[TB2_JOB_PATH_MAX];
        snprintf(source, sizeof(source), "%s", r->spec->source);
        if(manager_browse(m, "*", source)) {
            if(strcmp(source, r->spec->source)) {
                manager_clear_key(m);
                if(!manager_keep_server(m)) break;
            }
            snprintf(r->spec->source, sizeof(r->spec->source), "%s", source);
            manager_show(m, ManagerKey);
        }
        break;
    }
    case ManagerContinue:
        if(m->screen == ManagerDump) {
            if(r->settings_only)
                manager_done(m, Tb2SetupActionSettingsInspect);
            else
                manager_show(m, ManagerKey);
        } else
            manager_finish_key(m);
        break;
    case ManagerKeyFile: {
        char path[TB2_JOB_PATH_MAX];
        snprintf(path, sizeof(path), "%s", r->key_path);
        if(manager_browse(m, ".txt", path)) {
            manager_clear_key(m);
            snprintf(r->key_path, sizeof(r->key_path), "%s", path);
            r->key_from_file = true;
            manager_finish_key(m);
        }
        break;
    }
    case ManagerKeyManual:
        manager_manual(m);
        break;
    case ManagerRecordKey:
    case ManagerCandidateKey:
        manager_done(
            m, action == ManagerRecordKey ? Tb2SetupActionUseKey : Tb2SetupActionUseCandidate);
        break;
    case ManagerKeySaved:
        memset(r->input_key, 0, sizeof(*r->input_key));
        r->input_key->kind = Tb2InputKeySecret;
        memcpy(r->input_key->bytes, m->secret, sizeof(m->secret));
        memset(m->secret, 0, sizeof(m->secret));
        r->key_from_file = false;
        r->key_path[0] = 0;
        manager_finish_key(m);
        break;
    case ManagerUseRemembered:
        manager_schedule(m, Tb2SetupCheckPackage, m->preferences.package_dir);
        break;
    case ManagerKeepServer:
        if(manager_keep_server(m)) manager_show(m, ManagerCertificates);
        break;
    case ManagerChangeServer:
        manager_done(m, Tb2SetupActionPreviewServer);
        break;
    case ManagerUseConfigured:
        manager_schedule(m, Tb2SetupCheckPackage, m->configured);
        break;
    case ManagerPackageChoose:
        manager_schedule(
            m,
            Tb2SetupPackage,
            r->spec->imported_package[0] ? r->spec->imported_package : TB2_SPI_MEM_ROOT);
        break;
    case ManagerPackageNew:
        r->spec->imported_package[0] = 0;
        manager_show(m, ManagerTarget);
        break;
    case ManagerBuild:
        manager_done(m, Tb2SetupActionBuild);
        break;
    case ManagerRetry:
        if(r->status.state == Tb2UiAborted) break;
        manager_clear_key(m);
        if(r->directory[0]) {
            m->resume = true;
            manager_show(m, ManagerKey);
        } else
            manager_show(m, ManagerKey);
        break;
    case ManagerDetails:
    case ManagerJobResult:
        r->historical = m->historical;
        manager_done(m, Tb2SetupActionJobDetails);
        break;
    case ManagerLogOpen:
        r->historical = m->historical;
        manager_done(m, Tb2SetupActionOperationLog);
        break;
    case ManagerCatalogUp:
    case ManagerCatalogDown:
        if(m->scanning || !m->count) break;
        if(action == ManagerCatalogUp) {
            if(m->selected)
                m->selected--;
            else if(!m->first_page) {
                manager_scan_start(m, false, true);
                break;
            }
        } else if(m->selected + 1 < m->count)
            m->selected++;
        else if(m->scan_more || m->scan_reverse) {
            manager_scan_start(m, false, false);
            break;
        }
        manager_catalog_model(m);
        break;
    case ManagerCatalogOpen:
        if(m->scanning || !m->count) break;
        if(m->entries[m->selected].operation && r->operation) {
            const char* directory = m->entries[m->selected].directory;
            bool loaded = tb2_operation_load(r->filesystem, directory, r->operation);
            if(!loaded && !tb2_operation_info(r->filesystem, directory, r->operation)) {
                manager_error(m, ManagerCatalog, "Damaged operation. Cannot resume.");
                break;
            }
            if(!loaded) {
                r->operation->state = Tb2UiUnknown;
                snprintf(r->error, sizeof(r->error), "Status unclear. Check log before resume.");
            } else if(r->operation->torn)
                snprintf(
                    r->warning,
                    sizeof(r->warning),
                    "Status write interrupted. Retry last saved phase.");
            if(r->operation->modify_bound && !tb2_ui_job_load(r->storage, directory, r->spec)) {
                r->operation->state = Tb2UiUnknown;
                snprintf(r->error, sizeof(r->error), "Modify job data missing or damaged.");
            }
            snprintf(r->directory, sizeof(r->directory), "%s", directory);
            r->result = r->operation->result;
            r->historical = true;
            manager_clear_key(m);
            manager_done(m, Tb2SetupActionSavedOperation);
            break;
        }
        if(!m->entries[m->selected].valid ||
           !tb2_ui_job_load(r->storage, m->entries[m->selected].directory, r->spec)) {
            manager_error(m, ManagerCatalog, "Damaged job data. Cannot process.");
            break;
        }
        snprintf(r->directory, sizeof(r->directory), "%s", m->entries[m->selected].directory);
        if(r->operation) memset(r->operation, 0, sizeof(*r->operation));
        r->status = m->entries[m->selected].status;
        r->result = r->status.result;
        r->error[0] = r->warning[0] = 0;
        manager_clear_key(m);
        m->historical = true;
        m->log_offset = UINT32_MAX;
        manager_show(m, ManagerJob);
        break;
    case ManagerJobResume:
        if(r->status.state == Tb2UiAborted) break;
        manager_clear_key(m);
        m->resume = true;
        manager_show(m, ManagerKey);
        break;
    default:
        break;
    }
    return true;
}
static bool manager_run(Tb2SetupRequest* r) {
    r->action = Tb2SetupActionExit;
    Manager* m = calloc(1, sizeof(*m));
    if(!m) {
        snprintf(r->error, sizeof(r->error), "Not enough RAM for menu.");
        return false;
    }
    m->request = r;
    m->pending = -1;
    m->log_offset = UINT32_MAX;
    m->resume = r->directory[0] != 0;
    if(r->kind == Tb2SetupCertificates || r->kind == Tb2SetupTarget ||
       r->kind == Tb2SetupServerChoice || r->kind == Tb2SetupRecordKey) {
        if(r->kind != Tb2SetupRecordKey) m->resume = false;
        manager_preferences(m);
#ifndef TB2_SETUP_HOST_TEST
        if(r->defaults)
            snprintf(m->configured, sizeof(m->configured), "%s", r->defaults->imported_package);
#else
        Tb2SetupRequest* defaults = malloc(sizeof(*defaults));
        if(defaults) {
            *defaults = *r;
            defaults->spec = &m->scratch;
            memcpy(m->scratch.options.now, r->spec->options.now, TB2_DATE_SIZE);
            memcpy(m->scratch.options.expires, r->spec->options.expires, TB2_DATE_SIZE);
            if(setup_config(defaults))
                snprintf(m->configured, sizeof(m->configured), "%s", m->scratch.imported_package);
            free(defaults);
        }
#endif
    }
    m->dispatcher = view_dispatcher_alloc();
    m->menu = submenu_alloc();
    m->text = text_box_alloc();
    m->bytes = byte_input_alloc();
    m->catalog = view_alloc();
    view_allocate_model(m->catalog, ViewModelTypeLocking, sizeof(ManagerCatalogModel));
    view_set_context(m->catalog, m);
    view_set_draw_callback(m->catalog, manager_catalog_draw);
    view_set_input_callback(m->catalog, manager_catalog_input);
    view_dispatcher_set_event_callback_context(m->dispatcher, m);
    view_dispatcher_set_custom_event_callback(m->dispatcher, manager_action);
    view_dispatcher_set_navigation_event_callback(m->dispatcher, manager_back);
    view_dispatcher_set_tick_event_callback(m->dispatcher, manager_tick, MANAGER_TICK_MS);
    view_dispatcher_add_view(m->dispatcher, SetupMenu, submenu_get_view(m->menu));
    view_dispatcher_add_view(m->dispatcher, SetupDetails, text_box_get_view(m->text));
    view_dispatcher_add_view(m->dispatcher, 4, byte_input_get_view(m->bytes));
    view_dispatcher_add_view(m->dispatcher, 5, m->catalog);
    view_dispatcher_attach_to_gui(m->dispatcher, r->gui, ViewDispatcherTypeFullscreen);
    manager_show(
        m,
        r->kind == Tb2SetupApprove                                ? ManagerApprove :
        r->kind == Tb2SetupResult                                 ? ManagerResult :
        r->kind == Tb2SetupCertificates                           ? ManagerCertificates :
        r->kind == Tb2SetupTarget                                 ? ManagerTarget :
        r->kind == Tb2SetupServerChoice                           ? ManagerServer :
        r->kind == Tb2SetupResume || r->kind == Tb2SetupRecordKey ? ManagerKey :
                                                                    ManagerDump);
    if(r->kind == Tb2SetupNew) {
        manager_new(m);
        if(r->path[0]) {
            snprintf(r->spec->source, sizeof(r->spec->source), "%s", r->path);
            if(r->settings_only)
                manager_done(m, Tb2SetupActionSettingsInspect);
            else
                manager_show(m, ManagerKey);
        }
    }
    if(r->kind == Tb2SetupJobs) manager_scan_start(m, true, false);
    if((r->kind == Tb2SetupServerChoice || r->kind == Tb2SetupRecordKey) && r->result &&
       r->error[0])
        manager_error(m, r->kind == Tb2SetupRecordKey ? ManagerKey : ManagerServer, r->error);
    if(m->pending < 0) view_dispatcher_run(m->dispatcher);
    if(m->pending >= 0) {
        r->editor_kind = (Tb2SetupKind)m->pending;
        r->wizard = true;
        r->action = Tb2SetupActionEdit;
    }
    manager_scan_close(m);
    const unsigned ids[] = {SetupMenu, SetupDetails, 4, 5};
    for(unsigned i = 0; i < sizeof(ids) / sizeof(*ids); i++)
        view_dispatcher_remove_view(m->dispatcher, ids[i]);
    submenu_free(m->menu);
    text_box_free(m->text);
    byte_input_free(m->bytes);
    view_free(m->catalog);
    view_dispatcher_free(m->dispatcher);
    memset(m->secret, 0, sizeof(m->secret));
    free(m);
    return true;
}
