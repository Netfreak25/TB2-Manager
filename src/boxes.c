#include "setup.h"
#include "store.h"
#include "review.h"
#include <dialogs/dialogs.h>
#include <datetime/datetime.h>
#include <flipper_application/flipper_application.h>
#include <furi.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/view_dispatcher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOX_SCAN_BUDGET 4U
#include "menu_label.h"
#define BOX_TICK_MS   50U
#define BOX_TEXT_SIZE 1600U
typedef enum {
    BoxesList,
    BoxesRecord,
    BoxesVersions,
    BoxesVersion,
    BoxesText,
    BoxesAlias,
    BoxesApproval,
    BoxesRestore,
    BoxesConfirm,
    BoxesFlash,
    BoxesRestoreMode,
    BoxesRestoreApprove,
    BoxesNotes,
    BoxesSecret,
    BoxesRoot,
    BoxesExport,
    BoxesHistory,
    BoxesNoteList,
    BoxesOriginal,
    BoxesListError,
    BoxesCompare
} BoxScreen;
typedef enum {
    BoxOpen = 100,
    BoxUp,
    BoxDown,
    BoxPrevious,
    BoxNext,
    BoxNew,
    BoxUse,
    BoxDump,
    BoxModify,
    BoxOverview,
    BoxVersionsOpen,
    BoxAlias,
    BoxAliasDone,
    BoxVersionDetails,
    BoxOriginal,
    BoxWorking,
    BoxProtection,
    BoxApprovalDetails,
    BoxBuild,
    BoxRestore,
    BoxRestoreOriginal,
    BoxRestorePrevious,
    BoxFlash,
    BoxModifyVersion,
    BoxConfirm,
    BoxFlashConfirm,
    BoxRestoreCertificates,
    BoxCertificatesOnly,
    BoxOriginalConnection,
    BoxRestoreBuild,
    BoxNotes,
    BoxNoteEdit,
    BoxNoteDone,
    BoxNoteTested,
    BoxNoteRepair,
    BoxSecret,
    BoxSecretDetails,
    BoxKeyCandidate,
    BoxCompare,
    BoxDelete,
    BoxSerial,
    BoxBrowse,
    BoxImport,
    BoxExport,
    BoxExportFull,
    BoxDiagnostic,
    BoxPackage,
    BoxHistory,
    BoxNotesRead,
    BoxNotOriginal,
    BoxKeyFile,
    BoxIdentify,
    BoxIdentifyFirmware,
    BoxImportItems,
    BoxRetryList,
    BoxCompareImage,
    BoxCompareChip,
    BoxRename
} BoxEvent;
typedef struct {
    char title[32], names[2][TB2_JOB_NAME_MAX], details[2][48];
    uint8_t count, selected;
    bool loading, previous, more, versions;
} BoxListModel;
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* text;
    TextInput* keyboard;
    View* list;
    Tb2RecordPage page;
    Tb2BoxRecord box;
    Tb2BoxVersion version;
    Tb2BoxEntry entry;
    BoxScreen screen, back, failed_list;
    uint8_t selected, loaded;
    bool creating, normalized;
    bool originals_only, certificates, comparing;
    uint32_t pending;
    char labels[TB2_RECORD_PAGE_SIZE][TB2_JOB_NAME_MAX];
    char details[TB2_RECORD_PAGE_SIZE][48];
    char edit[TB2_RECORD_ALIAS_SIZE];
    char text_buffer[BOX_TEXT_SIZE];
} Boxes;

static void show(Boxes*, BoxScreen);
static bool list_screen(BoxScreen screen) {
    return screen == BoxesList || screen == BoxesVersions || screen == BoxesHistory ||
           screen == BoxesNoteList;
}
static const char* entry_title(const Tb2BoxEntry* e) {
    if(e->note) return e->text;
    switch(e->type) {
    case Tb2OperationDump:
    case Tb2OperationPureDump:
        return "Dump";
    case Tb2OperationFlash:
    case Tb2OperationPureFlash:
        return "Flash";
    case Tb2OperationAio:
        return "AIO";
    case Tb2OperationModify:
        return "Modify";
    case Tb2OperationRestore:
        return "Certificates restore";
    case Tb2EventClassification:
        return e->flags == Tb2VersionOriginal   ? "Original confirmed" :
               e->flags == Tb2VersionWorking    ? "Working confirmed" :
               e->flags == Tb2VersionProtected  ? "Protected" :
               e->flags == Tb2VersionClassified ? "Input classified" :
                                                  "Unprotected";
    default:
        return "Workshop action";
    }
}
static void entry_date(const Tb2BoxEntry* e, char* out, size_t size) {
    DateTime date;
    datetime_timestamp_to_datetime(e->timestamp, &date);
    snprintf(
        out,
        size,
        "%02u.%02u.%02u %02u:%02u",
        (unsigned)date.day,
        (unsigned)date.month,
        (unsigned)(date.year % 100),
        (unsigned)date.hour,
        (unsigned)date.minute);
}
static void event(void* ctx, uint32_t ev) {
    Boxes* b = ctx;
    view_dispatcher_send_custom_event(b->dispatcher, ev);
}
static void add(Boxes* b, const char* label, BoxEvent ev) {
    submenu_add_item(b->menu, label, ev, event, b);
}
static void text(Boxes* b, BoxScreen back, const char* message) {
    if(message != b->text_buffer) strlcpy(b->text_buffer, message, sizeof(b->text_buffer));
    b->back = back;
    b->screen = BoxesText;
    text_box_set_text(b->text, b->text_buffer);
    view_dispatcher_switch_to_view(b->dispatcher, BoxesText);
}
static void error(Boxes* b, BoxScreen back, Tb2RecordResult rc) {
    const char* message =
        rc == Tb2RecordCancelled ? "Record list stopped. Retry or Back to leave." :
        rc == Tb2RecordConflict  ? "Identity or version conflict. Select the correct box." :
        rc == Tb2RecordProtected ? "Protected version. Unprotect before deleting." :
                                   "Cannot read/save record. Check SD and retry.";
    text(b, back, message);
}
static void list_error(Boxes* b, BoxScreen screen, Tb2RecordResult rc) {
    tb2_record_page_close(b->request->filesystem, &b->page);
    b->failed_list = screen;
    error(b, BoxesListError, rc);
}
static void fit(Canvas* canvas, char* text_value, unsigned width) {
    size_t size = strlen(text_value);
    /* Width clipping is based on the actual selected SDK font. */
    while(size && canvas_string_width(canvas, text_value) > width)
        text_value[--size] = 0;
}
static void draw(Canvas* canvas, void* model) {
    BoxListModel* m = model;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 1, 9, m->title);
    canvas_set_font(canvas, FontSecondary);
    if(m->loading) {
        canvas_draw_str(canvas, 3, 31, "Loading records...");
        return;
    }
    if(!m->count)
        canvas_draw_str(canvas, 3, 31, m->versions ? "No versions" : "No records. Left: New");
    for(unsigned i = 0; i < m->count; i++) {
        char name[TB2_JOB_NAME_MAX], detail[48];
        strlcpy(name, m->names[i], sizeof(name));
        strlcpy(detail, m->details[i], sizeof(detail));
        fit(canvas, name, 116);
        fit(canvas, detail, 116);
        if(i == m->selected) canvas_draw_str(canvas, 0, 23 + 20 * i, ">");
        canvas_draw_str(canvas, 9, 23 + 20 * i, name);
        canvas_draw_str(canvas, 9, 32 + 20 * i, detail);
    }
    canvas_draw_str(canvas, 1, 63, m->previous ? "< Previous" : m->versions ? "< Back" : "< New");
    if(m->more) canvas_draw_str(canvas, 91, 63, "Next >");
}
static bool input(InputEvent* input_event, void* ctx) {
    if(input_event->type != InputTypeShort && input_event->type != InputTypeRepeat) return false;
    uint32_t ev;
    switch(input_event->key) {
    case InputKeyUp:
        ev = BoxUp;
        break;
    case InputKeyDown:
        ev = BoxDown;
        break;
    case InputKeyLeft:
        ev = BoxPrevious;
        break;
    case InputKeyRight:
        ev = BoxNext;
        break;
    case InputKeyOk:
        ev = BoxOpen;
        break;
    default:
        return false;
    }
    event(ctx, ev);
    return true;
}
static void publish_list(Boxes* b) {
    with_view_model(
        b->list,
        BoxListModel * m,
        {
            memset(m, 0, sizeof(*m));
            strlcpy(
                m->title,
                b->screen == BoxesVersions ? "Versions" :
                b->screen == BoxesHistory  ? "History" :
                b->screen == BoxesNoteList ? "Notes" :
                                             "Boxes",
                sizeof(m->title));
            m->loading = !b->page.done || b->loaded < b->page.count;
            m->versions = b->screen != BoxesList;
            m->previous = b->page.reverse ? b->page.more : b->page.anchor[0] != 0;
            m->more = b->page.reverse ? b->page.anchor[0] != 0 : b->page.more;
            unsigned start = (b->selected / 2) * 2;
            for(unsigned i = start; i < b->page.count && i < start + 2; i++) {
                strlcpy(m->names[m->count], b->labels[i], sizeof(m->names[0]));
                strlcpy(m->details[m->count], b->details[i], sizeof(m->details[0]));
                m->count++;
            }
            m->selected = b->selected % 2;
        },
        true);
}
static void begin_list(Boxes* b, BoxScreen screen, const char* anchor, bool reverse) {
    Tb2WorkflowIO* io = b->request->filesystem;
    tb2_record_page_close(io, &b->page);
    b->screen = screen;
    b->selected = b->loaded = 0;
    b->normalized = false;
    Tb2RecordResult rc = tb2_record_page_open(
        io, &b->page, screen != BoxesList ? b->request->box_id : NULL, anchor, reverse);
    b->page.prefix = screen == BoxesHistory ? 'e' : screen == BoxesNoteList ? 'n' : 'v';
    if(rc) {
        list_error(b, screen, rc);
        return;
    }
    publish_list(b);
    view_dispatcher_switch_to_view(b->dispatcher, BoxesList);
}
static void tick(void* ctx) {
    Boxes* b = ctx;
    if(!list_screen(b->screen)) return;
    Tb2WorkflowIO* io = b->request->filesystem;
    Tb2RecordResult rc = Tb2RecordOk;
    if(!b->page.done)
        rc = tb2_record_page_step(io, &b->page, BOX_SCAN_BUDGET);
    else if(b->loaded < b->page.count) {
        unsigned i = b->loaded++;
        if(b->screen == BoxesHistory || b->screen == BoxesNoteList) {
            rc = tb2_entry_load(
                io, b->request->box_id, b->page.ids[i], b->screen == BoxesNoteList, &b->entry);
            snprintf(
                b->labels[i],
                sizeof(b->labels[i]),
                "%.*s",
                (int)sizeof(b->labels[i]) - 1,
                rc ? "Damaged entry" : entry_title(&b->entry));
            entry_date(&b->entry, b->details[i], sizeof(b->details[i]));
        } else if(b->screen == BoxesVersions) {
            rc = tb2_version_load(io, b->request->box_id, b->page.ids[i], &b->version);
            snprintf(
                b->labels[i],
                sizeof(b->labels[i]),
                "%.*s",
                (int)sizeof(b->labels[i]) - 1,
                rc ? "Damaged version" : b->version.name);
            snprintf(
                b->details[i],
                sizeof(b->details[i]),
                "v%lu  %s",
                (unsigned long)b->version.number,
                b->version.flags & Tb2VersionDeleted  ? "Deleted" :
                b->version.flags & Tb2VersionOriginal ? "Original" :
                b->version.flags & Tb2VersionWorking  ? "Working" :
                                                        "Saved state");
        } else {
            rc = tb2_box_load(io, b->page.ids[i], &b->box);
            strlcpy(b->labels[i], rc ? "Damaged record" : b->box.alias, sizeof(b->labels[i]));
            snprintf(
                b->details[i],
                sizeof(b->details[i]),
                "%.47s",
                rc               ? "Check SD" :
                b->box.box_id[0] ? b->box.box_id :
                b->box.has_uid   ? "Chip linked" :
                                   "Manual identity");
        }
        /* A damaged record remains visible and cannot be selected as valid. */
        rc = Tb2RecordOk;
    }
    if(rc) {
        list_error(b, b->screen, rc);
        return;
    }
    if(b->page.done && !b->normalized) {
        if(b->page.reverse) {
            for(unsigned i = 0; i < (unsigned)b->page.count / 2U; i++) {
                char id[TB2_RECORD_ID_SIZE];
                unsigned other = b->page.count - 1 - i;
                memcpy(id, b->page.ids[i], sizeof(id));
                memcpy(b->page.ids[i], b->page.ids[other], sizeof(id));
                memcpy(b->page.ids[other], id, sizeof(id));
            }
            if(b->page.count) b->selected = b->page.count - 1;
        }
        b->normalized = true;
    }
    publish_list(b);
}
static void alias_done(void* ctx) {
    event(ctx, BoxAliasDone);
}
static void note_done(void* ctx) {
    event(ctx, BoxNoteDone);
}
static bool prepare_task(Boxes* b, Tb2RecordTaskKind kind) {
    Tb2RecordTask* task = b->request->record_task;
    if(!task) return false;
    tb2_record_wipe(task, sizeof(*task));
    task->kind = kind;
    strcpy(task->box, b->request->box_id);
    if(b->screen == BoxesVersion || b->screen == BoxesConfirm || b->screen == BoxesOriginal ||
       b->screen == BoxesCompare)
        strcpy(task->version, b->version.id);
    return true;
}
static void finish_task(Boxes* b) {
    b->request->action = Tb2SetupActionRecordTask;
    view_dispatcher_stop(b->dispatcher);
}
static void import_file(Boxes* b, bool key) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, key ? ".txt" : ".tar", NULL);
    options.base_path = TB2_APP_ROOT;
    options.hide_ext = false;
    FuriString* selected = furi_string_alloc_set(TB2_APP_ROOT);
    FuriString* start = furi_string_alloc_set(TB2_APP_ROOT);
    bool ok = dialog_file_browser_show(dialogs, selected, start, &options);
    Tb2RecordTask* task = b->request->record_task;
    if(ok && strlen(furi_string_get_cstr(selected)) < sizeof(task->path) &&
       prepare_task(b, key ? Tb2RecordTaskKeyCandidate : Tb2RecordTaskImport)) {
        snprintf(task->path, sizeof(task->path), "%s", furi_string_get_cstr(selected));
        if(!key) task->box[0] = 0;
    } else
        ok = false;
    furi_string_free(start);
    furi_string_free(selected);
    furi_record_close(RECORD_DIALOGS);
    if(ok && key) {
        finish_task(b);
        return;
    }
    if(ok) {
        b->pending = BoxImport;
        text(b, BoxesConfirm, "Import record?\nKeeps verified local data.");
    }
}
static void show(Boxes* b, BoxScreen screen) {
    if(screen == BoxesRecord && !tb2_record_id_valid(b->box.id)) screen = BoxesRoot;
    b->screen = screen;
    submenu_reset(b->menu);
    if(screen == BoxesListError) {
        submenu_set_header(b->menu, "Record list unavailable");
        add(b, "Retry", BoxRetryList);
    } else if(screen == BoxesRoot) {
        submenu_set_header(b->menu, "Boxes");
        add(b, "Identify box", BoxIdentify);
        add(b, "Identify Firmware", BoxIdentifyFirmware);
        add(b, "Open records", BoxBrowse);
        add(b, "New box", BoxNew);
        if(b->request->record_task) add(b, "Import record", BoxImport);
    } else if(screen == BoxesRecord) {
        tb2_menu_header(b->menu, b->request->gui, b->box.alias);
        if(b->request->kind == Tb2SetupSelectBox) add(b, "Use this box", BoxUse);
        add(b, "Overview", BoxOverview);
        if(b->request->kind != Tb2SetupSelectBox) add(b, "Dump chip", BoxDump);
        if(b->request->kind != Tb2SetupSelectBox) add(b, "Modify", BoxModify);
        add(b, "Versions", BoxVersionsOpen);
        if(b->request->kind != Tb2SetupSelectBox) add(b, "Restore", BoxRestore);
        if(b->request->record_task && b->request->kind != Tb2SetupSelectBox) {
            add(b, "Secret", BoxSecret);
            add(b, "Import", BoxImportItems);
            add(b, "Notes", BoxNotes);
            add(b, "Export", BoxExport);
        }
        add(b, "Edit alias", BoxAlias);
    } else if(screen == BoxesVersion) {
        submenu_set_header(b->menu, "Saved version");
        add(b, "Details", BoxVersionDetails);
        if(b->request->kind != Tb2SetupSelectBox && !(b->version.flags & Tb2VersionDeleted)) {
            add(b, "Flash", BoxFlash);
            add(b, "Modify", BoxModifyVersion);
            add(b, "Rename", BoxRename);
        }
        if(b->request->record_task && b->request->kind != Tb2SetupSelectBox) {
            add(b, "Compare", BoxCompare);
            add(b, "Export package", BoxPackage);
        }
        if(b->certificates && (b->version.flags & Tb2VersionOriginal))
            add(b, "Restore certificates", BoxRestoreCertificates);
        if(b->request->kind != Tb2SetupSelectBox) {
            if(b->version.flags & Tb2VersionSource) add(b, "Mark original", BoxOriginal);
            add(b, "Mark working", BoxWorking);
            add(b,
                b->version.flags & Tb2VersionProtected ? "Unprotect" : "Protect",
                BoxProtection);
            if(b->request->record_task) add(b, "Delete", BoxDelete);
        }
    } else if(screen == BoxesCompare) {
        submenu_set_header(b->menu, "Compare");
        add(b, "Image", BoxCompareImage);
        add(b, "Connected chip", BoxCompareChip);
    } else if(screen == BoxesOriginal) {
        submenu_set_header(b->menu, "Input provenance");
        add(b, "Mark as original", BoxOriginal);
        add(b, "Input, not original", BoxNotOriginal);
        add(b, "Version details", BoxVersionDetails);
    } else if(screen == BoxesExport) {
        submenu_set_header(b->menu, "Export record");
        add(b, "Complete record", BoxExportFull);
        add(b, "Diagnostic export", BoxDiagnostic);
    } else if(screen == BoxesNotes) {
        submenu_set_header(b->menu, "Workshop notes");
        add(b, "Read notes", BoxNotesRead);
        add(b, "Add note", BoxNoteEdit);
        add(b, "Buttons/speaker tested", BoxNoteTested);
        add(b, "Needs repair", BoxNoteRepair);
    } else if(screen == BoxesSecret) {
        submenu_set_header(b->menu, "Secret association");
        add(b, "Select key file", BoxKeyFile);
        add(b, "Association details", BoxSecretDetails);
        add(b, "Enter key proposal", BoxKeyCandidate);
    } else if(screen == BoxesRestore) {
        submenu_set_header(b->menu, "Restore");
        add(b, "Original image", BoxRestoreOriginal);
        add(b, "Previous version", BoxRestorePrevious);
        add(b, "Certificates", BoxRestoreCertificates);
    } else if(screen == BoxesRestoreMode) {
        submenu_set_header(b->menu, "Restore connection");
        add(b, "Certificates only", BoxCertificatesOnly);
        add(b, "Original connection", BoxOriginalConnection);
        add(b, "Original version details", BoxVersionDetails);
        if(b->request->kind == Tb2SetupRestoreDonor)
            add(b, "Other original", BoxRestoreCertificates);
    } else if(screen == BoxesRestoreApprove) {
        submenu_set_header(b->menu, "Restore approval");
        add(b, "Restore & Flash", BoxRestoreBuild);
    } else if(screen == BoxesConfirm) {
        submenu_set_header(b->menu, "Confirm action");
        add(b,
            b->pending == BoxImport     ? "Import record" :
            b->pending == BoxExportFull ? "Export with secrets" :
            b->pending == BoxDelete     ? "Delete version" :
            b->pending == BoxOriginal   ? "Mark as original" :
                                          "Tested and working",
            BoxConfirm);
    } else if(screen == BoxesFlash) {
        submenu_set_header(b->menu, "Full image restore");
        add(b, "Continue to chip check", BoxFlashConfirm);
        add(b, "Version details", BoxVersionDetails);
    } else
        return;
    view_dispatcher_switch_to_view(b->dispatcher, BoxesRecord);
}
static bool back(void* ctx) {
    Boxes* b = ctx;
    switch(b->screen) {
    case BoxesListError:
        if(b->failed_list != BoxesList) {
            show(b, BoxesRecord);
            break;
        }
        if(b->request->kind == Tb2SetupBoxes) {
            show(b, BoxesRoot);
            break;
        }
        b->request->action = Tb2SetupActionHome;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxesText:
        if(list_screen(b->back))
            begin_list(b, b->back, NULL, false);
        else
            show(b, b->back);
        break;
    case BoxesAlias:
        if(b->creating && b->box.has_uid) {
            b->request->action = Tb2SetupActionEdit;
            b->request->editor_kind = Tb2SetupRecordResult;
            view_dispatcher_stop(b->dispatcher);
            break;
        }
        if(b->pending == BoxNoteEdit) {
            tb2_record_wipe(b->request->record_task, sizeof(*b->request->record_task));
            show(b, BoxesNotes);
        } else if(b->creating)
            begin_list(b, BoxesList, NULL, false);
        else
            show(b, BoxesRecord);
        break;
    case BoxesVersion:
        begin_list(b, BoxesVersions, NULL, false);
        break;
    case BoxesCompare:
        show(b, BoxesVersion);
        break;
    case BoxesRestore:
    case BoxesExport:
    case BoxesNotes:
    case BoxesSecret:
        show(b, BoxesRecord);
        break;
    case BoxesConfirm:
        if(b->request->kind == Tb2SetupOriginalPrompt) {
            show(b, BoxesOriginal);
            break;
        }
        if(b->pending == BoxImport) {
            show(b, BoxesRoot);
            break;
        }
        if(b->pending == BoxExportFull) {
            show(b, BoxesExport);
            break;
        }
        show(b, BoxesVersion);
        break;
    case BoxesFlash:
    case BoxesRestoreMode:
        if(b->request->kind == Tb2SetupRestoreDonor)
            begin_list(b, BoxesVersions, NULL, false);
        else
            show(b, BoxesVersion);
        break;
    case BoxesRestoreApprove:
        b->request->action = Tb2SetupActionEdit;
        b->request->editor_kind = Tb2SetupRestoreKeys;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxesVersions:
        if(b->request->kind == Tb2SetupRestoreDonor) {
            b->request->action = Tb2SetupActionHome;
            view_dispatcher_stop(b->dispatcher);
            break;
        }
        b->comparing = false;
        show(b, BoxesRecord);
        break;
    case BoxesHistory:
        show(b, BoxesRecord);
        break;
    case BoxesNoteList:
        show(b, BoxesNotes);
        break;
    case BoxesRecord:
        begin_list(b, BoxesList, NULL, false);
        break;
    case BoxesList:
        if(b->request->kind == Tb2SetupBoxes) {
            show(b, BoxesRoot);
            break;
        }
        b->request->action = Tb2SetupActionHome;
        view_dispatcher_stop(b->dispatcher);
        break;
    default:
        b->request->action = Tb2SetupActionHome;
        view_dispatcher_stop(b->dispatcher);
        break;
    }
    return true;
}
static bool custom(void* ctx, uint32_t ev) {
    Boxes* b = ctx;
    Tb2WorkflowIO* io = b->request->filesystem;
    Tb2RecordResult rc = Tb2RecordOk;
    bool list = list_screen(b->screen);
    if(list && (!b->page.done || b->loaded < b->page.count)) return true;
    if(ev == BoxUp || ev == BoxDown) {
        if(ev == BoxUp && b->selected) b->selected--;
        if(ev == BoxDown && b->selected + 1 < b->page.count) b->selected++;
        publish_list(b);
        return true;
    }
    if(ev == BoxNext || ev == BoxPrevious) {
        bool previous = b->page.reverse ? b->page.more : b->page.anchor[0] != 0;
        bool next = b->page.reverse ? b->page.anchor[0] != 0 : b->page.more;
        if(ev == BoxPrevious && !previous) {
            if(b->screen == BoxesList)
                ev = BoxNew;
            else {
                show(b, BoxesRecord);
                return true;
            }
        } else if(b->page.count && (ev == BoxNext ? next : previous)) {
            char anchor[TB2_RECORD_ID_SIZE];
            memcpy(anchor, b->page.ids[ev == BoxNext ? b->page.count - 1 : 0], sizeof(anchor));
            begin_list(b, b->screen, anchor, ev == BoxPrevious);
            return true;
        } else
            return true;
    }
    switch(ev) {
    case BoxIdentify:
        if(prepare_task(b, Tb2RecordTaskIdentify)) finish_task(b);
        break;
    case BoxIdentifyFirmware:
        if(prepare_task(b, Tb2RecordTaskFirmwareHeaders)) finish_task(b);
        break;
    case BoxRetryList:
        begin_list(b, b->failed_list, NULL, false);
        break;
    case BoxHistory:
    case BoxNotesRead:
        begin_list(b, ev == BoxHistory ? BoxesHistory : BoxesNoteList, NULL, false);
        break;
    case BoxBrowse:
        begin_list(b, BoxesList, NULL, false);
        break;
    case BoxImport:
        import_file(b, false);
        break;
    case BoxExport:
        show(b, BoxesExport);
        break;
    case BoxExportFull:
        b->pending = ev;
        text(b, BoxesConfirm, "Export images, certificates and secrets?");
        break;
    case BoxDiagnostic:
    case BoxPackage:
        if(prepare_task(b, ev == BoxDiagnostic ? Tb2RecordTaskDiagnostic : Tb2RecordTaskPackage))
            finish_task(b);
        break;
    case BoxOpen:
        if(!list || !b->page.count) break;
        if(b->screen == BoxesHistory || b->screen == BoxesNoteList) {
            if(prepare_task(b, Tb2RecordTaskHistory)) {
                strcpy(b->request->record_task->entry, b->page.ids[b->selected]);
                b->request->record_task->flags = b->screen == BoxesNoteList;
                strlcpy(
                    b->request->record_task->note,
                    b->details[b->selected],
                    sizeof(b->request->record_task->note));
                finish_task(b);
            }
        } else if(b->screen == BoxesList) {
            rc = tb2_box_load(io, b->page.ids[b->selected], &b->box);
            if(!rc) {
                strcpy(b->request->box_id, b->box.id);
                show(b, BoxesRecord);
            }
        } else {
            rc = tb2_version_load(io, b->request->box_id, b->page.ids[b->selected], &b->version);
            if(!rc) {
                if(b->comparing) {
                    strcpy(b->request->record_task->other, b->version.id);
                    b->comparing = false;
                    finish_task(b);
                    break;
                }
                if(b->originals_only && !(b->version.flags & Tb2VersionOriginal)) {
                    text(b, BoxesRestore, "Choose an Original.");
                    break;
                }
                strcpy(b->request->version_id, b->version.id);
                show(
                    b, b->request->kind == Tb2SetupRestoreDonor ? BoxesRestoreMode : BoxesVersion);
            }
        }
        break;
    case BoxNew:
    case BoxAlias:
    case BoxSerial:
        b->pending = ev;
        b->creating = ev == BoxNew;
        strlcpy(
            b->edit,
            b->creating     ? "Box" :
            ev == BoxSerial ? b->box.serial :
                              b->box.alias,
            sizeof(b->edit));
        b->screen = BoxesAlias;
        text_input_set_header_text(
            b->keyboard,
            b->creating     ? "New box alias" :
            ev == BoxSerial ? "Printed serial (optional)" :
                              "Box alias");
        text_input_set_result_callback(
            b->keyboard,
            alias_done,
            b,
            b->edit,
            ev == BoxSerial ? sizeof(b->box.serial) : sizeof(b->edit),
            true);
        view_dispatcher_switch_to_view(b->dispatcher, BoxesAlias);
        break;
    case BoxAliasDone:
        if(!b->edit[0] && b->pending != BoxSerial) {
            text(b, BoxesRecord, "Enter a box alias.");
            break;
        }
        if(prepare_task(b, Tb2RecordTaskSaveBox)) {
            b->request->record_task->flags = b->creating ? 2 : b->pending == BoxSerial ? 1 : 0;
            if(b->creating) b->request->record_task->box[0] = 0;
            if(b->box.has_uid) {
                b->request->record_task->uid_available = true;
                memcpy(b->request->record_task->uid, b->box.uid, sizeof(b->box.uid));
            }
            strcpy(b->request->record_task->note, b->edit);
            finish_task(b);
        }
        break;
    case BoxUse:
        b->request->action = Tb2SetupActionBoxSelected;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxDump:
        b->request->path[0] = 0;
        b->request->version_id[0] = 0;
        b->request->editor_kind = Tb2SetupBoxes;
        b->request->action = Tb2SetupActionDump;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxModify:
        b->request->path[0] = 0;
        b->request->version_id[0] = 0;
        b->request->editor_kind = Tb2SetupBoxes;
        b->request->action = Tb2SetupActionModify;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxOverview:
        if(b->request->kind != Tb2SetupSelectBox && b->request->record_task) {
            if(prepare_task(b, Tb2RecordTaskOverview)) finish_task(b);
            break;
        }
        snprintf(
            b->text_buffer,
            sizeof(b->text_buffer),
            "%s\nBox ID: %s\nSerial: %s\nUID: %s\nRecord: %s\nSaved state",
            b->box.alias,
            b->box.box_id[0] ? b->box.box_id : "Unknown",
            b->box.serial[0] ? b->box.serial : "Unknown",
            b->box.has_uid ? "Linked" : "Unknown",
            b->box.id);
        text(b, BoxesRecord, b->text_buffer);
        break;
    case BoxVersionsOpen:
        b->comparing = false;
        b->originals_only = false;
        b->certificates = false;
        begin_list(b, BoxesVersions, NULL, false);
        break;
    case BoxCompare:
        show(b, BoxesCompare);
        break;
    case BoxRename:
    case BoxCompareChip:
        if(prepare_task(b, ev == BoxRename ? Tb2RecordTaskRenamePrepare : Tb2RecordTaskCompareChip))
            finish_task(b);
        break;
    case BoxCompareImage:
        if(prepare_task(b, Tb2RecordTaskCompare)) {
            b->comparing = true;
            b->originals_only = false;
            begin_list(b, BoxesVersions, NULL, false);
        }
        break;
    case BoxNotes:
        show(b, BoxesNotes);
        break;
    case BoxSecret:
        show(b, BoxesSecret);
        break;
    case BoxSecretDetails:
        if(prepare_task(b, Tb2RecordTaskSecret)) finish_task(b);
        break;
    case BoxNoteEdit:
        if(!prepare_task(b, Tb2RecordTaskNote)) break;
        b->pending = ev;
        b->screen = BoxesAlias;
        text_input_set_header_text(b->keyboard, "Workshop note");
        text_input_set_result_callback(
            b->keyboard,
            note_done,
            b,
            b->request->record_task->note,
            sizeof(b->request->record_task->note),
            true);
        view_dispatcher_switch_to_view(b->dispatcher, BoxesAlias);
        break;
    case BoxNoteTested:
    case BoxNoteRepair:
        if(!prepare_task(b, Tb2RecordTaskNote)) break;
        strcpy(
            b->request->record_task->note,
            ev == BoxNoteTested ? "Buttons and speaker tested" : "Needs repair");
        finish_task(b);
        break;
    case BoxNoteDone:
        if(b->request->record_task->note[0])
            finish_task(b);
        else
            show(b, BoxesNotes);
        break;
    case BoxRestore:
        show(b, BoxesRestore);
        break;
    case BoxRestoreOriginal:
    case BoxRestorePrevious:
        b->certificates = false;
        b->originals_only = ev == BoxRestoreOriginal;
        begin_list(b, BoxesVersions, NULL, false);
        break;
    case BoxRestoreCertificates:
        if(b->request->kind == Tb2SetupRestoreDonor) {
            b->certificates = b->originals_only = true;
            begin_list(b, BoxesVersions, NULL, false);
        } else if(b->screen == BoxesVersion) {
            show(b, BoxesRestoreMode);
        } else {
            b->request->version_id[0] = 0;
            b->request->restore_connection = false;
            b->request->action = Tb2SetupActionRestore;
            view_dispatcher_stop(b->dispatcher);
        }
        break;
    case BoxCertificatesOnly:
    case BoxOriginalConnection:
        b->request->restore_connection = ev == BoxOriginalConnection;
        b->request->action = b->request->kind == Tb2SetupRestoreDonor ?
                                 Tb2SetupActionRestoreSelected :
                                 Tb2SetupActionRestore;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxImportItems:
    case BoxKeyCandidate:
        if(prepare_task(b, Tb2RecordTaskImportInspect)) {
            b->request->record_task->import.stage = ev == BoxKeyCandidate ? Tb2ImportSecrets :
                                                                            Tb2ImportHome;
            b->request->action = Tb2SetupActionImports;
            view_dispatcher_stop(b->dispatcher);
        }
        break;
    case BoxKeyFile:
        import_file(b, true);
        break;
    case BoxRestoreBuild:
        b->request->action = Tb2SetupActionRestoreBuild;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxFlash:
        snprintf(
            b->text_buffer,
            sizeof(b->text_buffer),
            "%s\nFW: %s\nReplaces firmware/settings.\nNo secret needed.",
            b->version.name,
            b->version.firmware.known ? b->version.firmware.version : "Unknown");
        text(b, BoxesFlash, b->text_buffer);
        break;
    case BoxFlashConfirm:
        if(b->version.flags & Tb2VersionDeleted) {
            rc = Tb2RecordMissing;
            break;
        }
        rc = tb2_version_image_path(
            b->request->filesystem,
            b->request->box_id,
            b->version.id,
            &b->version.image,
            b->request->path);
        if(rc) {
            break;
        }
        b->request->editor_kind = Tb2SetupBoxes;
        b->request->action = Tb2SetupActionFlashVersion;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxModifyVersion:
        if(b->version.flags & Tb2VersionDeleted) {
            rc = Tb2RecordMissing;
            break;
        }
        rc = tb2_version_image_path(
            b->request->filesystem,
            b->request->box_id,
            b->version.id,
            &b->version.image,
            b->request->path);
        if(rc) break;
        b->request->editor_kind = Tb2SetupBoxes;
        b->request->action = Tb2SetupActionModify;
        view_dispatcher_stop(b->dispatcher);
        break;
    case BoxVersionDetails:
        if(b->request->kind != Tb2SetupOriginalPrompt &&
           b->request->kind != Tb2SetupRestoreDonor && b->request->kind != Tb2SetupSelectBox &&
           b->request->record_task) {
            if(prepare_task(b, Tb2RecordTaskVersionDetails)) finish_task(b);
            break;
        }
        snprintf(
            b->text_buffer,
            sizeof(b->text_buffer),
            "%s\nv%lu / %s\nFW: %s\nUTC: %s\nJob: %s\n%lu bytes\n%s\nSaved state",
            b->version.name,
            (unsigned long)b->version.number,
            b->version.id,
            b->version.firmware.known ? b->version.firmware.version : "Unknown",
            b->version.created,
            b->version.job,
            (unsigned long)b->version.image.size,
            b->version.flags & Tb2VersionProtected ? "Protected" : "Unprotected");
        text(
            b,
            b->request->kind == Tb2SetupOriginalPrompt ? BoxesOriginal :
            b->request->kind == Tb2SetupRestoreDonor   ? BoxesRestoreMode :
                                                         BoxesVersion,
            b->text_buffer);
        break;
    case BoxOriginal:
    case BoxWorking:
        b->pending = ev;
        text(
            b,
            BoxesConfirm,
            ev == BoxOriginal ? "Confirm original; protect version." :
                                "Confirm box test; protect version.");
        break;
    case BoxConfirm:
        if(b->pending == BoxImport) {
            finish_task(b);
            break;
        }
        if(b->pending == BoxExportFull) {
            if(prepare_task(b, Tb2RecordTaskExport)) finish_task(b);
            break;
        }
        if(b->pending == BoxDelete) {
            if(prepare_task(b, Tb2RecordTaskDelete)) finish_task(b);
            break;
        }
        if(prepare_task(b, Tb2RecordTaskClassify)) {
            b->request->record_task->flags = b->pending == BoxOriginal ? Tb2VersionOriginal :
                                                                         Tb2VersionWorking;
            finish_task(b);
        }
        break;
    case BoxNotOriginal:
        if(prepare_task(b, Tb2RecordTaskClassify)) {
            b->request->record_task->flags = Tb2VersionClassified;
            finish_task(b);
        }
        break;
    case BoxDelete:
        if(b->version.flags & Tb2VersionProtected) {
            rc = Tb2RecordProtected;
            break;
        }
        b->pending = ev;
        snprintf(
            b->text_buffer,
            sizeof(b->text_buffer),
            "Delete v%lu?\n%s\nShared objects remain.",
            (unsigned long)b->version.number,
            b->version.name);
        text(b, BoxesConfirm, b->text_buffer);
        break;
    case BoxProtection:
        if(prepare_task(b, Tb2RecordTaskClassify)) {
            b->request->record_task->flags =
                b->version.flags & Tb2VersionProtected ? 0 : Tb2VersionProtected;
            finish_task(b);
        }
        break;
    default:
        return false;
    }
    if(rc) error(b, b->screen == BoxesVersion ? BoxesVersion : BoxesRecord, rc);
    return true;
}
static bool run(Tb2SetupRequest* request) {
    if(!request->filesystem) return false;
    Boxes* b = calloc(1, sizeof(*b));
    if(!b) return false;
    b->request = request;
    b->dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(b->dispatcher, b);
    view_dispatcher_set_custom_event_callback(b->dispatcher, custom);
    view_dispatcher_set_navigation_event_callback(b->dispatcher, back);
    view_dispatcher_set_tick_event_callback(b->dispatcher, tick, BOX_TICK_MS);
    b->menu = submenu_alloc();
    b->text = text_box_alloc();
    b->keyboard = text_input_alloc();
    b->list = view_alloc();
    view_allocate_model(b->list, ViewModelTypeLocking, sizeof(BoxListModel));
    view_set_context(b->list, b);
    view_set_draw_callback(b->list, draw);
    view_set_input_callback(b->list, input);
    view_dispatcher_add_view(b->dispatcher, BoxesList, b->list);
    view_dispatcher_add_view(b->dispatcher, BoxesRecord, submenu_get_view(b->menu));
    view_dispatcher_add_view(b->dispatcher, BoxesText, text_box_get_view(b->text));
    view_dispatcher_add_view(b->dispatcher, BoxesAlias, text_input_get_view(b->keyboard));
    view_dispatcher_attach_to_gui(b->dispatcher, request->gui, ViewDispatcherTypeFullscreen);
    if(request->kind == Tb2SetupOriginalPrompt) {
        Tb2RecordResult rc = tb2_version_load(
            request->filesystem, request->box_id, request->version_id, &b->version);
        if(rc || !(b->version.flags & Tb2VersionSource) ||
           (b->version.flags & Tb2VersionClassified)) {
            request->action = Tb2SetupActionHome;
        } else {
            snprintf(
                b->text_buffer,
                sizeof(b->text_buffer),
                "%s\nFW: %s\nOriginal dump?",
                b->version.name,
                b->version.firmware.known ? b->version.firmware.version : "Unknown");
            text(b, BoxesOriginal, b->text_buffer);
        }
    } else if(request->kind == Tb2SetupRestoreDonor) {
        b->certificates = b->originals_only = true;
        Tb2RecordResult rc =
            request->version_id[0] ?
                tb2_version_load(
                    request->filesystem, request->box_id, request->version_id, &b->version) :
                Tb2RecordMissing;
        if(!rc) {
            snprintf(
                b->text_buffer,
                sizeof(b->text_buffer),
                "Suggested original\n%s\nv%lu\nUTC: %s\nFW: %s",
                b->version.name,
                (unsigned long)b->version.number,
                b->version.created,
                b->version.firmware.known ? b->version.firmware.version : "Unknown");
            text(b, BoxesRestoreMode, b->text_buffer);
        } else if(rc == Tb2RecordMissing) {
            text(b, BoxesVersions, "No match. Check Details.");
        } else
            error(b, BoxesRoot, rc);
    } else if(request->kind == Tb2SetupRestoreApprove) {
        snprintf(
            b->text_buffer,
            sizeof(b->text_buffer),
            "Keys OK.\nRestore CA/client/private; keep auth.\n%s\nArchive before Flash.",
            request->restore_connection ? "Restore original hosts/ports." :
                                          "Keep current settings.");
        text(b, BoxesRestoreApprove, b->text_buffer);
    } else if(request->kind == Tb2SetupBoxes) {
        Tb2RecordTask* task = request->record_task;
        if(task && task->kind == Tb2RecordTaskIdentify && task->flags == Tb2IdentifyCreate) {
            b->box.has_uid = true;
            memcpy(b->box.uid, task->uid, sizeof(b->box.uid));
            show(b, BoxesRoot);
            custom(b, BoxNew);
        } else if(!request->box_id[0])
            show(b, BoxesRoot);
        else {
            Tb2RecordResult rc = tb2_box_load(request->filesystem, request->box_id, &b->box);
            if(!rc && request->version_id[0])
                rc = tb2_version_load(
                    request->filesystem, request->box_id, request->version_id, &b->version);
            if(rc)
                error(b, BoxesRoot, rc);
            else if(request->version_id[0])
                show(b, BoxesVersion);
            else {
                request->version_id[0] = 0;
                show(b, BoxesRecord);
            }
        }
    } else {
        begin_list(b, BoxesList, NULL, false);
        if(request->error[0]) text(b, BoxesList, request->error);
    }
    if(request->kind != Tb2SetupOriginalPrompt || b->screen == BoxesText)
        view_dispatcher_run(b->dispatcher);
    tb2_record_page_close(request->filesystem, &b->page);
    view_dispatcher_remove_view(b->dispatcher, BoxesList);
    view_dispatcher_remove_view(b->dispatcher, BoxesRecord);
    view_dispatcher_remove_view(b->dispatcher, BoxesText);
    view_dispatcher_remove_view(b->dispatcher, BoxesAlias);
    view_free(b->list);
    submenu_free(b->menu);
    text_box_free(b->text);
    text_input_free(b->keyboard);
    view_dispatcher_free(b->dispatcher);
    tb2_record_wipe(b, sizeof(*b));
    free(b);
    return true;
}
static const Tb2Setup boxes = {.run = run};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_BOXES_ID,
    .ep_api_version = TB2_SETUP_API,
    .entry_point = &boxes};
const FlipperAppPluginDescriptor* tb2_boxes_entry(void) {
    return &descriptor;
}
