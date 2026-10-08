#include "review.h"
#include "probe.h"
#include "record_tasks.h"
#include <gui/gui.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REVIEW_TEXT_SIZE 1800U
#define REVIEW_LOG_CHUNK (REVIEW_TEXT_SIZE - 100U)
enum {
    ReviewResult,
    ReviewMenu,
    ReviewText
};
enum {
    ReviewDetails = 1,
    ReviewLog,
    ReviewPrevious,
    ReviewNext,
    ReviewContinue,
    ReviewBuild,
    ReviewRecordDone,
    ReviewRecordRetry
};
typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    DialogEx* dialog;
    Submenu* menu;
    TextBox* text;
    unsigned screen;
    uint32_t log_offset, log_size;
    bool log;
    char display[160], buffer[REVIEW_TEXT_SIZE];
} Review;
static void review_event(void* context, uint32_t event) {
    Review* r = context;
    view_dispatcher_send_custom_event(r->dispatcher, event);
}
static void review_dialog(DialogExResult result, void* context) {
    Review* r = context;
    if(r->request->kind == Tb2SetupRecordResult && r->request->record_task &&
       r->request->record_task->kind == Tb2RecordTaskIdentify) {
        review_event(r, result == DialogExResultLeft ? ReviewRecordRetry : ReviewRecordDone);
        return;
    }
    review_event(context, result == DialogExResultLeft ? ReviewDetails : ReviewContinue);
}
static bool review_is_identify(Review* r) {
    return r->request->kind == Tb2SetupRecordResult && r->request->record_task &&
           r->request->record_task->kind == Tb2RecordTaskIdentify;
}
static void review_identify(Review* r) {
    Tb2RecordTask* task = r->request->record_task;
    bool valid = !r->request->result && task->uid_available;
    bool module_failed = r->request->error[0] && strstr(r->request->error, "Module load failed");
    const char* title = NULL;
    const char* message = NULL;
    if(r->request->result) {
        if(module_failed) {
            title = "Module load failed";
            message = "Reinstall the complete FAP";
        } else if(task->uid_available) {
            if(r->request->result == TB2_PROBE_IO_ERROR) {
                title = "SD access failed";
                message = "Check SD card and retry";
            } else {
                title = "Box lookup failed";
                message = "Cannot read records";
            }
        } else if(r->request->result == Tb2SpiUnsupported) {
            title = "Unsupported chip";
            message = "Expected Winbond W25Q128FV";
        } else {
            title = "Chip detection failed";
            message = "Check chip; retry";
        }
    } else if(!valid) {
        title = "UID unavailable";
        message = "JEDEC OK; UID unreadable";
    } else {
        title = task->box[0] ? "Box identified" : "Unknown box";
        message = task->box[0] ? task->note : "Chip UID";
    }
    snprintf(r->display, sizeof(r->display), "%.*s", (int)sizeof(r->display) - 1, message);
    Canvas* canvas = gui_direct_draw_acquire(r->request->gui);
    canvas_set_font(canvas, FontSecondary);
    while(r->display[0] && canvas_string_width(canvas, r->display) > 118)
        r->display[strlen(r->display) - 1] = 0;
    gui_direct_draw_release(r->request->gui);
    if(valid) {
        size_t offset = strlen(r->display);
        r->display[offset++] = '\n';
        for(size_t i = 0; i < sizeof(task->uid); i++)
            snprintf(r->display + offset + i * 2, 3, "%02X", task->uid[i]);
    }
    dialog_ex_reset(r->dialog);
    dialog_ex_set_context(r->dialog, r);
    dialog_ex_set_result_callback(r->dialog, review_dialog);
    dialog_ex_set_header(r->dialog, title, 64, 0, AlignCenter, AlignTop);
    dialog_ex_set_text(r->dialog, r->display, 64, 19, AlignCenter, AlignTop);
    dialog_ex_set_left_button_text(r->dialog, "Retry");
    if(valid) dialog_ex_set_right_button_text(r->dialog, task->box[0] ? "Open" : "Create");
    r->screen = ReviewResult;
    view_dispatcher_switch_to_view(r->dispatcher, ReviewResult);
}
static void review_done(Review* r, Tb2SetupAction action) {
    r->request->action = action;
    view_dispatcher_stop(r->dispatcher);
}
static void review_text(Review* r) {
    text_box_set_text(r->text, r->buffer);
    r->screen = ReviewText;
    view_dispatcher_switch_to_view(r->dispatcher, ReviewText);
}
static void review_menu(Review* r) {
    submenu_reset(r->menu);
    if(r->request->kind == Tb2SetupRecordResult) {
        submenu_set_header(r->menu, r->request->result ? "Record action failed" : "Box record");
        submenu_add_item(r->menu, "Details", ReviewDetails, review_event, r);
        if(r->request->result)
            submenu_add_item(r->menu, "Retry", ReviewRecordRetry, review_event, r);
        submenu_add_item(
            r->menu,
            r->request->box_id[0] ? "Back to box" : "Back to boxes",
            ReviewRecordDone,
            review_event,
            r);
        r->screen = ReviewMenu;
        view_dispatcher_switch_to_view(r->dispatcher, ReviewMenu);
        return;
    }
    if(r->request->kind == Tb2SetupApprove) {
        submenu_set_header(r->menu, "Approval");
        submenu_add_item(r->menu, "Date / check results", ReviewDetails, review_event, r);
        submenu_add_item(
            r->menu,
            r->request->operation && r->request->operation->kind == Tb2OperationAio ?
                "Modify & Flash" :
                "Create image",
            ReviewBuild,
            review_event,
            r);
        r->screen = ReviewMenu;
        view_dispatcher_switch_to_view(r->dispatcher, ReviewMenu);
        return;
    }
    submenu_set_header(r->menu, r->log ? "Debug log" : "Result details");
    if(r->log) {
        submenu_add_item(r->menu, "Read page", ReviewLog, review_event, r);
        submenu_add_item(r->menu, "Previous page", ReviewPrevious, review_event, r);
        submenu_add_item(r->menu, "Next page", ReviewNext, review_event, r);
    } else {
        submenu_add_item(r->menu, "Paths / check results", ReviewDetails, review_event, r);
        submenu_add_item(r->menu, "View log", ReviewLog, review_event, r);
    }
    r->screen = ReviewMenu;
    view_dispatcher_switch_to_view(r->dispatcher, ReviewMenu);
}
static bool review_complete(Review* r) {
    return !r->request->historical && !r->request->result && r->request->flow &&
           r->request->flow->complete;
}
static void review_result(Review* r) {
    Tb2SetupRequest* q = r->request;
    bool complete = review_complete(r), aborted = q->status.state == Tb2UiAborted;
    dialog_ex_reset(r->dialog);
    dialog_ex_set_context(r->dialog, r);
    dialog_ex_set_result_callback(r->dialog, review_dialog);
    dialog_ex_set_header(
        r->dialog,
        complete                         ? "Image verified" :
        q->historical                    ? "Saved state" :
        aborted                          ? "Aborted" :
        q->result == TB2_PROBE_CANCELLED ? "Stopped" :
                                           "Not complete",
        64,
        0,
        AlignCenter,
        AlignTop);
    char path[TB2_JOB_PATH_MAX] = {0};
    tb2_job_image_path(q->spec, q->directory, path);
    const char* name = strrchr(path, '/');
    snprintf(
        r->display,
        sizeof(r->display),
        "%.*s",
        (int)sizeof(r->display) - 1,
        complete                     ? (name ? name + 1 : path) :
        q->error[0]                  ? q->error :
        q->flow && q->flow->error[0] ? q->flow->error :
                                       "Job details");
    Canvas* canvas = gui_direct_draw_acquire(q->gui);
    canvas_set_font(canvas, FontSecondary);
    while(r->display[0] && canvas_string_width(canvas, r->display) > 118)
        r->display[strlen(r->display) - 1] = 0;
    gui_direct_draw_release(q->gui);
    size_t used = strlen(r->display);
    snprintf(
        r->display + used,
        sizeof(r->display) - used,
        "\n%s",
        q->warning[0]       ? "SD warning: Details" :
        complete || aborted ? "Next = next box" :
                              "Try again");
    dialog_ex_set_text(r->dialog, r->display, 64, 19, AlignCenter, AlignTop);
    dialog_ex_set_left_button_text(r->dialog, "Details");
    dialog_ex_set_right_button_text(r->dialog, complete || aborted ? "Next" : "Retry");
    r->screen = ReviewResult;
    view_dispatcher_switch_to_view(r->dispatcher, ReviewResult);
}
static void review_details(Review* r) {
    Tb2SetupRequest* q = r->request;
    char path[TB2_JOB_PATH_MAX] = {0};
    tb2_job_image_path(q->spec, q->directory, path);
    int exists = path[0] ? q->filesystem->exists(q->filesystem->context, path) : 0;
    snprintf(
        r->buffer,
        sizeof(r->buffer),
        "%s\nDump: %s\nUTC: %s\nImage: %s\n%s\nJob: %s\nPackage: %s/package/\nBackups: %s/original/\nClient: %s/client/\nLog: %s/debug.log\nrc=%d\n%s\n%s",
        q->historical ? "Saved state" : "Job details",
        q->spec->source,
        q->spec->options.now,
        path,
        exists == 1 ? "Image present" :
        exists == 0 ? "Image missing" :
                      "SD read error",
        q->directory,
        q->directory,
        q->directory,
        q->directory,
        q->directory,
        q->result,
        q->error[0] ? q->error :
        q->flow     ? q->flow->error :
                      "",
        q->warning);
    review_text(r);
}
static void review_log(Review* r) {
    Tb2WorkflowIO* io = r->request->filesystem;
    char path[TB2_JOB_PATH_MAX];
    snprintf(path, sizeof(path), "%s/debug.log", r->request->directory);
    void* file = io->open(io->context, path, Tb2FileRead);
    uint64_t size = file ? io->size(io->context, file) : UINT64_MAX;
    bool ok = file && size <= UINT32_MAX;
    if(ok) {
        r->log_size = (uint32_t)size;
        if(r->log_offset > size)
            r->log_offset = size > REVIEW_LOG_CHUNK ? (uint32_t)size - REVIEW_LOG_CHUNK : 0;
        uint32_t wanted = (uint32_t)size - r->log_offset;
        if(wanted > REVIEW_LOG_CHUNK) wanted = REVIEW_LOG_CHUNK;
        int header = snprintf(
            r->buffer,
            sizeof(r->buffer),
            "debug.log\nByte %lu / %lu\n\n",
            (unsigned long)r->log_offset,
            (unsigned long)r->log_size);
        ok = io->seek(io->context, file, r->log_offset) &&
             io->read(io->context, file, r->buffer + header, wanted) == wanted;
        if(ok) r->buffer[header + wanted] = 0;
    }
    if(file) ok = io->close(io->context, file) && ok;
    if(!ok) snprintf(r->buffer, sizeof(r->buffer), "Cannot read log.\n%s", path);
    r->log = true;
    review_text(r);
}
static void review_operation(Review* r) {
    Tb2SetupRequest* q = r->request;
    Tb2Operation* op = q->operation;
    static const char* const phases[] = {
        "Read dump",
        "Verify dump",
        "Modify setup",
        "Check image",
        "Build image",
        "Export TAR",
        "Check flash file",
        "Erase / write",
        "Verify chip",
        "Complete",
        "Archive input",
        "Check backup",
        "Archive target"};
    static const char* const states[] = {
        "Unknown",
        "Prepared",
        "Interrupted",
        "Complete",
        "Interrupted",
        "Failed",
        "Aborted",
        "Complete",
        "Incomplete"};
    const char* path = op->image[0] ? op->image : op->source;
    /* The controller retains the current selected image across Preflight and
     * approval. SDK open waits forever if that same path is already open.
     * Historical or differently selected operations must not borrow it. */
    bool borrowed = !q->historical && !strcmp(q->path, op->image) && op->image[0] &&
                    q->filesystem->image_lease && *q->filesystem->image_lease;
    void* file = borrowed ? *q->filesystem->image_lease :
                            q->filesystem->open(q->filesystem->context, path, Tb2FileRead);
    bool present = file && q->filesystem->size(q->filesystem->context, file) == TB2_IMAGE_SIZE;
    if(file && !borrowed) present = q->filesystem->close(q->filesystem->context, file) && present;
    snprintf(
        r->buffer,
        sizeof(r->buffer),
        "%s\n%s\nSource: %s\nTarget: %s\nUTC: %.4s-%.2s-%.2s %.2s:%.2s:%.2s\nWinbond W25Q128FV\n16 MiB / EF 40 18\nStatus: %s\nPhase: %s\nrc=%ld\n%s\n%s\nLog: %s/debug.log",
        q->historical ? "Saved state" : "Operation details",
        present ? "Image present" : "Image missing or incomplete",
        op->source,
        path,
        op->created,
        op->created + 4,
        op->created + 6,
        op->created + 8,
        op->created + 10,
        op->created + 12,
        (unsigned)op->state < sizeof(states) / sizeof(states[0]) ? states[op->state] : states[0],
        (unsigned)op->phase < sizeof(phases) / sizeof(phases[0]) ? phases[op->phase] : "Unknown",
        (long)op->result,
        q->error,
        q->warning,
        q->directory);
    if(!tb2_operation_pure(op->kind)) {
        size_t used = strlen(r->buffer);
        snprintf(
            r->buffer + used,
            sizeof(r->buffer) - used,
            "\nPackage: %s/package/\nBackups: %s/original/",
            q->directory,
            q->directory);
    }
    review_text(r);
}
static bool review_custom(void* context, uint32_t event) {
    Review* r = context;
    switch(event) {
    case ReviewRecordDone:
        if(review_is_identify(r)) {
            Tb2RecordTask* task = r->request->record_task;
            if(r->request->result || !task->uid_available) break;
            task->flags = task->box[0] ? Tb2IdentifyOpen : Tb2IdentifyCreate;
            if(task->box[0]) strcpy(r->request->box_id, task->box);
        }
        review_done(r, Tb2SetupActionBoxes);
        break;
    case ReviewRecordRetry:
        review_done(r, Tb2SetupActionRecordTask);
        break;
    case ReviewBuild:
        review_done(r, Tb2SetupActionBuild);
        break;
    case ReviewDetails:
        if(r->request->kind == Tb2SetupRecordResult) {
            snprintf(
                r->buffer,
                sizeof(r->buffer),
                "%.*s",
                (int)sizeof(r->buffer) - 1,
                r->request->record_task ? r->request->record_task->report : "Action unavailable.");
            review_text(r);
        } else if(r->request->kind == Tb2SetupOperationDetails) {
            review_operation(r);
        } else if(r->request->kind == Tb2SetupApprove) {
            tb2_review_approval(r->request, r->buffer, sizeof(r->buffer));
            review_text(r);
        } else if(r->screen == ReviewResult)
            review_menu(r);
        else
            review_details(r);
        break;
    case ReviewContinue:
        if(review_complete(r) || r->request->status.state == Tb2UiAborted) {
            r->request->box_id[0] = r->request->version_id[0] = r->request->path[0] = 0;
            review_done(r, Tb2SetupActionModify);
        } else {
            r->request->editor_kind = Tb2SetupResume;
            review_done(r, Tb2SetupActionEdit);
        }
        break;
    case ReviewPrevious:
        r->log_offset = r->log_offset > REVIEW_LOG_CHUNK ? r->log_offset - REVIEW_LOG_CHUNK : 0;
        review_log(r);
        break;
    case ReviewNext:
        if(r->log_offset + REVIEW_LOG_CHUNK < r->log_size) r->log_offset += REVIEW_LOG_CHUNK;
        review_log(r);
        break;
    case ReviewLog:
        review_log(r);
        break;
    default:
        return false;
    }
    return true;
}
static bool review_back(void* context) {
    Review* r = context;
    if(review_is_identify(r)) {
        r->request->record_task->flags = Tb2IdentifyResult;
        review_done(r, Tb2SetupActionBoxes);
        return true;
    }
    if(r->screen == ReviewText)
        review_menu(r);
    else if(r->log && r->request->kind != Tb2SetupOperationLog) {
        r->log = false;
        review_menu(r);
    } else if(r->screen == ReviewMenu && r->request->kind == Tb2SetupResult)
        review_result(r);
    else if(
        r->request->kind == Tb2SetupOperationDetails && !r->request->historical &&
        !r->request->result && r->request->operation->phase == Tb2PhaseFlashPrepare &&
        !r->request->operation->approved) {
        r->request->editor_kind = Tb2SetupFlashApprove;
        review_done(r, Tb2SetupActionEdit);
    } else
        review_done(
            r,
            r->request->historical ? Tb2SetupActionJobs :
            r->request->kind == Tb2SetupOperationLog ||
                    r->request->kind == Tb2SetupOperationDetails ?
                                     Tb2SetupActionOperationResult :
                                     Tb2SetupActionHome);
    return true;
}
bool tb2_review_run(Tb2SetupRequest* request) {
    if(!request->filesystem) return false;
    Review* r = calloc(1, sizeof(*r));
    if(!r) return false;
    r->request = request;
    r->log_offset = UINT32_MAX;
    r->dispatcher = view_dispatcher_alloc();
    r->dialog = dialog_ex_alloc();
    r->menu = submenu_alloc();
    r->text = text_box_alloc();
    view_dispatcher_set_event_callback_context(r->dispatcher, r);
    view_dispatcher_set_custom_event_callback(r->dispatcher, review_custom);
    view_dispatcher_set_navigation_event_callback(r->dispatcher, review_back);
    view_dispatcher_add_view(r->dispatcher, ReviewResult, dialog_ex_get_view(r->dialog));
    view_dispatcher_add_view(r->dispatcher, ReviewMenu, submenu_get_view(r->menu));
    view_dispatcher_add_view(r->dispatcher, ReviewText, text_box_get_view(r->text));
    view_dispatcher_attach_to_gui(r->dispatcher, request->gui, ViewDispatcherTypeFullscreen);
    if(review_is_identify(r))
        review_identify(r);
    else if(request->kind == Tb2SetupApprove || request->kind == Tb2SetupRecordResult)
        review_custom(r, ReviewDetails);
    else if(request->kind == Tb2SetupResult)
        review_result(r);
    else if(request->kind == Tb2SetupOperationDetails)
        review_operation(r);
    else if(request->kind == Tb2SetupJobDetails)
        review_details(r);
    else
        review_log(r);
    view_dispatcher_run(r->dispatcher);
    for(unsigned i = 0; i < 3; i++)
        view_dispatcher_remove_view(r->dispatcher, i);
    dialog_ex_free(r->dialog);
    submenu_free(r->menu);
    text_box_free(r->text);
    view_dispatcher_free(r->dispatcher);
    free(r);
    return true;
}
