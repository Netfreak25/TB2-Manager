#include "review.h"
#include "record_tasks.h"
#include <dialogs/dialogs.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>

static bool header_back(void* context) {
    view_dispatcher_stop(context);
    return true;
}

/** Only invoked after the SPI worker joined and its module was unloaded. */
bool tb2_headers_ui(Tb2SetupRequest* r) {
    Tb2SlotHeaders* headers = &r->record_task->headers;
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogMessage* dialog = dialog_message_alloc();
    dialog_message_set_header(dialog, "Firmware headers", 64, 0, AlignCenter, AlignTop);
    dialog_message_set_text(
        dialog,
        headers->summary[0] ? headers->summary : "Identification failed\nSee Details",
        64,
        16,
        AlignCenter,
        AlignTop);
    dialog_message_set_buttons(dialog, "Details", NULL, "Retry");
    for(;;) {
        DialogMessageButton button = dialog_message_show(dialogs, dialog);
        if(button != DialogMessageButtonLeft) {
            r->action = button == DialogMessageButtonRight ? Tb2SetupActionRecordTask :
                                                             Tb2SetupActionBoxes;
            r->box_id[0] = r->version_id[0] = 0;
            break;
        }
        FuriString* details = furi_string_alloc_printf(
            "%s\n%s\n%s\nrc=%ld", headers->details, headers->error, r->error, (long)r->result);
        ViewDispatcher* dispatcher = view_dispatcher_alloc();
        TextBox* text = text_box_alloc();
        text_box_set_text(text, furi_string_get_cstr(details));
        view_dispatcher_set_event_callback_context(dispatcher, dispatcher);
        view_dispatcher_set_navigation_event_callback(dispatcher, header_back);
        view_dispatcher_add_view(dispatcher, 0, text_box_get_view(text));
        view_dispatcher_attach_to_gui(dispatcher, r->gui, ViewDispatcherTypeFullscreen);
        view_dispatcher_switch_to_view(dispatcher, 0);
        view_dispatcher_run(dispatcher);
        view_dispatcher_remove_view(dispatcher, 0);
        text_box_free(text);
        view_dispatcher_free(dispatcher);
        furi_string_free(details);
    }
    dialog_message_free(dialog);
    furi_record_close(RECORD_DIALOGS);
    return true;
}
