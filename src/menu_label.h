#pragma once

/** Native submenu headers do not elide long text in API 88.4. Measure the
 * actual primary font before handing the owned string to the SDK menu. */
static void tb2_menu_header(Submenu* menu, Gui* gui, const char* title) {
    char label[96];
    snprintf(label, sizeof(label), "%.*s", (int)sizeof(label) - 1, title);
    Canvas* canvas = gui_direct_draw_acquire(gui);
    canvas_set_font(canvas, FontPrimary);
    while(canvas_string_width(canvas, label) > 120 && label[0])
        label[strlen(label) - 1] = 0;
    gui_direct_draw_release(gui);
    submenu_set_header(menu, label);
}
