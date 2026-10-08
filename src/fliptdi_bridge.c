/* TB2-only FlipTDI shell. The FTDI protocol engine is derived from FlipTDI
 * (SkorP / flipperzero-good-faps); see third_party/flip_tdi/provenance.json. */
#include "fliptdi.h"
#include "paths.h"
#include <flipper_format/flipper_format.h>
#include <storage/storage.h>
#include "fliptdi/ftdi_usb.h"
#include "fliptdi/tb2_spi_backend.h"

#include <flipper_application/flipper_application.h>
#include <furi.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLIPTDI_TEST_STACK 1024U
#define FLIPTDI_RETRY_MS   100U
#define FLIPTDI_UI_TICK_MS 100U

typedef enum {
    FlipTdiViewMenu,
    FlipTdiViewText,
} FlipTdiView;

typedef enum {
    FlipTdiActionUsb = 1,
    FlipTdiActionTest,
    FlipTdiActionSettings,
    FlipTdiActionToggleClock,
    FlipTdiActionSaveClock,
    FlipTdiActionWiring,
    FlipTdiActionAbout,
} FlipTdiAction;

typedef enum {
    FlipTdiScreenMenu,
    FlipTdiScreenSettings,
    FlipTdiScreenUsb,
    FlipTdiScreenTest,
    FlipTdiScreenText,
} FlipTdiScreen;

typedef struct {
    Tb2SetupRequest* request;
    ViewDispatcher* dispatcher;
    Submenu* menu;
    TextBox* text;
    FuriMutex* mutex;
    FuriThread* worker;
    FtdiUsb* usb;
    Tb2SpiBackend* probe;
    atomic_bool stop;
    FlipTdiScreen screen;
    bool probe_transport;
    bool probe_match;
    uint8_t jedec[3];
    uint32_t default_hz;
    uint32_t draft_hz;
    bool clock_failed;
    char clock_label[32];
    char buffer[512];
} FlipTdiApp;

#define FLIPTDI_CONFIG_PATH    TB2_APP_ROOT "/core-flasher.conf"
#define FLIPTDI_CONFIG_TYPE    "TB2 Core Flasher"
#define FLIPTDI_CONFIG_VERSION 1U

/* Invalid or absent configuration always has the conservative default. */
static bool fliptdi_load_clock(Storage* storage, uint32_t* hz) {
    *hz = TB2_SPI_DEFAULT_HZ;
    FlipperFormat* file = flipper_format_file_alloc(storage);
    FuriString* type = furi_string_alloc();
    uint32_t version = 0, mhz = 0;
    bool ok = flipper_format_file_open_existing(file, FLIPTDI_CONFIG_PATH) &&
              flipper_format_read_header(file, type, &version) &&
              !strcmp(furi_string_get_cstr(type), FLIPTDI_CONFIG_TYPE) &&
              version == FLIPTDI_CONFIG_VERSION &&
              flipper_format_read_uint32(file, "Default SPI MHz", &mhz, 1) && mhz <= 16U &&
              tb2_spi_default_clock_valid(mhz * 1000000U);
    flipper_format_file_close(file);
    flipper_format_free(file);
    furi_string_free(type);
    if(ok) *hz = mhz * 1000000U;
    return ok;
}

static bool fliptdi_save_clock(Storage* storage, uint32_t hz) {
    if(!tb2_spi_default_clock_valid(hz)) return false;
    uint32_t mhz = hz / 1000000U;
    FlipperFormat* file = flipper_format_file_alloc(storage);
    bool ok =
        flipper_format_file_open_always(file, FLIPTDI_CONFIG_PATH) &&
        flipper_format_write_header_cstr(file, FLIPTDI_CONFIG_TYPE, FLIPTDI_CONFIG_VERSION) &&
        flipper_format_write_uint32(file, "Default SPI MHz", &mhz, 1);
    if(!flipper_format_file_close(file)) ok = false;
    flipper_format_free(file);
    uint32_t saved;
    return ok && fliptdi_load_clock(storage, &saved) && saved == hz;
}

static void fliptdi_show_settings(FlipTdiApp* app);

static void fliptdi_show_menu(FlipTdiApp* app);

static void fliptdi_set_text(FlipTdiApp* app, FlipTdiScreen screen, const char* text) {
    app->screen = screen;
    strlcpy(app->buffer, text, sizeof(app->buffer));
    text_box_set_text(app->text, app->buffer);
    text_box_set_focus(app->text, TextBoxFocusStart);
    view_dispatcher_switch_to_view(app->dispatcher, FlipTdiViewText);
}

static void fliptdi_probe_text(FlipTdiApp* app) {
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(app->probe_match) {
        snprintf(
            app->buffer,
            sizeof(app->buffer),
            "Hardware SPI test\n\nChip detected\nJEDEC: %02X %02X %02X\nWinbond W25Q128FV\nSPI: Mode 0 / %lu MHz\n\nBack: return",
            app->jedec[0],
            app->jedec[1],
            app->jedec[2],
            (unsigned long)(app->default_hz / 1000000U));
    } else if(app->probe_transport) {
        snprintf(
            app->buffer,
            sizeof(app->buffer),
            "Hardware SPI test\n\nWaiting for W25Q128FV\nLast ID: %02X %02X %02X\n\nPins: 2 MOSI, 3 MISO\n      4 CS,   5 SCK\n\nBack: cancel",
            app->jedec[0],
            app->jedec[1],
            app->jedec[2]);
    } else {
        strlcpy(
            app->buffer,
            "Hardware SPI test\n\nWaiting for chip...\n\nPins: 2 MOSI, 3 MISO\n      4 CS,   5 SCK\nPower: 3.3 V only\n\nBack: cancel",
            sizeof(app->buffer));
    }
    text_box_set_text(app->text, app->buffer);
    furi_mutex_release(app->mutex);
}

static int32_t fliptdi_probe_worker(void* context) {
    FlipTdiApp* app = context;
    static const uint8_t expected[3] = {0xEF, 0x40, 0x18};
    while(!atomic_load(&app->stop)) {
        uint8_t id[3] = {0};
        bool transport = tb2_spi_backend_probe_jedec(app->probe, id);
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->probe_transport = transport;
        memcpy(app->jedec, id, sizeof(app->jedec));
        app->probe_match = transport && !memcmp(id, expected, sizeof(expected));
        bool matched = app->probe_match;
        furi_mutex_release(app->mutex);
        if(matched) break;
        furi_delay_ms(FLIPTDI_RETRY_MS);
    }
    return 0;
}

static void fliptdi_stop_probe(FlipTdiApp* app) {
    atomic_store(&app->stop, true);
    if(app->worker) {
        furi_thread_join(app->worker);
        furi_thread_free(app->worker);
        app->worker = NULL;
    }
    tb2_spi_backend_free(app->probe);
    app->probe = NULL;
}

static bool fliptdi_start_probe(FlipTdiApp* app) {
    app->probe = tb2_spi_backend_alloc(app->default_hz);
    if(!app->probe) return false;
    atomic_store(&app->stop, false);
    app->probe_transport = app->probe_match = false;
    memset(app->jedec, 0, sizeof(app->jedec));
    app->worker =
        furi_thread_alloc_ex("FlipTDIProbe", FLIPTDI_TEST_STACK, fliptdi_probe_worker, app);
    if(!app->worker) {
        tb2_spi_backend_free(app->probe);
        app->probe = NULL;
        return false;
    }
    app->screen = FlipTdiScreenTest;
    fliptdi_probe_text(app);
    view_dispatcher_switch_to_view(app->dispatcher, FlipTdiViewText);
    furi_thread_start(app->worker);
    return true;
}

static void fliptdi_menu_event(void* context, uint32_t index) {
    FlipTdiApp* app = context;
    view_dispatcher_send_custom_event(app->dispatcher, index);
}

static bool fliptdi_custom_event(void* context, uint32_t event) {
    FlipTdiApp* app = context;
    switch((FlipTdiAction)event) {
    case FlipTdiActionUsb:
        app->clock_failed = false;
        app->usb = ftdi_usb_start(app->default_hz);
        if(app->usb) {
            fliptdi_set_text(
                app,
                FlipTdiScreenUsb,
                "Core Flasher USB\n\nUSB: ready (0403:6014)\nSPI: starting\nAccess: raw SPI\n\nConnect to WebUSB\n\nBack: stop bridge");
        } else {
            fliptdi_set_text(
                app,
                FlipTdiScreenText,
                "Core Flasher cannot start\n\nUSB is busy or memory is low.\nClose other USB apps and retry.\n\nBack: return");
        }
        return true;
    case FlipTdiActionTest:
        if(!fliptdi_start_probe(app))
            fliptdi_set_text(
                app,
                FlipTdiScreenText,
                "Hardware SPI test\n\nNot enough memory to start.\n\nBack: return");
        return true;
    case FlipTdiActionSettings:
        app->draft_hz = app->default_hz;
        fliptdi_show_settings(app);
        return true;
    case FlipTdiActionToggleClock:
        app->draft_hz = app->draft_hz == TB2_SPI_MAX_DEFAULT_HZ ? TB2_SPI_DEFAULT_HZ :
                                                                  app->draft_hz * 2U;
        fliptdi_show_settings(app);
        return true;
    case FlipTdiActionSaveClock:
        if(fliptdi_save_clock(app->request->storage, app->draft_hz)) {
            app->default_hz = app->draft_hz;
            fliptdi_show_menu(app);
        } else {
            submenu_set_header(app->menu, "Save failed: retry");
        }
        return true;
    case FlipTdiActionWiring:
        fliptdi_set_text(
            app,
            FlipTdiScreenText,
            "TB2 SPI wiring\n\nPin 2  MOSI / DI\nPin 3  MISO / DO\nPin 4  CS\nPin 5  SCK / CLK\nPin 8  GND\nPin 9  3.3 V\n\nNever use 5 V.");
        return true;
    case FlipTdiActionAbout:
        fliptdi_set_text(
            app,
            FlipTdiScreenText,
            "Core Flasher bridge\n\nFT232H-compatible WebUSB\nraw SPI bridge.\nFlash commands, backup and\nverify are owned by browser.\n\nBack: return");
        return true;
    default:
        return false;
    }
}

static void fliptdi_show_settings(FlipTdiApp* app) {
    app->screen = FlipTdiScreenSettings;
    submenu_reset(app->menu);
    submenu_set_header(app->menu, "Settings");
    snprintf(
        app->clock_label,
        sizeof(app->clock_label),
        "Default SPI: %lu MHz",
        (unsigned long)(app->draft_hz / 1000000U));
    submenu_add_item(
        app->menu, app->clock_label, FlipTdiActionToggleClock, fliptdi_menu_event, app);
    submenu_add_item(app->menu, "Save", FlipTdiActionSaveClock, fliptdi_menu_event, app);
    view_dispatcher_switch_to_view(app->dispatcher, FlipTdiViewMenu);
}

static void fliptdi_tick_event(void* context) {
    FlipTdiApp* app = context;
    if(app->screen == FlipTdiScreenTest) fliptdi_probe_text(app);
    if(app->screen == FlipTdiScreenUsb && app->usb) {
        Tb2SpiClockStatus status;
        if(!ftdi_usb_clock_status(app->usb, &status)) return;
        app->clock_failed |= status.clock_error;
        if(app->clock_failed) {
            if(ftdi_usb_stop(app->usb)) {
                app->usb = NULL;
                fliptdi_set_text(
                    app,
                    FlipTdiScreenText,
                    "Bridge stopped\n\nRequested SPI clock is below\nhardware minimum. Select a\nhigher clock in the browser.\n\nBack: return");
            }
            return;
        }
        snprintf(
            app->buffer,
            sizeof(app->buffer),
            "Core Flasher USB\nDefault: %lu MHz\nBrowser: %lu Hz\nApplied: %lu Hz\n\nBrowser 0: app default\nApplied 0: awaiting transfer\n\nConnect to WebUSB\nBack: stop bridge",
            (unsigned long)(status.default_hz / 1000000U),
            (unsigned long)status.requested_hz,
            (unsigned long)status.applied_hz);
        text_box_set_text(app->text, app->buffer);
    }
}

static bool fliptdi_back_event(void* context) {
    FlipTdiApp* app = context;
    if(app->screen == FlipTdiScreenMenu) {
        view_dispatcher_stop(app->dispatcher);
        return true;
    }
    if(app->screen == FlipTdiScreenTest) fliptdi_stop_probe(app);
    if(app->screen == FlipTdiScreenUsb) {
        if(!ftdi_usb_stop(app->usb)) {
            fliptdi_set_text(
                app,
                FlipTdiScreenUsb,
                "Core Flasher is active\n\nUSB could not be restored yet.\nDisconnect the browser and\npress Back to retry.");
            return true;
        }
        app->usb = NULL;
    }
    fliptdi_show_menu(app);
    return true;
}

static void fliptdi_show_menu(FlipTdiApp* app) {
    app->screen = FlipTdiScreenMenu;
    submenu_reset(app->menu);
    submenu_set_header(app->menu, "Core Flasher");
    submenu_add_item(app->menu, "Start USB bridge", FlipTdiActionUsb, fliptdi_menu_event, app);
    submenu_add_item(app->menu, "Test hardware SPI", FlipTdiActionTest, fliptdi_menu_event, app);
    submenu_add_item(app->menu, "Settings", FlipTdiActionSettings, fliptdi_menu_event, app);
    submenu_add_item(app->menu, "Wiring", FlipTdiActionWiring, fliptdi_menu_event, app);
    submenu_add_item(app->menu, "About", FlipTdiActionAbout, fliptdi_menu_event, app);
    view_dispatcher_switch_to_view(app->dispatcher, FlipTdiViewMenu);
}

static bool fliptdi_run(Tb2SetupRequest* request) {
    if(!request || !request->gui) return false;
    request->error[0] = 0;
    FlipTdiApp* app = calloc(1, sizeof(*app));
    if(!app) {
        strlcpy(request->error, "Not enough memory for Core Flasher.", sizeof(request->error));
        return false;
    }
    app->request = request;
    fliptdi_load_clock(request->storage, &app->default_hz);
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->dispatcher = view_dispatcher_alloc();
    app->menu = submenu_alloc();
    app->text = text_box_alloc();
    if(!app->mutex || !app->dispatcher || !app->menu || !app->text) {
        strlcpy(request->error, "Not enough memory for Core Flasher UI.", sizeof(request->error));
        if(app->text) text_box_free(app->text);
        if(app->menu) submenu_free(app->menu);
        if(app->dispatcher) view_dispatcher_free(app->dispatcher);
        if(app->mutex) furi_mutex_free(app->mutex);
        free(app);
        return false;
    }
    view_dispatcher_set_event_callback_context(app->dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->dispatcher, fliptdi_custom_event);
    view_dispatcher_set_navigation_event_callback(app->dispatcher, fliptdi_back_event);
    view_dispatcher_set_tick_event_callback(
        app->dispatcher, fliptdi_tick_event, FLIPTDI_UI_TICK_MS);
    view_dispatcher_add_view(app->dispatcher, FlipTdiViewMenu, submenu_get_view(app->menu));
    view_dispatcher_add_view(app->dispatcher, FlipTdiViewText, text_box_get_view(app->text));
    view_dispatcher_attach_to_gui(app->dispatcher, request->gui, ViewDispatcherTypeFullscreen);
    fliptdi_show_menu(app);
    view_dispatcher_run(app->dispatcher);

    if(app->worker || app->probe) fliptdi_stop_probe(app);
    if(app->usb) {
        /* Normal navigation cannot reach this branch unless USB restore failed;
         * keep the module mapped until the previous interface is restored. */
        while(!ftdi_usb_stop(app->usb))
            furi_delay_ms(100);
        app->usb = NULL;
    }
    view_dispatcher_remove_view(app->dispatcher, FlipTdiViewText);
    view_dispatcher_remove_view(app->dispatcher, FlipTdiViewMenu);
    text_box_free(app->text);
    submenu_free(app->menu);
    view_dispatcher_free(app->dispatcher);
    furi_mutex_free(app->mutex);
    free(app);
    request->action = Tb2SetupActionEdit;
    return true;
}

static const Tb2Setup fliptdi = {.run = fliptdi_run};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_FLIPTDI_ID,
    .ep_api_version = TB2_FLIPTDI_API,
    .entry_point = &fliptdi,
};

const FlipperAppPluginDescriptor* tb2_fliptdi_entry(void) {
    return &descriptor;
}
