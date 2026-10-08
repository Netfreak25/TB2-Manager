#pragma once
#include "job.h"
#include "server.h"
#include "settings.h"

#define TB2_UI_PREFERENCES_PATH TB2_APP_ROOT "/ui-prefs.bin"
#define TB2_UI_STATUS_NAME      "ui-status.bin"

enum {
    Tb2HardwareManualUid = 1U,
    Tb2HardwareSpiShift = 1U,
    Tb2HardwareSpiMask = 6U, /* Bits 1..2: 2, 4, 8, 16 MHz; legacy values retain meaning. */
};

typedef struct {
    char package_dir[TB2_JOB_PATH_MAX];
    char output_dir[TB2_JOB_PATH_MAX];
    /** Independent non-secret suggestions. Fields use Tb2ServerOtaHost etc. */
    Tb2ServerValues server_values;
    uint8_t server_fields;
    /** Runtime compatibility view for old common-host certificate workflows. */
    Tb2ServerChange server;
    /** Tb2Hardware* flags. Zero keeps automatic UID matching and the proven 2 MHz SPI profile. */
    uint8_t hardware_options;
} Tb2UiPreferences;

typedef enum {
    Tb2UiUnknown,
    Tb2UiPrepared,
    Tb2UiRunning,
    Tb2UiComplete,
    Tb2UiPaused,
    Tb2UiFailed,
    Tb2UiAborted,
    Tb2UiLegacyComplete,
    Tb2UiIncomplete,
} Tb2UiState;

typedef struct {
    Tb2UiState state;
    uint32_t action;
    int32_t result;
} Tb2UiStatus;

/** Read versioned proposals. Missing/corrupt input returns false and zeroes out.
 * Version 1 directories remain readable; server proposals then stay empty. */
bool tb2_ui_preferences_load(void* storage, Tb2UiPreferences* out);
/** Persist only non-secret proposals, with checked sync/close/readback. */
bool tb2_ui_preferences_save(void* storage, const Tb2UiPreferences* preferences);
/** Remove only the preference file; missing is success, other errors are retained. */
bool tb2_ui_preferences_reset(void* storage);

/** Read legacy/current job metadata without replay, repairs, hashing, or any writes. */
bool tb2_ui_job_load(void* storage, const char* directory, Tb2JobSpec* spec);
/** A present corrupt sidecar is Unknown. Only an absent sidecar permits journal fallback. */
Tb2UiStatus tb2_ui_status_read(void* storage, const char* directory, const Tb2JobSpec* spec);
/** Bind status to job.tb2, then write/sync/close/read back. Aborted requires journal proof. */
bool tb2_ui_status_write(
    void* storage,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2UiStatus* status);
