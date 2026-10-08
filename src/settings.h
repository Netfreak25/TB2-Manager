#pragma once

#include "server.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB2_WIFI_PROFILE_COUNT   10U
#define TB2_WIFI_SSID_SIZE       33U
#define TB2_WIFI_PSK_SIZE        65U
#define TB2_SETTINGS_PATCH_BYTES 1176U

enum {
    Tb2SettingsHosts = 1U,
    Tb2SettingsWifi = 2U,
    Tb2SettingsDevice = 4U,
};

enum {
    Tb2ServerOtaHost = 1U,
    Tb2ServerOtaPort = 2U,
    Tb2ServerIciHost = 4U,
    Tb2ServerIciPort = 8U,
};

enum {
    Tb2WifiSsid = 1U,
    Tb2WifiPsk = 2U,
    Tb2WifiSecurity = 4U,
    Tb2WifiPriority = 8U,
    Tb2WifiLastUsed = 16U,
};

typedef enum {
    Tb2WifiKeep,
    Tb2WifiUpdate,
    Tb2WifiAdd,
    Tb2WifiDelete,
} Tb2WifiOperation;

typedef struct {
    uint8_t present;
    bool any;
    char ssid[TB2_WIFI_SSID_SIZE];
    char psk[TB2_WIFI_PSK_SIZE];
    uint8_t security;
    uint8_t priority;
    uint16_t last_used;
} Tb2WifiSnapshot;

typedef struct {
    Tb2ServerValues servers;
    uint8_t server_present;
    Tb2WifiSnapshot wifi[TB2_WIFI_PROFILE_COUNT];
    bool region_present, lifecycle_present, offline_present, log_level_present;
    uint8_t region, lifecycle, offline, log_level;
} Tb2SettingsSnapshot;

typedef struct {
    Tb2WifiOperation operation;
    uint8_t fields;
    char ssid[TB2_WIFI_SSID_SIZE];
    char psk[TB2_WIFI_PSK_SIZE];
    uint8_t security;
    uint8_t priority;
} Tb2WifiChange;

typedef struct {
    uint8_t categories;
    uint8_t server_fields;
    char ota_host[TB2_SERVER_HOST_SIZE];
    char ici_host[TB2_SERVER_HOST_SIZE];
    uint16_t ota_port, ici_port;
    bool region_set;
    uint8_t region;
    Tb2WifiChange wifi[TB2_WIFI_PROFILE_COUNT];
    uint8_t device_fields;
    uint8_t lifecycle, offline, log_level;
} Tb2SettingsPatch;

enum {
    Tb2DeviceLifecycle = 1U,
    Tb2DeviceOffline = 2U,
    Tb2DeviceLogLevel = 4U,
};

/** Validates values independent of a particular image. Snapshot-dependent
 * constraints such as Add-on-empty and non-deletable profile 0 are checked by
 * the transform before any output is emitted. */
bool tb2_settings_patch_valid(const Tb2SettingsPatch* patch);

/** Read-only strict scan used by keyless inspection. Keeping this entry point
 * separate lets the Store module omit all patch/write code. */
int tb2_settings_scan(const Tb2SettingsIO* io, Tb2SettingsSnapshot* snapshot);

/** Strict two-pass transform of u16le-length framed key=value records.
 * Duplicate keys are accepted with last-record-wins semantics. Untouched
 * frames are copied byte-for-byte; changed keys are emitted once at the end.
 * A NULL patch performs read-only inspection and never calls write(). */
int tb2_settings_transform(
    const Tb2SettingsIO* io,
    const Tb2SettingsPatch* patch,
    Tb2SettingsSnapshot* snapshot,
    bool* changed);

/** Translates the legacy common-host job field into the new independent-host
 * patch without changing the persisted job.tb2 representation. */
bool tb2_settings_from_server(const Tb2ServerChange* server, Tb2SettingsPatch* patch);
bool tb2_settings_patch_encode(const Tb2SettingsPatch*, uint8_t bytes[TB2_SETTINGS_PATCH_BYTES]);
bool tb2_settings_patch_decode(const uint8_t bytes[TB2_SETTINGS_PATCH_BYTES], Tb2SettingsPatch*);
