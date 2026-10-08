#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB2_SERVER_HOST_SIZE 64U
#define TB2_SETTINGS_MAX     65535U
#define TB2_SERVER_HOST      1U
#define TB2_SERVER_HTTPS     2U
#define TB2_SERVER_MQTT      4U
#define TB2_SERVER_FIELDS    7U

/** Byte-only representation; encode ports explicitly, never serialize uint16_t. */
typedef struct {
    char host[TB2_SERVER_HOST_SIZE];
    uint8_t ports[4];
    uint8_t fields;
} Tb2ServerChange;

typedef struct {
    char https_host[TB2_SERVER_HOST_SIZE];
    char mqtt_host[TB2_SERVER_HOST_SIZE];
    uint16_t https_port, mqtt_port;
} Tb2ServerValues;

/** Exact original field values, including separate hostnames and port spelling.
 * Only these four records may be restored; no unrelated settings are retained. */
typedef struct {
    char values[4][TB2_SERVER_HOST_SIZE];
} Tb2ServerRecords;

typedef struct {
    void* context;
    uint32_t size;
    bool (*read)(void* context, uint32_t offset, void* bytes, size_t size);
    /* Optional sequential sink. NULL means read-only preview. */
    bool (*write)(void* context, const void* bytes, size_t size);
    bool (*cancelled)(void* context);
} Tb2SettingsIO;

bool tb2_server_host_valid(const char* host);
uint16_t tb2_server_port(const Tb2ServerChange* change, bool mqtt);
void tb2_server_set_port(Tb2ServerChange* change, bool mqtt, uint16_t port);
bool tb2_server_change_valid(const Tb2ServerChange* change);

/** Strict bounded two-pass codec. Only four exact keys are interpreted. Unknown
 * records, including binary values, are copied byte for byte. All framing and
 * duplicate/missing fields are checked before any output is written. The caller
 * must not call this function at all for the Keep workflow. */
int tb2_server_transform(
    const Tb2SettingsIO* io,
    const Tb2ServerChange* change,
    Tb2ServerValues* original,
    bool* changed);
int tb2_server_records_read(const Tb2SettingsIO*, Tb2ServerRecords*);
int tb2_server_restore(const Tb2SettingsIO*, const Tb2ServerRecords*, bool* changed);
