#include "settings.h"
#include "probe.h"
#include <stdio.h>
#include <string.h>

#define SETTINGS_COPY_SIZE 128U
#define SETTINGS_KEY_SIZE  64U

static const char key_ota_host[] = "ota/host";
static const char key_ota_port[] = "ota/port";
static const char key_ici_host[] = "ici/host";
static const char key_ici_port[] = "ici/port";
static const char key_region[] = "wifi/region";
static const char key_lifecycle[] = "toniebox/lifecycle_state";
static const char key_offline[] = "app/offline_mode";
static const char key_log_level[] = "log_backend_ici/default_level";

typedef enum {
    FieldUnknown,
    FieldOtaHost,
    FieldOtaPort,
    FieldIciHost,
    FieldIciPort,
    FieldRegion,
    FieldWifiSsid,
    FieldWifiPsk,
    FieldWifiSecurity,
    FieldWifiPriority,
    FieldWifiLastUsed,
    FieldLifecycle,
    FieldOffline,
    FieldLogLevel,
} SettingField;

typedef struct {
    uint32_t offset;
    uint16_t length, key_length, value_length;
    SettingField field;
    uint8_t profile;
    bool profile_key;
    char key[SETTINGS_KEY_SIZE];
} SettingRecord;

static int boundary(const Tb2SettingsIO* io) {
    return io->cancelled && io->cancelled(io->context) ? TB2_PROBE_CANCELLED : 0;
}

static bool read_exact(const Tb2SettingsIO* io, uint32_t offset, void* bytes, size_t size) {
    return offset <= io->size && size <= io->size - offset &&
           io->read(io->context, offset, bytes, size);
}

static bool printable(const char* value, size_t size, bool allow_empty) {
    if(!allow_empty && !size) return false;
    for(size_t i = 0; i < size; i++)
        if((unsigned char)value[i] < 32 || (unsigned char)value[i] > 126) return false;
    return true;
}

static bool psk_valid(const char* value) {
    size_t size = 0;
    while(size < TB2_WIFI_PSK_SIZE && value[size])
        size++;
    if(size >= TB2_WIFI_PSK_SIZE || !printable(value, size, false)) return false;
    if(size >= 8 && size <= 63) return true;
    if(size != 64) return false;
    for(size_t i = 0; i < size; i++)
        if(!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f') ||
             (value[i] >= 'A' && value[i] <= 'F')))
            return false;
    return true;
}

static bool security_valid(uint8_t value) {
    return value == 0 || value == 1 || value == 3 || value == 9;
}

static bool wifi_prefix(const char* key, uint8_t* profile, const char** suffix) {
    static const char prefix[] = "wifi/profile/";
    if(strncmp(key, prefix, sizeof(prefix) - 1)) return false;
    const char* p = key + sizeof(prefix) - 1;
    if(p[0] < '0' || p[0] > '9' || p[1] != '/') return false;
    *profile = (uint8_t)(p[0] - '0');
    *suffix = p + 2;
    return true;
}

static SettingField classify(const char* key, uint8_t* profile) {
    if(!strcmp(key, key_ota_host)) return FieldOtaHost;
    if(!strcmp(key, key_ota_port)) return FieldOtaPort;
    if(!strcmp(key, key_ici_host)) return FieldIciHost;
    if(!strcmp(key, key_ici_port)) return FieldIciPort;
    if(!strcmp(key, key_region)) return FieldRegion;
    if(!strcmp(key, key_lifecycle)) return FieldLifecycle;
    if(!strcmp(key, key_offline)) return FieldOffline;
    if(!strcmp(key, key_log_level)) return FieldLogLevel;
    const char* suffix = NULL;
    if(!wifi_prefix(key, profile, &suffix)) return FieldUnknown;
    if(!strcmp(suffix, "ssid")) return FieldWifiSsid;
    if(!strcmp(suffix, "psk")) return FieldWifiPsk;
    if(!strcmp(suffix, "security")) return FieldWifiSecurity;
    if(!strcmp(suffix, "priority")) return FieldWifiPriority;
    if(!strcmp(suffix, "last_used")) return FieldWifiLastUsed;
    return FieldUnknown;
}

static int parse_record(const Tb2SettingsIO* io, uint32_t offset, SettingRecord* record) {
    uint8_t frame[2];
    memset(record, 0, sizeof(*record));
    record->offset = offset;
    if(!read_exact(io, offset, frame, sizeof(frame))) return TB2_PROBE_CHECK_FAILED;
    record->length = (uint16_t)(frame[0] | (uint16_t)frame[1] << 8);
    if(!record->length || record->length > io->size - offset - 2U) return TB2_PROBE_CHECK_FAILED;
    bool equals = false, key_fits = true;
    uint8_t bytes[SETTINGS_COPY_SIZE];
    uint32_t cursor = 0;
    while(cursor < record->length) {
        size_t count = record->length - cursor;
        if(count > sizeof(bytes)) count = sizeof(bytes);
        if(!read_exact(io, offset + 2U + cursor, bytes, count)) return TB2_PROBE_IO_ERROR;
        for(size_t i = 0; i < count; i++) {
            uint8_t value = bytes[i];
            if(!equals) {
                if(value == '=') {
                    if(!cursor && !i) return TB2_PROBE_CHECK_FAILED;
                    equals = true;
                    record->key_length = (uint16_t)(cursor + i);
                    continue;
                }
                if(value < 33 || value > 126) return TB2_PROBE_CHECK_FAILED;
                size_t at = cursor + i;
                if(at + 1 < sizeof(record->key))
                    record->key[at] = (char)value;
                else
                    key_fits = false;
            }
        }
        cursor += (uint32_t)count;
    }
    if(!equals || record->key_length + 1U > record->length) return TB2_PROBE_CHECK_FAILED;
    record->value_length = (uint16_t)(record->length - record->key_length - 1U);
    if(key_fits) {
        record->key[record->key_length] = 0;
        const char* suffix = NULL;
        record->profile_key = wifi_prefix(record->key, &record->profile, &suffix);
        record->field = classify(record->key, &record->profile);
    }
    return 0;
}

static int
    read_value(const Tb2SettingsIO* io, const SettingRecord* record, void* value, size_t capacity) {
    if(record->value_length > capacity) return TB2_PROBE_CHECK_FAILED;
    return read_exact(
               io, record->offset + 2U + record->key_length + 1U, value, record->value_length) ?
               0 :
               TB2_PROBE_IO_ERROR;
}

static bool parse_port(const char* text, size_t length, uint16_t* result) {
    if(!length || length > 5) return false;
    uint32_t value = 0;
    for(size_t i = 0; i < length; i++) {
        if(text[i] < '0' || text[i] > '9') return false;
        value = value * 10U + (uint32_t)(text[i] - '0');
    }
    if(!value || value > UINT16_MAX) return false;
    *result = (uint16_t)value;
    return true;
}

static int snapshot_record(
    const Tb2SettingsIO* io,
    const SettingRecord* record,
    Tb2SettingsSnapshot* snapshot) {
    char text[TB2_WIFI_PSK_SIZE] = {0};
    uint8_t binary[2] = {0};
    int rc = 0;
    if(record->field >= FieldWifiSsid && record->field <= FieldWifiLastUsed)
        snapshot->wifi[record->profile].any = true;
    switch(record->field) {
    case FieldOtaHost:
    case FieldIciHost:
        if(!record->value_length || record->value_length >= TB2_SERVER_HOST_SIZE)
            return TB2_PROBE_CHECK_FAILED;
        rc = read_value(io, record, text, sizeof(text) - 1);
        if(!rc && (!printable(text, record->value_length, false) || !tb2_server_host_valid(text)))
            rc = TB2_PROBE_CHECK_FAILED;
        if(!rc) {
            strcpy(
                record->field == FieldOtaHost ? snapshot->servers.https_host :
                                                snapshot->servers.mqtt_host,
                text);
            snapshot->server_present |= record->field == FieldOtaHost ? Tb2ServerOtaHost :
                                                                        Tb2ServerIciHost;
        }
        break;
    case FieldOtaPort:
    case FieldIciPort: {
        if(!record->value_length || record->value_length >= sizeof(text))
            return TB2_PROBE_CHECK_FAILED;
        rc = read_value(io, record, text, sizeof(text) - 1);
        uint16_t port = 0;
        if(!rc && !parse_port(text, record->value_length, &port)) rc = TB2_PROBE_CHECK_FAILED;
        if(!rc) {
            if(record->field == FieldOtaPort)
                snapshot->servers.https_port = port;
            else
                snapshot->servers.mqtt_port = port;
            snapshot->server_present |= record->field == FieldOtaPort ? Tb2ServerOtaPort :
                                                                        Tb2ServerIciPort;
        }
        break;
    }
    case FieldRegion:
        if(record->value_length != 1 || read_value(io, record, binary, 1) ||
           (binary[0] != '0' && binary[0] != '1'))
            return TB2_PROBE_CHECK_FAILED;
        snapshot->region = (uint8_t)(binary[0] - '0');
        snapshot->region_present = true;
        break;
    case FieldWifiSsid:
    case FieldWifiPsk: {
        size_t capacity = record->field == FieldWifiSsid ? TB2_WIFI_SSID_SIZE : TB2_WIFI_PSK_SIZE;
        if(!record->value_length || record->value_length >= capacity ||
           read_value(io, record, text, capacity - 1) ||
           !printable(text, record->value_length, false))
            return TB2_PROBE_CHECK_FAILED;
        strcpy(
            record->field == FieldWifiSsid ? snapshot->wifi[record->profile].ssid :
                                             snapshot->wifi[record->profile].psk,
            text);
        snapshot->wifi[record->profile].present |= record->field == FieldWifiSsid ? Tb2WifiSsid :
                                                                                    Tb2WifiPsk;
        break;
    }
    case FieldWifiSecurity:
        if(record->value_length != 1 || read_value(io, record, binary, 1) || binary[0] < '0' ||
           binary[0] > '9' || !security_valid(binary[0] - '0'))
            return TB2_PROBE_CHECK_FAILED;
        snapshot->wifi[record->profile].security = (uint8_t)(binary[0] - '0');
        snapshot->wifi[record->profile].present |= Tb2WifiSecurity;
        break;
    case FieldWifiPriority:
        if(record->value_length != 1 || read_value(io, record, binary, 1))
            return TB2_PROBE_CHECK_FAILED;
        snapshot->wifi[record->profile].priority = binary[0];
        snapshot->wifi[record->profile].present |= Tb2WifiPriority;
        break;
    case FieldWifiLastUsed:
        if(record->value_length != 2 || read_value(io, record, binary, 2))
            return TB2_PROBE_CHECK_FAILED;
        snapshot->wifi[record->profile].last_used =
            (uint16_t)(binary[0] | (uint16_t)binary[1] << 8);
        snapshot->wifi[record->profile].present |= Tb2WifiLastUsed;
        break;
    case FieldLifecycle:
    case FieldOffline:
    case FieldLogLevel:
        if(record->value_length != 1 || read_value(io, record, binary, 1))
            return TB2_PROBE_CHECK_FAILED;
        if(record->field == FieldLifecycle) {
            if(binary[0] > 8) return TB2_PROBE_CHECK_FAILED;
            snapshot->lifecycle = binary[0];
            snapshot->lifecycle_present = true;
        } else if(record->field == FieldOffline) {
            if(binary[0] > 1) return TB2_PROBE_CHECK_FAILED;
            snapshot->offline = binary[0];
            snapshot->offline_present = true;
        } else {
            if(binary[0] > 4) return TB2_PROBE_CHECK_FAILED;
            snapshot->log_level = binary[0];
            snapshot->log_level_present = true;
        }
        break;
    default:
        break;
    }
    return rc;
}

int tb2_settings_scan(const Tb2SettingsIO* io, Tb2SettingsSnapshot* snapshot) {
    if(!io || !io->read || !snapshot || !io->size || io->size > TB2_SETTINGS_MAX)
        return TB2_PROBE_CHECK_FAILED;
    memset(snapshot, 0, sizeof(*snapshot));
    for(uint32_t offset = 0; offset < io->size;) {
        int rc = boundary(io);
        SettingRecord record = {0};
        if(!rc) rc = parse_record(io, offset, &record);
        if(!rc) rc = snapshot_record(io, &record, snapshot);
        if(rc) return rc;
        offset += 2U + record.length;
    }
    return 0;
}

bool tb2_settings_patch_valid(const Tb2SettingsPatch* patch) {
    if(!patch || !patch->categories ||
       (patch->categories & ~(Tb2SettingsHosts | Tb2SettingsWifi | Tb2SettingsDevice)) ||
       (patch->server_fields & 0xf0U) || (patch->device_fields & 0xf8U))
        return false;
    if((patch->server_fields & Tb2ServerOtaHost) && !tb2_server_host_valid(patch->ota_host))
        return false;
    if((patch->server_fields & Tb2ServerIciHost) && !tb2_server_host_valid(patch->ici_host))
        return false;
    if((patch->server_fields & Tb2ServerOtaPort) && !patch->ota_port) return false;
    if((patch->server_fields & Tb2ServerIciPort) && !patch->ici_port) return false;
    if(patch->region_set && patch->region > 1) return false;
    if((patch->device_fields & Tb2DeviceLifecycle) &&
       (patch->lifecycle < 1 || patch->lifecycle > 8))
        return false;
    if((patch->device_fields & Tb2DeviceOffline) && patch->offline > 1) return false;
    if((patch->device_fields & Tb2DeviceLogLevel) && patch->log_level > 4) return false;
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++) {
        const Tb2WifiChange* wifi = &patch->wifi[i];
        if(wifi->operation > Tb2WifiDelete || (wifi->fields & 0xe0U) ||
           (i == 0 && wifi->operation == Tb2WifiDelete))
            return false;
        if(wifi->operation == Tb2WifiKeep && wifi->fields) return false;
        if((wifi->fields & Tb2WifiSsid) && (!memchr(wifi->ssid, 0, sizeof(wifi->ssid)) ||
                                            !printable(wifi->ssid, strlen(wifi->ssid), false)))
            return false;
        if((wifi->fields & Tb2WifiPsk) && wifi->psk[0] && !psk_valid(wifi->psk)) return false;
        if((wifi->fields & Tb2WifiSecurity) && !security_valid(wifi->security)) return false;
        if(wifi->operation == Tb2WifiAdd &&
           ((wifi->fields & (Tb2WifiSsid | Tb2WifiSecurity | Tb2WifiPriority)) !=
            (Tb2WifiSsid | Tb2WifiSecurity | Tb2WifiPriority)))
            return false;
    }
    return true;
}

static bool text_diff(bool present, const char* existing, const char* wanted) {
    return !present || strcmp(existing, wanted);
}

static bool field_changed(
    const Tb2SettingsSnapshot* s,
    const Tb2SettingsPatch* p,
    SettingField field,
    uint8_t profile) {
    switch(field) {
    case FieldOtaHost:
        return (p->server_fields & Tb2ServerOtaHost) &&
               text_diff(s->server_present & Tb2ServerOtaHost, s->servers.https_host, p->ota_host);
    case FieldOtaPort:
        return (p->server_fields & Tb2ServerOtaPort) &&
               (!(s->server_present & Tb2ServerOtaPort) || s->servers.https_port != p->ota_port);
    case FieldIciHost:
        return (p->server_fields & Tb2ServerIciHost) &&
               text_diff(s->server_present & Tb2ServerIciHost, s->servers.mqtt_host, p->ici_host);
    case FieldIciPort:
        return (p->server_fields & Tb2ServerIciPort) &&
               (!(s->server_present & Tb2ServerIciPort) || s->servers.mqtt_port != p->ici_port);
    case FieldRegion:
        return p->region_set && (!s->region_present || s->region != p->region);
    case FieldLifecycle:
        return (p->device_fields & Tb2DeviceLifecycle) &&
               (!s->lifecycle_present || s->lifecycle != p->lifecycle);
    case FieldOffline:
        return (p->device_fields & Tb2DeviceOffline) &&
               (!s->offline_present || s->offline != p->offline);
    case FieldLogLevel:
        return (p->device_fields & Tb2DeviceLogLevel) &&
               (!s->log_level_present || s->log_level != p->log_level);
    case FieldWifiSsid:
    case FieldWifiPsk:
    case FieldWifiSecurity:
    case FieldWifiPriority:
    case FieldWifiLastUsed: {
        const Tb2WifiChange* change = &p->wifi[profile];
        const Tb2WifiSnapshot* old = &s->wifi[profile];
        if(change->operation == Tb2WifiDelete) return old->any;
        if(change->operation == Tb2WifiKeep) return false;
        uint8_t flag = field == FieldWifiSsid     ? Tb2WifiSsid :
                       field == FieldWifiPsk      ? Tb2WifiPsk :
                       field == FieldWifiSecurity ? Tb2WifiSecurity :
                       field == FieldWifiPriority ? Tb2WifiPriority :
                                                    Tb2WifiLastUsed;
        bool requested = (change->fields & flag) ||
                         (field == FieldWifiPsk && (change->fields & Tb2WifiSecurity) &&
                          change->security == 0) ||
                         (field == FieldWifiLastUsed && change->operation == Tb2WifiAdd);
        if(!requested) return false;
        if(field == FieldWifiPsk && (!change->psk[0] || change->security == 0))
            return (old->present & Tb2WifiPsk) != 0;
        if(field == FieldWifiSsid) return text_diff(old->present & flag, old->ssid, change->ssid);
        if(field == FieldWifiPsk) return text_diff(old->present & flag, old->psk, change->psk);
        if(field == FieldWifiSecurity)
            return !(old->present & flag) || old->security != change->security;
        if(field == FieldWifiPriority)
            return !(old->present & flag) || old->priority != change->priority;
        return !(old->present & flag) || old->last_used != 0;
    }
    default:
        return false;
    }
}

static bool any_change(const Tb2SettingsSnapshot* s, const Tb2SettingsPatch* p) {
    const SettingField scalars[] = {
        FieldOtaHost,
        FieldOtaPort,
        FieldIciHost,
        FieldIciPort,
        FieldRegion,
        FieldLifecycle,
        FieldOffline,
        FieldLogLevel};
    for(unsigned i = 0; i < sizeof(scalars) / sizeof(*scalars); i++)
        if(field_changed(s, p, scalars[i], 0)) return true;
    for(unsigned profile = 0; profile < TB2_WIFI_PROFILE_COUNT; profile++)
        for(SettingField field = FieldWifiSsid; field <= FieldWifiLastUsed; field++)
            if(field_changed(s, p, field, (uint8_t)profile)) return true;
    return false;
}

static bool omit_record(
    const Tb2SettingsSnapshot* s,
    const Tb2SettingsPatch* p,
    const SettingRecord* record) {
    if(record->profile_key && p->wifi[record->profile].operation == Tb2WifiDelete) return true;
    return field_changed(s, p, record->field, record->profile);
}

static int copy_record(const Tb2SettingsIO* io, uint32_t offset, uint32_t size) {
    uint8_t bytes[SETTINGS_COPY_SIZE];
    while(size) {
        int rc = boundary(io);
        if(rc) return rc;
        size_t count = size < sizeof(bytes) ? size : sizeof(bytes);
        if(!read_exact(io, offset, bytes, count) || !io->write(io->context, bytes, count))
            return TB2_PROBE_IO_ERROR;
        offset += (uint32_t)count;
        size -= (uint32_t)count;
    }
    return 0;
}

static int emit(const Tb2SettingsIO* io, const char* key, const void* value, size_t size) {
    size_t key_size = strlen(key);
    size_t length = key_size + 1U + size;
    if(length > UINT16_MAX) return TB2_PROBE_CHECK_FAILED;
    uint8_t frame[2] = {(uint8_t)length, (uint8_t)(length >> 8)};
    static const char equals = '=';
    return io->write(io->context, frame, sizeof(frame)) && io->write(io->context, key, key_size) &&
                   io->write(io->context, &equals, 1) &&
                   (!size || io->write(io->context, value, size)) ?
               0 :
               TB2_PROBE_IO_ERROR;
}

static int emit_text(const Tb2SettingsIO* io, const char* key, const char* value) {
    return emit(io, key, value, strlen(value));
}

static int emit_port(const Tb2SettingsIO* io, const char* key, uint16_t value) {
    char text[6];
    snprintf(text, sizeof(text), "%u", value);
    return emit_text(io, key, text);
}

static int emit_wifi(
    const Tb2SettingsIO* io,
    const Tb2SettingsSnapshot* s,
    const Tb2SettingsPatch* p,
    uint8_t profile) {
    const Tb2WifiChange* change = &p->wifi[profile];
    if(change->operation == Tb2WifiKeep || change->operation == Tb2WifiDelete) return 0;
    char key[40];
#define EMIT_WIFI(field_name, data, data_size)                              \
    do {                                                                    \
        snprintf(key, sizeof(key), "wifi/profile/%u/" field_name, profile); \
        int emit_rc = emit(io, key, data, data_size);                       \
        if(emit_rc) return emit_rc;                                         \
    } while(false)
    if(field_changed(s, p, FieldWifiSsid, profile))
        EMIT_WIFI("ssid", change->ssid, strlen(change->ssid));
    if(field_changed(s, p, FieldWifiPsk, profile) && change->psk[0] && change->security != 0)
        EMIT_WIFI("psk", change->psk, strlen(change->psk));
    if(field_changed(s, p, FieldWifiSecurity, profile)) {
        char value = (char)('0' + change->security);
        EMIT_WIFI("security", &value, 1);
    }
    if(field_changed(s, p, FieldWifiPriority, profile))
        EMIT_WIFI("priority", &change->priority, 1);
    if(field_changed(s, p, FieldWifiLastUsed, profile)) {
        static const uint8_t zero[2] = {0};
        EMIT_WIFI("last_used", zero, sizeof(zero));
    }
#undef EMIT_WIFI
    return 0;
}

static int
    emit_changes(const Tb2SettingsIO* io, const Tb2SettingsSnapshot* s, const Tb2SettingsPatch* p) {
    int rc = 0;
    if(field_changed(s, p, FieldOtaHost, 0)) rc = emit_text(io, key_ota_host, p->ota_host);
    if(!rc && field_changed(s, p, FieldOtaPort, 0)) rc = emit_port(io, key_ota_port, p->ota_port);
    if(!rc && field_changed(s, p, FieldIciHost, 0)) rc = emit_text(io, key_ici_host, p->ici_host);
    if(!rc && field_changed(s, p, FieldIciPort, 0)) rc = emit_port(io, key_ici_port, p->ici_port);
    if(!rc && field_changed(s, p, FieldRegion, 0)) {
        char region = (char)('0' + p->region);
        rc = emit(io, key_region, &region, 1);
    }
    for(unsigned i = 0; !rc && i < TB2_WIFI_PROFILE_COUNT; i++)
        rc = emit_wifi(io, s, p, (uint8_t)i);
    if(!rc && field_changed(s, p, FieldLifecycle, 0))
        rc = emit(io, key_lifecycle, &p->lifecycle, 1);
    if(!rc && field_changed(s, p, FieldOffline, 0)) rc = emit(io, key_offline, &p->offline, 1);
    if(!rc && field_changed(s, p, FieldLogLevel, 0))
        rc = emit(io, key_log_level, &p->log_level, 1);
    return rc;
}

static int
    validate_against_snapshot(const Tb2SettingsSnapshot* snapshot, const Tb2SettingsPatch* patch) {
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++) {
        const Tb2WifiChange* change = &patch->wifi[i];
        const Tb2WifiSnapshot* old = &snapshot->wifi[i];
        if(change->operation == Tb2WifiAdd && old->any) return TB2_PROBE_CHECK_FAILED;
        if(change->operation == Tb2WifiDelete && (!i || !old->any)) return TB2_PROBE_CHECK_FAILED;
        if(change->operation == Tb2WifiUpdate && !old->any) return TB2_PROBE_CHECK_FAILED;
        uint8_t security = change->fields & Tb2WifiSecurity ? change->security : old->security;
        bool security_known = (change->fields & Tb2WifiSecurity) ||
                              (old->present & Tb2WifiSecurity);
        const char* psk = change->fields & Tb2WifiPsk ? change->psk : old->psk;
        bool psk_known = (change->fields & Tb2WifiPsk) || (old->present & Tb2WifiPsk);
        if(change->operation != Tb2WifiKeep && change->operation != Tb2WifiDelete) {
            if(!security_known || !security_valid(security)) return TB2_PROBE_CHECK_FAILED;
            if(security && (!psk_known || !psk_valid(psk))) return TB2_PROBE_CHECK_FAILED;
        }
    }
    return 0;
}

int tb2_settings_transform(
    const Tb2SettingsIO* io,
    const Tb2SettingsPatch* patch,
    Tb2SettingsSnapshot* snapshot,
    bool* changed) {
    if(!changed || (patch && !tb2_settings_patch_valid(patch))) return TB2_PROBE_CHECK_FAILED;
    *changed = false;
    int rc = tb2_settings_scan(io, snapshot);
    if(rc || !patch) return rc;
    rc = validate_against_snapshot(snapshot, patch);
    if(rc) return rc;
    *changed = any_change(snapshot, patch);
    if(!io->write) return 0;
    for(uint32_t offset = 0; !rc && offset < io->size;) {
        SettingRecord record = {0};
        rc = boundary(io);
        if(!rc) rc = parse_record(io, offset, &record);
        if(!rc && !omit_record(snapshot, patch, &record))
            rc = copy_record(io, offset, 2U + record.length);
        offset += 2U + record.length;
    }
    if(!rc) rc = emit_changes(io, snapshot, patch);
    return rc;
}

bool tb2_settings_from_server(const Tb2ServerChange* server, Tb2SettingsPatch* patch) {
    if(!server || !patch || !tb2_server_change_valid(server)) return false;
    memset(patch, 0, sizeof(*patch));
    if(!server->fields) return true;
    patch->categories = Tb2SettingsHosts;
    if(server->fields & TB2_SERVER_HOST) {
        patch->server_fields |= Tb2ServerOtaHost | Tb2ServerIciHost;
        strcpy(patch->ota_host, server->host);
        strcpy(patch->ici_host, server->host);
    }
    if(server->fields & TB2_SERVER_HTTPS) {
        patch->server_fields |= Tb2ServerOtaPort;
        patch->ota_port = tb2_server_port(server, false);
    }
    if(server->fields & TB2_SERVER_MQTT) {
        patch->server_fields |= Tb2ServerIciPort;
        patch->ici_port = tb2_server_port(server, true);
    }
    return tb2_settings_patch_valid(patch);
}

static void patch_put32(uint8_t* bytes, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        bytes[i] = (uint8_t)(value >> (8U * i));
}
static uint32_t patch_get32(const uint8_t* bytes) {
    uint32_t value = 0;
    for(unsigned i = 0; i < 4; i++)
        value |= (uint32_t)bytes[i] << (8U * i);
    return value;
}
static uint32_t patch_crc(const uint8_t* bytes, size_t size) {
    uint32_t crc = 0xffffffffU;
    while(size--) {
        crc ^= *bytes++;
        for(unsigned i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}
bool tb2_settings_patch_encode(
    const Tb2SettingsPatch* patch,
    uint8_t bytes[TB2_SETTINGS_PATCH_BYTES]) {
    if(!tb2_settings_patch_valid(patch) || !bytes) return false;
    memset(bytes, 0, TB2_SETTINGS_PATCH_BYTES);
    patch_put32(bytes, 0x38534254U);
    patch_put32(bytes + 4, 1U);
    patch_put32(bytes + 8, TB2_SETTINGS_PATCH_BYTES - 16U);
    size_t at = 16;
    bytes[at++] = patch->categories;
    bytes[at++] = patch->server_fields;
    bytes[at++] = patch->region_set;
    bytes[at++] = patch->region;
    bytes[at++] = patch->device_fields;
    bytes[at++] = patch->lifecycle;
    bytes[at++] = patch->offline;
    bytes[at++] = patch->log_level;
    memcpy(bytes + at, patch->ota_host, TB2_SERVER_HOST_SIZE);
    at += TB2_SERVER_HOST_SIZE;
    memcpy(bytes + at, patch->ici_host, TB2_SERVER_HOST_SIZE);
    at += TB2_SERVER_HOST_SIZE;
    bytes[at++] = (uint8_t)patch->ota_port;
    bytes[at++] = (uint8_t)(patch->ota_port >> 8);
    bytes[at++] = (uint8_t)patch->ici_port;
    bytes[at++] = (uint8_t)(patch->ici_port >> 8);
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++) {
        const Tb2WifiChange* wifi = &patch->wifi[i];
        bytes[at++] = wifi->operation;
        bytes[at++] = wifi->fields;
        bytes[at++] = wifi->security;
        bytes[at++] = wifi->priority;
        memcpy(bytes + at, wifi->ssid, TB2_WIFI_SSID_SIZE);
        at += TB2_WIFI_SSID_SIZE;
        memcpy(bytes + at, wifi->psk, TB2_WIFI_PSK_SIZE);
        at += TB2_WIFI_PSK_SIZE;
    }
    if(at != TB2_SETTINGS_PATCH_BYTES) return false;
    patch_put32(bytes + 12, patch_crc(bytes + 16, TB2_SETTINGS_PATCH_BYTES - 16U));
    return true;
}
bool tb2_settings_patch_decode(
    const uint8_t bytes[TB2_SETTINGS_PATCH_BYTES],
    Tb2SettingsPatch* patch) {
    if(!bytes || !patch || patch_get32(bytes) != 0x38534254U || patch_get32(bytes + 4) != 1U ||
       patch_get32(bytes + 8) != TB2_SETTINGS_PATCH_BYTES - 16U ||
       patch_get32(bytes + 12) != patch_crc(bytes + 16, TB2_SETTINGS_PATCH_BYTES - 16U))
        return false;
    memset(patch, 0, sizeof(*patch));
    size_t at = 16;
    patch->categories = bytes[at++];
    patch->server_fields = bytes[at++];
    patch->region_set = bytes[at++] != 0;
    patch->region = bytes[at++];
    patch->device_fields = bytes[at++];
    patch->lifecycle = bytes[at++];
    patch->offline = bytes[at++];
    patch->log_level = bytes[at++];
    memcpy(patch->ota_host, bytes + at, TB2_SERVER_HOST_SIZE);
    at += TB2_SERVER_HOST_SIZE;
    memcpy(patch->ici_host, bytes + at, TB2_SERVER_HOST_SIZE);
    at += TB2_SERVER_HOST_SIZE;
    patch->ota_port = (uint16_t)(bytes[at] | (uint16_t)bytes[at + 1] << 8);
    at += 2;
    patch->ici_port = (uint16_t)(bytes[at] | (uint16_t)bytes[at + 1] << 8);
    at += 2;
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++) {
        Tb2WifiChange* wifi = &patch->wifi[i];
        wifi->operation = (Tb2WifiOperation)bytes[at++];
        wifi->fields = bytes[at++];
        wifi->security = bytes[at++];
        wifi->priority = bytes[at++];
        memcpy(wifi->ssid, bytes + at, TB2_WIFI_SSID_SIZE);
        at += TB2_WIFI_SSID_SIZE;
        memcpy(wifi->psk, bytes + at, TB2_WIFI_PSK_SIZE);
        at += TB2_WIFI_PSK_SIZE;
    }
    if(at != TB2_SETTINGS_PATCH_BYTES || !memchr(patch->ota_host, 0, sizeof(patch->ota_host)) ||
       !memchr(patch->ici_host, 0, sizeof(patch->ici_host))) {
        memset(patch, 0, sizeof(*patch));
        return false;
    }
    for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++)
        if(!memchr(patch->wifi[i].ssid, 0, TB2_WIFI_SSID_SIZE) ||
           !memchr(patch->wifi[i].psk, 0, TB2_WIFI_PSK_SIZE)) {
            memset(patch, 0, sizeof(*patch));
            return false;
        }
    if(!tb2_settings_patch_valid(patch)) {
        memset(patch, 0, sizeof(*patch));
        return false;
    }
    return true;
}
