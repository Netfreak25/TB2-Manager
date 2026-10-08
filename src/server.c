#include "server.h"
#include "probe.h"
#include <stdio.h>
#include <string.h>

#define SETTINGS_COPY_SIZE 256U
static const char* const setting_keys[] = {"ota/host=", "ota/port=", "ici/host=", "ici/port="};

bool tb2_server_host_valid(const char* host) {
    if(!host) return false;
    size_t length = 0, label = 0;
    unsigned dots = 0;
    bool digits_only = true;
    for(; length < TB2_SERVER_HOST_SIZE && host[length]; length++) {
        unsigned char c = (unsigned char)host[length];
        if(c == '.') {
            if(!label || host[length - 1] == '-') return false;
            label = 0;
            dots++;
        } else {
            if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '-'))
                return false;
            if(!label && c == '-') return false;
            if(++label > 63) return false;
            if(c < '0' || c > '9') digits_only = false;
        }
    }
    return length && length < TB2_SERVER_HOST_SIZE && label && host[length - 1] != '-' &&
           !(digits_only && dots == 3);
}

uint16_t tb2_server_port(const Tb2ServerChange* change, bool mqtt) {
    unsigned i = mqtt ? 2 : 0;
    return (uint16_t)(change->ports[i] | (uint16_t)change->ports[i + 1] << 8);
}

void tb2_server_set_port(Tb2ServerChange* change, bool mqtt, uint16_t port) {
    unsigned i = mqtt ? 2 : 0;
    change->ports[i] = (uint8_t)port;
    change->ports[i + 1] = (uint8_t)(port >> 8);
}

bool tb2_server_change_valid(const Tb2ServerChange* change) {
    return change && !(change->fields & ~TB2_SERVER_FIELDS) &&
           memchr(change->host, 0, sizeof(change->host)) &&
           (!(change->fields & TB2_SERVER_HOST) || tb2_server_host_valid(change->host)) &&
           (!(change->fields & TB2_SERVER_HTTPS) || tb2_server_port(change, false)) &&
           (!(change->fields & TB2_SERVER_MQTT) || tb2_server_port(change, true));
}

static int boundary(const Tb2SettingsIO* io) {
    return io->cancelled && io->cancelled(io->context) ? TB2_PROBE_CANCELLED : 0;
}

static int record(
    const Tb2SettingsIO* io,
    uint32_t offset,
    uint16_t* length,
    int* field,
    char value[TB2_SERVER_HOST_SIZE]) {
    uint8_t bytes[TB2_SERVER_HOST_SIZE + 10U];
    if(offset > io->size || io->size - offset < 2) return TB2_PROBE_CHECK_FAILED;
    if(!io->read(io->context, offset, bytes, 2)) return TB2_PROBE_IO_ERROR;
    *length = (uint16_t)(bytes[0] | (uint16_t)bytes[1] << 8);
    if(!*length || *length > io->size - offset - 2) return TB2_PROBE_CHECK_FAILED;
    size_t n = *length < sizeof(bytes) ? *length : sizeof(bytes);
    if(!io->read(io->context, offset + 2, bytes, n)) return TB2_PROBE_IO_ERROR;
    *field = -1;
    for(unsigned i = 0; i < 4; i++) {
        size_t prefix = strlen(setting_keys[i]);
        if(n < prefix || memcmp(bytes, setting_keys[i], prefix)) continue;
        size_t size = *length - prefix;
        if(!size || size >= TB2_SERVER_HOST_SIZE || prefix + size > n)
            return TB2_PROBE_CHECK_FAILED;
        for(size_t j = 0; j < size; j++)
            if(bytes[prefix + j] < 33 || bytes[prefix + j] >= 127) return TB2_PROBE_CHECK_FAILED;
        memcpy(value, bytes + prefix, size);
        value[size] = 0;
        *field = (int)i;
        break;
    }
    return 0;
}

static bool parse_port(const char* text, uint16_t* port) {
    uint32_t value = 0;
    for(const char* p = text; *p; p++) {
        if(*p < '0' || *p > '9') return false;
        value = value * 10U + (unsigned)(*p - '0');
        if(value > UINT16_MAX) return false;
    }
    *port = (uint16_t)value;
    return value != 0;
}

static int copy_record(const Tb2SettingsIO* io, uint32_t offset, uint32_t size) {
    uint8_t bytes[SETTINGS_COPY_SIZE];
    while(size) {
        int rc = boundary(io);
        if(rc) return rc;
        size_t n = size < sizeof(bytes) ? size : sizeof(bytes);
        if(!io->read(io->context, offset, bytes, n) || !io->write(io->context, bytes, n))
            return TB2_PROBE_IO_ERROR;
        offset += (uint32_t)n;
        size -= (uint32_t)n;
    }
    return 0;
}

static int transform(
    const Tb2SettingsIO* io,
    const Tb2ServerChange* change,
    const Tb2ServerRecords* restore,
    Tb2ServerValues* original,
    bool* changed) {
    if(!io || !io->read || !original || !changed ||
       (!restore && !tb2_server_change_valid(change)) || !io->size || io->size > TB2_SETTINGS_MAX)
        return TB2_PROBE_CHECK_FAILED;
    memset(original, 0, sizeof(*original));
    *changed = false;
    unsigned seen = 0;
    for(uint32_t offset = 0; offset < io->size;) {
        uint16_t size = 0;
        int field = -1, rc = boundary(io);
        char value[TB2_SERVER_HOST_SIZE];
        if(!rc) rc = record(io, offset, &size, &field, value);
        if(rc) return rc;
        if(field >= 0) {
            if(seen & (1U << field)) return TB2_PROBE_CHECK_FAILED;
            seen |= 1U << field;
            if(field == 0 || field == 2)
                memcpy(
                    field == 0 ? original->https_host : original->mqtt_host,
                    value,
                    strlen(value) + 1);
            else if(!parse_port(value, field == 1 ? &original->https_port : &original->mqtt_port))
                return TB2_PROBE_CHECK_FAILED;
        }
        offset += 2U + size;
    }
    if(seen != 15U) return TB2_PROBE_CHECK_FAILED;
    for(uint32_t offset = 0; offset < io->size;) {
        uint16_t size = 0;
        int field = -1, rc = boundary(io);
        char value[TB2_SERVER_HOST_SIZE], replacement[TB2_SERVER_HOST_SIZE];
        if(!rc) rc = record(io, offset, &size, &field, value);
        if(rc) return rc;
        replacement[0] = 0;
        if(restore && field >= 0)
            memcpy(replacement, restore->values[field], strlen(restore->values[field]) + 1);
        if(change && (field == 0 || field == 2) && (change->fields & TB2_SERVER_HOST))
            memcpy(replacement, change->host, strlen(change->host) + 1);
        if(change && ((field == 1 && (change->fields & TB2_SERVER_HTTPS)) ||
                      (field == 3 && (change->fields & TB2_SERVER_MQTT)))) {
            uint16_t existing = field == 1 ? original->https_port : original->mqtt_port;
            uint16_t desired = tb2_server_port(change, field == 3);
            if(existing != desired) snprintf(replacement, sizeof(replacement), "%u", desired);
        }
        bool replace = replacement[0] && strcmp(replacement, value);
        *changed |= replace;
        if(io->write) {
            if(replace) {
                size_t prefix = strlen(setting_keys[field]);
                size_t length = prefix + strlen(replacement);
                uint8_t frame[2] = {(uint8_t)length, (uint8_t)(length >> 8)};
                if(!io->write(io->context, frame, 2) ||
                   !io->write(io->context, setting_keys[field], prefix) ||
                   !io->write(io->context, replacement, strlen(replacement)))
                    return TB2_PROBE_IO_ERROR;
            } else {
                rc = copy_record(io, offset, 2U + size);
                if(rc) return rc;
            }
        }
        offset += 2U + size;
    }
    return 0;
}
int tb2_server_transform(
    const Tb2SettingsIO* io,
    const Tb2ServerChange* change,
    Tb2ServerValues* original,
    bool* changed) {
    return transform(io, change, NULL, original, changed);
}
int tb2_server_records_read(const Tb2SettingsIO* io, Tb2ServerRecords* values) {
    if(!io || !values) return TB2_PROBE_CHECK_FAILED;
    memset(values, 0, sizeof(*values));
    Tb2SettingsIO read_only = *io;
    read_only.write = NULL;
    Tb2ServerChange keep = {0};
    Tb2ServerValues parsed;
    bool changed;
    int rc = transform(&read_only, &keep, NULL, &parsed, &changed);
    unsigned seen = 0;
    for(uint32_t offset = 0; !rc && offset < io->size;) {
        uint16_t size = 0;
        int field = -1;
        char value[TB2_SERVER_HOST_SIZE];
        rc = boundary(io);
        if(!rc) rc = record(io, offset, &size, &field, value);
        if(!rc && field >= 0) {
            if(seen & (1U << field)) rc = TB2_PROBE_CHECK_FAILED;
            seen |= 1U << field;
            strcpy(values->values[field], value);
        }
        offset += 2U + size;
    }
    if(!rc && seen != 15U) rc = TB2_PROBE_CHECK_FAILED;
    if(rc) memset(values, 0, sizeof(*values));
    return rc;
}
int tb2_server_restore(const Tb2SettingsIO* io, const Tb2ServerRecords* values, bool* changed) {
    if(!values) return TB2_PROBE_CHECK_FAILED;
    for(unsigned i = 0; i < 4; i++) {
        const char* value = values->values[i];
        if(!value[0] || !memchr(value, 0, TB2_SERVER_HOST_SIZE)) return TB2_PROBE_CHECK_FAILED;
        for(const char* p = value; *p; p++)
            if((unsigned char)*p < 33 || (unsigned char)*p >= 127) return TB2_PROBE_CHECK_FAILED;
        uint16_t port;
        if((i & 1U) && !parse_port(value, &port)) return TB2_PROBE_CHECK_FAILED;
    }
    Tb2ServerValues original;
    return transform(io, NULL, values, &original, changed);
}
