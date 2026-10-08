#include "identity.h"
#include "probe.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDENTITY_CHUNK       2048U
#define MCUBOOT_HEADER_BYTES 32U
static uint32_t little32(const uint8_t* bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}
static int
    firmware_at(Tb2Reader* io, uint32_t base, const char* stage, Tb2FirmwareIdentity* identity) {
    memset(identity, 0, sizeof(*identity));
    if(!io || !io->read || io->image_size != TB2_IMAGE_SIZE) return TB2_PROBE_CHECK_FAILED;
    uint8_t header[MCUBOOT_HEADER_BYTES];
    if(base > TB2_IMAGE_SIZE - TB2_SLOT_SIZE ||
       !io->read(io->context, base, header, sizeof(header)))
        return TB2_PROBE_IO_ERROR;
    uint32_t header_size = header[8] | (uint32_t)header[9] << 8;
    uint32_t payload = little32(header + 12);
    if(little32(header) != TB2_MCUBOOT_MAGIC || header_size < sizeof(header) ||
       header_size > TB2_SLOT_SIZE || !payload || payload > TB2_SLOT_SIZE - header_size)
        return 0;
    uint8_t* bytes = malloc(IDENTITY_CHUNK);
    if(!bytes) return TB2_PROBE_IO_ERROR;
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0) ? TB2_PROBE_IO_ERROR : 0;
    uint32_t length = header_size + payload;
    for(uint32_t offset = 0; !rc && offset < length;) {
        if(io->cancelled && io->cancelled(io->context)) {
            rc = TB2_PROBE_CANCELLED;
            break;
        }
        size_t count = length - offset;
        if(count > IDENTITY_CHUNK) count = IDENTITY_CHUNK;
        if(!io->read(io->context, base + offset, bytes, count) ||
           (!offset && memcmp(header, bytes, sizeof(header))) ||
           mbedtls_sha256_update(&hash, bytes, count)) {
            rc = TB2_PROBE_IO_ERROR;
            break;
        }
        offset += (uint32_t)count;
        if(io->progress) io->progress(io->context, stage, offset, length);
    }
    if(!rc && mbedtls_sha256_finish(&hash, identity->digest)) rc = TB2_PROBE_IO_ERROR;
    mbedtls_sha256_free(&hash);
    free(bytes);
    if(!rc) {
        snprintf(
            identity->version,
            sizeof(identity->version),
            "%u.%u.%u+%lu",
            header[20],
            header[21],
            (unsigned)(header[22] | (uint16_t)header[23] << 8),
            (unsigned long)little32(header + 24));
        identity->known = true;
    } else
        memset(identity, 0, sizeof(*identity));
    return rc;
}

int tb2_identity_firmware(Tb2Reader* io, Tb2FirmwareIdentity* identity) {
    return firmware_at(io, TB2_PRIMARY_OFFSET, "Identify slot A", identity);
}

int tb2_identity_firmwares(
    Tb2Reader* io,
    Tb2FirmwareIdentity* primary,
    Tb2FirmwareIdentity* secondary) {
    if(!primary || !secondary) return TB2_PROBE_CHECK_FAILED;
    int rc = firmware_at(io, TB2_PRIMARY_OFFSET, "Identify slot A", primary);
    if(!rc) rc = firmware_at(io, TB2_SECONDARY_OFFSET, "Identify slot B", secondary);
    if(rc) {
        memset(primary, 0, sizeof(*primary));
        memset(secondary, 0, sizeof(*secondary));
    }
    return rc;
}
