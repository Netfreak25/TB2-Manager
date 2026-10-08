#pragma once
#include "reader.h"

#define TB2_IDENTITY_BOX_SIZE 65U
typedef struct {
    bool known;
    char version[32];
    uint8_t digest[32];
} Tb2FirmwareIdentity;

typedef struct {
    Tb2FirmwareIdentity firmware;
    Tb2FirmwareIdentity secondary;
    char box_id[TB2_IDENTITY_BOX_SIZE];
    uint32_t offset, block_count, disk_version;
    bool filesystem_known;
    uint8_t artifacts; /* Five encrypted box files copied through an optional sink. */
} Tb2ImageIdentity;

/** Keyless primary-slot identity. Invalid/unsupported headers yield Unknown;
 * transport/SD failure and cancellation remain errors. Hashes only the header
 * and firmware payload; no LittleFS, TLV or claimed signature verification. */
int tb2_identity_firmware(Tb2Reader*, Tb2FirmwareIdentity*);
/** Keyless identities for both MCUboot slots. Neither result is described as
 * active; an invalid slot remains Unknown while transport failures are errors. */
int tb2_identity_firmwares(
    Tb2Reader*,
    Tb2FirmwareIdentity* primary,
    Tb2FirmwareIdentity* secondary);
/** Keyless, read-only structural discovery. Ambiguous LittleFS aliases yield
 * Unknown. Only toniebox/id is interpreted; no endpoint or Wi-Fi parsing. */
int tb2_reader_identity(Tb2Reader*, Tb2ImageIdentity*);
int tb2_reader_settings_identity(Tb2Reader*, Tb2ReadResult*, Tb2ImageIdentity*);
/** Uses geometry from a fresh verified source/result to copy the paired encrypted
 * files. Does not decrypt, rerun discovery, or claim certificate validity. */
int tb2_reader_artifacts(Tb2Reader*, Tb2ImageIdentity*);
