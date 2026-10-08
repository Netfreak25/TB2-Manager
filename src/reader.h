#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "server.h"

/* TB2 format constants, shared by the core, SD adapter and synthetic fixtures. */
#define TB2_IMAGE_SIZE         (16U * 1024U * 1024U)
#define TB2_LFS_BLOCK_SIZE     4096U
#define TB2_SN_SIZE            8U
#define TB2_AES_KEY_SIZE       16U
#define TB2_KEY_TEXT_MAX       40U
#define TB2_PLAIN_MAX          0xA00U
#define TB2_CRYPT_MAX          (1U + 16U + TB2_PLAIN_MAX + 16U)
#define TB2_PRIMARY_OFFSET     0x20000U
#define TB2_SLOT_SIZE          0x400000U
#define TB2_SECONDARY_OFFSET   (TB2_PRIMARY_OFFSET + TB2_SLOT_SIZE)
#define TB2_MCUBOOT_MAGIC      0x96F3B83DU
/* The second PC KDF profile reads these RAM-initializer positions. They are
 * candidates, never accepted without decrypting and parsing the original set. */
#define TB2_LEGACY_INFO_OFFSET (0x19BB00U + 0x20224058U - 0x20223000U)
#define TB2_LEGACY_SALT_OFFSET (TB2_LEGACY_INFO_OFFSET + 16U)

typedef struct {
    void* context;
    uint64_t image_size;
    bool (*read)(void* context, uint32_t offset, void* data, size_t size);
    bool (*event)(void* context, const char* operation, int code, const char* detail);
    bool (*cancelled)(void* context);
    void (*progress)(void* context, const char* stage, uint32_t done, uint32_t total);
    /* Create-new, sync, close and read back before returning success. Names are
     * relative to a fresh job directory. Private data must never be logged. */
    bool (*backup)(void* context, const char* name, const void* data, size_t size);
    int (*random)(void* context, unsigned char* data, size_t size);
} Tb2Reader;

typedef struct {
    uint32_t offset;
    uint32_t block_count;
    uint32_t disk_version;
    uint32_t encrypted_files;
    uint8_t source_sha256[32];
    unsigned profile; /* 1 = firmware_constants, 2 = image_static_ram_init, 3 = direct AES. */
    uint8_t ca_sha256[32], client_sha256[32]; /* Validated plaintext DER, never a secret. */
    char error[224];
} Tb2ReadResult;

typedef enum {
    Tb2InputKeyInvalid,
    Tb2InputKeySecret,
    Tb2InputKeyAes
} Tb2InputKeyKind;

typedef struct {
    Tb2InputKeyKind kind;
    uint8_t bytes[TB2_AES_KEY_SIZE];
} Tb2InputKey;

/** Read-only bounded-memory extraction. Return codes match TB2_PROBE_*.
 * Successful extraction is not a new image, certificate replacement or a
 * certificate-validity/trust decision. The MCU-SN is never logged or saved. */
int tb2_reader_run(Tb2Reader* io, const uint8_t serial[TB2_SN_SIZE], Tb2ReadResult* result);

/** Same validation and read-only guarantees; direct AES bypasses HKDF only,
 * never DER parsing, client-key matching or dynamic filesystem validation. */
int tb2_reader_run_key(Tb2Reader* io, const Tb2InputKey* input, Tb2ReadResult* result);

/** Keyless source binding for settings-only changes. Discovers one structural
 * LittleFS, captures its geometry and hashes the complete 16 MiB source. It
 * does not decrypt, back up or interpret certificates. */
int tb2_reader_settings(Tb2Reader* io, Tb2ReadResult* result);
/** Read-only preview after explicit Change. Validates dump/key identity and
 * source stability, but creates no backup, job, or plaintext credential file. */
int tb2_reader_server_preview(
    Tb2Reader* io,
    const Tb2InputKey* input,
    Tb2ReadResult* result,
    Tb2ServerValues* values);

/** Validate and extract originals, optionally preserving the exact four original
 * connection values. NULL leaves settings uninterpreted. */
int tb2_reader_restore_source(Tb2Reader*, const Tb2InputKey*, Tb2ReadResult*, Tb2ServerRecords*);

/** Keyscanner secret.txt (16 hex) or aes_key.txt (32 hex), optional UTF-8 BOM
 * and trailing CR/LF. No JSON, spaces, embedded NULs or truncated input.
 * On failure the output is cleared, so no previous key can be reused. */
bool tb2_reader_parse_key(const char* text, size_t size, Tb2InputKey* input);

/** Resolve a previously validated profile. Caller must still verify the source
 * fingerprint and decrypted CA; this function alone does not validate a key. */
int tb2_reader_derive_aes(
    Tb2Reader* io,
    const Tb2InputKey* input,
    unsigned profile,
    uint8_t key[TB2_AES_KEY_SIZE]);

/** Strict optional config: 16 hex digits, with only trailing CR/LF permitted. */
bool tb2_reader_parse_serial(const char* text, size_t size, uint8_t serial[TB2_SN_SIZE]);
