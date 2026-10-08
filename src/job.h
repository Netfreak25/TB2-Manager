#pragma once
#include "package.h"
#include "reader.h"
#include "paths.h"
#include "server.h"

#define TB2_JOB_PATH_MAX         256U
#define TB2_JOB_NAME_MAX         160U
#define TB2_JOB_VERSION          1U
#define TB2_JOB_RECORD_SIZE      284U
#define TB2_JOB_LEGACY_SPEC_SIZE 670U
#define TB2_JOB_SHARED_SPEC_SIZE 671U
#define TB2_JOB_OUTPUT_SPEC_SIZE 927U
#define TB2_JOB_SPEC_SIZE        1000U

/* Persistent metadata contains no MCU-SN/AES/private key. Key-file paths are
 * deliberately not stored: scanner folder names can themselves be secrets. */
typedef struct {
    char source[TB2_JOB_PATH_MAX];
    char imported_package[TB2_JOB_PATH_MAX];
    Tb2PackageOptions options;
    uint8_t shared_image; /* 0: legacy job-local; 1: SPI auto; 2: explicit output. */
    char output_path[TB2_JOB_PATH_MAX]; /* Since 0.4.4, immutable once job starts. */
    Tb2ServerChange server; /* Explicit override, zero means Keep. */
    uint8_t export_archive;
} Tb2JobSpec;

/** Stable byte offsets, independent of struct padding and compiler ABI. Legacy
 * 670/671/927-byte jobs decode with Keep and without automatic archive export. */
bool tb2_job_spec_size(size_t size);
bool tb2_job_spec_encode(const Tb2JobSpec* spec, uint8_t bytes[TB2_JOB_SPEC_SIZE]);
bool tb2_job_spec_decode(const uint8_t* bytes, size_t size, Tb2JobSpec* spec);
bool tb2_job_spec_equal(const Tb2JobSpec* left, const Tb2JobSpec* right);

typedef enum {
    Tb2JobFilePending = 1,
    Tb2JobFileDone,
    Tb2JobReadDone,
    Tb2JobApproved,
    Tb2JobPackageDone,
    Tb2JobImageDone,
    Tb2JobCancelled,
    Tb2JobFileDiscarded,
    Tb2JobImportDone,
    Tb2JobImageStarted,
} Tb2JobRecordKind;

typedef struct {
    uint32_t sequence;
    Tb2JobRecordKind kind;
    uint32_t size;
    uint32_t flags;
    char name[TB2_JOB_NAME_MAX];
    uint8_t digest[32];
    uint8_t payload[64];
} Tb2JobRecord;

/** Architecture-independent framing. CRC detects incomplete/corrupted writes,
 * not malicious modification. SHA-256 binds the actual artifacts separately. */
void tb2_job_encode(const Tb2JobRecord* record, uint8_t bytes[TB2_JOB_RECORD_SIZE]);
bool tb2_job_decode(
    const uint8_t bytes[TB2_JOB_RECORD_SIZE],
    uint32_t sequence,
    Tb2JobRecord* record);
void tb2_job_set_read(Tb2JobRecord* record, const Tb2ReadResult* result);
bool tb2_job_get_read(const Tb2JobRecord* record, Tb2ReadResult* result);
bool tb2_job_relative_path(const char* name);
uint32_t tb2_job_crc(const void* bytes, size_t size);
/** Stable per-job destination; rejects source/output aliasing (case-insensitive).
 * New jobs use the selected output_path; both legacy path modes stay unchanged. */
bool tb2_job_image_path(
    const Tb2JobSpec* spec,
    const char* directory,
    char output[TB2_JOB_PATH_MAX]);

/** Strict line-oriented configuration, no quoting/escaping/unknown fields.
 * The input is not logged. Supported names: https_host, ici_host, expires_utc,
 * package_dir. UTC start comes from the displayed/confirmed Flipper RTC. */
bool tb2_job_parse_config(const char* text, size_t size, Tb2JobSpec* spec, char error[224]);
