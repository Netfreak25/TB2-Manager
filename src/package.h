#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TB2_PACKAGE_FILES         6U
#define TB2_PACKAGE_FILE_MAX      4096U
#define TB2_HOST_MAX              64U
#define TB2_DATE_SIZE             15U
#define TB2_PACKAGE_MISSING       4
#define TB2_PACKAGE_EXPORT_DER    (1UL << 31)
#define TB2_PACKAGE_REISSUE_SHIFT 8U
#define TB2_PACKAGE_FILENAMES \
    {"ca-root.pem", "ca-key.pem", "teddy-cert.pem", "teddy-key.pem", "ici.pem", "ici.key"}

extern const char* const tb2_package_names[TB2_PACKAGE_FILES];

typedef struct {
    char https_host[TB2_HOST_MAX];
    char ici_host[TB2_HOST_MAX];
    char now[TB2_DATE_SIZE]; /* Confirmed UTC YYYYMMDDhhmmss. */
    char expires[TB2_DATE_SIZE]; /* Only used for explicitly approved issuance. */
} Tb2PackageOptions;

typedef struct {
    void* context;
    /* Missing=4, success=0, otherwise actual I/O failure. Never partial success.
     * data=NULL queries the size without reading any bytes. Read from a
     * job-owned snapshot; imported originals remain untouched. */
    int (*read)(void* context, const char* name, void* data, size_t capacity, size_t* size);
    /* Create, sync, close and read back. Existing files may only match exactly.
     * Persist keys before returning; do not overwrite a different valid key. */
    bool (*save)(void* context, const char* name, const void* data, size_t size);
    bool (*event)(void* context, const char* operation, int rc, const char* detail);
    bool (*cancelled)(void* context);
    int (*random)(void* context, unsigned char* data, size_t size);
} Tb2PackageIO;

typedef struct {
    uint32_t missing;
    uint32_t generated;
    uint32_t reissue; /* Existing leaves lacking the explicitly requested DNS SAN. */
    uint8_t ca_sha256[32];
    uint8_t package_sha256[32];
    uint32_t validity; /* Historical import: bit 0 expired, bit 1 not yet valid. */
    char error[224];
} Tb2PackageResult;

#define TB2_PACKAGE_IMPORT_FILES 7U
typedef struct {
    Tb2PackageResult package;
    uint32_t size[TB2_PACKAGE_IMPORT_FILES];
    uint8_t sha256[TB2_PACKAGE_IMPORT_FILES][32];
} Tb2PackageImportResult;

/** Strict DNS names and real calendar dates. No wildcard or DN injection. */
static inline bool tb2_package_options_valid(const Tb2PackageOptions* o) {
    if(!o) return false;
    const char* hosts[] = {o->https_host, o->ici_host};
    for(unsigned h = 0; h < 2; h++) {
        size_t n = 0, label = 0;
        for(; n < TB2_HOST_MAX && hosts[h][n]; n++) {
            char c = hosts[h][n];
            if(c == '.') {
                if(!label || hosts[h][n - 1] == '-') return false;
                label = 0;
                continue;
            }
            if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '-') ||
               (!label && c == '-') || ++label > 63)
                return false;
        }
        if(!n || n >= TB2_HOST_MAX || !label || hosts[h][n - 1] == '-') return false;
    }
    const char* dates[] = {o->now, o->expires};
    for(unsigned d = 0; d < 2; d++) {
        const char* date = dates[d];
        if(date[14]) return false;
        for(unsigned i = 0; i < 14; i++)
            if(date[i] < '0' || date[i] > '9') return false;
        unsigned year = 0;
        for(unsigned i = 0; i < 4; i++)
            year = year * 10U + (unsigned)(date[i] - '0');
        unsigned month = (unsigned)(date[4] - '0') * 10U + (unsigned)(date[5] - '0');
        unsigned day = (unsigned)(date[6] - '0') * 10U + (unsigned)(date[7] - '0');
        static const uint8_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if(year < 2024 || year > 2099 || !month || month > 12 || !day) return false;
        unsigned limit = days[month - 1] +
                         (month == 2 && year % 4U == 0 && (year % 100U != 0 || year % 400U == 0));
        if(day > limit || (unsigned)(date[8] - '0') * 10U + (unsigned)(date[9] - '0') >= 24U ||
           (unsigned)(date[10] - '0') * 10U + (unsigned)(date[11] - '0') >= 60U ||
           (unsigned)(date[12] - '0') * 10U + (unsigned)(date[13] - '0') >= 60U)
            return false;
    }
    return strcmp(o->now, o->expires) < 0;
}

/** Inspect/validate every available file, with explicit UTC validity checks.
 * approved_missing=0 is read-only and reports missing bits with rc=4.
 * A nonzero mask permits only those absent files, never replacement of invalid
 * files. Missing private key with an existing certificate is not regenerable.
 * On success with approval, also exports the exact CA DER as ca.der.
 * PEM/DER detection is content based; only P-256/P-384 and SHA-256/384 allowed. */
int tb2_package_run(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    uint32_t approved_missing,
    Tb2PackageResult* result);
/** Host-change path. Approve reissue bits shifted by TB2_PACKAGE_REISSUE_SHIFT.
 * save() must write a separate job-owned overlay; read() prefers that overlay.
 * Existing CA, key files, leaf expiry, and all previous SAN entries are retained. */
int tb2_package_update(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    uint32_t approval,
    Tb2PackageResult* result);
/** Validate an existing historical package without hostname replacement or
 * certificate issuance. Pair, chain, signature and key-usage checks remain
 * mandatory; validity is reported in result instead of rejecting storage. */
int tb2_package_inspect(
    Tb2PackageIO*,
    const Tb2PackageOptions*,
    bool export_ca_der,
    Tb2PackageResult*);
