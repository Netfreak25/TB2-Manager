#pragma once
#include "workflow.h"
#include "identity.h"

#define TB2_RECORD_ID_SIZE       33U
#define TB2_RECORD_PAGE_SIZE     6U
#define TB2_RECORD_ALIAS_SIZE    49U
#define TB2_RECORD_BOX_ID_SIZE   65U
#define TB2_RECORD_NOTE_SIZE     161U
#define TB2_RECORD_CHUNK         4096U
#define TB2_RECORD_ARTIFACTS     12U
#define TB2_RECORD_META_MAX      1536U
#define TB2_BOX_PAYLOAD_SIZE     288U
#define TB2_VERSION_PAYLOAD_SIZE 1376U
#define TB2_SECRET_PAYLOAD_SIZE  96U
#define TB2_ENTRY_PAYLOAD_SIZE   448U

typedef enum {
    Tb2RecordOk,
    Tb2RecordMissing,
    Tb2RecordCorrupt,
    Tb2RecordIo,
    Tb2RecordConflict,
    Tb2RecordCancelled,
    Tb2RecordProtected
} Tb2RecordResult;

typedef enum {
    Tb2RecordBox = 1,
    Tb2RecordVersion,
    Tb2RecordSecret,
    Tb2RecordNote,
    Tb2RecordEvent,
    Tb2RecordBinding,
    Tb2RecordFolder,
    Tb2RecordEdition,
    Tb2RecordPackage
} Tb2RecordKind;

typedef struct {
    uint8_t digest[32];
    uint32_t size; /* Zero means unavailable, never an empty archived object. */
} Tb2ObjectRef;

typedef struct {
    char id[TB2_RECORD_ID_SIZE];
    char alias[TB2_RECORD_ALIAS_SIZE];
    char serial[41];
    char box_id[TB2_RECORD_BOX_ID_SIZE];
    uint8_t uid[8];
    bool has_uid;
    uint32_t generation;
    uint32_t next_version;
    char secret[TB2_RECORD_ID_SIZE]; /* Last validated association; never a key value/path. */
    char candidate[TB2_RECORD_ID_SIZE]; /* Explicit unverified proposal, separate from secret. */
} Tb2BoxRecord;

enum {
    Tb2VersionSource = 1U,
    Tb2VersionOriginal = 2U,
    Tb2VersionWorking = 4U,
    Tb2VersionProtected = 8U,
    Tb2VersionDeleted = 16U,
    Tb2VersionImageChecked = 32U,
    Tb2VersionCertificatesChecked = 64U,
    Tb2VersionEndpointsKnown = 128U,
    Tb2VersionClassified = 256U,
    Tb2VersionSettingsChecked = 512U
};

/** The artifact order is stable: CA/client/private, two authentication files,
 * then the existing seven server-package files. Absence is explicit. */
typedef struct {
    char id[TB2_RECORD_ID_SIZE], box[TB2_RECORD_ID_SIZE], parent[TB2_RECORD_ID_SIZE];
    char job[128], created[TB2_DATE_SIZE], app[16], name[TB2_JOB_PATH_MAX];
    uint32_t number, flags, generation;
    Tb2FirmwareIdentity firmware;
    Tb2ObjectRef image, artifacts[TB2_RECORD_ARTIFACTS];
    Tb2ServerValues endpoints;
    uint8_t ca_fingerprint[32], client_fingerprint[32];
    char secret[TB2_RECORD_ID_SIZE]; /* Validated key/profile association for this image. */
} Tb2BoxVersion;

typedef struct {
    char id[TB2_RECORD_ID_SIZE];
    Tb2InputKey key;
    uint32_t profile;
    uint8_t firmware[32];
    bool verified;
    uint32_t generation;
} Tb2BoxSecret;

enum {
    Tb2EventClassification = 256U
}; /* Hardware event types retain operation kinds. */

/** Immutable workshop entries. type/state/code carry structured facts; text is
 * an explicit user's note. Diagnostics deliberately omit note text. */
typedef struct {
    char id[TB2_RECORD_ID_SIZE], box[TB2_RECORD_ID_SIZE], version[TB2_RECORD_ID_SIZE];
    char job[128], text[TB2_RECORD_NOTE_SIZE];
    uint32_t timestamp, type, state, flags, sequence, generation;
    int32_t code;
    bool note;
} Tb2BoxEntry;

/** Explicit byte framing, CRC and binding; two checked generations. No struct
 * padding, pointers or key paths are serialized. A failed save leaves the last
 * valid generation readable. Callers use generation for optimistic concurrency. */
Tb2RecordResult tb2_record_read(
    Tb2WorkflowIO*,
    const char* base,
    Tb2RecordKind,
    const char* binding,
    void* payload,
    size_t size,
    uint32_t* generation);
Tb2RecordResult tb2_record_write(
    Tb2WorkflowIO*,
    const char* base,
    Tb2RecordKind,
    const char* binding,
    const void* payload,
    size_t size,
    uint32_t* generation);
/** Read-only first-publication preflight. A present file must be an exact,
 * shorter prefix of this same generation; complete corrupt data is rejected. */
Tb2RecordResult tb2_record_can_create(
    Tb2WorkflowIO*,
    const char* base,
    Tb2RecordKind,
    const char* binding,
    const void* payload,
    size_t size);
bool tb2_record_id_valid(const char* id);
/** One read-only pass over direct box folders. Errors/duplicates never mean Unknown.
 * except_id is only used when retrying publication of an owned new record. */
Tb2RecordResult tb2_box_find_uid(
    Tb2WorkflowIO*,
    const uint8_t uid[8],
    const char* except_id,
    Tb2BoxRecord*,
    bool* found);
bool tb2_record_new_id(Tb2WorkflowIO*, char id[TB2_RECORD_ID_SIZE]);
void tb2_record_wipe(void* bytes, size_t size);
bool tb2_record_path(char path[TB2_JOB_PATH_MAX], const char* box, const char* child);
bool tb2_object_path(char path[TB2_JOB_PATH_MAX], const Tb2ObjectRef* object);

Tb2RecordResult tb2_box_load(Tb2WorkflowIO*, const char* id, Tb2BoxRecord*);
Tb2RecordResult tb2_box_save(Tb2WorkflowIO*, Tb2BoxRecord*);
Tb2RecordResult tb2_version_load(Tb2WorkflowIO*, const char* box, const char* id, Tb2BoxVersion*);
Tb2RecordResult tb2_version_save(Tb2WorkflowIO*, Tb2BoxVersion*);
/** Explicit display-name update only; paths and all identity fields stay bound. */
Tb2RecordResult tb2_version_rename(Tb2WorkflowIO*, Tb2BoxVersion*);
typedef struct {
    char first[TB2_RECORD_ID_SIZE], latest[TB2_RECORD_ID_SIZE];
    uint32_t first_number, latest_number;
} Tb2Originals;
/** Bounded, cancellable metadata scan. First original is global; latest is
 * restricted to the given firmware when known. Never uses wall-clock age. */
Tb2RecordResult
    tb2_originals(Tb2WorkflowIO*, const char* box, const Tb2FirmwareIdentity*, Tb2Originals*);
/** Import preflight: identity/content must match. Local sequence and user
 * classifications remain authoritative when the same version already exists. */
bool tb2_version_same_content(const Tb2BoxVersion*, const Tb2BoxVersion*);
bool tb2_entry_same_content(const Tb2BoxEntry*, const Tb2BoxEntry*);
Tb2RecordResult tb2_secret_load(Tb2WorkflowIO*, const char* box, const char* id, Tb2BoxSecret*);
Tb2RecordResult tb2_secret_save(Tb2WorkflowIO*, const char* box, Tb2BoxSecret*);
Tb2RecordResult
    tb2_entry_load(Tb2WorkflowIO*, const char* box, const char* id, bool note, Tb2BoxEntry*);
Tb2RecordResult tb2_entry_save(Tb2WorkflowIO*, Tb2BoxEntry*);
Tb2RecordResult tb2_box_can_create(Tb2WorkflowIO*, Tb2BoxRecord*);
Tb2RecordResult tb2_version_can_create(Tb2WorkflowIO*, Tb2BoxVersion*);
Tb2RecordResult tb2_secret_can_create(Tb2WorkflowIO*, const char* box, Tb2BoxSecret*);
Tb2RecordResult tb2_entry_can_create(Tb2WorkflowIO*, Tb2BoxEntry*);

/** Streaming, checked publication into content-addressed storage. An expected
 * reference binds size and digest when supplied. The caller owns staging_dir.
 * No version is published by this function; failure cannot authorize flashing. */
Tb2RecordResult tb2_object_put(
    Tb2WorkflowIO*,
    const char* source,
    const char* staging_dir,
    const Tb2ObjectRef* expected,
    Tb2ObjectRef* result);
Tb2RecordResult tb2_object_verify(Tb2WorkflowIO*, const Tb2ObjectRef*);
/** Keyless whole-file SHA-256; expected_size prevents accepting partial images. */
Tb2RecordResult
    tb2_file_inspect(Tb2WorkflowIO*, const char*, uint32_t expected_size, Tb2ObjectRef*);
/** Checked working copy; never overwrites a differing target. */
Tb2RecordResult tb2_object_materialize(
    Tb2WorkflowIO*,
    const Tb2ObjectRef*,
    const char* staging,
    const char* target);
/** Remove the version reference first. Each object requires a complete bounded
 * reference scan; corruption, cancellation or ambiguous names keep the object. */
Tb2RecordResult tb2_version_delete(Tb2WorkflowIO*, const char* box, const char* version);

/** Constant-size page selected by IDs, in ascending or descending order. Only
 * direct children are enumerated; names are validated before opening metadata.
 * step() visits at most budget entries; close() is mandatory even on cancel. */
typedef struct {
    void* directory;
    char ids[TB2_RECORD_PAGE_SIZE][TB2_RECORD_ID_SIZE];
    char anchor[TB2_RECORD_ID_SIZE];
    uint8_t count;
    bool reverse, more, versions, done, strict;
    char prefix; /* Default v; n/e/k select notes/events/secrets in the same bounded scanner. */
} Tb2RecordPage;
Tb2RecordResult tb2_record_page_open(
    Tb2WorkflowIO*,
    Tb2RecordPage*,
    const char* box,
    const char* anchor,
    bool reverse);
Tb2RecordResult tb2_record_page_step(Tb2WorkflowIO*, Tb2RecordPage*, unsigned budget);
void tb2_record_page_close(Tb2WorkflowIO*, Tb2RecordPage*);
