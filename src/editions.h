#pragma once
#include "records.h"
#include "file_version.h"

#define TB2_FOLDER_NAME_SIZE            85U
#define TB2_FOLDER_PAYLOAD_SIZE         96U
#define TB2_EDITION_PAYLOAD_SIZE        640U
#define TB2_SERVER_PACKAGE_PAYLOAD_SIZE 416U
#define TB2_SERVER_PACKAGE_OBJECTS      7U

typedef enum {
    Tb2ImageUnclassified,
    Tb2ImageOriginal,
    Tb2ImageModified
} Tb2ImageKind;
typedef enum {
    Tb2PackageMatchPending,
    Tb2PackageMatched,
    Tb2PackageMismatch
} Tb2PackageMatch;
enum {
    Tb2EditionPublished = 1U
};
enum {
    Tb2PackageExpired = 1U,
    Tb2PackageNotYetValid = 2U
};

/** Folder ownership is independent of the editable alias. */
typedef struct {
    char name[TB2_FOLDER_NAME_SIZE];
    uint32_t generation;
} Tb2BoxFolder;

/** Sidecar for immutable 0.7 versions. A reservation is not a published image.
 * Paths and numeric labels are frozen once reserved; package assignments are
 * independently versioned, and never rewrite the original version artifacts. */
typedef struct {
    char id[TB2_RECORD_ID_SIZE], box[TB2_RECORD_ID_SIZE];
    Tb2FileVersion label;
    Tb2ImageKind kind;
    uint32_t revision, number, flags, generation;
    Tb2ObjectRef image;
    Tb2FirmwareIdentity primary, secondary;
    bool label_manual;
    uint8_t settings_categories, wifi_profiles, region;
    bool region_known;
    char path[TB2_JOB_PATH_MAX], package[TB2_RECORD_ID_SIZE];
    Tb2PackageMatch match;
} Tb2Edition;

/** Checked historical server artifact. Validity is separate from signatures
 * and key pairs. All seven objects are immutable and shared by their hashes. */
typedef struct {
    char id[TB2_RECORD_ID_SIZE], box[TB2_RECORD_ID_SIZE];
    Tb2ObjectRef objects[TB2_SERVER_PACKAGE_OBJECTS];
    uint8_t digest[32], ca_fingerprint[32];
    uint32_t validity, generation;
} Tb2ServerPackage;

Tb2RecordResult tb2_folder_load(Tb2WorkflowIO*, const char* box, Tb2BoxFolder*);
Tb2RecordResult tb2_folder_save(Tb2WorkflowIO*, const char* box, Tb2BoxFolder*);
Tb2RecordResult tb2_edition_load(Tb2WorkflowIO*, const char* box, const char* id, Tb2Edition*);
Tb2RecordResult tb2_edition_save(Tb2WorkflowIO*, Tb2Edition*);
Tb2RecordResult
    tb2_server_package_load(Tb2WorkflowIO*, const char* box, const char* id, Tb2ServerPackage*);
Tb2RecordResult tb2_server_package_save(Tb2WorkflowIO*, Tb2ServerPackage*);
Tb2RecordResult tb2_edition_can_create(Tb2WorkflowIO*, Tb2Edition*);
Tb2RecordResult tb2_server_package_can_create(Tb2WorkflowIO*, Tb2ServerPackage*);

/** FAT-safe readable component. Reserved DOS names receive a prefix. */
void tb2_file_stem(const char* alias, char stem[TB2_RECORD_ALIAS_SIZE]);
bool tb2_file_name(
    const char* alias,
    const Tb2FileVersion*,
    Tb2ImageKind,
    uint32_t revision,
    const char* extension,
    char* output,
    size_t size);
/** Creates only a new owned folder, or checks a saved ownership marker. */
Tb2RecordResult tb2_folder_claim(Tb2WorkflowIO*, const Tb2BoxRecord*, Tb2BoxFolder*);
/** Six-entry scans include pending reservations and tombstones. A matching
 * existing reservation is reused without allocating another revision. */
Tb2RecordResult tb2_file_reserve(Tb2WorkflowIO*, const Tb2BoxRecord*, Tb2Edition*);
Tb2RecordResult tb2_file_publish(
    Tb2WorkflowIO*,
    Tb2Edition*,
    Tb2BoxVersion*,
    const char* source,
    bool move_source);
/** Resolve a published readable image first and fall back to the legacy 0.7
 * content-addressed object. The selected path is always checked by callers. */
Tb2RecordResult tb2_version_image_path(
    Tb2WorkflowIO*,
    const char* box,
    const char* version,
    const Tb2ObjectRef*,
    char path[TB2_JOB_PATH_MAX]);
Tb2RecordResult tb2_file_duplicate(
    Tb2WorkflowIO*,
    const char* box,
    const Tb2ObjectRef*,
    char version[TB2_RECORD_ID_SIZE]);
Tb2RecordResult tb2_file_latest(
    Tb2WorkflowIO*,
    const char* box,
    const Tb2FileVersion*,
    Tb2ImageKind,
    char version[TB2_RECORD_ID_SIZE]);

/** Own assignment wins; otherwise the greatest strictly earlier Modified
 * label/revision with an assignment. Deleted anchors remain authoritative. */
Tb2RecordResult tb2_package_effective(
    Tb2WorkflowIO*,
    const Tb2Edition*,
    Tb2ServerPackage*,
    char from[TB2_RECORD_ID_SIZE]);
Tb2RecordResult tb2_package_assign(Tb2WorkflowIO*, Tb2Edition*, const char* package);
Tb2RecordResult
    tb2_editions_referenced(Tb2WorkflowIO*, const char* box, const Tb2ObjectRef*, bool* found);
