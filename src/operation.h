#pragma once
#include "spi.h"
#include "archive.h"
#include "ui_store.h"

#define TB2_OPERATION_NAME         "operation.tb2"
#define TB2_OPERATION_JOURNAL      "operation.bin"
#define TB2_OPERATION_SPEC_SIZE    292U
#define TB2_OPERATION_RECORD_SIZE  512U
#define TB2_OPERATION_RECORD_LIMIT 1024U
typedef enum {
    Tb2OperationDump = 1,
    Tb2OperationFlash,
    Tb2OperationAio,
    Tb2OperationModify,
    Tb2OperationRestore,
    Tb2OperationPureDump,
    Tb2OperationPureFlash
} Tb2OperationKind;

/** Persisted standalone intent, independent of any active box selection. */
static inline bool tb2_operation_pure(Tb2OperationKind kind) {
    return kind == Tb2OperationPureDump || kind == Tb2OperationPureFlash;
}
static inline bool tb2_operation_dump(Tb2OperationKind kind) {
    return kind == Tb2OperationDump || kind == Tb2OperationPureDump;
}
static inline bool tb2_operation_flash(Tb2OperationKind kind) {
    return kind == Tb2OperationFlash || kind == Tb2OperationPureFlash;
}
typedef enum {
    Tb2PhaseSource,
    Tb2PhaseSourceVerify,
    Tb2PhaseModifySetup,
    Tb2PhaseModifyCheck,
    Tb2PhaseModifyBuild,
    Tb2PhaseExport,
    Tb2PhaseFlashPrepare,
    Tb2PhaseFlashProgram,
    Tb2PhaseFlashVerify,
    Tb2PhaseComplete,
    Tb2PhaseArchiveSource,
    Tb2PhaseBackupCheck,
    Tb2PhaseArchiveTarget
} Tb2OperationPhase;
typedef struct Tb2Operation {
    Tb2OperationKind kind;
    char created[TB2_DATE_SIZE];
    char source[TB2_JOB_PATH_MAX];
    char image[TB2_JOB_PATH_MAX];
    Tb2UiState state;
    Tb2OperationPhase phase;
    int32_t result;
    bool approved, modify_bound, torn, settings_only;
    uint32_t spec_crc, descriptor_crc, sequence;
    Tb2SpiReceipt dump, flash;
    Tb2ArchiveReceipt archive;
    uint8_t package_hash[32], ca_hash[32], image_hash[32];
    uint8_t format;
} Tb2Operation;

typedef enum {
    Tb2OperationLoad,
    Tb2OperationSave,
    Tb2OperationCreate,
    Tb2OperationBind
} Tb2OperationAccess;

/** Metadata only, used during bounded directory enumeration. No journal access. */
bool tb2_operation_info(Tb2WorkflowIO* io, const char* directory, Tb2Operation* operation);
/** Read-only bounded status lookup. A torn tail is explicit, never silently repaired. */
bool tb2_operation_load(Tb2WorkflowIO* io, const char* directory, Tb2Operation* operation);
/** Exclusive descriptor creation and checked initial status. Never stores secrets. */
bool tb2_operation_create(Tb2WorkflowIO* io, const char* directory, Tb2Operation* operation);
/** Retry only a shorter, byte-identical first descriptor in an owned child
 * directory with no journal. Never repairs complete or conflicting metadata. */
bool tb2_operation_retry_create(Tb2WorkflowIO*, const char*, Tb2Operation*);
/** Bind Modify metadata in an owned job directory, also after a failed first save. */
bool tb2_operation_bind(Tb2WorkflowIO*, const char* directory, Tb2Operation*, const Tb2JobSpec*);
/** Append, sync and independently read back. Only an explicitly allowed torn tail
 * can be truncated. Abort is terminal, and bound paths/UIDs/fingerprints cannot change. */
bool tb2_operation_save(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2Operation* operation,
    bool repair_tail);
