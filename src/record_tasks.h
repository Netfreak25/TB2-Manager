#pragma once
#include "records.h"
#include "imports.h"
#include "spi.h"

#define TB2_RECORD_REPORT_SIZE 2048U
#define TB2_RECORD_MOVE_SOURCE 0x80000000U
typedef enum {
    Tb2RecordTaskCompare,
    Tb2RecordTaskDelete,
    Tb2RecordTaskNote,
    Tb2RecordTaskSecret,
    Tb2RecordTaskKeyCandidate,
    Tb2RecordTaskHistory,
    Tb2RecordTaskExport,
    Tb2RecordTaskImport,
    Tb2RecordTaskDiagnostic,
    Tb2RecordTaskPackage,
    Tb2RecordTaskSaveBox,
    Tb2RecordTaskClassify,
    Tb2RecordTaskOverview,
    Tb2RecordTaskVersionDetails,
    Tb2RecordTaskIdentify,
    Tb2RecordTaskImportInspect,
    Tb2RecordTaskImportImage,
    Tb2RecordTaskImportKey,
    Tb2RecordTaskImportPackage,
    Tb2RecordTaskFilePreview,
    Tb2RecordTaskFilePublish,
    Tb2RecordTaskPackageAssign,
    Tb2RecordTaskTargetReserve,
    Tb2RecordTaskFirmwareHeaders,
    Tb2RecordTaskRenamePrepare,
    Tb2RecordTaskRename,
    Tb2RecordTaskCompareChip
} Tb2RecordTaskKind;

typedef enum {
    Tb2IdentifyResult,
    Tb2IdentifyOpen,
    Tb2IdentifyCreate
} Tb2IdentifyChoice;

/** Resident-owned request/result. No view, callback or module-owned allocation
 * crosses the worker boundary. report never contains a key value or key path. */
typedef struct Tb2RecordTask {
    Tb2RecordTaskKind kind;
    char box[TB2_RECORD_ID_SIZE], version[TB2_RECORD_ID_SIZE], other[TB2_RECORD_ID_SIZE];
    char entry[TB2_RECORD_ID_SIZE], staging[128];
    char path[TB2_JOB_PATH_MAX], note[TB2_RECORD_NOTE_SIZE];
    Tb2InputKey key;
    uint8_t uid[8];
    bool uid_available;
    uint32_t timestamp;
    uint32_t flags;
    Tb2ObjectRef archive_receipt;
    union {
        Tb2ImportDraft import;
        Tb2SlotHeaders headers;
        Tb2SpiResult comparison;
    }; /* Mutually exclusive transient actions; keeps the existing task layout. */
    Tb2RecordResult result;
    char report[TB2_RECORD_REPORT_SIZE];
} Tb2RecordTask;

Tb2RecordResult tb2_record_task_run(Tb2WorkflowIO*, Tb2RecordTask*);
