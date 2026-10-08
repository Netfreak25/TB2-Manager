#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "workflow.h"
#include "ui_store.h"
#include "operation.h"

#define TB2_SETUP_ID     "tb2_setup"
#define TB2_SETUP_API    13U
#define TB2_EDITOR_API   4U
#define TB2_SETUP_ASSET  "plugins/tb2_setup.fal"
#define TB2_AUX_ID       "tb2_aux"
#define TB2_AUX_ASSET    "plugins/tb2_aux.fal"
#define TB2_EXPORT_ID    "tb2_export"
#define TB2_EXPORT_ASSET "plugins/tb2_export.fal"

typedef enum {
    Tb2SetupPackage,
    Tb2SetupOutput,
    Tb2SetupCheckPackage,
    Tb2SetupLoadConfig,
    Tb2SetupHelp,
    Tb2SetupConfigHelp,
    Tb2SetupMenu,
    Tb2SetupApprove,
    Tb2SetupResult,
    Tb2SetupStatus,
    Tb2SetupCreate,
    Tb2SetupRoot,
    Tb2SetupNew,
    Tb2SetupJobs,
    Tb2SetupServerEditor,
    Tb2SetupCertificates,
    Tb2SetupFolderOnly,
    Tb2SetupTarget,
    Tb2SetupServerChoice,
    Tb2SetupOperation,
    Tb2SetupExport,
    Tb2SetupDumpTarget,
    Tb2SetupFlashApprove,
    Tb2SetupHardwareResult,
    Tb2SetupResume,
    Tb2SetupOperationLog,
    Tb2SetupBoxes,
    Tb2SetupSelectBox,
    Tb2SetupJobDetails,
    Tb2SetupRestoreKeys,
    Tb2SetupRestoreApprove,
    Tb2SetupDefaults,
    Tb2SetupRecordResult,
    Tb2SetupRecordKey,
    Tb2SetupOriginalPrompt,
    Tb2SetupOperationDetails,
    Tb2SetupRestoreDonor,
    Tb2SetupImports,
    Tb2SetupModifyMenu,
    Tb2SetupSettingsEditor,
    Tb2SetupVersionLabel,
    Tb2SetupFlipTdi,
    Tb2SetupActions,
    Tb2SetupManage,
    Tb2SetupImages,
    Tb2SetupFirmwareHeaders,
    Tb2SetupAioImport,
} Tb2SetupKind;
typedef enum {
    Tb2SetupActionExit,
    Tb2SetupActionInspect,
    Tb2SetupActionBuild,
    Tb2SetupActionResume,
    Tb2SetupActionHome,
    Tb2SetupActionModify,
    Tb2SetupActionDump,
    Tb2SetupActionFlash,
    Tb2SetupActionAio,
    Tb2SetupActionJobs,
    Tb2SetupActionPreviewServer,
    Tb2SetupActionApplyServer,
    Tb2SetupActionKeepServer,
    Tb2SetupActionEdit,
    Tb2SetupActionCertificates,
    Tb2SetupActionTarget,
    Tb2SetupActionRead,
    Tb2SetupActionVerifyRead,
    Tb2SetupActionProgram,
    Tb2SetupActionVerifyFlash,
    Tb2SetupActionRetryOperation,
    Tb2SetupActionSavedOperation,
    Tb2SetupActionOperationLog,
    Tb2SetupActionOperationResult,
    Tb2SetupActionBoxes,
    Tb2SetupActionBoxSelected,
    Tb2SetupActionJobDetails,
    Tb2SetupActionResult,
    Tb2SetupActionFlashVersion,
    Tb2SetupActionUseKey,
    Tb2SetupActionRestore,
    Tb2SetupActionRestoreCheck,
    Tb2SetupActionRestoreBuild,
    Tb2SetupActionRecordTask,
    Tb2SetupActionUseCandidate,
    Tb2SetupActionOperationDetails,
    Tb2SetupActionRestoreSavedKeys,
    Tb2SetupActionRestoreSelected,
    Tb2SetupActionImports,
    Tb2SetupActionSettingsInspect,
    Tb2SetupActionSettingsBuild,
    Tb2SetupActionFlipTdi,
    Tb2SetupActionPureDump,
    Tb2SetupActionPureFlash,
    Tb2SetupActionAioImport,
} Tb2SetupAction;
typedef enum {
    Tb2ModifyGuided,
    Tb2ModifyHosts,
    Tb2ModifyWifi,
    Tb2ModifyDevice,
    Tb2ModifyCertificates,
} Tb2ModifyMode;
/** Graphical setup runs synchronously with no worker/backend resident and frees
 * every view before return. Status requests are headless and may run on the
 * worker before/after the backend; normal exit is action Exit, not an error. */
typedef struct {
    void* storage;
    void* gui;
    void* context;
    Tb2WorkflowIO* filesystem; /* Headless job creation only; resident owner. */
    Tb2Operation* operation;
    Tb2OperationAccess operation_access;
    bool (*event)(void* context, const char* operation, int rc, const char* detail);
    Tb2SetupKind kind;
    Tb2SetupKind editor_kind;
    Tb2JobSpec* spec; /* Config defaults already carry the frontend RTC dates. */
    Tb2JobSpec* defaults; /* Resident-owned snapshot loaded before GUI allocation. */
    struct Tb2RecordTask* record_task;
    Tb2InputKey* input_key;
    Tb2InputKey* donor_key;
    Tb2SettingsSnapshot* settings_snapshot;
    Tb2SettingsPatch* settings_patch;
    Tb2ImageIdentity* image_identity;
    const Tb2WorkflowResult* flow;
    Tb2ModifyMode modify_mode;
    bool restore_connection;
    bool settings_only;
    bool key_from_file;
    bool wizard; /* Internal editors retain choices when navigating Back. */
    bool historical;
    bool dump_target;
    uint8_t hardware_options;
    int result;
    Tb2UiStatus status;
    Tb2SetupAction action;
    /* Keep frequently accessed control fields within short ARM offsets. */
    char key_path[TB2_JOB_PATH_MAX];
    char directory[128];
    char path[TB2_JOB_PATH_MAX];
    char error[224];
    char warning[224];
    char box_id[33], version_id[33]; /* Owned IDs, never plugin pointers. */
    char box_alias[49];
    Tb2ServerValues server_values; /* Only populated after explicit Change. */
    Tb2UiPreferences preferences;
} Tb2SetupRequest;
typedef struct {
    bool (*run)(Tb2SetupRequest* request);
} Tb2Setup;
bool tb2_setup_config(Tb2SetupRequest*);
bool tb2_setup_defaults(Tb2SetupRequest*);
bool tb2_setup_status(Tb2SetupRequest*);
bool tb2_setup_status_values(
    void* storage,
    const char* directory,
    const Tb2JobSpec* spec,
    const Tb2UiStatus* status,
    char* warning,
    size_t warning_size);
