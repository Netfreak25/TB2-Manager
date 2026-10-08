#pragma once
#include "records.h"
#include "workshop.h"
#include "setup.h"
#include "record_tasks.h"

#define TB2_STORE_ID    "tb2_store"
#define TB2_STORE_API   5U
#define TB2_STORE_ASSET "plugins/tb2_store.fal"
#define TB2_BOXES_ID    "tb2_boxes"
#define TB2_BOXES_ASSET "plugins/tb2_boxes.fal"

typedef enum {
    Tb2StoreArchive,
    Tb2StoreVerify,
    Tb2StoreBackup,
    Tb2StoreFindUid,
    Tb2StoreCheckout,
    Tb2StoreBind,
    Tb2StoreLoadBinding,
    Tb2StoreCapture,
    Tb2StoreDescribe,
    Tb2StoreBoundBackup,
    Tb2StoreSaveKey,
    Tb2StoreLoadKey,
    Tb2StoreKeyFile,
    Tb2StoreRestorePlan,
    Tb2StoreLoadRestorePlan,
    Tb2StoreStatus,
    Tb2StoreDeleteVersion,
    Tb2StoreSaveEntry,
    Tb2StoreTask,
    Tb2StorePreflight,
    Tb2StoreFlashReady,
    Tb2StoreDefaults,
    Tb2StoreRestoreKeys,
    Tb2StoreOriginal,
    Tb2StoreSettingsPreferences,
    Tb2StorePublish
} Tb2StoreAction;

typedef struct {
    Tb2WorkflowIO* io;
    Tb2SetupRequest* selection;
    void* storage;
    Tb2StoreAction action;
    Tb2BoxRecord* box;
    Tb2BoxVersion* version;
    Tb2BoxEntry* entry;
    const Tb2Operation* operation;
    const Tb2WorkflowResult* flow;
    const Tb2JobSpec* spec;
    Tb2UiStatus status;
    uint32_t timestamp;
    int32_t result_code;
    Tb2RecordTask* task;
    void* log_context;
    void* (*open_log)(void* context, const char* path); /* Resident-owned SDK handle. */
    char* run_directory;
    uint32_t* log_sequence;
    uint32_t required_bytes, workflow_action;
    bool resume;
    const Tb2FirmwareIdentity* firmware;
    const char* source;
    const char* staging;
    const Tb2ObjectRef* expected;
    uint8_t uid[8];
    bool found;
    bool uid_available;
    bool restore_connection;
    bool candidate_key; /* Explicit proposal selection; never implicit fallback. */
    bool readable_target; /* existing_version names a reserved readable edition. */
    char record_id[TB2_RECORD_ID_SIZE], version_id[TB2_RECORD_ID_SIZE];
    char alias[TB2_RECORD_ALIAS_SIZE];
    const char* existing_version;
    uint32_t descriptor_crc;
    const char* created;
    const Tb2ImageIdentity* identity;
    bool checked;
    bool settings_only;
    bool hardware;
    const Tb2ServerValues* endpoints;
    const char* artifact_directory;
    const char* package_directory;
    const uint8_t* ca_fingerprint;
    const uint8_t* client_fingerprint;
    const uint8_t* package_hash;
    const uint8_t* package_ca_hash;
    Tb2InputKey* key;
    Tb2InputKey* donor_key;
    const Tb2SettingsPatch* settings_patch;
    uint32_t profile;
    Tb2WorkshopSlot slot;
    uint32_t version_flags;
    char path[TB2_JOB_PATH_MAX];
    char error[160];
} Tb2StoreRequest;

typedef struct {
    Tb2RecordResult (*run)(Tb2StoreRequest*);
} Tb2Store;

Tb2RecordResult tb2_store_run(Tb2StoreRequest*);
Tb2RecordResult tb2_store_key_file(Tb2StoreRequest*);
/** Read a selected proposal file before record publication. Leaves existing keys untouched. */
Tb2RecordResult tb2_store_task_key_file(Tb2StoreRequest*);
Tb2RecordResult tb2_store_preflight(Tb2StoreRequest*);
