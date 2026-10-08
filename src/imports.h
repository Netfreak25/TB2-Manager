#pragma once
#include "editions.h"

#define TB2_IMPORTS_ID "tb2_imports"
typedef enum {
    Tb2ImportHome,
    Tb2ImportSecrets,
    Tb2ImportKeyPreview,
    Tb2ImportImageType,
    Tb2ImportImageVersion,
    Tb2ImportImagePreview,
    Tb2ImportPackageSource,
    Tb2ImportPackagePreview,
    Tb2ImportPackageTarget,
    Tb2EditFirmware,
    Tb2EditReview,
    Tb2EditHosts,
    Tb2EditWifi,
    Tb2EditWifiProfile,
    Tb2EditDevice,
    Tb2ImportDone
} Tb2ImportStage;
/** Owned wizard data survives unload; no SDK objects or callbacks are retained. */
typedef struct {
    Tb2ImportStage stage;
    Tb2FileVersion label;
    Tb2ImageKind image_kind;
    Tb2ImageIdentity identity;
    Tb2ObjectRef image;
    uint32_t revision;
    bool label_confirmed, label_manual, manual_identity, identity_checked;
    bool package_folder, duplicate;
    bool package_checked;
    char output[TB2_JOB_PATH_MAX];
    char package[TB2_RECORD_ID_SIZE];
    Tb2PackageImportResult package_result;
} Tb2ImportDraft;
