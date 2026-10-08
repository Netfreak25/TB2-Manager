#pragma once
#include "workflow.h"
#include "identity.h"
#include "restore.h"

#define TB2_BACKEND_ID    "tb2_builder_core"
#define TB2_BACKEND_API   11U
#define TB2_BACKEND_FILE  "tb2_backend"
#define TB2_BACKEND_ASSET "plugins/" TB2_BACKEND_FILE ".fal"
#define TB2_CERT_ID       "tb2_cert"
#define TB2_CERT_ASSET    "plugins/tb2_cert.fal"

typedef enum {
    Tb2BackendInspectIdentity,
    Tb2BackendInspectSettings,
} Tb2BackendInspectAction;

/** Bounded, value-only inspection request. The resident controller owns every
 * pointer and unloads Core before passing the resulting values to Store. */
typedef struct {
    Tb2BackendInspectAction action;
    Tb2WorkflowIO* io;
    const char* source;
    const char* artifact_directory;
    Tb2ImageIdentity* identity;
    Tb2ReadResult* read;
    Tb2SettingsSnapshot* settings;
    bool reuse_geometry;
} Tb2BackendInspect;

/* Private, versioned interface. All IO remains with the owning application;
 * no allocated object or function pointer may outlive the loaded backend. */
typedef struct {
    int (*run)(
        Tb2WorkflowIO*,
        const char*,
        const Tb2JobSpec*,
        const Tb2InputKey*,
        Tb2WorkflowAction,
        uint32_t,
        Tb2WorkflowResult*);
    int (*combined)(
        Tb2WorkflowIO*,
        const char*,
        const Tb2JobSpec*,
        const Tb2InputKey*,
        const Tb2SettingsPatch*,
        Tb2WorkflowAction,
        uint32_t,
        Tb2WorkflowResult*);
    size_t (*crypto_peak)(void);
    int (*restore)(Tb2RestoreRequest*);
    int (*package_import)(
        Tb2WorkflowIO*,
        const char* read_directory,
        const char* save_directory,
        uint32_t timestamp,
        Tb2PackageImportResult*);
    int (*inspect)(Tb2BackendInspect*);
} Tb2Backend;
int tb2_identity_file(Tb2WorkflowIO*, const char*, const char*, Tb2ImageIdentity*, bool);
