#pragma once
#include "workflow.h"
#include "identity.h"

#define TB2_SPI_ID       "tb2_spi"
#define TB2_SPI_API      8U
#define TB2_SPI_ASSET    "plugins/tb2_spi.fal"
#define TB2_SPI_PAGE     256U
#define TB2_SPI_CHUNK    4096U
#define TB2_SPI_ID_SIZE  3U
#define TB2_SPI_UID_SIZE 8U

enum {
    Tb2SpiNoChip = 10,
    Tb2SpiUnsupported,
    Tb2SpiDifferentChip,
    Tb2SpiTimeout,
    Tb2SpiProtected,
    Tb2SpiMismatch,
    Tb2SpiTransportError
};
typedef enum {
    Tb2SpiDetect,
    Tb2SpiRead,
    Tb2SpiVerifyRead,
    Tb2SpiPreflight,
    Tb2SpiFlash,
    Tb2SpiVerifyFlash,
    Tb2SpiFirmware,
    Tb2SpiInspectFile,
    Tb2SpiHeaders,
    Tb2SpiCompare
} Tb2SpiAction;

typedef enum {
    Tb2HeaderNotRead,
    Tb2HeaderValid,
    Tb2HeaderEmpty,
    Tb2HeaderUnknown,
    Tb2HeaderInvalid,
    Tb2HeaderReadFailed
} Tb2HeaderStatus;
typedef struct {
    Tb2HeaderStatus status;
    uint8_t major, minor;
    uint16_t revision;
    uint32_t build;
} Tb2SlotHeader;
/** Transient header values only; never a fingerprint or verification receipt. */
typedef struct {
    Tb2SlotHeader slots[2];
    char error[160];
    char summary[128], details[256];
} Tb2SlotHeaders;
typedef enum {
    Tb2SpiPhaseDetect,
    Tb2SpiPhaseFile,
    Tb2SpiPhaseRead,
    Tb2SpiPhaseErase,
    Tb2SpiPhaseWrite,
    Tb2SpiPhaseVerify,
    Tb2SpiPhaseFirmware
} Tb2SpiPhase;
enum {
    Tb2SpiBound = 1U,
    Tb2SpiOwned = 2U,
    Tb2SpiDumpSaved = 4U,
    Tb2SpiDumpVerified = 8U,
    Tb2SpiFileChecked = 16U,
    Tb2SpiEraseStarted = 32U,
    Tb2SpiWriteDone = 64U,
    Tb2SpiFlashVerified = 128U,
    Tb2SpiDigestBound = 256U,
    Tb2SpiManual = 512U /* Explicit manual identity; never substitutes a known UID. */
};

/** Persisted separately with CRC and operation/path binding by the coordinator.
 * Flags never grant a live file lease. UID and digest are not logged as text. */
typedef struct {
    uint32_t flags;
    uint8_t uid[TB2_SPI_UID_SIZE];
    uint8_t digest[32];
} Tb2SpiReceipt;

typedef struct {
    void* context;
    bool (*begin)(void* context);
    void (*end)(void* context);
    /* Exactly one CS-low transaction; always releases the bus, also on error. */
    bool (*transfer)(void* context, const uint8_t* tx, size_t tx_size, uint8_t* rx, size_t rx_size);
    uint32_t (*milliseconds)(void* context);
    void (*delay)(void* context, uint32_t milliseconds);
} Tb2SpiTransport;

typedef struct {
    Tb2SpiPhase phase;
    uint32_t offset;
    char error[160];
    union {
        bool uid_available;
        bool different; /* Compare only, meaningful exclusively after success. */
    };
    uint8_t uid[TB2_SPI_UID_SIZE];
    Tb2FirmwareIdentity firmware, secondary;
} Tb2SpiResult;

typedef struct {
    Tb2WorkflowIO* io;
    const char* path;
    Tb2SpiAction action;
    Tb2SpiReceipt* receipt;
    Tb2SpiResult* result;
    void* context;
    bool (*checkpoint)(void* context, const Tb2SpiReceipt* receipt, Tb2SpiPhase phase);
    /* Frontend-owned read handle. Successful preflight returns a lease; Flash
     * consumes it without another full preflight hash. All failure paths close
     * it. Callers may supply only a fresh validated, continuously held lease. */
    void** lease;
    struct Tb2Operation* operation; /* Optional durable coordinator binding. */
    const char* directory; /* Operation directory; InspectFile: optional artifact output. */
    void* wait_context;
    /* Resident callback, active only while polling for a connected chip. */
    void (*waiting)(void* context, bool active);
    bool probe_uid; /* Detect-only: return unavailable UID after bounded attempts. */
    const uint8_t* expected_uid; /* A known record UID never permits a different readable UID. */
    bool backup; /* Owned pre-flash dump, with a separate durable child operation. */
    uint8_t speed; /* Direct hardware: index 0..3 selects 2, 4, 8, 16 MHz. */
    union {
        Tb2ImageIdentity* identity; /* InspectFile only; caller-owned value result. */
        Tb2SlotHeaders* headers; /* Headers only; no receipt, file or record binding. */
    };
} Tb2SpiRequest;

int tb2_spi_run(Tb2SpiTransport* transport, Tb2SpiRequest* request);
int tb2_spi_headers_run(Tb2SpiTransport* transport, Tb2SpiRequest* request);
/** Module-local persistence adapter; never loads a second module from a callback. */
int tb2_spi_operation_run(Tb2SpiTransport* transport, Tb2SpiRequest* request);
typedef struct {
    int (*run)(Tb2SpiRequest* request);
    bool (*operation)(
        Tb2WorkflowIO*,
        const char*,
        struct Tb2Operation*,
        unsigned access,
        const Tb2JobSpec*);
} Tb2Spi;
