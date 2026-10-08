#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB2_PROBE_VERSION      "0.8.10"
#define TB2_PROBE_BLOCK_SIZE   4096U
#define TB2_PROBE_BLOCK_COUNT  32U
#define TB2_PROBE_IMAGE_SIZE   (TB2_PROBE_BLOCK_SIZE * TB2_PROBE_BLOCK_COUNT)
#define TB2_PROBE_BUFFER_SIZE  4096U
#define TB2_PROBE_CANCELLED    1
#define TB2_PROBE_IO_ERROR     2
#define TB2_PROBE_CHECK_FAILED 3

/** Narrow platform boundary; every I/O callback must transfer the exact length.
 * Scratch I/O is restricted to a newly created synthetic file by the caller.
 * event() returns false on a logging failure; processing then stops. */
typedef struct {
    void* context;
    bool (*read)(void* context, uint32_t offset, void* data, size_t size);
    bool (*write)(void* context, uint32_t offset, const void* data, size_t size);
    bool (*sync)(void* context);
    bool (*event)(void* context, const char* operation, int code, const char* detail);
    bool (*cancelled)(void* context);
    int (*random)(void* context, unsigned char* data, size_t size);
    bool (*artifact)(void* context, const char* name, const void* data, size_t size);
    void (*sample)(void* context, const char* stage);
} Tb2Probe;

/** Execute known-answer crypto tests, both CA curves and SD-backed LittleFS.
 * Does not accept a user image, user identity or user key. */
int tb2_probe_run(Tb2Probe* probe);

/** Measured Mbed TLS allocations, including tracking headers. Single worker only. */
size_t tb2_probe_crypto_peak(void);
size_t tb2_probe_crypto_current(void);
/** Start tracked crypto allocations; never reset while an allocation is live. */
int tb2_probe_crypto_begin(void);

/** Overflow-safe backing-file range validation, shared by all LFS callbacks. */
bool tb2_probe_range_valid(uint32_t offset, size_t size);
