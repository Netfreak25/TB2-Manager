#pragma once
#include "workflow.h"
#include <storage/storage.h>
typedef struct {
    Storage* storage;
    void* context;
    bool (*event)(void*, const char*, int, const char*);
    bool (*cancelled)(void*);
    void (*progress)(void*, const char*, uint32_t, uint32_t);
    int (*random)(void*, unsigned char*, size_t);
} Tb2NativeIO;
Tb2WorkflowIO tb2_native_io(Tb2NativeIO* native);
