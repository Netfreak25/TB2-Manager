#pragma once
#include "records.h"

#define TB2_WORKSHOP_SLOTS 3U
typedef enum {
    Tb2WorkshopSource,
    Tb2WorkshopTarget,
    Tb2WorkshopBackup
} Tb2WorkshopSlot;
typedef struct {
    char box[TB2_RECORD_ID_SIZE];
    char versions[TB2_WORKSHOP_SLOTS][TB2_RECORD_ID_SIZE];
    uint32_t numbers[TB2_WORKSHOP_SLOTS];
    uint32_t descriptor_crc, generation, published;
} Tb2WorkshopBinding;

/** Separate sidecar; job.tb2 and its immutable inputs remain untouched. The
 * directory digest and descriptor CRC bind this record to exactly one job. */
Tb2RecordResult tb2_workshop_load(
    Tb2WorkflowIO*,
    const char* directory,
    uint32_t descriptor_crc,
    Tb2WorkshopBinding*);
Tb2RecordResult tb2_workshop_bind(
    Tb2WorkflowIO*,
    const char* directory,
    uint32_t descriptor_crc,
    const char* box,
    Tb2WorkshopBinding*);
Tb2RecordResult tb2_workshop_reserve(
    Tb2WorkflowIO*,
    const char* directory,
    Tb2WorkshopBinding*,
    Tb2WorkshopSlot,
    Tb2BoxRecord*);
Tb2RecordResult tb2_workshop_publish(
    Tb2WorkflowIO*,
    const char* directory,
    Tb2WorkshopBinding*,
    Tb2WorkshopSlot,
    Tb2BoxVersion*);
/** Link an already published version without rewriting its provenance. */
Tb2RecordResult tb2_workshop_link(
    Tb2WorkflowIO*,
    const char*,
    Tb2WorkshopBinding*,
    Tb2WorkshopSlot,
    const Tb2BoxVersion*);
