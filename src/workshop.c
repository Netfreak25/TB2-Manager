#include "workshop.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BINDING_PAYLOAD           160U
#define BINDING_NAME              "box-binding"
#define BINDING_DESCRIPTOR_OFFSET (4U * TB2_RECORD_ID_SIZE + TB2_WORKSHOP_SLOTS * 4U)
#define BINDING_PUBLISHED_OFFSET  (BINDING_DESCRIPTOR_OFFSET + 4U)
static void put32(uint8_t* out, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        out[i] = (uint8_t)(value >> (8 * i));
}
static uint32_t get32(const uint8_t* in) {
    uint32_t n = 0;
    for(unsigned i = 0; i < 4; i++)
        n |= (uint32_t)in[i] << (8 * i);
    return n;
}
static bool
    location(const char* directory, char path[TB2_JOB_PATH_MAX], char id[TB2_RECORD_ID_SIZE]) {
    if(!directory || !directory[0]) return false;
    uint8_t digest[32];
    if(mbedtls_sha256((const uint8_t*)directory, strlen(directory), digest, 0)) return false;
    for(unsigned i = 0; i < 16; i++)
        snprintf(id + i * 2, 3, "%02x", digest[i]);
    int n = snprintf(path, TB2_JOB_PATH_MAX, "%s/%s", directory, BINDING_NAME);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static bool valid(const Tb2WorkshopBinding* b) {
    if(!tb2_record_id_valid(b->box) || (b->published & ~7U)) return false;
    for(unsigned i = 0; i < TB2_WORKSHOP_SLOTS; i++) {
        if(b->versions[i][0]) {
            if(!tb2_record_id_valid(b->versions[i]) || !b->numbers[i]) return false;
        } else if(b->numbers[i] || (b->published & (1U << i)))
            return false;
    }
    return true;
}
static Tb2RecordResult save(Tb2WorkflowIO* io, const char* directory, Tb2WorkshopBinding* b) {
    uint8_t bytes[BINDING_PAYLOAD] = {0};
    char path[TB2_JOB_PATH_MAX], id[TB2_RECORD_ID_SIZE];
    if(!valid(b) || !location(directory, path, id)) return Tb2RecordCorrupt;
    memcpy(bytes, b->box, TB2_RECORD_ID_SIZE);
    for(unsigned i = 0; i < TB2_WORKSHOP_SLOTS; i++) {
        memcpy(bytes + (i + 1) * TB2_RECORD_ID_SIZE, b->versions[i], TB2_RECORD_ID_SIZE);
        put32(bytes + 4 * TB2_RECORD_ID_SIZE + i * 4, b->numbers[i]);
    }
    put32(bytes + BINDING_DESCRIPTOR_OFFSET, b->descriptor_crc);
    put32(bytes + BINDING_PUBLISHED_OFFSET, b->published);
    return tb2_record_write(io, path, Tb2RecordBinding, id, bytes, sizeof(bytes), &b->generation);
}
Tb2RecordResult tb2_workshop_load(
    Tb2WorkflowIO* io,
    const char* directory,
    uint32_t crc,
    Tb2WorkshopBinding* b) {
    memset(b, 0, sizeof(*b));
    uint8_t bytes[BINDING_PAYLOAD];
    char path[TB2_JOB_PATH_MAX], id[TB2_RECORD_ID_SIZE];
    if(!location(directory, path, id)) return Tb2RecordCorrupt;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordBinding, id, bytes, sizeof(bytes), &b->generation);
    if(rc) return rc;
    memcpy(b->box, bytes, TB2_RECORD_ID_SIZE);
    for(unsigned i = 0; i < TB2_WORKSHOP_SLOTS; i++) {
        memcpy(b->versions[i], bytes + (i + 1) * TB2_RECORD_ID_SIZE, TB2_RECORD_ID_SIZE);
        b->numbers[i] = get32(bytes + 4 * TB2_RECORD_ID_SIZE + i * 4);
    }
    b->descriptor_crc = get32(bytes + BINDING_DESCRIPTOR_OFFSET);
    b->published = get32(bytes + BINDING_PUBLISHED_OFFSET);
    if(!valid(b)) return Tb2RecordCorrupt;
    return b->descriptor_crc == crc ? Tb2RecordOk : Tb2RecordConflict;
}
Tb2RecordResult tb2_workshop_bind(
    Tb2WorkflowIO* io,
    const char* directory,
    uint32_t crc,
    const char* box_id,
    Tb2WorkshopBinding* b) {
    if(!tb2_record_id_valid(box_id)) return Tb2RecordCorrupt;
    Tb2RecordResult rc = tb2_workshop_load(io, directory, crc, b);
    if(!rc) return strcmp(box_id, b->box) ? Tb2RecordConflict : Tb2RecordOk;
    if(rc != Tb2RecordMissing && rc != Tb2RecordCorrupt) return rc;
    Tb2BoxRecord* box = calloc(1, sizeof(*box));
    rc = box ? tb2_box_load(io, box_id, box) : Tb2RecordIo;
    free(box);
    if(rc) return rc;
    memcpy(b->box, box_id, TB2_RECORD_ID_SIZE);
    b->descriptor_crc = crc;
    return save(io, directory, b);
}
Tb2RecordResult tb2_workshop_reserve(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2WorkshopBinding* b,
    Tb2WorkshopSlot slot,
    Tb2BoxRecord* box) {
    if((unsigned)slot >= TB2_WORKSHOP_SLOTS || !valid(b) || strcmp(box->id, b->box))
        return Tb2RecordConflict;
    if(b->versions[slot][0]) return Tb2RecordOk;
    if(box->next_version == UINT32_MAX) return Tb2RecordConflict;
    box->next_version++;
    Tb2RecordResult rc = tb2_box_save(io, box);
    if(rc) return rc;
    if(!tb2_record_new_id(io, b->versions[slot])) return Tb2RecordIo;
    b->numbers[slot] = box->next_version;
    /* Sortable prefix plus 96 random bits; RTC never controls version order. */
    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%08lx", (unsigned long)box->next_version);
    memcpy(b->versions[slot], prefix, 8);
    return save(io, directory, b);
}
Tb2RecordResult tb2_workshop_publish(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2WorkshopBinding* b,
    Tb2WorkshopSlot slot,
    Tb2BoxVersion* version) {
    if((unsigned)slot >= TB2_WORKSHOP_SLOTS || !valid(b) || strcmp(version->box, b->box) ||
       strcmp(version->id, b->versions[slot]) || version->number != b->numbers[slot])
        return Tb2RecordConflict;
    Tb2RecordResult rc = tb2_version_save(io, version);
    if(rc) return rc;
    b->published |= 1U << slot;
    return save(io, directory, b);
}
Tb2RecordResult tb2_workshop_link(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2WorkshopBinding* b,
    Tb2WorkshopSlot slot,
    const Tb2BoxVersion* v) {
    if((unsigned)slot >= TB2_WORKSHOP_SLOTS || !valid(b) || strcmp(v->box, b->box) ||
       !v->generation || !v->number || (v->flags & Tb2VersionDeleted) ||
       (b->versions[slot][0] && strcmp(b->versions[slot], v->id)))
        return Tb2RecordConflict;
    strcpy(b->versions[slot], v->id);
    b->numbers[slot] = v->number;
    b->published |= 1U << slot;
    return save(io, directory, b);
}
