#include "records.h"
#include <stdlib.h>
#include <string.h>

Tb2RecordResult tb2_box_find_uid(
    Tb2WorkflowIO* io,
    const uint8_t uid[8],
    const char* except_id,
    Tb2BoxRecord* out,
    bool* found) {
    *found = false;
    memset(out, 0, sizeof(*out));
    bool zero = true, erased = true;
    for(unsigned i = 0; i < sizeof(out->uid); i++) {
        if(uid[i]) zero = false;
        if(uid[i] != UINT8_MAX) erased = false;
    }
    if(zero || erased) return Tb2RecordCorrupt;
    if(io->cancelled && io->cancelled(io->context)) return Tb2RecordCancelled;
    int present = io->exists(io->context, TB2_BOXES_ROOT);
    if(present <= 0) return present < 0 ? Tb2RecordIo : Tb2RecordOk;
    Tb2BoxRecord* box = calloc(1, sizeof(*box));
    if(!box) return Tb2RecordIo;
    void* directory = io->dir_open(io->context, TB2_BOXES_ROOT);
    Tb2RecordResult rc = directory ? Tb2RecordOk : Tb2RecordIo;
    while(!rc) {
        if(io->cancelled && io->cancelled(io->context)) {
            rc = Tb2RecordCancelled;
            break;
        }
        char name[80];
        bool folder = false;
        int next = io->dir_read(io->context, directory, name, sizeof(name), &folder);
        if(next <= 0) {
            if(next < 0) rc = Tb2RecordIo;
            break;
        }
        if(!folder || !tb2_record_id_valid(name) || (except_id && !strcmp(name, except_id)))
            continue;
        rc = tb2_box_load(io, name, box);
        if(!rc && box->has_uid && !memcmp(box->uid, uid, sizeof(box->uid))) {
            if(*found)
                rc = Tb2RecordConflict;
            else {
                *out = *box;
                *found = true;
            }
        }
    }
    if(directory && !io->dir_close(io->context, directory)) rc = Tb2RecordIo;
    free(box);
    if(rc) {
        *found = false;
        memset(out, 0, sizeof(*out));
    }
    return rc;
}
