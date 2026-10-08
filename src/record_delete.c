#include "records.h"
#include "editions.h"
#include <stdlib.h>
#include <string.h>

static bool same(const Tb2ObjectRef* a, const Tb2ObjectRef* b) {
    return a->size && a->size == b->size && !memcmp(a->digest, b->digest, 32);
}
typedef struct {
    Tb2RecordPage boxes, versions;
    Tb2BoxRecord box;
    Tb2BoxVersion version;
} ReferenceScan;
static Tb2RecordResult referenced(Tb2WorkflowIO* io, const Tb2ObjectRef* object, bool* found) {
    ReferenceScan* scan = calloc(1, sizeof(*scan));
    if(!scan) return Tb2RecordIo;
    *found = false;
    Tb2RecordResult rc;
    char boxes_after[TB2_RECORD_ID_SIZE] = {0};
    do {
        rc = tb2_record_page_open(io, &scan->boxes, NULL, boxes_after, false);
        scan->boxes.strict = true;
        while(!rc && !scan->boxes.done)
            rc = tb2_record_page_step(io, &scan->boxes, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && !*found && i < scan->boxes.count; i++) {
            rc = tb2_box_load(io, scan->boxes.ids[i], &scan->box);
            if(!rc) rc = tb2_editions_referenced(io, scan->box.id, object, found);
            char versions_after[TB2_RECORD_ID_SIZE] = {0};
            if(rc || *found) break;
            do {
                rc =
                    tb2_record_page_open(io, &scan->versions, scan->box.id, versions_after, false);
                scan->versions.strict = true;
                while(!rc && !scan->versions.done)
                    rc = tb2_record_page_step(io, &scan->versions, TB2_RECORD_PAGE_SIZE);
                for(unsigned j = 0; !rc && !*found && j < scan->versions.count; j++) {
                    rc = tb2_version_load(io, scan->box.id, scan->versions.ids[j], &scan->version);
                    if(rc) continue;
                    bool deleted = (scan->version.flags & Tb2VersionDeleted) != 0;
                    *found = !deleted && same(object, &scan->version.image);
                    /* Legacy fixed package bindings remain historical anchors. */
                    for(unsigned k = deleted ? 5 : 0; !*found && k < TB2_RECORD_ARTIFACTS; k++)
                        *found = same(object, &scan->version.artifacts[k]);
                }
                if(scan->versions.count)
                    strcpy(versions_after, scan->versions.ids[scan->versions.count - 1]);
            } while(!rc && !*found && scan->versions.more);
        }
        if(scan->boxes.count) strcpy(boxes_after, scan->boxes.ids[scan->boxes.count - 1]);
    } while(!rc && !*found && scan->boxes.more);
    tb2_record_page_close(io, &scan->boxes);
    tb2_record_page_close(io, &scan->versions);
    free(scan);
    return rc;
}
Tb2RecordResult tb2_version_delete(Tb2WorkflowIO* io, const char* box, const char* id) {
    if(io->cancelled && io->cancelled(io->context)) return Tb2RecordCancelled;
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!v) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_version_load(io, box, id, v);
    if(!rc && (v->flags & Tb2VersionProtected)) rc = Tb2RecordProtected;
    if(!rc && !(v->flags & Tb2VersionDeleted)) {
        v->flags |= Tb2VersionDeleted;
        rc = tb2_version_save(io, v);
    }
    for(unsigned i = 0; !rc && i <= TB2_RECORD_ARTIFACTS; i++) {
        const Tb2ObjectRef* ref = i ? &v->artifacts[i - 1] : &v->image;
        if(!ref->size) continue;
        bool shared = false;
        rc = referenced(io, ref, &shared);
        if(!rc && !shared) {
            char path[TB2_JOB_PATH_MAX];
            if(!tb2_object_path(path, ref)) {
                rc = Tb2RecordCorrupt;
                break;
            }
            int exists = io->exists(io->context, path);
            if(exists < 0 || (exists && !io->remove(io->context, path))) rc = Tb2RecordIo;
        }
        if(io->progress)
            io->progress(io->context, "Check references", i + 1, TB2_RECORD_ARTIFACTS + 1);
    }
    free(v);
    return rc;
}
