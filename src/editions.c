#include "editions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOLDER_COLLISION_LIMIT 64U

static bool stopped(Tb2WorkflowIO* io) {
    return io->cancelled && io->cancelled(io->context);
}
static bool same_object(const Tb2ObjectRef* a, const Tb2ObjectRef* b) {
    return a->size == b->size && !memcmp(a->digest, b->digest, sizeof(a->digest));
}
void tb2_file_stem(const char* alias, char stem[TB2_RECORD_ALIAS_SIZE]) {
    size_t size = 0;
    while(*alias && size + 1 < TB2_RECORD_ALIAS_SIZE) {
        unsigned char c = (unsigned char)*alias++;
        if(c < 32 || c > 126 || strchr("<>:\"/\\|?*", c)) c = '_';
        if(!size && (c == ' ' || c == '.')) continue;
        if(c == '_' && size && stem[size - 1] == '_') continue;
        stem[size++] = (char)c;
    }
    while(size && (stem[size - 1] == '.' || stem[size - 1] == ' '))
        size--;
    stem[size] = 0;
    if(!size) {
        strcpy(stem, "Box");
        return;
    }
    char upper[TB2_RECORD_ALIAS_SIZE];
    for(size_t i = 0; i <= size; i++)
        upper[i] = stem[i] >= 'a' && stem[i] <= 'z' ? stem[i] - ('a' - 'A') : stem[i];
    char* dot = strchr(upper, '.');
    if(dot) *dot = 0;
    bool reserved = !strcmp(upper, "CON") || !strcmp(upper, "PRN") || !strcmp(upper, "AUX") ||
                    !strcmp(upper, "NUL") ||
                    (strlen(upper) == 4 &&
                     (!strncmp(upper, "COM", 3) || !strncmp(upper, "LPT", 3)) && upper[3] >= '1' &&
                     upper[3] <= '9');
    if(reserved) {
        if(size + 1 == TB2_RECORD_ALIAS_SIZE) size--;
        memmove(stem + 1, stem, size);
        stem[0] = '_';
        stem[size + 1] = 0;
    }
}
bool tb2_file_name(
    const char* alias,
    const Tb2FileVersion* label,
    Tb2ImageKind kind,
    uint32_t revision,
    const char* extension,
    char* out,
    size_t size) {
    if(!alias || !revision || (kind != Tb2ImageOriginal && kind != Tb2ImageModified) ||
       (strcmp(extension, "bin") && strcmp(extension, "tar")))
        return false;
    char stem[TB2_RECORD_ALIAS_SIZE], version[TB2_FILE_VERSION_TEXT], suffix[16] = {0};
    tb2_file_stem(alias, stem);
    if(!tb2_file_version_format(label, version, sizeof(version))) return false;
    if(revision > 1) snprintf(suffix, sizeof(suffix), "_r%lu", (unsigned long)revision);
    int n = snprintf(
        out,
        size,
        "%s_%s%s%s.%s",
        stem,
        version,
        kind == Tb2ImageModified ? "_mod" : "",
        suffix,
        extension);
    return n > 0 && (size_t)n < size;
}
static bool folder_path(char* out, const Tb2BoxFolder* folder) {
    int n = snprintf(out, TB2_JOB_PATH_MAX, "%s/%s", TB2_IMAGES_ROOT, folder->name);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static Tb2RecordResult
    folder_owner(Tb2WorkflowIO* io, const char* box, const Tb2BoxFolder* folder, bool create) {
    char path[TB2_JOB_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s/.tb2-owner", TB2_IMAGES_ROOT, folder->name);
    if(n <= 0 || n >= (int)sizeof(path)) return Tb2RecordCorrupt;
    uint8_t payload[TB2_RECORD_ID_SIZE] = {0};
    uint32_t generation = 0;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordFolder, box, payload, sizeof(payload), &generation);
    if(create && (rc == Tb2RecordMissing || rc == Tb2RecordCorrupt)) {
        memcpy(payload, box, sizeof(payload));
        rc = tb2_record_write(
            io, path, Tb2RecordFolder, box, payload, sizeof(payload), &generation);
    }
    if(!rc && memcmp(payload, box, sizeof(payload))) rc = Tb2RecordConflict;
    return rc;
}
Tb2RecordResult
    tb2_folder_claim(Tb2WorkflowIO* io, const Tb2BoxRecord* box, Tb2BoxFolder* folder) {
    Tb2RecordResult rc = tb2_folder_load(io, box->id, folder);
    char path[TB2_JOB_PATH_MAX];
    if(!rc) {
        if(!folder_path(path, folder)) return Tb2RecordCorrupt;
        int present = io->exists(io->context, path);
        if(present < 0) return Tb2RecordIo;
        if(present) return folder_owner(io, box->id, folder, false);
        if(!io->mkdir(io->context, TB2_IMAGES_ROOT) || !io->mkdir(io->context, path))
            return Tb2RecordIo;
        return folder_owner(io, box->id, folder, true);
    }
    if(rc != Tb2RecordMissing && rc != Tb2RecordCorrupt) return rc;
    char stem[TB2_RECORD_ALIAS_SIZE];
    tb2_file_stem(box->alias, stem);
    for(unsigned attempt = 0; attempt < FOLDER_COLLISION_LIMIT; attempt++) {
        if(stopped(io)) return Tb2RecordCancelled;
        if(!attempt)
            snprintf(folder->name, sizeof(folder->name), "%s", stem);
        else
            snprintf(folder->name, sizeof(folder->name), "%s_%.16s_%u", stem, box->id, attempt);
        if(!folder_path(path, folder)) return Tb2RecordCorrupt;
        int present = io->exists(io->context, path);
        if(present < 0) return Tb2RecordIo;
        if(present) {
            rc = folder_owner(io, box->id, folder, false);
            if(rc == Tb2RecordIo) return rc;
            if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) continue;
            if(rc) return rc;
        } else {
            if(!io->mkdir(io->context, TB2_IMAGES_ROOT) || !io->mkdir(io->context, path))
                return Tb2RecordIo;
            rc = folder_owner(io, box->id, folder, true);
            if(rc) return rc;
        }
        /* The checked owner marker precedes publication of the box path.
         * An orphan with no marker is never adopted after power loss. */
        return tb2_folder_save(io, box->id, folder);
    }
    return Tb2RecordConflict;
}
typedef Tb2RecordResult (*EditionVisitor)(Tb2WorkflowIO*, const Tb2Edition*, void*);
static Tb2RecordResult
    visit_editions(Tb2WorkflowIO* io, const char* box, EditionVisitor visit, void* context) {
    Tb2RecordPage* page = calloc(1, sizeof(*page));
    Tb2Edition* e = calloc(1, sizeof(*e));
    if(!page || !e) {
        free(page);
        free(e);
        return Tb2RecordIo;
    }
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    do {
        rc = tb2_record_page_open(io, page, box, anchor, false);
        page->prefix = 'f';
        page->strict = true;
        while(!rc && !page->done)
            rc = tb2_record_page_step(io, page, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && i < page->count; i++) {
            rc = tb2_edition_load(io, box, page->ids[i], e);
            if(!rc) rc = visit(io, e, context);
        }
        if(page->count) strcpy(anchor, page->ids[page->count - 1]);
    } while(!rc && page->more);
    tb2_record_page_close(io, page);
    free(page);
    free(e);
    return rc;
}
typedef struct {
    const Tb2Edition* wanted;
    uint32_t revision;
} RevisionScan;
static Tb2RecordResult revision_visit(Tb2WorkflowIO* io, const Tb2Edition* e, void* ctx) {
    (void)io;
    RevisionScan* scan = ctx;
    if(e->kind == scan->wanted->kind &&
       !tb2_file_version_compare(&e->label, &scan->wanted->label) && e->revision > scan->revision)
        scan->revision = e->revision;
    return Tb2RecordOk;
}
Tb2RecordResult tb2_file_reserve(Tb2WorkflowIO* io, const Tb2BoxRecord* box, Tb2Edition* e) {
    if(stopped(io)) return Tb2RecordCancelled;
    if(!tb2_record_id_valid(box->id) || !tb2_file_version_valid(&e->label) ||
       (e->kind != Tb2ImageOriginal && e->kind != Tb2ImageModified))
        return Tb2RecordCorrupt;
    Tb2Edition* old = calloc(1, sizeof(*old));
    if(!old) return Tb2RecordIo;
    Tb2RecordResult rc = e->id[0] ? tb2_edition_load(io, box->id, e->id, old) : Tb2RecordMissing;
    if(!rc) {
        if(old->kind != e->kind || tb2_file_version_compare(&old->label, &e->label) ||
           (e->image.size && !same_object(&old->image, &e->image)))
            rc = Tb2RecordConflict;
        else
            *e = *old;
        free(old);
        return rc;
    }
    free(old);
    if(rc == Tb2RecordCorrupt && !e->generation && e->number && e->revision && e->path[0]) {
        rc = tb2_edition_can_create(io, e);
        return rc ? rc : tb2_edition_save(io, e);
    }
    if(rc != Tb2RecordMissing) return rc;
    strcpy(e->box, box->id);
    Tb2BoxFolder folder;
    rc = tb2_folder_claim(io, box, &folder);
    RevisionScan scan = {.wanted = e};
    if(!rc) rc = visit_editions(io, box->id, revision_visit, &scan);
    if(rc) return rc;
    char name[TB2_JOB_NAME_MAX], tar[TB2_JOB_PATH_MAX];
    e->revision = scan.revision;
    for(;;) {
        if(stopped(io)) return Tb2RecordCancelled;
        if(e->revision == UINT32_MAX) return Tb2RecordConflict;
        e->revision++;
        if(!tb2_file_name(box->alias, &e->label, e->kind, e->revision, "bin", name, sizeof(name)))
            return Tb2RecordCorrupt;
        int n = snprintf(e->path, sizeof(e->path), "%s/%s/%s", TB2_IMAGES_ROOT, folder.name, name);
        if(n <= 0 || n >= (int)sizeof(e->path)) return Tb2RecordCorrupt;
        strcpy(tar, e->path);
        strcpy(tar + strlen(tar) - 3, "tar");
        int bin_exists = io->exists(io->context, e->path),
            tar_exists = io->exists(io->context, tar);
        if(bin_exists < 0 || tar_exists < 0) return Tb2RecordIo;
        if(!bin_exists && !tar_exists) break;
    }
    if(!e->id[0] && !tb2_record_new_id(io, e->id)) return Tb2RecordIo;
    /* Existing versions keep their local number. New imports reserve one
     * monotonically before publishing the edition; failed attempts may leave gaps. */
    if(!e->number) {
        Tb2BoxRecord current;
        rc = tb2_box_load(io, box->id, &current);
        if(!rc && current.next_version == UINT32_MAX) rc = Tb2RecordConflict;
        if(!rc) {
            e->number = ++current.next_version;
            rc = tb2_box_save(io, &current);
        }
    }
    return rc ? rc : tb2_edition_save(io, e);
}
Tb2RecordResult tb2_file_duplicate(
    Tb2WorkflowIO* io,
    const char* box,
    const Tb2ObjectRef* image,
    char version[TB2_RECORD_ID_SIZE]) {
    version[0] = 0;
    if(image->size != TB2_IMAGE_SIZE) return Tb2RecordCorrupt;
    Tb2RecordPage* page = calloc(1, sizeof(*page));
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!page || !v) {
        free(page);
        free(v);
        return Tb2RecordIo;
    }
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    do {
        rc = tb2_record_page_open(io, page, box, anchor, false);
        page->strict = true;
        while(!rc && !page->done)
            rc = tb2_record_page_step(io, page, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && i < page->count; i++) {
            rc = tb2_version_load(io, box, page->ids[i], v);
            if(!rc && !(v->flags & Tb2VersionDeleted) && same_object(&v->image, image)) {
                strcpy(version, v->id);
                break;
            }
        }
        if(page->count) strcpy(anchor, page->ids[page->count - 1]);
    } while(!rc && !version[0] && page->more);
    tb2_record_page_close(io, page);
    free(page);
    free(v);
    return rc;
}
typedef struct {
    Tb2Edition selected;
    const Tb2FileVersion* label;
    Tb2ImageKind kind;
} LatestScan;
static Tb2RecordResult latest_visit(Tb2WorkflowIO* io, const Tb2Edition* e, void* context) {
    LatestScan* s = context;
    if(!(e->flags & Tb2EditionPublished) || e->kind != s->kind ||
       tb2_file_version_compare(&e->label, s->label) || e->revision <= s->selected.revision)
        return Tb2RecordOk;
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!v) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_version_load(io, e->box, e->id, v);
    if(rc == Tb2RecordMissing && (e->flags & Tb2EditionPublished)) rc = Tb2RecordCorrupt;
    if(!rc && !same_object(&e->image, &v->image)) rc = Tb2RecordConflict;
    if(!rc && !(v->flags & Tb2VersionDeleted)) s->selected = *e;
    free(v);
    return rc;
}
Tb2RecordResult tb2_file_latest(
    Tb2WorkflowIO* io,
    const char* box,
    const Tb2FileVersion* label,
    Tb2ImageKind kind,
    char version[TB2_RECORD_ID_SIZE]) {
    LatestScan* scan = calloc(1, sizeof(*scan));
    if(!scan) return Tb2RecordIo;
    scan->label = label;
    scan->kind = kind;
    version[0] = 0;
    Tb2RecordResult rc = visit_editions(io, box, latest_visit, scan);
    if(!rc) strcpy(version, scan->selected.id);
    free(scan);
    return rc;
}
Tb2RecordResult tb2_file_publish(
    Tb2WorkflowIO* io,
    Tb2Edition* e,
    Tb2BoxVersion* v,
    const char* source,
    bool move_source) {
    bool unclassified_dump = (v->flags & (Tb2VersionSource | Tb2VersionClassified)) ==
                             Tb2VersionSource;
    bool kind_matches = e->kind == Tb2ImageOriginal ?
                            (v->flags & Tb2VersionOriginal) || unclassified_dump :
                            !(v->flags & Tb2VersionOriginal);
    if(strcmp(e->id, v->id) || strcmp(e->box, v->box) || e->number != v->number ||
       (v->flags & Tb2VersionDeleted) || v->image.size != TB2_IMAGE_SIZE || !kind_matches ||
       (e->image.size && !same_object(&e->image, &v->image)))
        return Tb2RecordConflict;
    Tb2RecordResult rc = Tb2RecordOk;
    int present = io->exists(io->context, e->path);
    if(present < 0) return Tb2RecordIo;
    if(present) {
        Tb2ObjectRef actual;
        rc = tb2_file_inspect(io, e->path, v->image.size, &actual);
        if(!rc && !same_object(&actual, &v->image)) rc = Tb2RecordConflict;
    } else if(move_source) {
        if(!io->move_new || !io->move_new(io->context, source, e->path)) rc = Tb2RecordIo;
        if(!rc) {
            Tb2ObjectRef actual;
            rc = tb2_file_inspect(io, e->path, v->image.size, &actual);
            if(!rc && !same_object(&actual, &v->image)) rc = Tb2RecordConflict;
        }
        if(rc && io->exists(io->context, source) == 0 && io->exists(io->context, e->path) == 1)
            io->move_new(io->context, e->path, source);
    } else {
        void* input = io->open(io->context, source, Tb2FileRead);
        void* output = input ? io->open(io->context, e->path, Tb2FileNew) : NULL;
        uint8_t* bytes = output ? malloc(TB2_RECORD_CHUNK) : NULL;
        if(!input || !output || !bytes || io->size(io->context, input) != v->image.size)
            rc = Tb2RecordIo;
        for(uint32_t offset = 0; !rc && offset < v->image.size;) {
            if(stopped(io)) {
                rc = Tb2RecordCancelled;
                break;
            }
            size_t count = v->image.size - offset;
            if(count > TB2_RECORD_CHUNK) count = TB2_RECORD_CHUNK;
            if(io->read(io->context, input, bytes, count) != count ||
               io->write(io->context, output, bytes, count) != count)
                rc = Tb2RecordIo;
            offset += (uint32_t)count;
            if(io->progress) io->progress(io->context, "Import image", offset, v->image.size);
        }
        if(output) {
            bool synced = io->sync(io->context, output);
            bool closed = io->close(io->context, output);
            if(!synced || !closed) rc = Tb2RecordIo;
        }
        if(input && !io->close(io->context, input)) rc = Tb2RecordIo;
        if(bytes) {
            memset(bytes, 0, TB2_RECORD_CHUNK);
            free(bytes);
        }
        if(!rc) {
            Tb2ObjectRef actual;
            rc = tb2_file_inspect(io, e->path, v->image.size, &actual);
            if(!rc && !same_object(&actual, &v->image)) rc = Tb2RecordConflict;
        }
        if(rc && io->exists(io->context, e->path) == 1) io->remove(io->context, e->path);
    }
    if(!rc) rc = tb2_version_save(io, v);
    if(!rc) {
        e->image = v->image;
        e->flags |= Tb2EditionPublished;
        rc = tb2_edition_save(io, e);
    }
    return rc;
}

static int edition_order(const Tb2Edition* a, const Tb2Edition* b) {
    int order = tb2_file_version_compare(&a->label, &b->label);
    return order ? order : a->revision > b->revision ? 1 : a->revision < b->revision ? -1 : 0;
}
static Tb2RecordResult own_package(Tb2WorkflowIO* io, const Tb2Edition* e, Tb2ServerPackage* p) {
    if(e->kind != Tb2ImageModified) return Tb2RecordMissing;
    if(e->package[0]) return tb2_server_package_load(io, e->box, e->package, p);
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!v) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_version_load(io, e->box, e->id, v);
    if(rc == Tb2RecordMissing && (e->flags & Tb2EditionPublished)) rc = Tb2RecordCorrupt;
    if(!rc && !v->artifacts[5].size) rc = Tb2RecordMissing;
    if(!rc) {
        memset(p, 0, sizeof(*p));
        strcpy(p->id, v->id);
        strcpy(p->box, v->box);
        for(unsigned i = 0; i < TB2_SERVER_PACKAGE_OBJECTS; i++) {
            p->objects[i] = v->artifacts[5 + i];
            if(!p->objects[i].size) rc = Tb2RecordCorrupt;
        }
        memcpy(p->ca_fingerprint, v->artifacts[11].digest, 32);
    }
    free(v);
    return rc;
}
typedef struct {
    const Tb2Edition* wanted;
    Tb2Edition best;
} PackageScan;
static Tb2RecordResult package_visit(Tb2WorkflowIO* io, const Tb2Edition* e, void* context) {
    PackageScan* s = context;
    if(e->kind != Tb2ImageModified || !(e->flags & Tb2EditionPublished) ||
       edition_order(e, s->wanted) >= 0)
        return Tb2RecordOk;
    if(s->best.id[0] && edition_order(e, &s->best) < 0) return Tb2RecordOk;
    Tb2ServerPackage* p = calloc(1, sizeof(*p));
    if(!p) return Tb2RecordIo;
    Tb2RecordResult rc = e->package[0] ? Tb2RecordOk : own_package(io, e, p);
    if(rc == Tb2RecordMissing && !e->package[0])
        rc = Tb2RecordOk;
    else if(!rc) {
        if(s->best.id[0] && !edition_order(e, &s->best))
            rc = Tb2RecordConflict;
        else {
            s->best = *e;
        }
    }
    free(p);
    return rc;
}
Tb2RecordResult tb2_package_effective(
    Tb2WorkflowIO* io,
    const Tb2Edition* e,
    Tb2ServerPackage* p,
    char from[TB2_RECORD_ID_SIZE]) {
    memset(p, 0, sizeof(*p));
    from[0] = 0;
    if(e->kind != Tb2ImageModified) return Tb2RecordMissing;
    Tb2RecordResult rc = own_package(io, e, p);
    if(!rc) {
        strcpy(from, e->id);
        return rc;
    }
    /* An explicit missing/broken binding is an error, never a request to fall
     * back silently to an older certificate set. */
    if(e->package[0] || rc != Tb2RecordMissing) return rc;
    PackageScan* scan = calloc(1, sizeof(*scan));
    if(!scan) return Tb2RecordIo;
    scan->wanted = e;
    rc = visit_editions(io, e->box, package_visit, scan);
    if(!rc && !scan->best.id[0]) rc = Tb2RecordMissing;
    if(!rc) {
        rc = own_package(io, &scan->best, p);
        if(!rc) strcpy(from, scan->best.id);
    }
    free(scan);
    return rc;
}
typedef struct {
    const Tb2ObjectRef* object;
    bool found;
} EditionReferences;
static Tb2RecordResult pending_reference(Tb2WorkflowIO* io, const Tb2Edition* e, void* context) {
    (void)io;
    EditionReferences* r = context;
    if(!(e->flags & Tb2EditionPublished) && e->image.size && same_object(r->object, &e->image))
        r->found = true;
    return Tb2RecordOk;
}
Tb2RecordResult tb2_editions_referenced(
    Tb2WorkflowIO* io,
    const char* box,
    const Tb2ObjectRef* object,
    bool* found) {
    EditionReferences refs = {.object = object};
    *found = false;
    Tb2RecordResult rc = visit_editions(io, box, pending_reference, &refs);
    if(rc || refs.found) {
        *found = refs.found;
        return rc;
    }
    Tb2RecordPage* page = calloc(1, sizeof(*page));
    Tb2ServerPackage* p = calloc(1, sizeof(*p));
    if(!page || !p) {
        free(page);
        free(p);
        return Tb2RecordIo;
    }
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    do {
        rc = tb2_record_page_open(io, page, box, anchor, false);
        page->prefix = 'p';
        page->strict = true;
        while(!rc && !page->done)
            rc = tb2_record_page_step(io, page, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && !*found && i < page->count; i++) {
            rc = tb2_server_package_load(io, box, page->ids[i], p);
            for(unsigned j = 0; !rc && !*found && j < TB2_SERVER_PACKAGE_OBJECTS; j++)
                *found = same_object(object, &p->objects[j]);
        }
        if(page->count) strcpy(anchor, page->ids[page->count - 1]);
    } while(!rc && !*found && page->more);
    tb2_record_page_close(io, page);
    free(page);
    free(p);
    return rc;
}
Tb2RecordResult tb2_package_assign(Tb2WorkflowIO* io, Tb2Edition* e, const char* package) {
    if(e->kind != Tb2ImageModified || !(e->flags & Tb2EditionPublished) ||
       !tb2_record_id_valid(package))
        return Tb2RecordConflict;
    Tb2ServerPackage* p = calloc(1, sizeof(*p));
    if(!p) return Tb2RecordIo;
    Tb2RecordResult rc = own_package(io, e, p);
    if(!rc && strcmp(p->id, package)) rc = Tb2RecordConflict;
    if(rc == Tb2RecordMissing && !e->package[0]) rc = Tb2RecordOk;
    if(!rc) rc = tb2_server_package_load(io, e->box, package, p);
    for(unsigned i = 0; !rc && i < TB2_SERVER_PACKAGE_OBJECTS; i++)
        rc = tb2_object_verify(io, &p->objects[i]);
    if(!rc) {
        strcpy(e->package, package);
        e->match = Tb2PackageMatchPending;
        rc = tb2_edition_save(io, e);
    }
    free(p);
    return rc;
}
