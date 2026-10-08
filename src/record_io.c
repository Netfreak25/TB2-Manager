#include "records.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_MAGIC  0x37524254U
#define RECORD_SCHEMA 1U
#define RECORD_HEADER 56U

void tb2_record_wipe(void* data, size_t size) {
    volatile uint8_t* bytes = data;
    while(size--)
        *bytes++ = 0;
}

static void digest_hex(const uint8_t* bytes, char* text) {
    static const char hex[] = "0123456789abcdef";
    for(unsigned i = 0; i < 32; i++) {
        text[2 * i] = hex[bytes[i] >> 4];
        text[2 * i + 1] = hex[bytes[i] & 15];
    }
    text[64] = 0;
}
bool tb2_object_path(char path[TB2_JOB_PATH_MAX], const Tb2ObjectRef* ref) {
    if(!ref || !ref->size) return false;
    char hex[65];
    digest_hex(ref->digest, hex);
    int n = snprintf(path, TB2_JOB_PATH_MAX, "%s/%.2s/%s", TB2_OBJECTS_ROOT, hex, hex);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static void put32(uint8_t* out, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        out[i] = (uint8_t)(value >> (8U * i));
}
static uint32_t get32(const uint8_t* in) {
    uint32_t value = 0;
    for(unsigned i = 0; i < 4; i++)
        value |= (uint32_t)in[i] << (8U * i);
    return value;
}
bool tb2_record_id_valid(const char* id) {
    if(!id) return false;
    for(unsigned i = 0; i < TB2_RECORD_ID_SIZE - 1; i++) {
        if(!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return false;
    }
    return !id[TB2_RECORD_ID_SIZE - 1];
}
bool tb2_record_new_id(Tb2WorkflowIO* io, char id[TB2_RECORD_ID_SIZE]) {
    uint8_t bytes[16];
    static const char hex[] = "0123456789abcdef";
    if(!io->random || io->random(io->context, bytes, sizeof(bytes))) return false;
    for(unsigned i = 0; i < sizeof(bytes); i++) {
        id[2 * i] = hex[bytes[i] >> 4];
        id[2 * i + 1] = hex[bytes[i] & 15];
    }
    id[TB2_RECORD_ID_SIZE - 1] = 0;
    return true;
}
bool tb2_record_path(char path[TB2_JOB_PATH_MAX], const char* box, const char* child) {
    if(!tb2_record_id_valid(box) || !child || strchr(child, '/') || strchr(child, '\\') ||
       strstr(child, ".."))
        return false;
    int n = snprintf(
        path, TB2_JOB_PATH_MAX, "%s/%s%s%s", TB2_BOXES_ROOT, box, child[0] ? "/" : "", child);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static bool slot_path(char* path, const char* base, unsigned slot) {
    int n = snprintf(path, TB2_JOB_PATH_MAX, "%s.%u", base, slot);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static Tb2RecordResult read_slot(
    Tb2WorkflowIO* io,
    const char* path,
    Tb2RecordKind kind,
    const char* binding,
    uint8_t* bytes,
    size_t size,
    uint32_t* sequence) {
    int present = io->exists(io->context, path);
    if(present <= 0) return present ? Tb2RecordIo : Tb2RecordMissing;
    void* file = io->open(io->context, path, Tb2FileRead);
    if(!file) return Tb2RecordIo;
    bool length = io->size(io->context, file) == size;
    bool read = length && io->read(io->context, file, bytes, size) == size;
    bool closed = io->close(io->context, file);
    if(!closed || (length && !read)) return Tb2RecordIo;
    if(!length || get32(bytes) != RECORD_MAGIC || get32(bytes + 4) != RECORD_SCHEMA ||
       get32(bytes + 8) != (uint32_t)kind || get32(bytes + 12) != size || !get32(bytes + 16) ||
       memcmp(bytes + 20, binding, TB2_RECORD_ID_SIZE - 1) ||
       get32(bytes + size - 4) != tb2_job_crc(bytes, size - 4))
        return Tb2RecordCorrupt;
    *sequence = get32(bytes + 16);
    return Tb2RecordOk;
}
Tb2RecordResult tb2_record_read(
    Tb2WorkflowIO* io,
    const char* base,
    Tb2RecordKind kind,
    const char* binding,
    void* payload,
    size_t size,
    uint32_t* generation) {
    if(!io || !payload || !generation || !size || size > TB2_RECORD_META_MAX ||
       !tb2_record_id_valid(binding))
        return Tb2RecordCorrupt;
    size_t total = RECORD_HEADER + size;
    uint8_t* bytes = malloc(total);
    if(!bytes) return Tb2RecordIo;
    char path[TB2_JOB_PATH_MAX];
    uint32_t best = 0;
    Tb2RecordResult result = Tb2RecordMissing;
    for(unsigned slot = 0; slot < 2; slot++) {
        uint32_t sequence = 0;
        Tb2RecordResult rc = slot_path(path, base, slot) ?
                                 read_slot(io, path, kind, binding, bytes, total, &sequence) :
                                 Tb2RecordCorrupt;
        if(rc == Tb2RecordIo) {
            result = rc;
            break;
        }
        if(rc == Tb2RecordOk) {
            if(sequence == best && memcmp(payload, bytes + RECORD_HEADER - 4, size)) {
                result = Tb2RecordCorrupt;
                break;
            }
            if(sequence > best) {
                memcpy(payload, bytes + RECORD_HEADER - 4, size);
                best = sequence;
            }
            result = Tb2RecordOk;
        } else if(!best && rc != Tb2RecordMissing)
            result = rc;
    }
    *generation = result == Tb2RecordOk ? best : 0;
    tb2_record_wipe(bytes, total);
    free(bytes);
    return result;
}
Tb2RecordResult tb2_record_write(
    Tb2WorkflowIO* io,
    const char* base,
    Tb2RecordKind kind,
    const char* binding,
    const void* payload,
    size_t size,
    uint32_t* generation) {
    if(!payload || !generation || !size || size > TB2_RECORD_META_MAX) return Tb2RecordCorrupt;
    size_t total = RECORD_HEADER + size;
    uint8_t* bytes = calloc(1, total);
    if(!bytes) return Tb2RecordIo;
    uint32_t previous = 0;
    Tb2RecordResult rc = tb2_record_read(io, base, kind, binding, bytes, size, &previous);
    bool pending = rc == Tb2RecordCorrupt && !*generation;
    if(rc != Tb2RecordOk && rc != Tb2RecordMissing && !pending) goto done;
    if(previous != *generation || previous == UINT32_MAX) {
        rc = Tb2RecordConflict;
        goto done;
    }
    uint32_t next = previous + 1;
    char path[TB2_JOB_PATH_MAX];
    if(!slot_path(path, base, next & 1U)) {
        rc = Tb2RecordCorrupt;
        goto done;
    }
    memset(bytes, 0, total);
    put32(bytes, RECORD_MAGIC);
    put32(bytes + 4, RECORD_SCHEMA);
    put32(bytes + 8, kind);
    put32(bytes + 12, (uint32_t)total);
    put32(bytes + 16, next);
    memcpy(bytes + 20, binding, TB2_RECORD_ID_SIZE - 1);
    memcpy(bytes + RECORD_HEADER - 4, payload, size);
    put32(bytes + total - 4, tb2_job_crc(bytes, total - 4));
    if(pending) {
        /* First publication can tear before any valid generation exists. Only
         * an exact, shorter prefix of this same first record is retryable.
         * A second slot or a full-length invalid record is never repaired. */
        char other[TB2_JOB_PATH_MAX];
        if(!slot_path(other, base, 0) || io->exists(io->context, other) != 0) goto done;
        void* partial = io->open(io->context, path, Tb2FileRead);
        uint64_t length = partial ? io->size(io->context, partial) : UINT64_MAX;
        uint8_t* check = length < total ? malloc(length ? (size_t)length : 1) : NULL;
        bool matches = partial && check &&
                       io->read(io->context, partial, check, (size_t)length) == length &&
                       !memcmp(check, bytes, (size_t)length);
        if(partial) matches = io->close(io->context, partial) && matches;
        if(check) {
            tb2_record_wipe(check, (size_t)length);
            free(check);
        }
        if(!matches) goto done;
    }
    int present = io->exists(io->context, path);
    if(present < 0) {
        rc = Tb2RecordIo;
        goto done;
    }
    void* file = io->open(io->context, path, present ? Tb2FileUpdate : Tb2FileNew);
    bool ok = file && io->write(io->context, file, bytes, total) == total &&
              io->truncate(io->context, file) && io->sync(io->context, file);
    if(file) ok = io->close(io->context, file) && ok;
    if(!ok) {
        rc = Tb2RecordIo;
        goto done;
    }
    uint32_t read_sequence = 0;
    rc = read_slot(io, path, kind, binding, bytes, total, &read_sequence);
    if(rc == Tb2RecordOk &&
       (read_sequence != next || memcmp(bytes + RECORD_HEADER - 4, payload, size)))
        rc = Tb2RecordCorrupt;
    if(rc == Tb2RecordOk) *generation = next;
done:
    tb2_record_wipe(bytes, total);
    free(bytes);
    return rc;
}

Tb2RecordResult tb2_record_can_create(
    Tb2WorkflowIO* io,
    const char* base,
    Tb2RecordKind kind,
    const char* binding,
    const void* payload,
    size_t size) {
    if(!io || !payload || !size || size > TB2_RECORD_META_MAX || !tb2_record_id_valid(binding))
        return Tb2RecordCorrupt;
    char path[TB2_JOB_PATH_MAX];
    if(!slot_path(path, base, 0)) return Tb2RecordCorrupt;
    int present = io->exists(io->context, path);
    if(present != 0) return present < 0 ? Tb2RecordIo : Tb2RecordConflict;
    if(!slot_path(path, base, 1)) return Tb2RecordCorrupt;
    present = io->exists(io->context, path);
    if(present <= 0) return present < 0 ? Tb2RecordIo : Tb2RecordOk;
    size_t total = RECORD_HEADER + size;
    uint8_t* bytes = calloc(2, total);
    if(!bytes) return Tb2RecordIo;
    put32(bytes, RECORD_MAGIC);
    put32(bytes + 4, RECORD_SCHEMA);
    put32(bytes + 8, kind);
    put32(bytes + 12, (uint32_t)total);
    put32(bytes + 16, 1);
    memcpy(bytes + 20, binding, TB2_RECORD_ID_SIZE - 1);
    memcpy(bytes + RECORD_HEADER - 4, payload, size);
    put32(bytes + total - 4, tb2_job_crc(bytes, total - 4));
    void* file = io->open(io->context, path, Tb2FileRead);
    uint64_t length = file ? io->size(io->context, file) : UINT64_MAX;
    Tb2RecordResult rc = !file ? Tb2RecordIo : length >= total ? Tb2RecordCorrupt : Tb2RecordOk;
    if(!rc && io->read(io->context, file, bytes + total, (size_t)length) != length)
        rc = Tb2RecordIo;
    if(!rc && memcmp(bytes, bytes + total, (size_t)length)) rc = Tb2RecordConflict;
    if(file && !io->close(io->context, file)) rc = Tb2RecordIo;
    tb2_record_wipe(bytes, 2 * total);
    free(bytes);
    return rc;
}

Tb2RecordResult tb2_record_page_open(
    Tb2WorkflowIO* io,
    Tb2RecordPage* page,
    const char* box,
    const char* anchor,
    bool reverse) {
    memset(page, 0, sizeof(*page));
    if(!io->dir_open || !io->dir_read || !io->dir_close ||
       (anchor && anchor[0] && !tb2_record_id_valid(anchor)))
        return Tb2RecordCorrupt;
    page->versions = box != NULL;
    page->reverse = reverse;
    if(anchor) snprintf(page->anchor, sizeof(page->anchor), "%s", anchor);
    char path[TB2_JOB_PATH_MAX];
    if(box && !tb2_record_path(path, box, "")) return Tb2RecordCorrupt;
    int exists = io->exists(io->context, box ? path : TB2_BOXES_ROOT);
    if(!exists) {
        page->done = true;
        return Tb2RecordOk;
    }
    if(exists < 0) return Tb2RecordIo;
    page->directory = io->dir_open(io->context, box ? path : TB2_BOXES_ROOT);
    return page->directory ? Tb2RecordOk : Tb2RecordIo;
}
void tb2_record_page_close(Tb2WorkflowIO* io, Tb2RecordPage* page) {
    if(page->directory) io->dir_close(io->context, page->directory);
    page->directory = NULL;
    page->done = true;
}
Tb2RecordResult tb2_record_page_step(Tb2WorkflowIO* io, Tb2RecordPage* page, unsigned budget) {
    if(page->done) return Tb2RecordOk;
    char name[80];
    for(unsigned n = 0; n < budget; n++) {
        if(io->cancelled && io->cancelled(io->context)) {
            tb2_record_page_close(io, page);
            return Tb2RecordCancelled;
        }
        bool directory = false;
        int rc = io->dir_read(io->context, page->directory, name, sizeof(name), &directory);
        if(rc <= 0) {
            bool closed = io->dir_close(io->context, page->directory);
            page->directory = NULL;
            page->done = true;
            return rc == 0 && closed ? Tb2RecordOk : Tb2RecordIo;
        }
        char* id = name;
        if(!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if(page->versions) {
            char prefix = page->prefix ? page->prefix : 'v';
            if(name[0] != prefix || name[1] != '-') continue;
            if(directory || strlen(name) != 36 ||
               (strcmp(name + 34, ".0") && strcmp(name + 34, ".1"))) {
                if(page->strict) return Tb2RecordCorrupt;
                continue;
            }
            name[34] = 0;
            id = name + 2;
        } else if(!directory)
            continue;
        if(!tb2_record_id_valid(id)) {
            if(page->strict) return Tb2RecordCorrupt;
            continue;
        }
        int anchor_order = strcmp(id, page->anchor);
        if(page->anchor[0] && (page->reverse ? anchor_order >= 0 : anchor_order <= 0)) continue;
        unsigned at = 0;
        while(at < page->count) {
            int order = strcmp(id, page->ids[at]);
            if(!order) break;
            if(page->reverse ? order > 0 : order < 0) break;
            at++;
        }
        if(at < page->count && !strcmp(id, page->ids[at])) continue;
        if(page->count == TB2_RECORD_PAGE_SIZE) page->more = true;
        if(at >= TB2_RECORD_PAGE_SIZE) continue;
        if(page->count < TB2_RECORD_PAGE_SIZE) page->count++;
        for(unsigned j = page->count - 1; j > at; j--)
            memcpy(page->ids[j], page->ids[j - 1], TB2_RECORD_ID_SIZE);
        memcpy(page->ids[at], id, TB2_RECORD_ID_SIZE);
    }
    return Tb2RecordOk;
}
