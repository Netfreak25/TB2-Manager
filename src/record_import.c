#include "record_import.h"
#include "editions.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMPORT_BLOCK  512U
#define IMPORT_HEADER 56U
typedef struct {
    Tb2WorkflowIO* live;
    Tb2WorkflowIO staged;
    Tb2RecordTask* task;
    char root[128];
    Tb2BoxRecord incoming, current;
    Tb2BoxVersion version, existing;
    uint8_t bytes[TB2_RECORD_CHUNK];
    bool new_box;
} RecordImport;

/* The adapter only rewrites canonical record paths. File/directory handles
 * remain owned by the resident IO layer, including all close/error paths. */
static bool mapped(RecordImport* a, const char* path, char out[TB2_JOB_PATH_MAX]) {
    size_t prefix = strlen(TB2_APP_ROOT);
    if(strncmp(path, TB2_APP_ROOT, prefix) || (path[prefix] && path[prefix] != '/')) return false;
    int n = snprintf(out, TB2_JOB_PATH_MAX, "%s%s", a->root, path + prefix);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static void* s_open(void* ctx, const char* path, Tb2FileMode mode) {
    RecordImport* a = ctx;
    char p[TB2_JOB_PATH_MAX];
    return mapped(a, path, p) ? a->live->open(a->live->context, p, mode) : NULL;
}
static int s_exists(void* ctx, const char* path) {
    RecordImport* a = ctx;
    char p[TB2_JOB_PATH_MAX];
    return mapped(a, path, p) ? a->live->exists(a->live->context, p) : -1;
}
static void* s_dir(void* ctx, const char* path) {
    RecordImport* a = ctx;
    char p[TB2_JOB_PATH_MAX];
    return mapped(a, path, p) ? a->live->dir_open(a->live->context, p) : NULL;
}
static size_t s_read(void* ctx, void* f, void* bytes, size_t size) {
    RecordImport* a = ctx;
    return a->live->read(a->live->context, f, bytes, size);
}
static uint64_t s_size(void* ctx, void* f) {
    RecordImport* a = ctx;
    return a->live->size(a->live->context, f);
}
static bool s_close(void* ctx, void* f) {
    RecordImport* a = ctx;
    return a->live->close(a->live->context, f);
}
static bool s_dir_close(void* ctx, void* f) {
    RecordImport* a = ctx;
    return a->live->dir_close(a->live->context, f);
}
static int s_next(void* ctx, void* f, char* name, size_t size, bool* dir) {
    RecordImport* a = ctx;
    return a->live->dir_read(a->live->context, f, name, size, dir);
}
static bool s_cancel(void* ctx) {
    RecordImport* a = ctx;
    return a->live->cancelled && a->live->cancelled(a->live->context);
}
static void s_progress(void* ctx, const char* stage, uint32_t done, uint32_t total) {
    RecordImport* a = ctx;
    if(a->live->progress) a->live->progress(a->live->context, stage, done, total);
}
static bool all_zero(const uint8_t* bytes, size_t size) {
    for(size_t i = 0; i < size; i++)
        if(bytes[i]) return false;
    return true;
}
static bool octal(const uint8_t* bytes, size_t size, uint32_t* value) {
    *value = 0;
    bool ended = false, digit = false;
    for(size_t i = 0; i < size; i++) {
        uint8_t c = bytes[i];
        if(!c || c == ' ') {
            if(digit) ended = true;
            continue;
        }
        if(ended || c < '0' || c > '7' || *value > (UINT32_MAX - (c - '0')) / 8U) return false;
        *value = *value * 8 + c - '0';
        digit = true;
    }
    return digit;
}
static uint32_t little32(const uint8_t* bytes) {
    uint32_t n = 0;
    for(unsigned i = 0; i < 4; i++)
        n |= (uint32_t)bytes[i] << (i * 8);
    return n;
}
static bool hex_digest(const char* hex, uint8_t digest[32]) {
    if(strlen(hex) != 64) return false;
    for(unsigned i = 0; i < 64; i++) {
        unsigned value = hex[i] >= '0' && hex[i] <= '9' ? hex[i] - '0' :
                         hex[i] >= 'a' && hex[i] <= 'f' ? hex[i] - 'a' + 10 :
                                                          16;
        if(value > 15) return false;
        if(!(i & 1U))
            digest[i / 2] = (uint8_t)(value << 4);
        else
            digest[i / 2] |= (uint8_t)value;
    }
    return true;
}
/** Closed namespace: one box, exact metadata names, SHA-named regular objects.
 * No path normalization is needed or permitted. */
static bool member_name(
    RecordImport* a,
    const char* name,
    uint32_t size,
    Tb2RecordKind* kind,
    uint8_t hash[32]) {
    *kind = 0;
    if(!strncmp(name, "objects/", 8)) {
        if(strlen(name) != 75 || name[10] != '/' || name[8] != name[11] || name[9] != name[12])
            return false;
        return size && size <= TB2_IMAGE_SIZE && hex_digest(name + 11, hash);
    }
    if(strncmp(name, "boxes/", 6) || strlen(name) < 44 || name[38] != '/') return false;
    char id[TB2_RECORD_ID_SIZE];
    memcpy(id, name + 6, 32);
    id[32] = 0;
    if(!tb2_record_id_valid(id) || (a->task->box[0] && strcmp(a->task->box, id))) return false;
    const char* child = name + 39;
    size_t payload = 0;
    if(!strcmp(child, "box.0") || !strcmp(child, "box.1")) {
        *kind = Tb2RecordBox;
        payload = TB2_BOX_PAYLOAD_SIZE;
    } else if(!strcmp(child, "files.0") || !strcmp(child, "files.1")) {
        *kind = Tb2RecordFolder;
        payload = TB2_FOLDER_PAYLOAD_SIZE;
    } else {
        if(strlen(child) != 36 || child[1] != '-' || child[34] != '.' ||
           (child[35] != '0' && child[35] != '1'))
            return false;
        char entry[TB2_RECORD_ID_SIZE];
        memcpy(entry, child + 2, 32);
        entry[32] = 0;
        if(!tb2_record_id_valid(entry)) return false;
        switch(child[0]) {
        case 'f':
            *kind = Tb2RecordEdition;
            payload = TB2_EDITION_PAYLOAD_SIZE;
            break;
        case 'p':
            *kind = Tb2RecordPackage;
            payload = TB2_SERVER_PACKAGE_PAYLOAD_SIZE;
            break;
        case 'v':
            *kind = Tb2RecordVersion;
            payload = TB2_VERSION_PAYLOAD_SIZE;
            break;
        case 'k':
            *kind = Tb2RecordSecret;
            payload = TB2_SECRET_PAYLOAD_SIZE;
            break;
        case 'n':
            *kind = Tb2RecordNote;
            payload = TB2_ENTRY_PAYLOAD_SIZE;
            break;
        case 'e':
            *kind = Tb2RecordEvent;
            payload = TB2_ENTRY_PAYLOAD_SIZE;
            break;
        default:
            return false;
        }
    }
    if(size != payload + IMPORT_HEADER) return false;
    strcpy(a->task->box, id);
    return true;
}
static bool make_parents(RecordImport* a, char* path) {
    size_t prefix = strlen(a->root);
    for(char* p = path + prefix; *p; p++) {
        if(*p != '/') continue;
        *p = 0;
        bool ok = a->live->mkdir(a->live->context, path);
        *p = '/';
        if(!ok) return false;
    }
    return true;
}
static Tb2RecordResult extract(RecordImport* a) {
    Tb2WorkflowIO* io = a->live;
    void* input = io->open(io->context, a->task->path, Tb2FileRead);
    if(!input) return Tb2RecordIo;
    uint64_t length = io->size(io->context, input);
    Tb2RecordResult rc = length >= IMPORT_BLOCK * 2 && length <= UINT32_MAX &&
                                 !(length % IMPORT_BLOCK) ?
                             Tb2RecordOk :
                             Tb2RecordCorrupt;
    uint32_t offset = 0;
    bool ended = false;
    while(!rc && offset < length) {
        if(s_cancel(a)) {
            rc = Tb2RecordCancelled;
            break;
        }
        if(io->read(io->context, input, a->bytes, IMPORT_BLOCK) != IMPORT_BLOCK) {
            rc = Tb2RecordIo;
            break;
        }
        offset += IMPORT_BLOCK;
        if(all_zero(a->bytes, IMPORT_BLOCK)) {
            if(length - offset != IMPORT_BLOCK ||
               io->read(io->context, input, a->bytes, IMPORT_BLOCK) != IMPORT_BLOCK ||
               !all_zero(a->bytes, IMPORT_BLOCK))
                rc = Tb2RecordCorrupt;
            ended = true;
            break;
        }
        uint32_t size, checksum, sum = 0;
        for(unsigned i = 0; i < IMPORT_BLOCK; i++)
            sum += i >= 148 && i < 156 ? ' ' : a->bytes[i];
        if(!memchr(a->bytes, 0, 100) || !octal(a->bytes + 124, 12, &size) ||
           !octal(a->bytes + 148, 8, &checksum) || sum != checksum ||
           (a->bytes[156] != '0' && a->bytes[156] != 0) || memcmp(a->bytes + 257, "ustar\0", 6) ||
           memcmp(a->bytes + 263, "00", 2) || !all_zero(a->bytes + 157, 100) ||
           !all_zero(a->bytes + 345, 167)) {
            rc = Tb2RecordCorrupt;
            break;
        }
        char name[100], path[TB2_JOB_PATH_MAX];
        strcpy(name, (char*)a->bytes);
        uint8_t expected[32];
        Tb2RecordKind kind;
        uint64_t padded = ((uint64_t)size + IMPORT_BLOCK - 1) / IMPORT_BLOCK * IMPORT_BLOCK;
        if(padded > length - offset || !member_name(a, name, size, &kind, expected)) {
            rc = Tb2RecordCorrupt;
            break;
        }
        int n = snprintf(path, sizeof(path), "%s/%s", a->root, name);
        if(n <= 0 || n >= (int)sizeof(path)) {
            rc = Tb2RecordCorrupt;
            break;
        }
        if(kind) {
            /* Even the alternate generation is a duplicate logical member. */
            size_t last = strlen(path) - 1;
            char slot = path[last];
            path[last] = slot == '0' ? '1' : '0';
            int other = io->exists(io->context, path);
            path[last] = slot;
            if(other != 0) {
                rc = Tb2RecordConflict;
                break;
            }
        }
        if(io->exists(io->context, path) != 0 || !make_parents(a, path)) {
            rc = Tb2RecordConflict;
            break;
        }
        void* output = io->open(io->context, path, Tb2FileNew);
        if(!output) {
            rc = Tb2RecordIo;
            break;
        }
        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        if(mbedtls_sha256_starts(&sha, 0)) rc = Tb2RecordIo;
        for(uint32_t done = 0; !rc && done < size;) {
            size_t count = size - done;
            if(count > sizeof(a->bytes)) count = sizeof(a->bytes);
            if(s_cancel(a))
                rc = Tb2RecordCancelled;
            else if(
                io->read(io->context, input, a->bytes, count) != count ||
                io->write(io->context, output, a->bytes, count) != count ||
                mbedtls_sha256_update(&sha, a->bytes, count))
                rc = Tb2RecordIo;
            done += (uint32_t)count;
            s_progress(a, "Check import", offset + done, (uint32_t)length);
        }
        if(!rc && kind) {
            size_t name_size = strlen(name);
            if(little32(a->bytes) != 0x37524254U || little32(a->bytes + 4) != 1 ||
               little32(a->bytes + 8) != (uint32_t)kind || little32(a->bytes + 12) != size ||
               !little32(a->bytes + 16) ||
               (little32(a->bytes + 16) & 1U) != (unsigned)(name[name_size - 1] - '0') ||
               memcmp(a->bytes + 20, a->task->box, 32) ||
               little32(a->bytes + size - 4) != tb2_job_crc(a->bytes, size - 4))
                rc = Tb2RecordCorrupt;
        }
        uint8_t actual[32];
        if(!rc && mbedtls_sha256_finish(&sha, actual)) rc = Tb2RecordIo;
        if(!rc && !kind && memcmp(actual, expected, 32)) rc = Tb2RecordCorrupt;
        mbedtls_sha256_free(&sha);
        bool synced = io->sync(io->context, output), closed = io->close(io->context, output);
        if(!synced || !closed) rc = Tb2RecordIo;
        size_t padding = (size_t)padded - size;
        if(!rc && padding &&
           (io->read(io->context, input, a->bytes, padding) != padding ||
            !all_zero(a->bytes, padding)))
            rc = Tb2RecordCorrupt;
        offset += (uint32_t)padded;
    }
    if(!rc && (!ended || !a->task->box[0])) rc = Tb2RecordCorrupt;
    if(!io->close(io->context, input)) rc = Tb2RecordIo;
    return rc;
}

static Tb2RecordResult identity(RecordImport* a) {
    Tb2RecordResult rc = tb2_box_load(&a->staged, a->task->box, &a->incoming);
    if(rc) return rc;
    rc = tb2_box_load(a->live, a->task->box, &a->current);
    a->new_box = rc == Tb2RecordMissing || rc == Tb2RecordCorrupt;
    if(a->new_box) {
        a->current = a->incoming;
        a->current.generation = 0;
        a->current.next_version = 0;
        a->current.secret[0] = a->current.candidate[0] = 0;
        rc = tb2_box_can_create(a->live, &a->current);
    }
    if(rc) return rc;
    if((a->current.has_uid && a->incoming.has_uid && memcmp(a->current.uid, a->incoming.uid, 8)) ||
       (a->current.box_id[0] && a->incoming.box_id[0] &&
        strcmp(a->current.box_id, a->incoming.box_id)))
        return Tb2RecordConflict;
    Tb2RecordPage page;
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    bool more;
    do {
        rc = tb2_record_page_open(a->live, &page, NULL, anchor, false);
        page.strict = true;
        while(!rc && !page.done)
            rc = tb2_record_page_step(a->live, &page, 4);
        more = page.more;
        for(unsigned i = 0; !rc && i < page.count; i++) {
            if(!strcmp(page.ids[i], a->task->box)) {
                strcpy(anchor, page.ids[i]);
                continue; /* The same record was checked above, including a pending first write. */
            }
            Tb2BoxRecord box;
            rc = tb2_box_load(a->live, page.ids[i], &box);
            if(!rc && strcmp(box.id, a->task->box) &&
               ((box.has_uid && a->incoming.has_uid && !memcmp(box.uid, a->incoming.uid, 8)) ||
                (box.box_id[0] && !strcmp(box.box_id, a->incoming.box_id))))
                rc = Tb2RecordConflict;
            strcpy(anchor, page.ids[i]);
        }
        tb2_record_page_close(a->live, &page);
    } while(!rc && more);
    return rc;
}
static Tb2RecordResult object(RecordImport* a, const Tb2ObjectRef* ref, bool publish) {
    if(!ref->size) return Tb2RecordOk;
    if(!publish) return tb2_object_verify(&a->staged, ref);
    char canonical[TB2_JOB_PATH_MAX], path[TB2_JOB_PATH_MAX];
    Tb2ObjectRef result;
    if(!tb2_object_path(canonical, ref) || !mapped(a, canonical, path)) return Tb2RecordCorrupt;
    return tb2_object_put(a->live, path, a->task->staging, ref, &result);
}
/** Persist local numbering before version publication, so a power cut cannot
 * assign another number to the same incomplete imported version on retry. */
static Tb2RecordResult reserve_number(RecordImport* a, bool publish) {
    char child[40], path[TB2_JOB_PATH_MAX];
    snprintf(child, sizeof(child), "i-%s", a->version.id);
    if(!tb2_record_path(path, a->task->box, child)) return Tb2RecordCorrupt;
    uint8_t bytes[36] = {0};
    uint32_t generation = 0, number = 0;
    Tb2RecordResult rc = tb2_record_read(
        a->live, path, Tb2RecordBinding, a->task->box, bytes, sizeof(bytes), &generation);
    bool create = rc == Tb2RecordMissing || rc == Tb2RecordCorrupt;
    if(create) {
        if(a->current.next_version == UINT32_MAX) return Tb2RecordConflict;
        number = a->current.next_version + 1;
        for(unsigned i = 0; i < 4; i++)
            bytes[i] = (uint8_t)(number >> (8 * i));
        memcpy(bytes + 4, a->version.image.digest, 32);
        rc = tb2_record_can_create(
            a->live, path, Tb2RecordBinding, a->task->box, bytes, sizeof(bytes));
    } else if(!rc) {
        number = little32(bytes);
        if(!number || memcmp(bytes + 4, a->version.image.digest, 32)) rc = Tb2RecordConflict;
    }
    if(!rc && publish && create)
        rc = tb2_record_write(
            a->live, path, Tb2RecordBinding, a->task->box, bytes, sizeof(bytes), &generation);
    if(!rc) {
        a->version.number = number;
        a->version.generation = 0;
        rc = tb2_version_can_create(a->live, &a->version);
    }
    if(!rc && publish && number > a->current.next_version) {
        a->current.next_version = number;
        rc = tb2_box_save(a->live, &a->current);
    }
    return rc;
}
static Tb2RecordResult version(RecordImport* a, const char* id, bool publish) {
    Tb2RecordResult rc = tb2_version_load(&a->staged, a->task->box, id, &a->version);
    if(rc) return rc;
    bool missing = false;
    rc = tb2_version_load(a->live, a->task->box, id, &a->existing);
    if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) {
        missing = true;
        rc = reserve_number(a, publish);
    } else if(!rc && !tb2_version_same_content(&a->existing, &a->version))
        rc = Tb2RecordConflict;
    if(!rc && a->version.secret[0]) {
        Tb2BoxSecret key;
        rc = tb2_secret_load(&a->staged, a->task->box, a->version.secret, &key);
        tb2_record_wipe(&key, sizeof(key));
    }
    if(!rc && a->version.parent[0]) {
        Tb2BoxVersion* parent = calloc(1, sizeof(*parent));
        rc = parent ? tb2_version_load(&a->staged, a->task->box, a->version.parent, parent) :
                      Tb2RecordIo;
        free(parent);
    }
    bool deleted = (a->version.flags & Tb2VersionDeleted) != 0;
    if(!rc && !deleted) rc = object(a, &a->version.image, publish);
    for(unsigned j = deleted ? 5 : 0; !rc && j < TB2_RECORD_ARTIFACTS; j++)
        rc = object(a, &a->version.artifacts[j], publish);
    if(!rc && missing && publish) {
        a->version.generation = 0;
        rc = tb2_version_save(a->live, &a->version);
    }
    return rc;
}
static Tb2RecordResult key(RecordImport* a, const char* id, bool publish) {
    Tb2BoxSecret keys[2];
    Tb2RecordResult rc = tb2_secret_load(&a->staged, a->task->box, id, keys);
    if(!rc) {
        rc = tb2_secret_load(a->live, a->task->box, id, keys + 1);
        if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) {
            keys[0].generation = 0;
            keys[0].verified = false;
            rc = tb2_secret_can_create(a->live, a->task->box, keys);
            if(!rc && publish) {
                rc = tb2_secret_save(a->live, a->task->box, keys);
                if(!rc && !a->current.candidate[0]) strcpy(a->current.candidate, id);
            }
        } else if(
            !rc && (keys[0].key.kind != keys[1].key.kind ||
                    memcmp(keys[0].key.bytes, keys[1].key.bytes, sizeof(keys[0].key.bytes))))
            rc = Tb2RecordConflict;
        else if(!rc && publish && !keys[1].verified && !a->current.candidate[0])
            strcpy(a->current.candidate, id);
    }
    tb2_record_wipe(keys, sizeof(keys));
    return rc;
}
static Tb2RecordResult entry(RecordImport* a, const char* id, bool note, bool publish) {
    Tb2BoxEntry* items = calloc(2, sizeof(*items));
    if(!items) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_entry_load(&a->staged, a->task->box, id, note, items);
    if(!rc) {
        rc = tb2_entry_load(a->live, a->task->box, id, note, items + 1);
        if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) {
            items[0].generation = 0;
            rc = tb2_entry_can_create(a->live, items);
            if(!rc && publish) {
                rc = tb2_entry_save(a->live, items);
            }
        } else if(!rc && !tb2_entry_same_content(items, items + 1))
            rc = Tb2RecordConflict;
    }
    free(items);
    return rc;
}
static Tb2RecordResult import_entries(RecordImport* a, char prefix, bool publish) {
    Tb2RecordPage page;
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    bool more;
    do {
        rc = tb2_record_page_open(&a->staged, &page, a->task->box, anchor, false);
        page.prefix = prefix;
        page.strict = true;
        while(!rc && !page.done)
            rc = tb2_record_page_step(&a->staged, &page, 4);
        more = page.more;
        for(unsigned i = 0; !rc && i < page.count; i++) {
            rc = prefix == 'v' ? version(a, page.ids[i], publish) :
                 prefix == 'k' ? key(a, page.ids[i], publish) :
                                 entry(a, page.ids[i], prefix == 'n', publish);
            strcpy(anchor, page.ids[i]);
        }
        tb2_record_page_close(&a->staged, &page);
    } while(!rc && more);
    return rc;
}
Tb2RecordResult tb2_record_import(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    RecordImport* a = calloc(1, sizeof(*a));
    if(!a) return Tb2RecordIo;
    a->live = io;
    a->task = task;
    a->staged = (Tb2WorkflowIO){
        .context = a,
        .open = s_open,
        .read = s_read,
        .size = s_size,
        .close = s_close,
        .exists = s_exists,
        .dir_open = s_dir,
        .dir_read = s_next,
        .dir_close = s_dir_close,
        .cancelled = s_cancel,
        .progress = s_progress};
    char id[TB2_RECORD_ID_SIZE];
    Tb2RecordResult rc = tb2_record_new_id(io, id) ? Tb2RecordOk : Tb2RecordIo;
    if(!rc) {
        int n = snprintf(task->staging, sizeof(task->staging), "%s/import-%s", TB2_JOBS_ROOT, id);
        if(n <= 0 || n >= (int)sizeof(task->staging))
            rc = Tb2RecordCorrupt;
        else if(
            io->exists(io->context, task->staging) != 0 ||
            !io->mkdir(io->context, TB2_JOBS_ROOT) || !io->mkdir(io->context, task->staging))
            rc = Tb2RecordIo;
        snprintf(a->root, sizeof(a->root), "%s", task->staging);
    }
    if(!rc) rc = extract(a);
    if(!rc) rc = identity(a);
    const char prefixes[] = "kvne";
    for(unsigned i = 0; !rc && i < 4; i++)
        rc = import_entries(a, prefixes[i], false);
    if(!rc && a->incoming.secret[0]) {
        Tb2BoxSecret secret;
        rc = tb2_secret_load(&a->staged, task->box, a->incoming.secret, &secret);
        tb2_record_wipe(&secret, sizeof(secret));
    }
    if(!rc && a->incoming.candidate[0]) {
        Tb2BoxSecret secret;
        rc = tb2_secret_load(&a->staged, task->box, a->incoming.candidate, &secret);
        tb2_record_wipe(&secret, sizeof(secret));
    }
    /* All archive members/references/conflicts have been checked. Objects are
     * published before each referencing version; a partial import is retryable
     * and never creates a complete-looking version with missing binary data. */
    if(!rc && a->new_box) {
        a->current.secret[0] = a->current.candidate[0] = 0;
        rc = tb2_box_save(io, &a->current);
    }
    for(unsigned i = 0; !rc && i < 4; i++)
        rc = import_entries(a, prefixes[i], true);
    if(!rc) rc = tb2_box_save(io, &a->current);
    if(!rc)
        snprintf(
            task->report,
            sizeof(task->report),
            "Record imported.\n%s\nResults remain Saved state.\nAlias and verified keys kept.\nImported keys need image validation; jobs cannot resume.",
            a->current.alias);
    tb2_record_wipe(a, sizeof(*a));
    free(a);
    return rc;
}
