#include "records.h"
#include "editions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOX_PAYLOAD     TB2_BOX_PAYLOAD_SIZE
#define VERSION_PAYLOAD TB2_VERSION_PAYLOAD_SIZE
#define SECRET_PAYLOAD  TB2_SECRET_PAYLOAD_SIZE
#define ENTRY_PAYLOAD   TB2_ENTRY_PAYLOAD_SIZE
#define VERSION_FLAGS   1023U

typedef struct {
    uint8_t* bytes;
    size_t cursor, capacity;
    bool encode, valid;
} Codec;
static void field(Codec* c, void* data, size_t size) {
    if(!c->valid || size > c->capacity - c->cursor) {
        c->valid = false;
        return;
    }
    if(c->encode)
        memcpy(c->bytes + c->cursor, data, size);
    else
        memcpy(data, c->bytes + c->cursor, size);
    c->cursor += size;
}
static void number(Codec* c, uint32_t* value) {
    uint8_t bytes[4];
    if(c->encode)
        for(unsigned i = 0; i < 4; i++)
            bytes[i] = (uint8_t)(*value >> (8 * i));
    field(c, bytes, sizeof(bytes));
    if(!c->encode && c->valid) {
        *value = 0;
        for(unsigned i = 0; i < 4; i++)
            *value |= (uint32_t)bytes[i] << (8 * i);
    }
}
static void flag(Codec* c, bool* value) {
    uint8_t byte = *value ? 1 : 0;
    field(c, &byte, 1);
    if(byte > 1) c->valid = false;
    if(!c->encode) *value = byte == 1;
}
static void string(Codec* c, char* value, size_t size) {
    if(c->encode) {
        const char* end = memchr(value, 0, size);
        if(!end) {
            c->valid = false;
            return;
        }
        size_t length = (size_t)(end - value);
        field(c, value, length);
        if(size - length > c->capacity - c->cursor) {
            c->valid = false;
            return;
        }
        memset(c->bytes + c->cursor, 0, size - length);
        c->cursor += size - length;
    } else
        field(c, value, size);
    bool ended = false;
    for(size_t i = 0; i < size; i++) {
        unsigned char ch = (unsigned char)value[i];
        if(!ch)
            ended = true;
        else if((ended && !c->encode) || (!ended && (ch < 32 || ch > 126))) {
            c->valid = false;
            break;
        }
    }
    if(!ended) c->valid = false;
}
static void object(Codec* c, Tb2ObjectRef* ref) {
    field(c, ref->digest, sizeof(ref->digest));
    number(c, &ref->size);
}
static bool box_codec(Tb2BoxRecord* box, uint8_t* bytes, bool encode) {
    Codec c = {.bytes = bytes, .capacity = BOX_PAYLOAD, .encode = encode, .valid = true};
    string(&c, box->id, sizeof(box->id));
    string(&c, box->alias, sizeof(box->alias));
    string(&c, box->serial, sizeof(box->serial));
    string(&c, box->box_id, sizeof(box->box_id));
    field(&c, box->uid, sizeof(box->uid));
    flag(&c, &box->has_uid);
    number(&c, &box->next_version);
    string(&c, box->secret, sizeof(box->secret));
    string(&c, box->candidate, sizeof(box->candidate));
    return c.valid && tb2_record_id_valid(box->id) && box->alias[0] &&
           (!box->secret[0] || tb2_record_id_valid(box->secret)) &&
           (!box->candidate[0] || tb2_record_id_valid(box->candidate));
}
static bool version_codec(Tb2BoxVersion* v, uint8_t* bytes, bool encode) {
    Codec c = {.bytes = bytes, .capacity = VERSION_PAYLOAD, .encode = encode, .valid = true};
    string(&c, v->id, sizeof(v->id));
    string(&c, v->box, sizeof(v->box));
    string(&c, v->parent, sizeof(v->parent));
    string(&c, v->job, sizeof(v->job));
    string(&c, v->created, sizeof(v->created));
    string(&c, v->app, sizeof(v->app));
    string(&c, v->name, sizeof(v->name));
    number(&c, &v->number);
    number(&c, &v->flags);
    flag(&c, &v->firmware.known);
    string(&c, v->firmware.version, sizeof(v->firmware.version));
    field(&c, v->firmware.digest, sizeof(v->firmware.digest));
    object(&c, &v->image);
    for(unsigned i = 0; i < TB2_RECORD_ARTIFACTS; i++)
        object(&c, &v->artifacts[i]);
    string(&c, v->endpoints.https_host, sizeof(v->endpoints.https_host));
    string(&c, v->endpoints.mqtt_host, sizeof(v->endpoints.mqtt_host));
    uint32_t https = v->endpoints.https_port, mqtt = v->endpoints.mqtt_port;
    number(&c, &https);
    number(&c, &mqtt);
    v->endpoints.https_port = (uint16_t)https;
    v->endpoints.mqtt_port = (uint16_t)mqtt;
    field(&c, v->ca_fingerprint, sizeof(v->ca_fingerprint));
    field(&c, v->client_fingerprint, sizeof(v->client_fingerprint));
    string(&c, v->secret, sizeof(v->secret));
    return c.valid && tb2_record_id_valid(v->box) && tb2_record_id_valid(v->id) &&
           (!v->parent[0] || tb2_record_id_valid(v->parent)) && v->number &&
           !(v->flags & ~VERSION_FLAGS) && (!v->secret[0] || tb2_record_id_valid(v->secret)) &&
           v->image.size == TB2_IMAGE_SIZE &&
           (!(v->flags & Tb2VersionOriginal) || (v->flags & Tb2VersionSource)) &&
           (!(v->flags & Tb2VersionEndpointsKnown) ||
            (https && mqtt && https <= UINT16_MAX && mqtt <= UINT16_MAX));
}
static bool secret_codec(Tb2BoxSecret* key, uint8_t* bytes, bool encode) {
    Codec c = {.bytes = bytes, .capacity = SECRET_PAYLOAD, .encode = encode, .valid = true};
    string(&c, key->id, sizeof(key->id));
    uint32_t kind = key->key.kind;
    number(&c, &kind);
    key->key.kind = (Tb2InputKeyKind)kind;
    if(encode && kind == Tb2InputKeySecret)
        memset(key->key.bytes + TB2_SN_SIZE, 0, TB2_AES_KEY_SIZE - TB2_SN_SIZE);
    field(&c, key->key.bytes, sizeof(key->key.bytes));
    number(&c, &key->profile);
    field(&c, key->firmware, sizeof(key->firmware));
    flag(&c, &key->verified);
    return c.valid && tb2_record_id_valid(key->id) &&
           (kind == Tb2InputKeySecret || kind == Tb2InputKeyAes) &&
           (!key->verified ||
            (kind == Tb2InputKeyAes ? key->profile == 3 : key->profile == 1 || key->profile == 2));
}
static bool entry_codec(Tb2BoxEntry* e, uint8_t* bytes, bool encode) {
    Codec c = {.bytes = bytes, .capacity = ENTRY_PAYLOAD, .encode = encode, .valid = true};
    string(&c, e->id, sizeof(e->id));
    string(&c, e->box, sizeof(e->box));
    string(&c, e->version, sizeof(e->version));
    string(&c, e->job, sizeof(e->job));
    string(&c, e->text, sizeof(e->text));
    number(&c, &e->timestamp);
    number(&c, &e->type);
    number(&c, &e->state);
    number(&c, &e->flags);
    number(&c, &e->sequence);
    uint32_t code = (uint32_t)e->code;
    number(&c, &code);
    e->code = (int32_t)code;
    flag(&c, &e->note);
    return c.valid && tb2_record_id_valid(e->id) && tb2_record_id_valid(e->box) &&
           (!e->version[0] || tb2_record_id_valid(e->version)) && (!e->note || e->text[0]);
}
static bool entry_path(char* out, const char* box, const char* id, const char* prefix) {
    char child[40];
    if(!tb2_record_id_valid(id)) return false;
    snprintf(child, sizeof(child), "%s%s", prefix, id);
    return tb2_record_path(out, box, child);
}
bool tb2_version_same_content(const Tb2BoxVersion* a, const Tb2BoxVersion* b) {
    Tb2BoxVersion* copies = calloc(2, sizeof(*copies));
    uint8_t* bytes = calloc(2, VERSION_PAYLOAD);
    if(!copies || !bytes) {
        free(copies);
        free(bytes);
        return false;
    }
    copies[0] = *a;
    copies[1] = *b;
    copies[1].number = copies[0].number;
    const uint32_t local_flags = Tb2VersionOriginal | Tb2VersionWorking | Tb2VersionProtected |
                                 Tb2VersionClassified | Tb2VersionDeleted;
    copies[1].flags = (copies[1].flags & ~local_flags) | (copies[0].flags & local_flags);
    bool same = version_codec(copies, bytes, true) &&
                version_codec(copies + 1, bytes + VERSION_PAYLOAD, true) &&
                !memcmp(bytes, bytes + VERSION_PAYLOAD, VERSION_PAYLOAD);
    free(copies);
    free(bytes);
    return same;
}
bool tb2_entry_same_content(const Tb2BoxEntry* a, const Tb2BoxEntry* b) {
    Tb2BoxEntry copies[2] = {*a, *b};
    uint8_t* bytes = calloc(2, ENTRY_PAYLOAD);
    if(!bytes) return false;
    bool same = entry_codec(copies, bytes, true) &&
                entry_codec(copies + 1, bytes + ENTRY_PAYLOAD, true) &&
                !memcmp(bytes, bytes + ENTRY_PAYLOAD, ENTRY_PAYLOAD);
    free(bytes);
    return same;
}
Tb2RecordResult
    tb2_entry_load(Tb2WorkflowIO* io, const char* box, const char* id, bool note, Tb2BoxEntry* e) {
    char path[TB2_JOB_PATH_MAX], expected[TB2_RECORD_ID_SIZE], wanted_box[TB2_RECORD_ID_SIZE];
    if(!tb2_record_id_valid(id) || !entry_path(path, box, id, note ? "n-" : "e-"))
        return Tb2RecordCorrupt;
    memcpy(expected, id, sizeof(expected));
    memcpy(wanted_box, box, sizeof(wanted_box));
    box = wanted_box;
    memset(e, 0, sizeof(*e));
    /* History writes run after worker join on the 4-KiB UI stack. Keep the
     * serialized entry off that stack across resident IO/log callbacks. */
    uint8_t* bytes = malloc(ENTRY_PAYLOAD);
    if(!bytes) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_record_read(
        io, path, note ? Tb2RecordNote : Tb2RecordEvent, box, bytes, ENTRY_PAYLOAD, &e->generation);
    if(!rc && (!entry_codec(e, bytes, false) || strcmp(e->id, expected) || strcmp(e->box, box) ||
               e->note != note))
        rc = Tb2RecordCorrupt;
    tb2_record_wipe(bytes, ENTRY_PAYLOAD);
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_entry_save(Tb2WorkflowIO* io, Tb2BoxEntry* e) {
    uint8_t* bytes = calloc(2, ENTRY_PAYLOAD);
    Tb2BoxEntry* old = calloc(1, sizeof(*old));
    if(!bytes || !old) {
        free(bytes);
        free(old);
        return Tb2RecordIo;
    }
    char path[TB2_JOB_PATH_MAX];
    Tb2RecordResult rc = entry_codec(e, bytes, true) &&
                                 entry_path(path, e->box, e->id, e->note ? "n-" : "e-") ?
                             Tb2RecordOk :
                             Tb2RecordCorrupt;
    if(!rc) {
        rc = tb2_entry_load(io, e->box, e->id, e->note, old);
        if(!rc) {
            if(!entry_codec(old, bytes + ENTRY_PAYLOAD, true) ||
               memcmp(bytes, bytes + ENTRY_PAYLOAD, ENTRY_PAYLOAD))
                rc = Tb2RecordConflict;
            else
                e->generation = old->generation;
        } else if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !e->generation) {
            rc = tb2_record_write(
                io,
                path,
                e->note ? Tb2RecordNote : Tb2RecordEvent,
                e->box,
                bytes,
                ENTRY_PAYLOAD,
                &e->generation);
        }
    }
    free(old);
    free(bytes);
    return rc;
}
static Tb2RecordResult
    pending_model(Tb2WorkflowIO* io, Tb2RecordKind kind, const char* box, void* model) {
    uint8_t* bytes = calloc(1, VERSION_PAYLOAD);
    if(!bytes) return Tb2RecordIo;
    char path[TB2_JOB_PATH_MAX];
    size_t size = 0;
    bool valid = false;
    if(kind == Tb2RecordBox) {
        Tb2BoxRecord* value = model;
        size = BOX_PAYLOAD;
        valid = box_codec(value, bytes, true) && tb2_record_path(path, value->id, "box");
        box = value->id;
    } else if(kind == Tb2RecordVersion) {
        Tb2BoxVersion* value = model;
        if(value->flags & (Tb2VersionOriginal | Tb2VersionWorking))
            value->flags |= Tb2VersionProtected;
        size = VERSION_PAYLOAD;
        valid = version_codec(value, bytes, true) && entry_path(path, value->box, value->id, "v-");
        box = value->box;
    } else if(kind == Tb2RecordSecret) {
        Tb2BoxSecret* value = model;
        size = SECRET_PAYLOAD;
        valid = secret_codec(value, bytes, true) && entry_path(path, box, value->id, "k-");
    } else {
        Tb2BoxEntry* value = model;
        size = ENTRY_PAYLOAD;
        valid = entry_codec(value, bytes, true) &&
                entry_path(path, value->box, value->id, value->note ? "n-" : "e-");
        box = value->box;
    }
    Tb2RecordResult rc = valid ? tb2_record_can_create(io, path, kind, box, bytes, size) :
                                 Tb2RecordCorrupt;
    tb2_record_wipe(bytes, VERSION_PAYLOAD);
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_box_can_create(Tb2WorkflowIO* io, Tb2BoxRecord* value) {
    return pending_model(io, Tb2RecordBox, NULL, value);
}
Tb2RecordResult tb2_version_can_create(Tb2WorkflowIO* io, Tb2BoxVersion* value) {
    return pending_model(io, Tb2RecordVersion, NULL, value);
}
Tb2RecordResult tb2_secret_can_create(Tb2WorkflowIO* io, const char* box, Tb2BoxSecret* value) {
    return pending_model(io, Tb2RecordSecret, box, value);
}
Tb2RecordResult tb2_entry_can_create(Tb2WorkflowIO* io, Tb2BoxEntry* value) {
    return pending_model(io, value->note ? Tb2RecordNote : Tb2RecordEvent, NULL, value);
}
Tb2RecordResult tb2_box_load(Tb2WorkflowIO* io, const char* id, Tb2BoxRecord* box) {
    char wanted[TB2_RECORD_ID_SIZE];
    bool valid_id = tb2_record_id_valid(id);
    if(valid_id) memcpy(wanted, id, sizeof(wanted));
    memset(box, 0, sizeof(*box));
    if(!valid_id) return Tb2RecordCorrupt;
    id = wanted;
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[BOX_PAYLOAD];
    if(!tb2_record_path(path, id, "box")) return Tb2RecordCorrupt;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordBox, id, bytes, sizeof(bytes), &box->generation);
    if(!rc && (!box_codec(box, bytes, false) || strcmp(box->id, id))) rc = Tb2RecordCorrupt;
    return rc;
}
Tb2RecordResult tb2_box_save(Tb2WorkflowIO* io, Tb2BoxRecord* box) {
    uint8_t bytes[BOX_PAYLOAD] = {0};
    char path[TB2_JOB_PATH_MAX];
    if(!box_codec(box, bytes, true) || !tb2_record_path(path, box->id, "box"))
        return Tb2RecordCorrupt;
    Tb2BoxRecord* old = calloc(1, sizeof(*old));
    if(!old) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_box_load(io, box->id, old);
    if(!rc && (old->generation != box->generation || box->next_version < old->next_version ||
               (old->has_uid && (!box->has_uid || memcmp(old->uid, box->uid, 8))) ||
               (old->box_id[0] && strcmp(old->box_id, box->box_id))))
        rc = Tb2RecordConflict;
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !box->generation) {
        tb2_record_path(path, box->id, "");
        rc = io->mkdir(io->context, TB2_APP_ROOT) && io->mkdir(io->context, TB2_BOXES_ROOT) &&
                     io->mkdir(io->context, path) ?
                 Tb2RecordOk :
                 Tb2RecordIo;
        tb2_record_path(path, box->id, "box");
    }
    if(!rc)
        rc = tb2_record_write(
            io, path, Tb2RecordBox, box->id, bytes, sizeof(bytes), &box->generation);
    free(old);
    return rc;
}
Tb2RecordResult
    tb2_version_load(Tb2WorkflowIO* io, const char* box, const char* id, Tb2BoxVersion* v) {
    char wanted_box[TB2_RECORD_ID_SIZE], wanted_id[TB2_RECORD_ID_SIZE];
    bool valid_ids = tb2_record_id_valid(box) && tb2_record_id_valid(id);
    if(valid_ids) {
        memcpy(wanted_box, box, sizeof(wanted_box));
        memcpy(wanted_id, id, sizeof(wanted_id));
    }
    memset(v, 0, sizeof(*v));
    if(!valid_ids) return Tb2RecordCorrupt;
    box = wanted_box;
    id = wanted_id;
    char path[TB2_JOB_PATH_MAX];
    if(!entry_path(path, box, id, "v-")) return Tb2RecordCorrupt;
    uint8_t* bytes = malloc(VERSION_PAYLOAD);
    if(!bytes) return Tb2RecordIo;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordVersion, box, bytes, VERSION_PAYLOAD, &v->generation);
    if(!rc && (!version_codec(v, bytes, false) || strcmp(v->id, id) || strcmp(v->box, box)))
        rc = Tb2RecordCorrupt;
    free(bytes);
    return rc;
}
static bool immutable_version(const Tb2BoxVersion* a, const Tb2BoxVersion* b) {
    const uint8_t empty[32] = {0};
    if((memcmp(a->ca_fingerprint, empty, 32) &&
        memcmp(a->ca_fingerprint, b->ca_fingerprint, 32)) ||
       (memcmp(a->client_fingerprint, empty, 32) &&
        memcmp(a->client_fingerprint, b->client_fingerprint, 32)))
        return false;
    if(strcmp(a->id, b->id) || strcmp(a->box, b->box) || strcmp(a->parent, b->parent) ||
       strcmp(a->created, b->created) || strcmp(a->job, b->job) || strcmp(a->app, b->app) ||
       strcmp(a->name, b->name) || a->number != b->number ||
       ((a->flags ^ b->flags) & Tb2VersionSource) || (a->flags & Tb2VersionDeleted) ||
       a->image.size != b->image.size || memcmp(a->image.digest, b->image.digest, 32) ||
       (a->secret[0] && strcmp(a->secret, b->secret)))
        return false;
    if(a->firmware.known &&
       (!b->firmware.known || memcmp(a->firmware.digest, b->firmware.digest, 32)))
        return false;
    for(unsigned i = 0; i < TB2_RECORD_ARTIFACTS; i++)
        if(a->artifacts[i].size && (a->artifacts[i].size != b->artifacts[i].size ||
                                    memcmp(a->artifacts[i].digest, b->artifacts[i].digest, 32)))
            return false;
    if((a->flags & Tb2VersionEndpointsKnown) &&
       (!(b->flags & Tb2VersionEndpointsKnown) ||
        strcmp(a->endpoints.https_host, b->endpoints.https_host) ||
        strcmp(a->endpoints.mqtt_host, b->endpoints.mqtt_host) ||
        a->endpoints.https_port != b->endpoints.https_port ||
        a->endpoints.mqtt_port != b->endpoints.mqtt_port))
        return false;
    return true;
}
Tb2RecordResult tb2_originals(
    Tb2WorkflowIO* io,
    const char* box,
    const Tb2FirmwareIdentity* firmware,
    Tb2Originals* out) {
    memset(out, 0, sizeof(*out));
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    Tb2RecordPage* page = calloc(1, sizeof(*page));
    if(!v || !page) {
        free(v);
        free(page);
        return Tb2RecordIo;
    }
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    do {
        rc = tb2_record_page_open(io, page, box, anchor, false);
        page->strict = true;
        while(!rc && !page->done)
            rc = tb2_record_page_step(io, page, 4);
        for(unsigned i = 0; !rc && i < page->count; i++) {
            rc = tb2_version_load(io, box, page->ids[i], v);
            if(!rc && (v->flags & Tb2VersionOriginal) && !(v->flags & Tb2VersionDeleted)) {
                if(!out->first_number || v->number < out->first_number) {
                    out->first_number = v->number;
                    strcpy(out->first, v->id);
                }
                bool matches =
                    !firmware || !firmware->known ||
                    (v->firmware.known && !memcmp(firmware->digest, v->firmware.digest, 32));
                if(matches && v->number > out->latest_number) {
                    out->latest_number = v->number;
                    strcpy(out->latest, v->id);
                }
            }
        }
        if(page->count) strcpy(anchor, page->ids[page->count - 1]);
    } while(!rc && page->more);
    tb2_record_page_close(io, page);
    free(page);
    free(v);
    return rc;
}
static Tb2RecordResult version_save(Tb2WorkflowIO* io, Tb2BoxVersion* v, bool rename) {
    char path[TB2_JOB_PATH_MAX];
    if(!entry_path(path, v->box, v->id, "v-")) return Tb2RecordCorrupt;
    uint8_t* bytes = calloc(1, VERSION_PAYLOAD);
    Tb2BoxVersion* old = calloc(1, sizeof(*old));
    if(!bytes || !old) {
        free(bytes);
        free(old);
        return Tb2RecordIo;
    }
    Tb2RecordResult rc = tb2_version_load(io, v->box, v->id, old);
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !v->generation)
        rc = Tb2RecordOk;
    else if(!rc) {
        /* A display rename is explicit and cannot relax any other invariant. */
        if(rename) strcpy(old->name, v->name);
        if(old->generation != v->generation || !immutable_version(old, v))
            rc = Tb2RecordConflict;
        else if((old->flags & Tb2VersionProtected) && (v->flags & Tb2VersionDeleted))
            rc = Tb2RecordProtected;
    }
    if(!rc && !old->generation) {
        Tb2BoxRecord* box = calloc(1, sizeof(*box));
        rc = box ? tb2_box_load(io, v->box, box) : Tb2RecordIo;
        free(box);
        if(v->flags & (Tb2VersionOriginal | Tb2VersionWorking)) v->flags |= Tb2VersionProtected;
    } else if(!rc && ((~old->flags & v->flags) & (Tb2VersionOriginal | Tb2VersionWorking)))
        v->flags |= Tb2VersionProtected;
    if(!rc && !version_codec(v, bytes, true)) rc = Tb2RecordCorrupt;
    if(!rc)
        rc = tb2_record_write(
            io, path, Tb2RecordVersion, v->box, bytes, VERSION_PAYLOAD, &v->generation);
    free(old);
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_version_save(Tb2WorkflowIO* io, Tb2BoxVersion* v) {
    return version_save(io, v, false);
}
Tb2RecordResult tb2_version_rename(Tb2WorkflowIO* io, Tb2BoxVersion* v) {
    if(!v->generation || !v->name[0] || !memchr(v->name, 0, sizeof(v->name)))
        return Tb2RecordCorrupt;
    return version_save(io, v, true);
}
Tb2RecordResult
    tb2_secret_load(Tb2WorkflowIO* io, const char* box, const char* id, Tb2BoxSecret* key) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[SECRET_PAYLOAD];
    char wanted[TB2_RECORD_ID_SIZE];
    bool valid_id = tb2_record_id_valid(id);
    if(valid_id) memcpy(wanted, id, sizeof(wanted));
    memset(key, 0, sizeof(*key));
    if(!valid_id) return Tb2RecordCorrupt;
    id = wanted;
    if(!entry_path(path, box, id, "k-")) return Tb2RecordCorrupt;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordSecret, box, bytes, sizeof(bytes), &key->generation);
    if(!rc && (!secret_codec(key, bytes, false) || strcmp(key->id, id))) rc = Tb2RecordCorrupt;
    tb2_record_wipe(bytes, sizeof(bytes));
    if(rc) tb2_record_wipe(key, sizeof(*key));
    return rc;
}
Tb2RecordResult tb2_secret_save(Tb2WorkflowIO* io, const char* box, Tb2BoxSecret* key) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[SECRET_PAYLOAD] = {0};
    if(!entry_path(path, box, key->id, "k-") || !secret_codec(key, bytes, true)) {
        tb2_record_wipe(bytes, sizeof(bytes));
        return Tb2RecordCorrupt;
    }
    Tb2BoxSecret* old = calloc(1, sizeof(*old));
    if(!old) {
        tb2_record_wipe(bytes, sizeof(bytes));
        return Tb2RecordIo;
    }
    Tb2RecordResult rc = tb2_secret_load(io, box, key->id, old);
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !key->generation)
        rc = Tb2RecordOk;
    else if(
        !rc && (old->generation != key->generation || old->key.kind != key->key.kind ||
                memcmp(old->key.bytes, key->key.bytes, sizeof(key->key.bytes)) ||
                (old->verified && (!key->verified || old->profile != key->profile ||
                                   memcmp(old->firmware, key->firmware, sizeof(key->firmware))))))
        rc = Tb2RecordConflict;
    if(!rc)
        rc = tb2_record_write(
            io, path, Tb2RecordSecret, box, bytes, sizeof(bytes), &key->generation);
    tb2_record_wipe(old, sizeof(*old));
    free(old);
    tb2_record_wipe(bytes, sizeof(bytes));
    return rc;
}

static bool folder_char_invalid(char value) {
    static const char forbidden[] = "<>:\"/\\|?*";
    for(size_t i = 0; forbidden[i]; i++)
        if(value == forbidden[i]) return true;
    return false;
}
static bool folder_codec(Tb2BoxFolder* folder, uint8_t* bytes, bool encode) {
    Codec c = {
        .bytes = bytes, .capacity = TB2_FOLDER_PAYLOAD_SIZE, .encode = encode, .valid = true};
    string(&c, folder->name, sizeof(folder->name));
    if(!c.valid) return false;
    size_t length = strlen(folder->name);
    if(!c.valid || !length || folder->name[length - 1] == '.' || folder->name[length - 1] == ' ')
        return false;
    for(size_t i = 0; i < length; i++)
        if(folder_char_invalid(folder->name[i])) return false;
    return true;
}
static bool edition_codec(Tb2Edition* e, uint8_t* bytes, bool encode) {
    Codec c = {
        .bytes = bytes, .capacity = TB2_EDITION_PAYLOAD_SIZE, .encode = encode, .valid = true};
    string(&c, e->id, sizeof(e->id));
    string(&c, e->box, sizeof(e->box));
    field(&c, &e->label.major, 1);
    field(&c, &e->label.minor, 1);
    field(&c, &e->label.patch, 1);
    uint32_t kind = e->kind, match_state = e->match;
    number(&c, &kind);
    number(&c, &e->revision);
    number(&c, &e->number);
    number(&c, &e->flags);
    object(&c, &e->image);
    flag(&c, &e->primary.known);
    string(&c, e->primary.version, sizeof(e->primary.version));
    field(&c, e->primary.digest, sizeof(e->primary.digest));
    flag(&c, &e->secondary.known);
    string(&c, e->secondary.version, sizeof(e->secondary.version));
    field(&c, e->secondary.digest, sizeof(e->secondary.digest));
    flag(&c, &e->label_manual);
    field(&c, &e->settings_categories, 1);
    field(&c, &e->wifi_profiles, 1);
    field(&c, &e->region, 1);
    flag(&c, &e->region_known);
    string(&c, e->path, sizeof(e->path));
    string(&c, e->package, sizeof(e->package));
    number(&c, &match_state);
    e->kind = (Tb2ImageKind)kind;
    e->match = (Tb2PackageMatch)match_state;
    return c.valid && tb2_record_id_valid(e->id) && tb2_record_id_valid(e->box) &&
           tb2_file_version_valid(&e->label) && e->revision && e->number &&
           (kind == Tb2ImageOriginal || kind == Tb2ImageModified) &&
           !(e->flags & ~Tb2EditionPublished) && (!e->primary.known || e->primary.version[0]) &&
           (!e->secondary.known || e->secondary.version[0]) &&
           !(e->settings_categories & ~(Tb2SettingsHosts | Tb2SettingsWifi | Tb2SettingsDevice)) &&
           e->wifi_profiles <= TB2_WIFI_PROFILE_COUNT && (!e->region_known || e->region <= 1) &&
           (!e->image.size || e->image.size == TB2_IMAGE_SIZE) &&
           (!(e->flags & Tb2EditionPublished) || e->image.size == TB2_IMAGE_SIZE) &&
           !strncmp(e->path, TB2_IMAGES_ROOT "/", sizeof(TB2_IMAGES_ROOT)) &&
           !strstr(e->path, "..") && !strchr(e->path, '\\') &&
           (!e->package[0] || (kind == Tb2ImageModified && tb2_record_id_valid(e->package))) &&
           match_state <= Tb2PackageMismatch;
}
static bool server_package_codec(Tb2ServerPackage* p, uint8_t* bytes, bool encode) {
    Codec c = {
        .bytes = bytes,
        .capacity = TB2_SERVER_PACKAGE_PAYLOAD_SIZE,
        .encode = encode,
        .valid = true};
    string(&c, p->id, sizeof(p->id));
    string(&c, p->box, sizeof(p->box));
    for(unsigned i = 0; i < TB2_SERVER_PACKAGE_OBJECTS; i++) {
        object(&c, &p->objects[i]);
        if(!p->objects[i].size || p->objects[i].size > TB2_PACKAGE_FILE_MAX) c.valid = false;
    }
    field(&c, p->digest, sizeof(p->digest));
    field(&c, p->ca_fingerprint, sizeof(p->ca_fingerprint));
    number(&c, &p->validity);
    return c.valid && tb2_record_id_valid(p->id) && tb2_record_id_valid(p->box) &&
           !(p->validity & ~(Tb2PackageExpired | Tb2PackageNotYetValid));
}
Tb2RecordResult tb2_folder_load(Tb2WorkflowIO* io, const char* box, Tb2BoxFolder* folder) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[TB2_FOLDER_PAYLOAD_SIZE];
    memset(folder, 0, sizeof(*folder));
    if(!tb2_record_path(path, box, "files")) return Tb2RecordCorrupt;
    Tb2RecordResult rc =
        tb2_record_read(io, path, Tb2RecordFolder, box, bytes, sizeof(bytes), &folder->generation);
    if(!rc && !folder_codec(folder, bytes, false)) rc = Tb2RecordCorrupt;
    return rc;
}
Tb2RecordResult tb2_folder_save(Tb2WorkflowIO* io, const char* box, Tb2BoxFolder* folder) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[TB2_FOLDER_PAYLOAD_SIZE] = {0};
    Tb2BoxFolder old;
    if(!tb2_record_path(path, box, "files") || !folder_codec(folder, bytes, true))
        return Tb2RecordCorrupt;
    Tb2RecordResult rc = tb2_folder_load(io, box, &old);
    if(!rc && strcmp(old.name, folder->name)) return Tb2RecordConflict;
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !folder->generation) rc = Tb2RecordOk;
    return rc ? rc :
                tb2_record_write(
                    io, path, Tb2RecordFolder, box, bytes, sizeof(bytes), &folder->generation);
}
Tb2RecordResult
    tb2_edition_load(Tb2WorkflowIO* io, const char* box, const char* id, Tb2Edition* e) {
    char path[TB2_JOB_PATH_MAX], wanted[TB2_RECORD_ID_SIZE], owner[TB2_RECORD_ID_SIZE];
    if(!entry_path(path, box, id, "f-")) return Tb2RecordCorrupt;
    strcpy(wanted, id);
    strcpy(owner, box);
    memset(e, 0, sizeof(*e));
    uint8_t* bytes = malloc(TB2_EDITION_PAYLOAD_SIZE);
    if(!bytes) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_record_read(
        io, path, Tb2RecordEdition, owner, bytes, TB2_EDITION_PAYLOAD_SIZE, &e->generation);
    if(!rc && (!edition_codec(e, bytes, false) || strcmp(e->id, wanted) || strcmp(e->box, owner)))
        rc = Tb2RecordCorrupt;
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_edition_save(Tb2WorkflowIO* io, Tb2Edition* e) {
    char path[TB2_JOB_PATH_MAX];
    if(!entry_path(path, e->box, e->id, "f-")) return Tb2RecordCorrupt;
    uint8_t* bytes = calloc(1, TB2_EDITION_PAYLOAD_SIZE);
    Tb2Edition* old = calloc(1, sizeof(*old));
    if(!bytes || !old) {
        free(bytes);
        free(old);
        return Tb2RecordIo;
    }
    Tb2RecordResult rc = tb2_edition_load(io, e->box, e->id, old);
    if(!rc &&
       (old->generation != e->generation || old->kind != e->kind ||
        tb2_file_version_compare(&old->label, &e->label) || old->revision != e->revision ||
        old->number != e->number || strcmp(old->path, e->path) || (old->flags & ~e->flags) ||
        memcmp(&old->primary, &e->primary, sizeof(e->primary)) ||
        memcmp(&old->secondary, &e->secondary, sizeof(e->secondary)) ||
        old->label_manual != e->label_manual ||
        old->settings_categories != e->settings_categories ||
        old->wifi_profiles != e->wifi_profiles || old->region != e->region ||
        old->region_known != e->region_known ||
        (old->image.size &&
         (old->image.size != e->image.size || memcmp(old->image.digest, e->image.digest, 32)))))
        rc = Tb2RecordConflict;
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !e->generation) rc = Tb2RecordOk;
    if(!rc && !edition_codec(e, bytes, true)) rc = Tb2RecordCorrupt;
    if(!rc)
        rc = tb2_record_write(
            io, path, Tb2RecordEdition, e->box, bytes, TB2_EDITION_PAYLOAD_SIZE, &e->generation);
    free(old);
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_version_image_path(
    Tb2WorkflowIO* io,
    const char* box,
    const char* version,
    const Tb2ObjectRef* image,
    char path[TB2_JOB_PATH_MAX]) {
    Tb2Edition* edition = calloc(1, sizeof(*edition));
    if(!edition) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_edition_load(io, box, version, edition);
    if(!rc) {
        if(!(edition->flags & Tb2EditionPublished) || edition->image.size != image->size ||
           memcmp(edition->image.digest, image->digest, sizeof(image->digest)))
            rc = Tb2RecordConflict;
        else
            snprintf(path, TB2_JOB_PATH_MAX, "%s", edition->path);
    } else if(rc == Tb2RecordMissing) {
        rc = tb2_object_path(path, image) ? Tb2RecordOk : Tb2RecordCorrupt;
    }
    free(edition);
    return rc;
}
Tb2RecordResult tb2_server_package_load(
    Tb2WorkflowIO* io,
    const char* box,
    const char* id,
    Tb2ServerPackage* p) {
    char path[TB2_JOB_PATH_MAX], wanted[TB2_RECORD_ID_SIZE], owner[TB2_RECORD_ID_SIZE];
    if(!entry_path(path, box, id, "p-")) return Tb2RecordCorrupt;
    strcpy(wanted, id);
    strcpy(owner, box);
    memset(p, 0, sizeof(*p));
    uint8_t* bytes = malloc(TB2_SERVER_PACKAGE_PAYLOAD_SIZE);
    if(!bytes) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_record_read(
        io, path, Tb2RecordPackage, owner, bytes, TB2_SERVER_PACKAGE_PAYLOAD_SIZE, &p->generation);
    if(!rc &&
       (!server_package_codec(p, bytes, false) || strcmp(p->id, wanted) || strcmp(p->box, owner)))
        rc = Tb2RecordCorrupt;
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_server_package_save(Tb2WorkflowIO* io, Tb2ServerPackage* p) {
    char path[TB2_JOB_PATH_MAX];
    if(!entry_path(path, p->box, p->id, "p-")) return Tb2RecordCorrupt;
    uint8_t* bytes = calloc(2, TB2_SERVER_PACKAGE_PAYLOAD_SIZE);
    if(!bytes) return Tb2RecordIo;
    uint32_t generation = 0;
    Tb2RecordResult rc = tb2_record_read(
        io, path, Tb2RecordPackage, p->box, bytes, TB2_SERVER_PACKAGE_PAYLOAD_SIZE, &generation);
    if(!server_package_codec(p, bytes + TB2_SERVER_PACKAGE_PAYLOAD_SIZE, true))
        rc = Tb2RecordCorrupt;
    else if(
        !rc &&
        (generation != p->generation ||
         memcmp(bytes, bytes + TB2_SERVER_PACKAGE_PAYLOAD_SIZE, TB2_SERVER_PACKAGE_PAYLOAD_SIZE)))
        rc = Tb2RecordConflict;
    else if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && !p->generation)
        rc = Tb2RecordOk;
    if(!rc)
        rc = tb2_record_write(
            io,
            path,
            Tb2RecordPackage,
            p->box,
            bytes + TB2_SERVER_PACKAGE_PAYLOAD_SIZE,
            TB2_SERVER_PACKAGE_PAYLOAD_SIZE,
            &p->generation);
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_edition_can_create(Tb2WorkflowIO* io, Tb2Edition* e) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t* bytes = calloc(1, TB2_EDITION_PAYLOAD_SIZE);
    if(!bytes) return Tb2RecordIo;
    bool valid = entry_path(path, e->box, e->id, "f-") && edition_codec(e, bytes, true);
    Tb2RecordResult rc =
        valid ? tb2_record_can_create(
                    io, path, Tb2RecordEdition, e->box, bytes, TB2_EDITION_PAYLOAD_SIZE) :
                Tb2RecordCorrupt;
    free(bytes);
    return rc;
}
Tb2RecordResult tb2_server_package_can_create(Tb2WorkflowIO* io, Tb2ServerPackage* p) {
    char path[TB2_JOB_PATH_MAX];
    uint8_t* bytes = calloc(1, TB2_SERVER_PACKAGE_PAYLOAD_SIZE);
    if(!bytes) return Tb2RecordIo;
    bool valid = entry_path(path, p->box, p->id, "p-") && server_package_codec(p, bytes, true);
    Tb2RecordResult rc =
        valid ? tb2_record_can_create(
                    io, path, Tb2RecordPackage, p->box, bytes, TB2_SERVER_PACKAGE_PAYLOAD_SIZE) :
                Tb2RecordCorrupt;
    free(bytes);
    return rc;
}
