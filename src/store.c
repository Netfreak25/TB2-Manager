#include "store.h"
#include <mbedtls/sha256.h>
#include "probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Worker-only archive frames must not inflate the headless UI status/event
 * dispatcher frame. Keep these two heavy handlers out of line on both hosts. */
#ifdef _MSC_VER
#define STORE_WORKER_FRAME __declspec(noinline)
#else
#define STORE_WORKER_FRAME __attribute__((noinline))
#endif

static Tb2RecordResult find_uid(Tb2StoreRequest* r) {
    return tb2_box_find_uid(r->io, r->uid, NULL, r->box, &r->found);
}
static Tb2RecordResult
    verify_image(Tb2WorkflowIO* io, const char* box, const Tb2BoxVersion* version) {
    char path[TB2_JOB_PATH_MAX];
    Tb2RecordResult rc = tb2_version_image_path(io, box, version->id, &version->image, path);
    Tb2ObjectRef actual = {0};
    if(!rc) rc = tb2_file_inspect(io, path, version->image.size, &actual);
    if(!rc && (actual.size != version->image.size ||
               memcmp(actual.digest, version->image.digest, sizeof(actual.digest))))
        rc = Tb2RecordConflict;
    return rc;
}
static Tb2RecordResult find_backup(Tb2StoreRequest* r) {
    r->found = false;
    const Tb2FirmwareIdentity* primary = r->identity ? &r->identity->firmware : r->firmware;
    const Tb2FirmwareIdentity* secondary = r->identity ? &r->identity->secondary : NULL;
    if(!primary || !primary->known) return Tb2RecordOk;
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
        rc = tb2_record_page_open(r->io, page, r->box->id, anchor, false);
        while(!rc && !page->done)
            rc = tb2_record_page_step(r->io, page, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && i < page->count; i++) {
            rc = tb2_version_load(r->io, r->box->id, page->ids[i], v);
            bool firmware_match = !rc && v->firmware.known &&
                                  !memcmp(v->firmware.digest, primary->digest, 32);
            if(firmware_match && secondary) {
                Tb2Edition edition;
                Tb2RecordResult edition_rc = tb2_edition_load(r->io, r->box->id, v->id, &edition);
                if(!edition_rc)
                    firmware_match = edition.secondary.known == secondary->known &&
                                     (!secondary->known || !memcmp(
                                                               edition.secondary.digest,
                                                               secondary->digest,
                                                               sizeof(secondary->digest)));
                else if(edition_rc == Tb2RecordMissing)
                    firmware_match = !secondary->known;
                else
                    rc = edition_rc;
            }
            if(!rc && firmware_match && (v->flags & Tb2VersionSource) &&
               !(v->flags & Tb2VersionDeleted)) {
                Tb2RecordResult checked = verify_image(r->io, r->box->id, v);
                if(!checked && (!r->found || v->number > r->version->number)) {
                    *r->version = *v;
                    r->found = true;
                } else if(checked == Tb2RecordCancelled)
                    rc = checked;
                /* Missing/corrupt images cannot satisfy the backup requirement.
                 * The coordinator creates and verifies a new dump instead. */
            }
        }
        if(page->count) memcpy(anchor, page->ids[page->count - 1], sizeof(anchor));
    } while(!rc && page->more);
    tb2_record_page_close(r->io, page);
    free(page);
    free(v);
    return rc;
}
static Tb2RecordResult verify_version(Tb2StoreRequest* r) {
    if(r->version->flags & Tb2VersionDeleted) return Tb2RecordMissing;
    Tb2RecordResult rc = verify_image(r->io, r->version->box, r->version);
    for(unsigned i = 0; !rc && i < TB2_RECORD_ARTIFACTS; i++)
        if(r->version->artifacts[i].size) rc = tb2_object_verify(r->io, &r->version->artifacts[i]);
    return rc;
}
static Tb2RecordResult archive_image(Tb2StoreRequest* r) {
    Tb2RecordResult rc =
        tb2_object_put(r->io, r->source, r->staging, r->expected, &r->version->image);
    if(!rc) rc = tb2_version_save(r->io, r->version);
    return rc;
}
static Tb2RecordResult unique_identity(Tb2StoreRequest* r) {
    if(!r->uid_available && (!r->identity || !r->identity->box_id[0])) return Tb2RecordOk;
    Tb2RecordPage* page = calloc(1, sizeof(*page));
    Tb2BoxRecord* other = calloc(1, sizeof(*other));
    if(!page || !other) {
        free(page);
        free(other);
        return Tb2RecordIo;
    }
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    do {
        rc = tb2_record_page_open(r->io, page, NULL, anchor, false);
        while(!rc && !page->done)
            rc = tb2_record_page_step(r->io, page, TB2_RECORD_PAGE_SIZE);
        for(unsigned i = 0; !rc && i < page->count; i++) {
            rc = tb2_box_load(r->io, page->ids[i], other);
            if(!rc && strcmp(other->id, r->record_id) &&
               ((r->uid_available && other->has_uid &&
                 !memcmp(other->uid, r->uid, sizeof(r->uid))) ||
                (r->identity && r->identity->box_id[0] && other->box_id[0] &&
                 !strcmp(other->box_id, r->identity->box_id))))
                rc = Tb2RecordConflict;
        }
        if(page->count) memcpy(anchor, page->ids[page->count - 1], sizeof(anchor));
    } while(!rc && page->more);
    tb2_record_page_close(r->io, page);
    free(page);
    free(other);
    return rc;
}
static Tb2RecordResult identify_box(Tb2StoreRequest* r) {
    Tb2RecordResult rc = tb2_box_load(r->io, r->record_id, r->box);
    if(!rc) rc = unique_identity(r);
    if(rc) return rc;
    bool changed = false;
    if(r->uid_available) {
        if(r->box->has_uid && memcmp(r->box->uid, r->uid, sizeof(r->uid)))
            return Tb2RecordConflict;
        if(!r->box->has_uid) {
            memcpy(r->box->uid, r->uid, sizeof(r->uid));
            r->box->has_uid = changed = true;
        }
    }
    if(r->identity && r->identity->box_id[0]) {
        if(r->box->box_id[0] && strcmp(r->box->box_id, r->identity->box_id))
            return Tb2RecordConflict;
        if(!r->box->box_id[0]) {
            strcpy(r->box->box_id, r->identity->box_id);
            changed = true;
        }
    }
    return changed ? tb2_box_save(r->io, r->box) : Tb2RecordOk;
}
static Tb2RecordResult bind(Tb2StoreRequest* r, Tb2WorkshopBinding* b) {
    Tb2RecordResult rc = tb2_workshop_load(r->io, r->staging, r->descriptor_crc, b);
    if(!rc && strcmp(b->box, r->record_id)) return Tb2RecordConflict;
    if(rc != Tb2RecordOk && rc != Tb2RecordMissing && rc != Tb2RecordCorrupt) return rc;
    rc = identify_box(r);
    if(!rc) rc = tb2_workshop_bind(r->io, r->staging, r->descriptor_crc, r->record_id, b);
    return rc;
}
static Tb2RecordResult package_binding(Tb2StoreRequest* r) {
    if(!r->package_hash || !r->package_ca_hash ||
       memcmp(r->version->artifacts[11].digest, r->package_ca_hash, 32))
        return Tb2RecordConflict;
    uint8_t* bytes = malloc(TB2_RECORD_CHUNK);
    if(!bytes) return Tb2RecordIo;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    Tb2RecordResult rc = mbedtls_sha256_starts(&sha, 0) ? Tb2RecordIo : Tb2RecordOk;
    for(unsigned i = 0; !rc && i < 6; i++) {
        const Tb2ObjectRef* object = &r->version->artifacts[5 + i];
        uint32_t size = object->size;
        uint8_t frame[] = {
            (uint8_t)i,
            (uint8_t)size,
            (uint8_t)(size >> 8),
            (uint8_t)(size >> 16),
            (uint8_t)(size >> 24)};
        char path[TB2_JOB_PATH_MAX];
        void* file =
            tb2_object_path(path, object) ? r->io->open(r->io->context, path, Tb2FileRead) : NULL;
        if(!file || r->io->size(r->io->context, file) != size ||
           mbedtls_sha256_update(&sha, frame, sizeof(frame)))
            rc = Tb2RecordIo;
        for(uint32_t offset = 0; !rc && offset < size;) {
            size_t count = size - offset;
            if(count > TB2_RECORD_CHUNK) count = TB2_RECORD_CHUNK;
            if(r->io->cancelled && r->io->cancelled(r->io->context))
                rc = Tb2RecordCancelled;
            else if(
                r->io->read(r->io->context, file, bytes, count) != count ||
                mbedtls_sha256_update(&sha, bytes, count))
                rc = Tb2RecordIo;
            offset += (uint32_t)count;
        }
        if(file && !r->io->close(r->io->context, file)) rc = Tb2RecordIo;
    }
    uint8_t hash[32];
    if(!rc && mbedtls_sha256_finish(&sha, hash)) rc = Tb2RecordIo;
    if(!rc && memcmp(hash, r->package_hash, 32)) rc = Tb2RecordConflict;
    mbedtls_sha256_free(&sha);
    tb2_record_wipe(bytes, TB2_RECORD_CHUNK);
    free(bytes);
    return rc;
}
static STORE_WORKER_FRAME Tb2RecordResult capture(Tb2StoreRequest* r, Tb2WorkshopBinding* b) {
    if(!r->source || !r->expected || r->expected->size != TB2_IMAGE_SIZE ||
       (unsigned)r->slot >= TB2_WORKSHOP_SLOTS)
        return Tb2RecordCorrupt;
    Tb2RecordResult rc = bind(r, b);
    char duplicate[TB2_RECORD_ID_SIZE] = {0};
    if(!rc && r->slot == Tb2WorkshopSource && (!r->existing_version || !r->existing_version[0]))
        rc = tb2_file_duplicate(r->io, r->record_id, r->expected, duplicate);
    const char* existing = r->existing_version && r->existing_version[0] ? r->existing_version :
                                                                           duplicate;
    if(!rc && existing[0] && !r->readable_target) {
        rc = tb2_version_load(r->io, r->record_id, existing, r->version);
        if(!rc && (r->version->image.size != r->expected->size ||
                   memcmp(r->version->image.digest, r->expected->digest, 32)))
            rc = Tb2RecordConflict;
        if(!rc) rc = verify_version(r);
        if(!rc) rc = tb2_workshop_link(r->io, r->staging, b, r->slot, r->version);
        if(!rc) strcpy(r->version_id, r->version->id);
        return rc;
    }
    Tb2Edition readable = {0};
    if(!rc && r->readable_target) {
        if(r->slot != Tb2WorkshopTarget || !existing[0]) return Tb2RecordCorrupt;
        rc = tb2_edition_load(r->io, r->record_id, existing, &readable);
        if(!rc && (readable.kind != Tb2ImageModified || strcmp(readable.path, r->source)))
            rc = Tb2RecordConflict;
        if(!rc && (readable.flags & Tb2EditionPublished)) {
            rc = tb2_version_load(r->io, r->record_id, existing, r->version);
            if(!rc && (r->version->image.size != r->expected->size ||
                       memcmp(r->version->image.digest, r->expected->digest, 32)))
                rc = Tb2RecordConflict;
            if(!rc) rc = verify_version(r);
            if(!rc) rc = tb2_workshop_link(r->io, r->staging, b, r->slot, r->version);
            if(!rc) strcpy(r->version_id, r->version->id);
            return rc;
        }
    } else if(!rc)
        rc = tb2_workshop_reserve(r->io, r->staging, b, r->slot, r->box);
    if(rc) return rc;
    rc = r->readable_target ? tb2_version_load(r->io, r->record_id, existing, r->version) :
                              tb2_version_load(r->io, b->box, b->versions[r->slot], r->version);
    if(!rc) {
        if(r->version->number != b->numbers[r->slot] ||
           r->version->image.size != r->expected->size ||
           memcmp(r->version->image.digest, r->expected->digest, 32) ||
           (r->version->flags & Tb2VersionDeleted))
            return Tb2RecordConflict;
        rc = verify_version(r);
    } else if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) {
        Tb2BoxVersion* v = r->version;
        strcpy(v->box, b->box);
        strcpy(v->id, r->readable_target ? readable.id : b->versions[r->slot]);
        if(r->slot == Tb2WorkshopTarget) strcpy(v->parent, b->versions[Tb2WorkshopSource]);
        v->number = r->readable_target ? readable.number : b->numbers[r->slot];
        v->flags = r->version_flags;
        if(r->slot != Tb2WorkshopTarget) v->flags |= Tb2VersionSource;
        if(r->identity) v->firmware = r->identity->firmware;
        if(r->readable_target && !v->firmware.known) v->firmware = readable.primary;
        snprintf(v->app, sizeof(v->app), "%s", TB2_PROBE_VERSION);
        snprintf(v->job, sizeof(v->job), "%s", r->staging);
        snprintf(v->created, sizeof(v->created), "%s", r->created ? r->created : "00000000000000");
        const char* base = strrchr(r->source, '/');
        snprintf(v->name, sizeof(v->name), "%s", base ? base + 1 : r->source);
        if(r->readable_target)
            v->image = *r->expected;
        else
            rc = tb2_object_put(r->io, r->source, r->staging, r->expected, &v->image);
    }
    if(!rc && r->identity && r->artifact_directory) {
        static const char* const names[] = {
            "ca.der.crypt",
            "client.der.crypt",
            "private.der.crypt",
            "ap-mode-auth.cred.crypt",
            "ici-auth.cred.crypt"};
        for(unsigned i = 0; !rc && i < 5; i++) {
            if(!(r->identity->artifacts & (1U << i))) continue;
            char path[TB2_JOB_PATH_MAX];
            int n = snprintf(path, sizeof(path), "%s/%s", r->artifact_directory, names[i]);
            if(n <= 0 || n >= (int)sizeof(path)) {
                rc = Tb2RecordCorrupt;
                break;
            }
            rc = tb2_object_put(r->io, path, r->staging, NULL, &r->version->artifacts[i]);
        }
    }
    if(!rc && r->package_directory) {
        static const char* const names[] = {
            "ca-root.pem",
            "ca-key.pem",
            "teddy-cert.pem",
            "teddy-key.pem",
            "ici.pem",
            "ici.key",
            "ca.der"};
        for(unsigned i = 0; !rc && i < 7; i++) {
            char path[TB2_JOB_PATH_MAX];
            int n = snprintf(path, sizeof(path), "%s/%s", r->package_directory, names[i]);
            if(n <= 0 || n >= (int)sizeof(path)) {
                rc = Tb2RecordCorrupt;
                break;
            }
            rc = tb2_object_put(r->io, path, r->staging, NULL, &r->version->artifacts[i + 5]);
        }
    }
    if(!rc) {
        if(r->ca_fingerprint) memcpy(r->version->ca_fingerprint, r->ca_fingerprint, 32);
        if(r->endpoints) {
            r->version->endpoints = *r->endpoints;
            r->version->flags |= Tb2VersionEndpointsKnown;
        }
        if(r->client_fingerprint)
            memcpy(r->version->client_fingerprint, r->client_fingerprint, 32);
        if(r->slot == Tb2WorkshopTarget && b->versions[Tb2WorkshopSource][0] &&
           !r->version->secret[0]) {
            Tb2BoxVersion* parent = calloc(1, sizeof(*parent));
            rc = parent ? tb2_version_load(r->io, b->box, b->versions[Tb2WorkshopSource], parent) :
                          Tb2RecordIo;
            if(!rc && r->version->firmware.known && parent->firmware.known &&
               !memcmp(r->version->firmware.digest, parent->firmware.digest, 32))
                strcpy(r->version->secret, parent->secret);
            free(parent);
        }
    }
    if(!rc && r->package_directory) rc = package_binding(r);
    if(!rc) {
        r->version->flags |= r->version_flags;
        if(r->readable_target) {
            if(r->settings_patch) {
                readable.settings_categories = r->settings_patch->categories;
                readable.region_known = r->settings_patch->region_set;
                readable.region = r->settings_patch->region;
                readable.wifi_profiles = 0;
                for(unsigned i = 0; i < TB2_WIFI_PROFILE_COUNT; i++)
                    if(r->settings_patch->wifi[i].operation != Tb2WifiKeep)
                        readable.wifi_profiles++;
            }
            rc = tb2_file_publish(r->io, &readable, r->version, r->source, false);
            if(!rc) rc = tb2_workshop_link(r->io, r->staging, b, r->slot, r->version);
        } else
            rc = tb2_workshop_publish(r->io, r->staging, b, r->slot, r->version);
    }
    if(!rc) strcpy(r->version_id, r->version->id);
    return rc;
}
/** Immutable restoration selection, separate from legacy job.tb2. No key values. */
static STORE_WORKER_FRAME Tb2RecordResult restore_plan(Tb2StoreRequest* r) {
    enum {
        PayloadSize = 72
    };
    char path[TB2_JOB_PATH_MAX], binding[TB2_RECORD_ID_SIZE];
    uint8_t digest[32], bytes[PayloadSize] = {0};
    uint32_t generation = 0;
    if(!r->staging || !tb2_record_id_valid(r->record_id) ||
       mbedtls_sha256((const uint8_t*)r->staging, strlen(r->staging), digest, 0))
        return Tb2RecordCorrupt;
    int n = snprintf(path, sizeof(path), "%s/restore-binding", r->staging);
    if(n <= 0 || n >= (int)sizeof(path)) return Tb2RecordCorrupt;
    for(unsigned i = 0; i < 16; i++)
        snprintf(binding + 2 * i, 3, "%02x", digest[i]);
    Tb2RecordResult rc =
        tb2_record_read(r->io, path, Tb2RecordBinding, binding, bytes, sizeof(bytes), &generation);
    if((rc == Tb2RecordMissing || rc == Tb2RecordCorrupt) && r->action == Tb2StoreRestorePlan) {
        rc = tb2_version_load(r->io, r->record_id, r->version_id, r->version);
        if(!rc &&
           (!(r->version->flags & Tb2VersionOriginal) || (r->version->flags & Tb2VersionDeleted)))
            rc = Tb2RecordConflict;
        if(rc) return rc;
        memcpy(bytes, r->record_id, TB2_RECORD_ID_SIZE);
        memcpy(bytes + TB2_RECORD_ID_SIZE, r->version_id, TB2_RECORD_ID_SIZE);
        bytes[66] = r->restore_connection;
        for(unsigned i = 0; i < 4; i++)
            bytes[68 + i] = (uint8_t)(r->descriptor_crc >> (8 * i));
        rc = tb2_record_write(
            r->io, path, Tb2RecordBinding, binding, bytes, sizeof(bytes), &generation);
    }
    if(rc) return rc;
    uint32_t crc = 0;
    for(unsigned i = 0; i < 4; i++)
        crc |= (uint32_t)bytes[68 + i] << (8 * i);
    if(!tb2_record_id_valid((const char*)bytes) || !tb2_record_id_valid((const char*)bytes + 33) ||
       bytes[66] > 1 || bytes[67] || crc != r->descriptor_crc ||
       strcmp((const char*)bytes, r->record_id))
        return Tb2RecordConflict;
    if(r->action == Tb2StoreRestorePlan &&
       (strcmp((const char*)bytes + 33, r->version_id) || (bytes[66] != r->restore_connection)))
        return Tb2RecordConflict;
    memcpy(r->version_id, bytes + 33, TB2_RECORD_ID_SIZE);
    r->restore_connection = bytes[66];
    return Tb2RecordOk;
}
static Tb2RecordResult store_key(Tb2StoreRequest* r) {
    if(!r->key) return Tb2RecordCorrupt;
    Tb2BoxSecret* secret = calloc(1, sizeof(*secret));
    if(!secret) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_box_load(r->io, r->record_id, r->box);
    if(rc) goto done;
    if(r->version_id[0]) {
        rc = tb2_version_load(r->io, r->record_id, r->version_id, r->version);
        if(rc) goto done;
    }
    if(r->action == Tb2StoreLoadKey) {
        const char* id = r->candidate_key                          ? r->box->candidate :
                         r->version_id[0] && r->version->secret[0] ? r->version->secret :
                                                                     r->box->secret;
        rc = id[0] ? tb2_secret_load(r->io, r->record_id, id, secret) : Tb2RecordMissing;
        if(!rc && !r->candidate_key && !secret->verified) rc = Tb2RecordConflict;
        if(!rc) {
            *r->key = secret->key;
            r->profile = secret->profile;
        }
    } else {
        if(!r->firmware || !r->firmware->known || r->profile < 1 || r->profile > 3 ||
           (r->version_id[0] && (!r->version->firmware.known ||
                                 memcmp(r->version->firmware.digest, r->firmware->digest, 32))) ||
           (r->key->kind != Tb2InputKeySecret && r->key->kind != Tb2InputKeyAes)) {
            rc = Tb2RecordCorrupt;
            goto done;
        }
        uint8_t material[50] = {0}, digest[32];
        material[0] = (uint8_t)r->key->kind;
        material[1] = (uint8_t)r->profile;
        memcpy(
            material + 2,
            r->key->bytes,
            r->key->kind == Tb2InputKeySecret ? TB2_SN_SIZE : TB2_AES_KEY_SIZE);
        memcpy(material + 18, r->firmware->digest, 32);
        int hashed = mbedtls_sha256(material, sizeof(material), digest, 0);
        tb2_record_wipe(material, sizeof(material));
        if(hashed) {
            rc = Tb2RecordIo;
            goto done;
        }
        char id[TB2_RECORD_ID_SIZE];
        for(unsigned i = 0; i < 16; i++)
            snprintf(id + 2 * i, 3, "%02x", digest[i]);
        tb2_record_wipe(digest, sizeof(digest));
        rc = tb2_secret_load(r->io, r->record_id, id, secret);
        if(rc != Tb2RecordOk && rc != Tb2RecordMissing && rc != Tb2RecordCorrupt) goto done;
        strcpy(secret->id, id);
        secret->key = *r->key;
        secret->profile = r->profile;
        secret->verified = true;
        memcpy(secret->firmware, r->firmware->digest, sizeof(secret->firmware));
        rc = tb2_secret_save(r->io, r->record_id, secret);
        if(!rc && r->version_id[0] && !r->version->secret[0]) {
            strcpy(r->version->secret, id);
            rc = tb2_version_save(r->io, r->version);
        }
        if(!rc && strcmp(r->box->secret, id)) {
            strcpy(r->box->secret, id);
            rc = tb2_box_save(r->io, r->box);
        }
    }
done:
    tb2_record_wipe(secret, sizeof(*secret));
    free(secret);
    return rc;
}
static Tb2RecordResult save_event(Tb2StoreRequest* r) {
    if(r->entry) {
        if(strcmp(r->entry->box, r->record_id)) return Tb2RecordConflict;
        if(!r->entry->id[0] && !tb2_record_new_id(r->io, r->entry->id)) return Tb2RecordIo;
        return tb2_entry_save(r->io, r->entry);
    }
    if(!r->operation || !r->staging) return Tb2RecordCorrupt;
    Tb2BoxEntry* e = calloc(1, sizeof(*e));
    if(!e) return Tb2RecordIo;
    strcpy(e->box, r->record_id);
    strcpy(e->version, r->version_id);
    snprintf(e->job, sizeof(e->job), "%s", r->staging);
    e->timestamp = r->timestamp;
    e->type = r->operation->kind;
    e->state = r->operation->state;
    e->sequence = r->operation->sequence;
    e->code = r->result_code;
    e->flags = r->operation->dump.flags | (r->operation->flash.flags << 16);
    Tb2RecordResult rc = tb2_record_new_id(r->io, e->id) ? tb2_entry_save(r->io, e) : Tb2RecordIo;
    free(e);
    return rc;
}
static STORE_WORKER_FRAME Tb2RecordResult original(Tb2StoreRequest* r) {
    Tb2Originals originals = {0};
    Tb2RecordResult rc = tb2_originals(r->io, r->record_id, r->firmware, &originals);
    r->found = !rc && r->firmware && r->firmware->known && originals.latest[0];
    if(r->found) strcpy(r->version_id, originals.latest);
    return rc;
}
Tb2RecordResult tb2_store_run(Tb2StoreRequest* r) {
    if(!r || !r->io) return Tb2RecordCorrupt;
    bool own_box = !r->box, own_version = !r->version;
    if(own_box) r->box = calloc(1, sizeof(*r->box));
    if(own_version) r->version = calloc(1, sizeof(*r->version));
    Tb2WorkshopBinding* b = calloc(1, sizeof(*b));
    Tb2RecordResult rc;
    if(!r->box || !r->version || !b) {
        rc = Tb2RecordIo;
        goto done;
    }
    switch(r->action) {
    case Tb2StoreOriginal:
        rc = original(r);
        break;
    case Tb2StoreRestoreKeys: {
        if(!r->donor_key || !r->key) {
            rc = Tb2RecordCorrupt;
            break;
        }
        Tb2InputKey* current = r->key;
        r->action = Tb2StoreLoadKey;
        r->key = r->donor_key;
        rc = store_key(r);
        r->key = current;
        r->version_id[0] = 0;
        if(!rc) rc = store_key(r);
        break;
    }
    case Tb2StoreTask:
        rc = tb2_record_task_run(r->io, r->task);
        break;
    case Tb2StoreDeleteVersion:
        rc = tb2_version_delete(r->io, r->record_id, r->version_id);
        break;
    case Tb2StoreSaveEntry:
        rc = save_event(r);
        break;
    case Tb2StoreRestorePlan:
    case Tb2StoreLoadRestorePlan:
        rc = restore_plan(r);
        break;
    case Tb2StoreCheckout:
        rc = tb2_version_load(r->io, r->record_id, r->version_id, r->version);
        if(!rc)
            rc = tb2_version_image_path(
                r->io, r->record_id, r->version_id, &r->version->image, r->path);
        if(!rc) rc = verify_version(r);
        break;
    case Tb2StoreSaveKey:
    case Tb2StoreLoadKey:
        rc = store_key(r);
        break;
    case Tb2StoreArchive:
        rc = archive_image(r);
        break;
    case Tb2StoreVerify:
        rc = own_version ? tb2_version_load(r->io, r->record_id, r->version_id, r->version) :
                           Tb2RecordOk;
        if(!rc) rc = verify_version(r);
        break;
    case Tb2StoreBackup:
        rc = own_box ? tb2_box_load(r->io, r->record_id, r->box) : Tb2RecordOk;
        if(!rc) rc = find_backup(r);
        if(!rc && r->found) strcpy(r->version_id, r->version->id);
        if(!rc && r->found && r->staging && r->staging[0]) {
            rc = tb2_workshop_load(r->io, r->staging, r->descriptor_crc, b);
            if(!rc) rc = tb2_workshop_link(r->io, r->staging, b, Tb2WorkshopBackup, r->version);
        }
        break;
    case Tb2StoreFlashReady:
        rc = tb2_workshop_load(r->io, r->staging, r->descriptor_crc, b);
        if(!rc && strcmp(b->box, r->record_id)) rc = Tb2RecordConflict;
        if(!rc) {
            unsigned slot = b->published & (1U << Tb2WorkshopBackup) ? Tb2WorkshopBackup :
                                                                       Tb2WorkshopSource;
            if(!(b->published & (1U << slot)) || !(b->published & (1U << Tb2WorkshopTarget)))
                rc = Tb2RecordMissing;
            if(!rc) rc = tb2_version_load(r->io, b->box, b->versions[slot], r->version);
            if(!rc && !(r->version->flags & Tb2VersionSource)) rc = Tb2RecordConflict;
            if(!rc) rc = verify_version(r);
            if(!rc)
                rc = tb2_version_load(r->io, b->box, b->versions[Tb2WorkshopTarget], r->version);
            if(!rc && r->expected &&
               (r->expected->size != r->version->image.size ||
                memcmp(r->expected->digest, r->version->image.digest, 32)))
                rc = Tb2RecordConflict;
            if(!rc) rc = verify_version(r);
        }
        break;
    case Tb2StoreBoundBackup:
        rc = tb2_workshop_load(r->io, r->staging, r->descriptor_crc, b);
        if(!rc && strcmp(b->box, r->record_id)) rc = Tb2RecordConflict;
        if(!rc && !(b->published & (1U << Tb2WorkshopBackup))) rc = Tb2RecordMissing;
        if(!rc) rc = tb2_version_load(r->io, b->box, b->versions[Tb2WorkshopBackup], r->version);
        if(!rc && !(r->version->flags & Tb2VersionSource)) rc = Tb2RecordConflict;
        if(!rc) rc = verify_version(r);
        break;
    case Tb2StoreDescribe:
        rc = tb2_box_load(r->io, r->record_id, r->box);
        if(!rc) {
            strcpy(r->alias, r->box->alias);
            r->uid_available = r->box->has_uid;
            memcpy(r->uid, r->box->uid, sizeof(r->uid));
        }
        break;
    case Tb2StoreFindUid:
        rc = find_uid(r);
        if(!rc && r->found) {
            strcpy(r->record_id, r->box->id);
            strcpy(r->alias, r->box->alias);
        }
        break;
    case Tb2StoreBind:
        rc = bind(r, b);
        break;
    case Tb2StoreLoadBinding:
        rc = tb2_workshop_load(r->io, r->staging, r->descriptor_crc, b);
        if(!rc) {
            strcpy(r->record_id, b->box);
            if((unsigned)r->slot < TB2_WORKSHOP_SLOTS) strcpy(r->version_id, b->versions[r->slot]);
        }
        break;
    case Tb2StoreCapture:
        rc = capture(r, b);
        break;
    default:
        rc = Tb2RecordCorrupt;
        break;
    }
done:
    if(rc)
        snprintf(
            r->error,
            sizeof(r->error),
            "%s",
            rc == Tb2RecordCancelled ? "Archive operation stopped." :
            rc == Tb2RecordConflict  ? "Record binding conflict. Select the correct box." :
            rc == Tb2RecordCorrupt   ? "Record or archive damaged. Check details." :
                                       "Cannot save/read box archive. Check SD and retry.");
    free(b);
    if(own_box) {
        free(r->box);
        r->box = NULL;
    }
    if(own_version) {
        free(r->version);
        r->version = NULL;
    }
    return rc;
}
