#include "record_tasks.h"
#include "backend.h"
#include "record_archive.h"
#include "record_import.h"
#include "editions.h"
#include "probe.h"
#include "package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE_TAR_BLOCK 512U
static const char* const import_package_names[TB2_PACKAGE_FILES] = TB2_PACKAGE_FILENAMES;

static bool package_path(char out[TB2_JOB_PATH_MAX], const char* directory, const char* name) {
    int n = snprintf(out, TB2_JOB_PATH_MAX, "%s/%s", directory, name);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static bool tar_octal(const uint8_t* bytes, size_t size, uint32_t* value) {
    *value = 0;
    bool digit = false, ended = false;
    for(size_t i = 0; i < size; i++) {
        uint8_t c = bytes[i];
        if(!c || c == ' ') {
            if(digit) ended = true;
            continue;
        }
        if(ended || c < '0' || c > '7' || *value > (UINT32_MAX - (c - '0')) / 8U) return false;
        *value = *value * 8U + c - '0';
        digit = true;
    }
    return digit;
}
static int package_name_index(const char* name) {
    for(unsigned i = 0; i < TB2_PACKAGE_FILES; i++)
        if(!strcmp(name, import_package_names[i])) return (int)i;
    return !strcmp(name, "ca.der") ? (int)TB2_PACKAGE_FILES : -1;
}
static Tb2RecordResult
    package_extract_tar(Tb2WorkflowIO* io, const char* archive, const char* target) {
    for(unsigned i = 0; i <= TB2_PACKAGE_FILES; i++) {
        char old[TB2_JOB_PATH_MAX];
        const char* name = i < TB2_PACKAGE_FILES ? import_package_names[i] : "ca.der";
        if(!package_path(old, target, name)) return Tb2RecordCorrupt;
        int present = io->exists(io->context, old);
        if(present < 0 || (present && !io->remove(io->context, old))) return Tb2RecordIo;
    }
    void* input = io->open(io->context, archive, Tb2FileRead);
    if(!input) return Tb2RecordIo;
    uint64_t archive_size = io->size(io->context, input), position = 0;
    uint8_t header[PACKAGE_TAR_BLOCK], seen = 0;
    Tb2RecordResult rc = Tb2RecordOk;
    for(;;) {
        if(io->read(io->context, input, header, sizeof(header)) != sizeof(header)) {
            rc = Tb2RecordCorrupt;
            break;
        }
        position += sizeof(header);
        bool zero = true;
        for(size_t i = 0; i < sizeof(header); i++)
            if(header[i]) zero = false;
        if(zero) {
            if(io->read(io->context, input, header, sizeof(header)) != sizeof(header)) {
                rc = Tb2RecordCorrupt;
                break;
            }
            position += sizeof(header);
            for(size_t i = 0; i < sizeof(header); i++)
                if(header[i]) rc = Tb2RecordCorrupt;
            if(position != archive_size) rc = Tb2RecordCorrupt;
            break;
        }
        uint32_t stored = 0, size = 0, sum = 0;
        if(!memchr(header, 0, 100) || !tar_octal(header + 148, 8, &stored) ||
           !tar_octal(header + 124, 12, &size) || size > TB2_PACKAGE_FILE_MAX ||
           (header[156] && header[156] != '0')) {
            rc = Tb2RecordCorrupt;
            break;
        }
        for(unsigned i = 0; i < sizeof(header); i++)
            sum += i >= 148 && i < 156 ? ' ' : header[i];
        int index = package_name_index((char*)header);
        if(sum != stored || index < 0 || (seen & (1U << index))) {
            rc = Tb2RecordCorrupt;
            break;
        }
        seen |= 1U << index;
        char path[TB2_JOB_PATH_MAX];
        if(!package_path(path, target, (char*)header)) {
            rc = Tb2RecordCorrupt;
            break;
        }
        void* output = io->open(io->context, path, Tb2FileNew);
        uint8_t bytes[PACKAGE_TAR_BLOCK];
        uint32_t padded = (size + PACKAGE_TAR_BLOCK - 1U) & ~(PACKAGE_TAR_BLOCK - 1U);
        for(uint32_t offset = 0; output && !rc && offset < padded; offset += sizeof(bytes)) {
            if(io->read(io->context, input, bytes, sizeof(bytes)) != sizeof(bytes))
                rc = Tb2RecordCorrupt;
            size_t count = size > offset ? size - offset : 0;
            if(count > sizeof(bytes)) count = sizeof(bytes);
            if(!rc && count && io->write(io->context, output, bytes, count) != count)
                rc = Tb2RecordIo;
        }
        position += padded;
        if(!output) rc = Tb2RecordIo;
        if(output) {
            bool ok = io->sync(io->context, output);
            ok = io->close(io->context, output) && ok;
            if(!ok) rc = Tb2RecordIo;
        }
        if(rc) break;
    }
    if(!io->close(io->context, input) && !rc) rc = Tb2RecordIo;
    if(!rc && (seen & 0x3fU) != 0x3fU) rc = Tb2RecordCorrupt;
    return rc;
}

static void hex(const uint8_t digest[32], char out[65]) {
    for(unsigned i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
}
static const char* match(const uint8_t a[32], const uint8_t b[32]) {
    const uint8_t empty[32] = {0};
    return !memcmp(a, empty, 32) || !memcmp(b, empty, 32) ? "Unknown" :
           !memcmp(a, b, 32)                              ? "Same" :
                                                            "Different";
}
static Tb2RecordResult compare(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    Tb2BoxVersion* versions = calloc(2, sizeof(*versions));
    if(!versions) return Tb2RecordIo;
    Tb2BoxVersion* a = versions;
    Tb2BoxVersion* b = versions + 1;
    Tb2RecordResult rc = tb2_version_load(io, task->box, task->version, a);
    if(!rc) rc = tb2_version_load(io, task->box, task->other, b);
    if(!rc) {
        bool endpoints = (a->flags & b->flags & Tb2VersionEndpointsKnown) != 0;
        bool package = a->artifacts[5].size && b->artifacts[5].size;
        bool package_same = package;
        for(unsigned i = 5; package_same && i < TB2_RECORD_ARTIFACTS; i++)
            package_same = a->artifacts[i].size == b->artifacts[i].size &&
                           !memcmp(a->artifacts[i].digest, b->artifacts[i].digest, 32);
        snprintf(
            task->report,
            sizeof(task->report),
            "Saved comparison\nv%lu: %s\nv%lu: %s\nFirmware: %s\n%s / %s\nImage: %s\nCA: %s\nClient: %s\nPackage: %s\nEndpoints: %s\nOTA: %s:%u / %s:%u\nICI: %s:%u / %s:%u\nImage check: %s / %s\nCert check: %s / %s\nWorking: %s / %s\nChip not checked.",
            (unsigned long)a->number,
            a->name,
            (unsigned long)b->number,
            b->name,
            a->firmware.known && b->firmware.known ?
                match(a->firmware.digest, b->firmware.digest) :
                "Unknown",
            a->firmware.known ? a->firmware.version : "Unknown",
            b->firmware.known ? b->firmware.version : "Unknown",
            match(a->image.digest, b->image.digest),
            match(a->ca_fingerprint, b->ca_fingerprint),
            match(a->client_fingerprint, b->client_fingerprint),
            !package     ? "Unknown" :
            package_same ? "Same" :
                           "Different",
            endpoints ? "Recorded" : "Unknown",
            a->endpoints.https_host[0] ? a->endpoints.https_host : "Unknown",
            a->endpoints.https_port,
            b->endpoints.https_host[0] ? b->endpoints.https_host : "Unknown",
            b->endpoints.https_port,
            a->endpoints.mqtt_host[0] ? a->endpoints.mqtt_host : "Unknown",
            a->endpoints.mqtt_port,
            b->endpoints.mqtt_host[0] ? b->endpoints.mqtt_host : "Unknown",
            b->endpoints.mqtt_port,
            a->flags & Tb2VersionImageChecked ? "Recorded" : "Pending",
            b->flags & Tb2VersionImageChecked ? "Recorded" : "Pending",
            a->flags & Tb2VersionCertificatesChecked ? "Recorded" : "Pending",
            b->flags & Tb2VersionCertificatesChecked ? "Recorded" : "Pending",
            a->flags & Tb2VersionWorking ? "User confirmed" : "Not confirmed",
            b->flags & Tb2VersionWorking ? "User confirmed" : "Not confirmed");
    }
    free(versions);
    return rc;
}
static Tb2RecordResult save_note(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    Tb2BoxEntry* e = calloc(1, sizeof(*e));
    if(!e) return Tb2RecordIo;
    Tb2RecordResult rc = Tb2RecordOk;
    if(!task->entry[0] && !tb2_record_new_id(io, task->entry)) rc = Tb2RecordIo;
    if(!rc) {
        strcpy(e->id, task->entry);
        strcpy(e->box, task->box);
        strcpy(e->version, task->version);
        strcpy(e->text, task->note);
        e->timestamp = task->timestamp;
        e->note = true;
        rc = tb2_entry_save(io, e);
    }
    if(!rc) snprintf(task->report, sizeof(task->report), "Note saved.\n%s", e->text);
    free(e);
    return rc;
}
static Tb2RecordResult history(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    Tb2BoxEntry* e = calloc(1, sizeof(*e));
    if(!e) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_entry_load(io, task->box, task->entry, task->flags != 0, e);
    static const char* const states[] = {
        "Unknown",
        "Prepared",
        "Interrupted",
        "Complete",
        "Stopped",
        "Failed",
        "Aborted",
        "Complete (legacy)",
        "Incomplete"};
    static const char* const actions[] = {
        "Unknown", "Dump", "Flash", "AIO", "Modify", "Certificates restore"};
    if(!rc)
        snprintf(
            task->report,
            sizeof(task->report),
            "Saved state\n%s UTC\n%s\n%s\nState: %s\nResult: %ld\nVersion: %s\nJob: %s\nSequence: %lu\nFlags: %lu\nSaved flash result; current chip not checked.",
            task->note,
            e->type < sizeof(actions) / sizeof(*actions) ? actions[e->type] :
                                                           "User classification",
            e->note ? e->text : "",
            e->type == Tb2EventClassification           ? "User confirmed" :
            e->state < sizeof(states) / sizeof(*states) ? states[e->state] :
                                                          "Unknown",
            (long)e->code,
            e->version,
            e->job,
            (unsigned long)e->sequence,
            (unsigned long)e->flags);
    free(e);
    return rc;
}
static Tb2RecordResult details(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!v) return Tb2RecordIo;
    bool version = task->kind == Tb2RecordTaskVersionDetails;
    Tb2RecordResult rc = version ? tb2_version_load(io, box->id, task->version, v) : Tb2RecordOk;
    Tb2Originals originals = {0};
    if(!rc) rc = tb2_originals(io, box->id, version ? &v->firmware : NULL, &originals);
    if(!rc && !version) {
        snprintf(
            task->report,
            sizeof(task->report),
            "%s\nBox ID: %s\nPrinted: %s\nChip UID: %s\nRecord: %s\nFirst original: %s (v%lu)\nLatest original: %s (v%lu)\nSequence: %lu\nSaved state; chip not checked.",
            box->alias,
            box->box_id[0] ? box->box_id : "Unknown",
            box->serial[0] ? box->serial : "Unknown",
            box->has_uid ? "Linked" : "Unknown",
            box->id,
            originals.first[0] ? originals.first : "None",
            (unsigned long)originals.first_number,
            originals.latest[0] ? originals.latest : "None",
            (unsigned long)originals.latest_number,
            (unsigned long)box->next_version);
    } else if(!rc) {
        char path[TB2_JOB_PATH_MAX], digest[65], firmware[65], ca[65], client[65];
        Tb2Edition* edition = calloc(1, sizeof(*edition));
        if(!edition) {
            free(v);
            return Tb2RecordIo;
        }
        Tb2RecordResult edition_rc = tb2_edition_load(io, box->id, v->id, edition);
        const Tb2FirmwareIdentity* primary = !edition_rc ? &edition->primary : &v->firmware;
        const char* secondary =
            !edition_rc && edition->secondary.known ? edition->secondary.version : "Unknown";
        bool located = !tb2_version_image_path(io, box->id, v->id, &v->image, path);
        int present = located ? io->exists(io->context, path) : -1;
        hex(v->image.digest, digest);
        hex(v->firmware.digest, firmware);
        hex(v->ca_fingerprint, ca);
        hex(v->client_fingerprint, client);
        snprintf(
            task->report,
            sizeof(task->report),
            "Saved state\n%s\nv%lu / %s\nDate UTC: %s\nSlot A: %s\nSlot B: %s\nFirmware SHA256: %s\nImage: %s\n%s\nSize: %lu\nSHA256: %s\nParent: %s\nJob: %s\nApp: %s\n%s\nImage check: %s\nCert check: %s\nCA: %s\nClient: %s\nPackage: %s\nOTA: %s:%u\nICI: %s:%u\nLatest original: %s (v%lu)\nHeader may differ from booted firmware.",
            v->name,
            (unsigned long)v->number,
            v->id,
            v->created,
            primary->known ? primary->version : "Unknown",
            secondary,
            v->firmware.known ? firmware : "Unknown",
            located ? path : "Unknown",
            present == 1 ? "File present; not checked now" :
            present == 0 ? "Image missing" :
                           "File access failed",
            (unsigned long)v->image.size,
            digest,
            v->parent,
            v->job,
            v->app,
            v->flags & Tb2VersionProtected ? "Protected" : "Unprotected",
            v->flags & Tb2VersionImageChecked ? "Recorded" : "Pending",
            v->flags & Tb2VersionCertificatesChecked ? "Recorded" : "Pending",
            v->flags & Tb2VersionCertificatesChecked ? ca : "Unknown",
            v->flags & Tb2VersionCertificatesChecked ? client : "Unknown",
            v->artifacts[5].size ? "Retained" : "Unavailable",
            v->flags & Tb2VersionEndpointsKnown ? v->endpoints.https_host : "Unknown",
            v->endpoints.https_port,
            v->flags & Tb2VersionEndpointsKnown ? v->endpoints.mqtt_host : "Unknown",
            v->endpoints.mqtt_port,
            v->firmware.known && originals.latest[0] ? originals.latest : "Unknown",
            (unsigned long)(v->firmware.known ? originals.latest_number : 0));
        free(edition);
    }
    free(v);
    return rc;
}
/** Parse full MCUboot ranges without the five-digit filename editor's limits. */
static bool header_version(const Tb2FirmwareIdentity* firmware, uint32_t parts[4]) {
    if(!firmware->known) return false;
    const char* text = firmware->version;
    static const uint32_t limits[] = {UINT8_MAX, UINT8_MAX, UINT16_MAX, UINT32_MAX};
    for(unsigned i = 0; i < 4; ++i) {
        parts[i] = 0;
        if(i == 3 && !*text) return true;
        if(*text < '0' || *text > '9') return false;
        do {
            unsigned digit = (unsigned)(*text++ - '0');
            if(parts[i] > (limits[i] - digit) / 10U) return false;
            parts[i] = parts[i] * 10U + digit;
        } while(*text >= '0' && *text <= '9');
        if(i < 2 && *text++ != '.') return false;
        if(i == 2 && *text && (*text++ != '+' || !*text)) return false;
    }
    return !*text;
}

static Tb2RecordResult version_action(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    if(task->kind == Tb2RecordTaskCompareChip)
        memset(&task->comparison, 0, sizeof(task->comparison));
    Tb2BoxVersion* version = calloc(1, sizeof(*version));
    if(!version) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_version_load(io, task->box, task->version, version);
    if(!rc && (version->flags & Tb2VersionDeleted)) rc = Tb2RecordMissing;
    if(!rc && task->kind == Tb2RecordTaskCompareChip) {
        rc = tb2_version_image_path(io, task->box, task->version, &version->image, task->path);
    } else if(!rc && task->kind == Tb2RecordTaskRename) {
        snprintf(version->name, sizeof(version->name), "%s", task->path);
        rc = tb2_version_rename(io, version);
        if(!rc) snprintf(task->report, sizeof(task->report), "Name saved.\n%s", version->name);
    } else if(!rc) {
        snprintf(task->path, sizeof(task->path), "%s", version->name);
        Tb2Edition* edition = calloc(1, sizeof(*edition));
        if(!edition)
            rc = Tb2RecordIo;
        else {
            rc = tb2_edition_load(io, task->box, task->version, edition);
            bool legacy = rc == Tb2RecordMissing;
            if(legacy) rc = Tb2RecordOk;
            uint32_t a[4], b[4];
            bool have_a = header_version(legacy ? &version->firmware : &edition->primary, a);
            bool have_b = !legacy && header_version(&edition->secondary, b);
            uint32_t* selected = have_a ? a : have_b ? b : NULL;
            if(have_a && have_b) {
                for(unsigned i = 0; i < 4; ++i) {
                    if(a[i] == b[i]) continue;
                    if(b[i] > a[i]) selected = b;
                    break;
                }
            }
            Tb2ImageKind kind = legacy ?
                                    ((version->flags & Tb2VersionOriginal) ? Tb2ImageOriginal :
                                     !(version->flags & Tb2VersionSource)  ? Tb2ImageModified :
                                                                             Tb2ImageUnclassified) :
                                    edition->kind;
            if(!rc && selected && kind != Tb2ImageUnclassified) {
                char stem[TB2_RECORD_ALIAS_SIZE], revision[16] = {0};
                tb2_file_stem(box->alias, stem);
                if(!legacy && edition->revision > 1)
                    snprintf(
                        revision, sizeof(revision), "_r%lu", (unsigned long)edition->revision);
                snprintf(
                    task->path,
                    sizeof(task->path),
                    "%s_%lu.%lu.%lu%s%s.bin",
                    stem,
                    (unsigned long)selected[0],
                    (unsigned long)selected[1],
                    (unsigned long)selected[2],
                    kind == Tb2ImageModified ? "_mod" : "",
                    revision);
            }
            free(edition);
        }
    }
    free(version);
    return rc;
}

static Tb2RecordResult save_box(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    if(task->flags == 2) {
        bool fresh = !task->box[0];
        if(fresh && !tb2_record_new_id(io, task->box)) return Tb2RecordIo;
        if(task->uid_available) {
            bool found = false;
            Tb2RecordResult match = tb2_box_find_uid(io, task->uid, task->box, box, &found);
            if(match || found) return match ? match : Tb2RecordConflict;
        }
        Tb2RecordResult rc = tb2_box_load(io, task->box, box);
        if(fresh && rc != Tb2RecordMissing) {
            task->box[0] = 0;
            return rc == Tb2RecordIo ? rc : Tb2RecordConflict;
        }
        if(rc != Tb2RecordMissing && rc != Tb2RecordCorrupt && rc != Tb2RecordOk) return rc;
        if(!rc) {
            if(strcmp(box->alias, task->note) ||
               (task->uid_available &&
                (!box->has_uid || memcmp(box->uid, task->uid, sizeof(box->uid)))))
                return Tb2RecordConflict;
            snprintf(task->report, sizeof(task->report), "Box record saved.\n%s", box->alias);
            return Tb2RecordOk; /* Retry cannot turn creation into an alias update. */
        }
        if(rc) {
            memset(box, 0, sizeof(*box));
            strcpy(box->id, task->box);
        }
        if(task->uid_available) {
            box->has_uid = true;
            memcpy(box->uid, task->uid, sizeof(box->uid));
        }
    }
    char* field = task->flags == 1 ? box->serial : box->alias;
    size_t capacity = task->flags == 1 ? sizeof(box->serial) : sizeof(box->alias);
    if(strlen(task->note) >= capacity) return Tb2RecordCorrupt;
    strcpy(field, task->note);
    Tb2RecordResult rc = tb2_box_save(io, box);
    if(!rc) snprintf(task->report, sizeof(task->report), "Box record saved.\n%s", box->alias);
    return rc;
}
static Tb2RecordResult classify(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    Tb2BoxVersion* v = calloc(1, sizeof(*v));
    if(!v) return Tb2RecordIo;
    Tb2RecordResult rc = tb2_version_load(io, task->box, task->version, v);
    if(!rc) {
        if(task->flags == Tb2VersionProtected)
            v->flags |= Tb2VersionProtected;
        else if(!task->flags)
            v->flags &= ~Tb2VersionProtected;
        else if(task->flags == Tb2VersionWorking)
            v->flags |= Tb2VersionWorking;
        else if(task->flags == Tb2VersionOriginal && (v->flags & Tb2VersionSource))
            v->flags |= Tb2VersionOriginal | Tb2VersionClassified;
        else if(task->flags == Tb2VersionClassified)
            v->flags |= Tb2VersionClassified;
        else
            rc = Tb2RecordConflict;
    }
    if(!rc) rc = tb2_version_save(io, v);
    if(!rc) {
        Tb2BoxEntry* e = calloc(1, sizeof(*e));
        if(!e)
            rc = Tb2RecordIo;
        else {
            if(!task->entry[0] && !tb2_record_new_id(io, task->entry)) rc = Tb2RecordIo;
            if(!rc) {
                strcpy(e->id, task->entry);
                strcpy(e->box, task->box);
                strcpy(e->version, task->version);
                e->timestamp = task->timestamp;
                e->type = Tb2EventClassification;
                e->flags = task->flags;
                rc = tb2_entry_save(io, e);
            }
            free(e);
        }
    }
    if(!rc)
        snprintf(
            task->report,
            sizeof(task->report),
            "Classification saved.\nv%lu\n%s\n%s",
            (unsigned long)v->number,
            v->name,
            v->flags & Tb2VersionProtected ? "Protected" : "Unprotected");
    free(v);
    return rc;
}
static Tb2RecordResult secret(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    Tb2BoxSecret* key = calloc(1, sizeof(*key));
    if(!key) return Tb2RecordIo;
    Tb2RecordResult rc = Tb2RecordOk;
    if(task->kind == Tb2RecordTaskKeyCandidate) {
        if(!task->entry[0] && !tb2_record_new_id(io, task->entry)) rc = Tb2RecordIo;
        if(!rc) {
            strcpy(key->id, task->entry);
            key->key = task->key;
            Tb2BoxSecret* existing = calloc(1, sizeof(*existing));
            rc = existing ? tb2_secret_load(io, box->id, key->id, existing) : Tb2RecordIo;
            if(!rc && (existing->key.kind != key->key.kind ||
                       memcmp(existing->key.bytes, key->key.bytes, sizeof(key->key.bytes))))
                rc = Tb2RecordConflict;
            else if(rc == Tb2RecordMissing || rc == Tb2RecordCorrupt)
                rc = tb2_secret_save(io, box->id, key);
            if(existing) {
                tb2_record_wipe(existing, sizeof(*existing));
                free(existing);
            }
        }
        if(!rc) {
            strcpy(box->candidate, key->id);
            rc = tb2_box_save(io, box);
        }
        if(!rc)
            snprintf(
                task->report,
                sizeof(task->report),
                "Unverified key saved.\nVerified key kept.\nValidate the proposal in Modify.");
    } else {
        rc = box->secret[0] ? tb2_secret_load(io, box->id, box->secret, key) : Tb2RecordMissing;
        if(rc == Tb2RecordMissing) rc = Tb2RecordOk;
        if(!rc) {
            char firmware[65];
            hex(key->firmware, firmware);
            snprintf(
                task->report,
                sizeof(task->report),
                "Secret association\nVerified: %s\nType: %s\nKDF: %lu\nFirmware: %s\nproposal: %s\nKey values and paths hidden.",
                key->verified ? "Available" : "None",
                key->key.kind == Tb2InputKeySecret ? "8-byte box secret" :
                key->key.kind == Tb2InputKeyAes    ? "16-byte AES" :
                                                     "Unknown",
                (unsigned long)key->profile,
                key->verified ? firmware : "Unknown",
                box->candidate[0] ? "Available" : "None");
        }
    }
    tb2_record_wipe(key, sizeof(*key));
    free(key);
    return rc;
}
static Tb2RecordResult import_inspect(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    (void)box;
    Tb2ImportDraft* draft = &task->import;
    if(!draft->identity_checked) return Tb2RecordCorrupt;
    Tb2RecordResult rc = tb2_file_inspect(io, task->path, TB2_IMAGE_SIZE, &draft->image);
    if(!rc) {
        draft->stage = draft->image_kind == Tb2ImageModified ? Tb2ImportImageVersion :
                                                               Tb2ImportImageType;
        draft->manual_identity = !draft->identity.box_id[0];
        draft->label_confirmed = false;
        memset(&draft->label, 0, sizeof(draft->label));
        snprintf(
            task->report,
            sizeof(task->report),
            "Image checked: 16 MiB, SHA-256 saved.\nBox ID: %s\nSlot A: %s\nSlot B: %s\nChoose type and file version.%s",
            draft->identity.box_id[0] ? draft->identity.box_id : "Unknown",
            draft->identity.firmware.known ? draft->identity.firmware.version : "Unknown",
            draft->identity.secondary.known ? draft->identity.secondary.version : "Unknown",
            draft->manual_identity ? "\nUnknown identity; manual box assignment." : "");
    }
    return rc;
}

static Tb2RecordResult import_preview(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    Tb2ImportDraft* draft = &task->import;
    if(!draft->label_confirmed || draft->image.size != TB2_IMAGE_SIZE ||
       (draft->image_kind != Tb2ImageOriginal && draft->image_kind != Tb2ImageModified))
        return Tb2RecordCorrupt;
    if(box->box_id[0] && draft->identity.box_id[0] && strcmp(box->box_id, draft->identity.box_id))
        return Tb2RecordConflict;
    char existing[TB2_RECORD_ID_SIZE];
    Tb2RecordResult rc = tb2_file_duplicate(io, box->id, &draft->image, existing);
    if(!rc && existing[0]) {
        draft->duplicate = true;
        strcpy(task->version, existing);
        Tb2Edition edition;
        rc = tb2_edition_load(io, box->id, existing, &edition);
        if(!rc) {
            draft->revision = edition.revision;
            snprintf(draft->output, sizeof(draft->output), "%s", edition.path);
        } else if(rc == Tb2RecordMissing) {
            Tb2BoxVersion version;
            rc = tb2_version_load(io, box->id, existing, &version);
            if(!rc) snprintf(draft->output, sizeof(draft->output), "Legacy version %s", existing);
        }
    } else if(!rc) {
        Tb2Edition edition = {
            .label = draft->label,
            .kind = draft->image_kind,
            .primary = draft->identity.firmware,
            .secondary = draft->identity.secondary,
            .label_manual = draft->label_manual};
        if(task->version[0]) strcpy(edition.id, task->version);
        edition.image = draft->image;
        rc = tb2_file_reserve(io, box, &edition);
        if(!rc) {
            draft->duplicate = false;
            draft->revision = edition.revision;
            strcpy(task->version, edition.id);
            snprintf(draft->output, sizeof(draft->output), "%s", edition.path);
        }
    }
    if(!rc) {
        char label[TB2_FILE_VERSION_TEXT];
        tb2_file_version_format(&draft->label, label, sizeof(label));
        draft->stage = Tb2ImportImagePreview;
        snprintf(
            task->report,
            sizeof(task->report),
            "%s\nBox: %s\nType: %s\nVersion: %s\nRevision: %lu\nTarget:\n%s",
            draft->duplicate ? "Already imported; no duplicate created." : "Import preview",
            box->alias,
            draft->image_kind == Tb2ImageOriginal ? "Original" : "Modified",
            label,
            (unsigned long)draft->revision,
            draft->output);
    }
    return rc;
}

static Tb2RecordResult target_reserve(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    Tb2ImportDraft* draft = &task->import;
    if(!draft->label_confirmed || !tb2_file_version_valid(&draft->label)) return Tb2RecordCorrupt;
    Tb2Edition edition = {
        .label = draft->label,
        .kind = Tb2ImageModified,
        .primary = draft->identity.firmware,
        .secondary = draft->identity.secondary,
        .label_manual = draft->label_manual};
    if(task->version[0]) strcpy(edition.id, task->version);
    Tb2RecordResult rc = tb2_file_reserve(io, box, &edition);
    if(!rc) {
        strcpy(task->version, edition.id);
        draft->revision = edition.revision;
        draft->image_kind = Tb2ImageModified;
        snprintf(draft->output, sizeof(draft->output), "%s", edition.path);
        snprintf(task->report, sizeof(task->report), "Modified image reserved.\n%s", edition.path);
    }
    return rc;
}

static Tb2RecordResult import_image(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box) {
    Tb2ImportDraft* draft = &task->import;
    bool captured_dump = task->kind == Tb2RecordTaskFilePublish;
    if(draft->duplicate) {
        if(captured_dump && io->exists(io->context, task->path) == 1 &&
           !io->remove(io->context, task->path))
            return Tb2RecordIo;
        snprintf(
            task->report,
            sizeof(task->report),
            "Verified dump already exists.\n%s\nTemporary duplicate removed.",
            draft->output);
        return Tb2RecordOk;
    }
    Tb2ObjectRef current;
    Tb2RecordResult rc = tb2_file_inspect(io, task->path, TB2_IMAGE_SIZE, &current);
    if(!rc && (current.size != draft->image.size ||
               memcmp(current.digest, draft->image.digest, sizeof(current.digest))))
        rc = Tb2RecordConflict;
    Tb2Edition edition = {0};
    if(!rc) rc = tb2_edition_load(io, box->id, task->version, &edition);
    if(!rc && (edition.flags & Tb2EditionPublished || edition.kind != draft->image_kind ||
               tb2_file_version_compare(&edition.label, &draft->label) ||
               edition.revision != draft->revision || strcmp(edition.path, draft->output)))
        rc = Tb2RecordConflict;
    Tb2BoxVersion version = {0};
    if(!rc) {
        strcpy(version.id, edition.id);
        strcpy(version.box, box->id);
        version.number = edition.number;
        version.image = draft->image;
        version.firmware = draft->identity.firmware;
        version.flags = Tb2VersionSource;
        if(!captured_dump) version.flags |= Tb2VersionClassified;
        if(!captured_dump && draft->image_kind == Tb2ImageOriginal)
            version.flags |= Tb2VersionOriginal | Tb2VersionProtected;
        snprintf(version.name, sizeof(version.name), "%s", strrchr(edition.path, '/') + 1);
        snprintf(version.app, sizeof(version.app), "%s", TB2_PROBE_VERSION);
        snprintf(
            version.created, sizeof(version.created), "%014lu", (unsigned long)task->timestamp);
        rc = tb2_file_publish(io, &edition, &version, task->path, captured_dump);
    }
    if(!rc) {
        draft->stage = Tb2ImportDone;
        snprintf(
            task->report,
            sizeof(task->report),
            captured_dump ? "Dump published.\n%s\nTemporary file moved; one BIN remains." :
                            "Image imported.\n%s\nChecked copy saved; source unchanged.",
            edition.path);
    }
    return rc;
}

static Tb2RecordResult package_stage(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    if(task->staging[0]) return io->mkdir(io->context, task->staging) ? Tb2RecordOk : Tb2RecordIo;
    char id[TB2_RECORD_ID_SIZE];
    if(!tb2_record_new_id(io, id)) return Tb2RecordIo;
    int n = snprintf(task->staging, sizeof(task->staging), "%s/package-%s", TB2_JOBS_ROOT, id);
    if(n <= 0 || n >= (int)sizeof(task->staging) || !io->mkdir(io->context, TB2_JOBS_ROOT) ||
       !io->mkdir(io->context, task->staging))
        return Tb2RecordIo;
    return Tb2RecordOk;
}

static Tb2RecordResult
    import_package(Tb2WorkflowIO* io, Tb2RecordTask* task, Tb2BoxRecord* box, bool publish) {
    Tb2RecordResult rc = package_stage(io, task);
    const char* directory = task->import.package_folder ? task->path : task->staging;
    if(!rc && !publish && !task->import.package_folder) {
        rc = package_extract_tar(io, task->path, task->staging);
        directory = task->staging;
    }
    Tb2PackageImportResult* result = &task->import.package_result;
    if(!rc && publish && !task->import.package_checked) rc = Tb2RecordConflict;
    if(!rc && publish) {
        Tb2ServerPackage saved = {0};
        strcpy(saved.box, box->id);
        if(task->import.package[0])
            strcpy(saved.id, task->import.package);
        else if(!tb2_record_new_id(io, saved.id))
            rc = Tb2RecordIo;
        saved.validity = result->package.validity;
        memcpy(saved.digest, result->package.package_sha256, sizeof(saved.digest));
        memcpy(saved.ca_fingerprint, result->package.ca_sha256, sizeof(saved.ca_fingerprint));
        for(unsigned i = 0; !rc && i < TB2_SERVER_PACKAGE_OBJECTS; i++) {
            char path[TB2_JOB_PATH_MAX];
            const char* root = i < TB2_PACKAGE_FILES ? directory : task->staging;
            const char* name = i < TB2_PACKAGE_FILES ? import_package_names[i] : "ca.der";
            Tb2ObjectRef expected = {.size = result->size[i]};
            memcpy(expected.digest, result->sha256[i], sizeof(expected.digest));
            if(!package_path(path, root, name))
                rc = Tb2RecordCorrupt;
            else
                rc = tb2_object_put(io, path, task->staging, &expected, &saved.objects[i]);
        }
        if(!rc) rc = tb2_server_package_save(io, &saved);
        if(!rc) {
            strcpy(task->import.package, saved.id);
            if(task->version[0]) {
                Tb2Edition edition;
                rc = tb2_edition_load(io, box->id, task->version, &edition);
                if(!rc) rc = tb2_package_assign(io, &edition, saved.id);
            }
        }
    }
    if(rc && result->package.error[0])
        snprintf(
            task->report,
            sizeof(task->report),
            "Server package rejected.\n%s",
            result->package.error);
    if(!rc) {
        task->import.stage = publish ? Tb2ImportDone : Tb2ImportPackageTarget;
        snprintf(
            task->report,
            sizeof(task->report),
            publish ? "Server package stored.\nAssignment: %s" :
                      "Package staged.\nChecking certificates, signatures and key pairs...",
            task->version[0] ? "Selected Modified version" : "Unassigned");
    }
    return rc;
}
Tb2RecordResult tb2_record_task_run(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    if(!io || !task) return Tb2RecordCorrupt;
    task->report[0] = 0;
    Tb2BoxRecord* box = calloc(1, sizeof(*box));
    if(!box) return Tb2RecordIo;
    Tb2RecordResult rc = task->kind == Tb2RecordTaskImport ||
                                 (task->kind == Tb2RecordTaskSaveBox && task->flags == 2) ?
                             Tb2RecordOk :
                             tb2_box_load(io, task->box, box);
    if(io->cancelled && io->cancelled(io->context)) rc = Tb2RecordCancelled;
    if(!rc) switch(task->kind) {
        case Tb2RecordTaskCompare:
            rc = compare(io, task);
            break;
        case Tb2RecordTaskRenamePrepare:
        case Tb2RecordTaskRename:
        case Tb2RecordTaskCompareChip:
            rc = version_action(io, task, box);
            break;
        case Tb2RecordTaskOverview:
        case Tb2RecordTaskVersionDetails:
            rc = details(io, task, box);
            break;
        case Tb2RecordTaskHistory:
            rc = history(io, task);
            break;
        case Tb2RecordTaskSaveBox:
            rc = save_box(io, task, box);
            break;
        case Tb2RecordTaskClassify:
            rc = classify(io, task);
            break;
        case Tb2RecordTaskExport:
        case Tb2RecordTaskPackage:
        case Tb2RecordTaskDiagnostic:
            rc = tb2_record_archive(io, task);
            break;
        case Tb2RecordTaskImport:
            rc = tb2_record_import(io, task);
            break;
        case Tb2RecordTaskDelete:
            rc = tb2_version_delete(io, task->box, task->version);
            if(!rc)
                snprintf(
                    task->report,
                    sizeof(task->report),
                    "Version deleted.\nUnused objects removed; shared objects and working BINs kept.");
            break;
        case Tb2RecordTaskNote:
            rc = save_note(io, task);
            break;
        case Tb2RecordTaskSecret:
        case Tb2RecordTaskKeyCandidate:
            rc = secret(io, task, box);
            break;
        case Tb2RecordTaskImportKey:
            /* Parsed by the storage adapter before this dispatcher runs. */
            rc = task->key.kind ? Tb2RecordOk : Tb2RecordCorrupt;
            break;
        case Tb2RecordTaskImportInspect:
            rc = import_inspect(io, task, box);
            break;
        case Tb2RecordTaskFilePreview:
            rc = import_preview(io, task, box);
            break;
        case Tb2RecordTaskImportImage:
        case Tb2RecordTaskFilePublish:
            rc = import_image(io, task, box);
            break;
        case Tb2RecordTaskImportPackage:
            rc = import_package(io, task, box, false);
            break;
        case Tb2RecordTaskPackageAssign:
            rc = import_package(io, task, box, true);
            break;
        case Tb2RecordTaskTargetReserve:
            rc = target_reserve(io, task, box);
            break;
        default:
            rc = Tb2RecordCorrupt;
            break;
        }
    if(rc && !task->report[0])
        snprintf(
            task->report,
            sizeof(task->report),
            "%s",
            rc == Tb2RecordProtected ?
                "Protected version. Unlock before deleting." :
            rc == Tb2RecordConflict ?
                "Record conflict. Existing association kept." :
            rc == Tb2RecordCancelled ?
                "Operation stopped. Saved data remains available." :
                "Record or SD failed. Check the card and retry. Unclear references block deletion.");
    task->result = rc;
    free(box);
    return rc;
}
